"""Bind reviewed protected inputs to one sequence and read-only handoff.

Not a CLI/installer or OS supervisor. Production requires an independently
reviewed actual package and trusted interpreter/source deployment. Constructors
perform no mutation; run() explicitly writes evidence/journal and changes apps.
"""
from pathlib import Path, PurePosixPath
import os
import sys
import threading
import time

from harbor_address_backend import AddressBackend
from harbor_address_compose import PinnedCompose, execution_model, remaining, require, validate_bind_sources
from harbor_address_evidence import AuditedCompose, Evidence, collect_partial, encode
from harbor_address_host import ProductionHost, ProductionReadOnly, ReadOnlyEngine
from harbor_address_inspect import FullPreservation
from harbor_address_journal import Journal
from harbor_address_package import load_package
from harbor_address_preservation import MountPreservation
from harbor_address_sequence import Sequence, fingerprint, validate_plan, MAINTENANCE_SCHEMAS, TRANSITION_SCHEMA

SOURCE_MODULES=('harbor_address_backend','harbor_address_compose','harbor_address_evidence','harbor_address_host',
                'harbor_address_input','harbor_address_inspect','harbor_address_journal','harbor_address_network','harbor_address_package',
                'harbor_address_preservation','harbor_address_sequence','harbor_address_session',
                'harbor_recovery_core','harbor_recovery_docker','harbor_recovery_host')


def assemble(values):
    """Pure linkage validation before writing any claim or process intent."""
    plan=validate_plan(values['plan.json'])
    require(plan['schema'] in MAINTENANCE_SCHEMAS,'SESSION_SCHEMA')
    model=values['model.json']
    projection=values['preservation.json']
    legacy=legacy_bindings(values)
    names={kind:{key:row['name'] for key,row in model.get(kind,{}).items()} for kind in ('networks','volumes')}
    expected=execution_model(values['base.json'],values['candidate.json'],resource_names=names,legacy_bindings=legacy)
    require(expected==model,'SESSION_MODEL_BINDING')
    require(type(projection) is dict and set(projection)=={'baseline','after_labels','after_host_mounts','auto_hostnames','auto_addresses'},
            'SESSION_PRESERVATION')
    full=FullPreservation(projection['baseline'],after_labels=projection['after_labels'],
                          after_host_mounts=projection['after_host_mounts'],auto_hostnames=projection['auto_hostnames'],
                          auto_addresses=projection['auto_addresses'])
    # PinnedCompose always selects exactly one service with --no-deps. Compose
    # removes non-selected dependencies before stamping this generated label.
    # Reject a full-model label before any claim; never learn it from post-state.
    require(all(row.get('com.docker.compose.depends_on') == ''
                for row in projection['after_labels'].values()), 'SESSION_NO_DEPS_LABEL')
    for service,raw in projection['baseline'].items():
        require(full.row(service,raw,recreated=False,mounts_verified=raw['Mounts'])==plan['baseline'][service], 'SESSION_BASELINE')
        require(model['services'][service]['image']==raw['Config']['Image'],'SESSION_IMAGE')
        # This execution path requires explicit container_name; Compose5.6
        # stamps that name (not the old ID) into the replacement label.
        require(model['services'][service]['container_name']==raw['Name'][1:],'SESSION_CONTAINER_NAME')
        require(values['host-policy.json']['images'][model['services'][service]['image']]==raw['Image'],'SESSION_IMAGE_ID')
    require(fingerprint(values['host-policy.json'])==plan['binding_sha256'] and
            values['host-policy.json']['inputs_sha256']==plan['inputs_sha256'], 'SESSION_HOST_BINDING')
    mount=MountPreservation(values['profile.json'])
    require(mount.profile['host_binding_sha256']==plan['binding_sha256'],'SESSION_PROFILE_BINDING')
    if plan['schema'] == TRANSITION_SCHEMA:
        require(values['host-policy.json']['schema']=='fds.harbor.production-address-host.v3',
                'SESSION_TRANSITION_HOST_REQUIRED')
        signal=projection['baseline']['postgresql']['Config'].get('StopSignal') or 'SIGTERM'
        require(signal=='SIGTERM' and model['services']['postgresql'].get('stop_signal','SIGTERM')=='SIGTERM',
                'SESSION_DB_SHUTDOWN_MISMATCH')
    return plan,model,full,mount


def legacy_bindings(values):
    """Explicit v2 only; reject old input before any claim, never after up."""
    policy=values['host-policy.json']
    baseline=values['preservation.json']['baseline']
    bindings={s:r['HostConfig'].get('Binds') or [] for s,r in baseline.items()}
    if policy.get('schema') not in ('fds.harbor.production-address-host.v2','fds.harbor.production-address-host.v3'):
        require(not any(bindings.values()),'SESSION_LEGACY_BIND_POLICY_REQUIRED')
        return None
    require(all(r['HostConfig'].get('Mounts') in (None,[]) for r in baseline.values()),'SESSION_LEGACY_HOST_MOUNTS')
    validate_bind_sources(bindings,policy['bind_sources'])
    return bindings


class ProtectedSession:
    def __init__(self, *, package_path, package_sha256, package_context,
                 journal_path, journal_context, evidence_path, evidence_context,
                 private_path, private_context, preparation_deadline, clock=time.monotonic):
        paths=[package_path,journal_path,evidence_path,private_path]
        require(all(type(p) is str and str(PurePosixPath(p))==p and p.startswith('/') and
                    p!='/' and '..' not in PurePosixPath(p).parts for p in paths),'SESSION_PATHS')
        require(all(a!=b and PurePosixPath(a) not in PurePosixPath(b).parents for i,a in enumerate(paths)
                    for j,b in enumerate(paths) if i!=j),'SESSION_PATH_OVERLAP')
        # Production does not have CI's no-SELinux option.
        require(all(type(c) is bytes and c and b'\0' not in c for c in
                    (package_context,journal_context,evidence_context,private_context)),'SESSION_CONTEXT')
        self.clock,self.used=clock,False
        self.pid,self.mutex=os.getpid(),threading.Lock()
        values=load_package(package_path,manifest_sha256=package_sha256,context=package_context,
                            deadline=preparation_deadline,clock=clock)
        plan,model,full,mount=assemble(values)
        # Old packages remain readable with inspect; never silently reinterpret
        # their I/O budget or network hash as a new mutation authorization.
        require(plan['schema']==TRANSITION_SCHEMA,'SESSION_TRANSITION_PLAN_REQUIRED')
        io=ProductionReadOnly(clock=clock);policy=values['host-policy.json']
        # This detects source/interpreter drift after a TRUSTED bootstrap. It
        # cannot make already imported arbitrary code trustworthy retroactively.
        sources={str(Path(sys.modules[n].__file__).resolve()) for n in SOURCE_MODULES}
        sources.add(str(Path(sys.executable).resolve()))
        require(sources <= set(policy['pinned_files']),'SESSION_UNPINNED_SOURCE')
        for path in sources:io.pinned(path,policy['pinned_files'][path],'file',preparation_deadline)
        engine=ReadOnlyEngine('1.56',clock=clock)
        host=ProductionHost(policy,profile=mount.profile,package_path=package_path,package_sha256=package_sha256,
             package_context=package_context,model_sha256=fingerprint(model),preservation_binding=full.binding,
             engine=engine,io=io,clock=clock)
        compose=policy['tools']['compose']
        process=PinnedCompose(binary=compose['path'],binary_sha256=compose['sha256'],binary_context=compose['selinux'].encode(),
                              private_directory=private_path,private_context=private_context,clock=clock,
                              legacy_bindings=legacy_bindings(values),bind_sources=policy.get('bind_sources'))
        self.evidence=Evidence(evidence_path,context=evidence_context,plan_sha256=fingerprint(plan),clock=clock)
        audited=AuditedCompose(process,self.evidence,clock=clock)
        backend=AddressBackend(plan,engine=engine,host_provider=host,preservation=full,mount_preservation=mount,
            execution_model=model,execution_model_sha256=fingerprint(model),process=audited,clock=clock,
            legacy_bindings=legacy_bindings(values))
        self.sequence=Sequence(plan,backend,Journal(journal_path,expected_selinux=journal_context),clock=clock)
        self.engine,self.ids=engine,{s:r['id'] for s,r in plan['baseline'].items()}

    def run(self, *, mutation_deadline, collection_deadline):
        require(self.mutex.acquire(blocking=False),'SESSION_BUSY')
        try:
            require(not self.used and os.getpid()==self.pid,'SESSION_SPENT');self.used=True
            remaining(mutation_deadline,self.clock);remaining(collection_deadline,self.clock)
            require(mutation_deadline<collection_deadline,'SESSION_COLLECTION_BUDGET')
            result,readback,sealed=None,None,False
            try:
                with self.evidence.locked(collection_deadline):
                    result=self.sequence.run(deadline_mono=mutation_deadline)
                    # A separate read/evidence budget does not extend mutation authority.
                    self.evidence.save(kind='SEQUENCE_RESULT',payloads={'private':encode(result)},diagnostic={},deadline=collection_deadline)
                    readback=collect_partial(self.engine,self.evidence,baseline_ids=self.ids,deadline=collection_deadline,clock=self.clock)
                sealed=True
            except Exception:
                pass  # fixed failure below; do not leak raw I/O exceptions
            return dict(sequence=result,collection=readback,private_evidence_path=self.evidence.path,
                        evidence_sealed=sealed,reason='EVIDENCE_SEALED' if sealed else 'EVIDENCE_OR_COLLECTION_UNAVAILABLE',
                        daemon_effects_may_continue=(result is None or result['status'] in
                            ('STOP_RECOVERY_REQUIRED','STOP_EXISTING_HISTORY_REQUIRES_REVIEW')),
                        runtime_acceptance=False,autostart_tested=False)
        finally:
            self.mutex.release()
