"""Synthetic continuation only. No production paths, Docker or credentials."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/production'),str(ROOT/'scripts/recovery')]
import harbor_address_sequence as seq
import harbor_address_session as session
import harbor_address_continuation as continuation
import harbor_address_compose as compose
import harbor_address_backend as backend
import harbor_address_journal as journal
import harbor_address_evidence as evidence
import harbor_address_package as package
import test_compose_backend as cb
import test_protected_runtime as rt
import test_sequence as sq


def reference():
    return dict(package=dict(path='/synthetic/old/package',sha256='a'*64,context='synthetic_t'),
        launch=dict(path='/synthetic/old/launch.json',sha256='b'*64,context='synthetic_t'),
        dispatch=dict(path='/synthetic/old/dispatch.claim',sha256='c'*64,context='synthetic_t'),
        evidence=dict(path='/synthetic/old/evidence',sha256='d'*64,context='synthetic_t'),
        plan_sha256='e'*64,source_revision='f'*40,sequence_record=4,database_record=5)


def fixture():
    x=rt.host_fixture();f=x['f'];prior=deepcopy(x['package'])
    for r in prior['preservation.json']['baseline'].values():
        r['RestartCount']=0;r['State'].update(Pid=50,StartedAt='synthetic-start',FinishedAt='synthetic-zero')
    for key in ('base.json','candidate.json'):
        for row in prior[key]['services'].values():row['volumes']=[]
    prior['host-policy.json'].update(schema='fds.harbor.production-address-host.v3',bind_sources={})
    prior['plan.json'].update(schema=seq.TRANSITION_SCHEMA,recreate_seconds={s:30 for s in seq.ORDER},
        db_shutdown={'strategy':'preserve-smart','effective_signal':'SIGTERM','on_timeout':'stop-and-handoff-no-retry'})
    rebind(prior)
    current=deepcopy(prior);projection=current['preservation.json']
    f['before']=deepcopy(prior['preservation.json']['baseline'])
    db=cb.recreated(f,'postgresql');db['State']['Pid']=90;db['State']['StartedAt']='synthetic-db-new'
    projection['baseline']['postgresql']=deepcopy(db)
    for key in ('after_labels','after_host_mounts'):projection[key].pop('postgresql',None)
    for key in ('auto_hostnames','auto_addresses'):projection[key].remove('postgresql')
    current['base.json']['services']['postgresql']['logging']['options']['syslog-address']=seq.NEW_ADDRESS
    current['model.json']=compose.execution_model(current['base.json'],current['candidate.json'],
        resource_names=f['names'],legacy_bindings={s:[] for s in seq.SERVICES},db_preserved=True)
    p=current['plan.json'];p.pop('db_shutdown');p['schema']=seq.DB_PRESERVED_SCHEMA;p['prior_execution']=reference()
    p['health_seconds'].pop('postgresql');p['recreate_seconds'].pop('postgresql')
    full=cb.i.FullPreservation(projection['baseline'],db_preserved=True,
                              **{k:v for k,v in projection.items() if k!='baseline'})
    p['baseline']={s:full.row(s,r,recreated=False,mounts_verified=r['Mounts']) for s,r in projection['baseline'].items()}
    rebind(current)
    return current,prior,db,f


def rebind(v):
    v['plan.json']['binding_sha256']=seq.fingerprint(v['host-policy.json'])
    v['profile.json']['host_binding_sha256']=v['plan.json']['binding_sha256']


class ContractTests(unittest.TestCase):
    def test_valid_assembly_links_prior_db_without_relabeling_it(self):
        v,old,db,f=fixture();p,model,full,mount=session.assemble(v)
        continuation.verify_linkage(v,old,db)
        self.assertEqual(seq.mutation_order(p),seq.ORDER[1:])
        self.assertEqual(model['services']['postgresql'],v['model.json']['services']['postgresql'])
        self.assertEqual(full.order,seq.ORDER[1:])
    def test_old_nine_service_plan_cannot_accept_new_db_or_partial_budgets(self):
        v,_,_,_=fixture();p=v['plan.json'];p['schema']=seq.TRANSITION_SCHEMA
        with self.assertRaises(ValueError):seq.validate_plan(p)
    def test_extra_db_budget_shutdown_or_subset_never_enables_db_call(self):
        changes=[lambda p:p['health_seconds'].update(postgresql=120),
            lambda p:p['recreate_seconds'].update(postgresql=360),lambda p:p['recreate_seconds'].pop('proxy'),
            lambda p:p.update(db_shutdown={}),lambda p:p.update(order=list(seq.ORDER[2:])),
            lambda p:p['baseline']['postgresql']['logging']['Config'].update({'syslog-address':seq.OLD_ADDRESS}),
            lambda p:p['baseline']['redis']['logging']['Config'].update({'syslog-address':seq.NEW_ADDRESS})]
        for change in changes:
            with self.subTest(change=change):
                p=fixture()[0]['plan.json'];change(p)
                with self.assertRaises(ValueError):seq.validate_plan(p)
    def test_preserved_db_model_or_target_metadata_changes_rejected(self):
        for change in (lambda v:v['candidate.json']['services']['postgresql'].update(restart='no'),
            lambda v:v['preservation.json']['after_labels'].update(postgresql={}),
            lambda v:v['preservation.json']['after_host_mounts'].update(postgresql=[]),
            lambda v:v['preservation.json']['auto_addresses'].append('postgresql')):
            v,_,_,_=fixture();change(v)
            with self.assertRaises(ValueError):session.assemble(v)
    def test_prior_db_full_config_mounts_process_and_eight_id_linkage(self):
        changes=[lambda v:v['preservation.json']['baseline']['postgresql']['Config']['Env'].append('bad=yes'),
            lambda v:v['preservation.json']['baseline']['postgresql']['HostConfig'].update(Privileged=True),
            lambda v:v['preservation.json']['baseline']['postgresql']['State'].update(Pid=99),
            lambda v:v['preservation.json']['baseline']['postgresql'].update(RestartCount=1),
            lambda v:v['preservation.json']['baseline']['redis'].update(Id='9'*64),
            lambda v:v['base.json']['services']['core'].update(restart='no'),
            lambda v:v['host-policy.json']['identity'].update(boot='33333333-3333-3333-3333-333333333333')]
        for change in changes:
            v,old,db,_=fixture();change(v)
            with self.subTest(change=change),self.assertRaises(ValueError):continuation.verify_linkage(v,old,db)
    def test_arbitrary_orders_are_rejected_at_transport_and_journal(self):
        v,_,_,_=fixture();ids={s:r['id'] for s,r in v['plan.json']['baseline'].items()}
        for order in (seq.ORDER[2:],('redis',),tuple(reversed(seq.ORDER[1:]))):
            with self.assertRaises(ValueError):journal.Journal('/synthetic/new/j',expected_selinux=None,order=order)
            with self.assertRaises(ValueError):compose.ComposeTransport(v['model.json'],model_sha256=seq.fingerprint(v['model.json']),
                plan_sha256='a'*64,ids=ids,process=None,verify=lambda _:ids,order=order)
    def test_old_paths_ancestor_or_nested_path_not_reused(self):
        ref=reference()
        for name in ('/synthetic/old','/synthetic/old/evidence','/synthetic/old/package/new'):
            with self.assertRaisesRegex(ValueError,'HISTORY_REUSE'):continuation.disjoint_history(ref,[name])
        continuation.disjoint_history(ref,['/synthetic/new/package','/synthetic/new/evidence'])
    def test_malformed_provenance_fails_before_assembly(self):
        for change in (lambda r:r.pop('dispatch'),lambda r:r['package'].update(path='/synthetic/../old'),
                       lambda r:r.update(sequence_record=True),lambda r:r.update(database_record=0),
                       lambda r:r['launch'].update(sha256='not-a-pin')):
            v,_,_,_=fixture();change(v['plan.json']['prior_execution'])
            with self.assertRaises(ValueError):session.assemble(v)


class ConnectedTests(unittest.TestCase):
    def setUp(self):
        self.v,self.prior,self.db,self.f=fixture()
        self.p,self.model,self.full,self.mount=session.assemble(self.v)
        self.f['before']=deepcopy(self.v['preservation.json']['baseline'])
        self.engine=cb.Engine(self.f);self.time=10.;self.calls=[];self.delay=0;self.rc=0
        self.after_write=lambda:None;self.after_render=lambda:None;outer=self
        class Process:
            def call(self,operation,model,*,deadline,service=None):
                outer.calls.append((operation,service))
                if operation=='render':outer.after_render();return 0
                outer.engine.rows[service]=cb.recreated(outer.f,service)
                outer.after_write();outer.time+=outer.delay;return outer.rc
        self.backend=backend.AddressBackend(self.p,engine=self.engine,host_provider=self.host,
            preservation=self.full,mount_preservation=self.mount,execution_model=self.model,
            execution_model_sha256=seq.fingerprint(self.model),process=Process(),clock=lambda:self.time)
        self.j=sq.MemoryJournal()
    def host(self,deadline):
        inp={k:deepcopy(v) for k,v in self.f['ma'].items() if k not in ('before','after','completed_services','labels')}
        inp['host_binding_sha256']=self.p['binding_sha256']
        return dict(binding_sha256=self.p['binding_sha256'],inputs_sha256=self.p['inputs_sha256'],at=self.time,
            logger_ipv4=True,model_sha256=seq.fingerprint(self.model),preservation_binding=self.full.binding,
            mount_inputs=inp,network_state=dict(topology_sha256='a'*64,pending_services=[]))
    def run_it(self):
        return seq.Sequence(self.p,self.backend,self.j,clock=lambda:self.time,
                            sleep=lambda s:setattr(self,'time',self.time+s)).run(deadline_mono=1000)
    def writes(self):return [s for op,s in self.calls if op=='recreate']
    def test_eight_full_layers_connected_and_db_logger_exactly_unchanged(self):
        fixed={s:deepcopy(self.engine.rows[s]) for s in ('postgresql','log')}
        r=self.run_it();self.assertEqual(r['reason'],'COMPLETE');self.assertEqual(self.writes(),list(seq.ORDER[1:]))
        self.assertEqual(r['healthy_services'],list(seq.ORDER[1:]));self.assertFalse(r['runtime_acceptance'])
        for s in fixed:self.assertEqual(self.engine.rows[s],fixed[s])
        for event in self.j.records:journal.validate_event(event,seq.ORDER[1:])
    def test_db_direct_transport_call_rejected_before_any_process(self):
        with self.assertRaisesRegex(ValueError,'TRANSPORT_SEQUENCE'):
            self.backend.recreate(service='postgresql',expected_id=self.db['Id'],plan_sha256=seq.fingerprint(self.p),
                                  deadline_mono=100,on_dispatch=lambda _:None)
        self.assertEqual(self.calls,[])
    def test_db_change_after_render_blocks_first_write(self):
        self.after_render=lambda:self.engine.rows['postgresql']['HostConfig'].update(Privileged=True)
        r=self.run_it();self.assertEqual(r['status'],'STOP_BEFORE_CHANGE');self.assertEqual(self.writes(),[])
    def test_db_health_restart_and_logger_loss_stop_after_only_first_write(self):
        changes=[lambda r:r['postgresql']['State']['Health'].update(Status='unhealthy'),
            lambda r:r['postgresql']['State'].update(StartedAt='restarted'),
            lambda r:r['postgresql'].update(RestartCount=1),
            lambda r:r['log']['State']['Health'].update(Status='unhealthy')]
        for change in changes:
            self.setUp();self.after_write=lambda:change(self.engine.rows)
            with self.subTest(change=change):
                r=self.run_it();self.assertEqual(r['status'],'STOP_RECOVERY_REQUIRED')
                self.assertEqual(self.writes(),['redis'])
    def test_late_failed_missing_health_and_mutation_drift_never_advance(self):
        for kind in ('late','rc','health','network','volume','config'):
            self.setUp()
            if kind=='late':self.delay=31
            if kind=='rc':self.rc=7
            if kind=='health':self.after_write=lambda:self.engine.rows['redis']['State']['Health'].update(Status='starting')
            if kind=='network':self.after_write=lambda:self.engine.rows['postgresql']['NetworkSettings'].update(extra='drift')
            if kind=='volume':self.after_write=lambda:self.engine.rows['redis']['Mounts'][0].update(Name='f'*64)
            if kind=='config':self.after_write=lambda:self.engine.rows['redis']['Config']['Env'].append('ADDED=private')
            with self.subTest(kind=kind):
                r=self.run_it();self.assertEqual(r['status'],'STOP_RECOVERY_REQUIRED');self.assertEqual(self.writes(),['redis'])
                self.assertNotIn('private',json.dumps(r))
    def test_existing_claim_and_evidence_fault_prevent_reexecution(self):
        self.j.spent=True;r=self.run_it();self.assertEqual(r['reason'],'EXISTING_HISTORY');self.assertEqual(self.calls,[])
        self.setUp();self.j.fail_kind='RECREATE_INTENT';r=self.run_it()
        self.assertEqual(self.calls,[]);self.assertFalse(r['journal_recorded'])


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Linux root protected temporary storage')
class LinuxProofTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='address-continuation-test-',dir='/root'))
        self.context=os.getxattr(self.root,'security.selinux').rstrip(b'\0') if 'security.selinux' in os.listxattr(self.root) else None
        # Production requires the supplied label. CI lacks SELinux; only the
        # context comparison is mapped to actual CI metadata, no access checks.
        self.original_context=evidence.context_check
        self.label_patches=[patch.object(module,'context_check',side_effect=lambda fd,c:self.original_context(fd,self.context))
                            for module in (evidence,package,continuation)]
        for p in self.label_patches:p.start()
        self.v,self.old,self.db,self.f=fixture();self.proof=self.make_proof()
        self.v['plan.json']['prior_execution']=self.proof
    def tearDown(self):
        for p in reversed(self.label_patches):p.stop()
        assert self.root.parent==Path('/root') and self.root.name.startswith('address-continuation-test-')
        shutil.rmtree(self.root)
    def deadline(self):return time.monotonic()+30
    def directory(self,name):p=self.root/name;p.mkdir(mode=0o700);return p
    def file(self,path,data):
        path.write_bytes(evidence.encode(data));path.chmod(0o600)
        return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),context='synthetic_t')
    def make_proof(self):
        ref=reference();p=self.directory('prior-package');e=self.directory('prior-evidence')
        raw={k:evidence.encode(v) for k,v in self.old.items()}
        sealed=package.seal_package(str(p),contents=raw,hashes={k:hashlib.sha256(v).hexdigest() for k,v in raw.items()},
                                    context=b'synthetic_t',deadline=self.deadline())
        ref['package']=dict(path=str(p),sha256=sealed['manifest_sha256'],context='synthetic_t')
        ref['plan_sha256']=seq.fingerprint(self.old['plan.json'])
        launch=dict(schema='fds.harbor.address-launch.v1',source={'revision':ref['source_revision']},session=dict(
            package_path=str(p),package_sha256=sealed['manifest_sha256'],package_context='synthetic_t',
            evidence_path=str(e),evidence_context='synthetic_t',
            journal_path=str(self.root/'prior-journal'),private_path=str(self.root/'prior-private')))
        ref['launch']=self.file(self.root/'launch.json',launch);ref['dispatch']=self.file(self.root/'dispatch.claim',{'spent':True})
        store=evidence.Evidence(str(e),context=b'synthetic_t',plan_sha256=ref['plan_sha256'])
        result=dict(status='STOP_RECOVERY_REQUIRED',reason='IO_OR_ADAPTER_FAILURE',plan_sha256=ref['plan_sha256'],
            claimed_services=['postgresql'],transport_entered_services=['postgresql'],healthy_services=[],
            this_invocation_may_have_changed=True,journal_recorded=True,runtime_acceptance=False,autostart_tested=False)
        with store.locked(self.deadline()):
            for kind in ('CALL_INTENT','PROCESS_INTENT','PROCESS_RESULT','CALL_END'):
                store.save(kind=kind,operation='recreate',service='postgresql',payloads={},deadline=self.deadline(),
                    diagnostic={'rc':0,'reason':'COMPLETED'} if kind=='PROCESS_RESULT' else {})
            store.save(kind='SEQUENCE_RESULT',payloads={'private':evidence.encode(result)},diagnostic={},deadline=self.deadline())
            store.save(kind='INSPECT',payloads={'private':evidence.encode(self.db)},diagnostic={'id':self.db['Id']},deadline=self.deadline())
        ref['evidence']=dict(path=str(e),sha256=hashlib.sha256((e/'evidence.closed').read_bytes()).hexdigest(),context='synthetic_t')
        return ref
    def verify(self):continuation.verify_prior(self.v,new_paths=[str(self.root/'new')],deadline=self.deadline())
    def test_actual_protected_package_and_sealed_evidence_linkage(self):
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()}
        self.verify()
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()})
    def test_different_launch_claim_unsealed_or_tampered_payload_rejected(self):
        for key in ('launch','dispatch','evidence'):
            old=self.proof[key]['sha256'];self.proof[key]['sha256']='0'*64
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify()
            self.proof[key]['sha256']=old
        data=Path(self.proof['evidence']['path'])/'000005.private.bin';data.write_bytes(b'{}')
        with self.assertRaises(ValueError):self.verify()
    def test_wrong_record_old_id_and_missing_proof_fail_before_new_store(self):
        self.proof['database_record']=4
        with self.assertRaises(ValueError):self.verify()
        self.proof['database_record']=5
        Path(self.proof['evidence']['path'],'evidence.closed').unlink()
        with self.assertRaises((ValueError,OSError)):self.verify()
        self.assertFalse((self.root/'new').exists())
    def test_linux_eight_service_journal_and_claim_reuse(self):
        obj=ConnectedTests();obj.setUp();path=self.directory('new-journal')
        obj.j=journal.Journal(str(path),expected_selinux=self.context,order=seq.ORDER[1:])
        self.assertEqual(obj.run_it()['reason'],'COMPLETE')
        read=journal.inspect_history(str(path),expected_selinux=self.context,
            expected_plan_sha256=seq.fingerprint(obj.p),order=seq.ORDER[1:])
        self.assertEqual(read['status'],'VALID_TERMINAL_HISTORY');self.assertFalse(read['may_resume'])
        obj.j=journal.Journal(str(path),expected_selinux=self.context,order=seq.ORDER[1:])
        self.assertEqual(obj.run_it()['reason'],'EXISTING_HISTORY');self.assertEqual(len(obj.writes()),8)
    def protected_session(self, *, missing_proof=False):
        obj=ConnectedTests();obj.setUp()
        obj.v=deepcopy(self.v)
        pins=obj.v['host-policy.json']['pinned_files']
        for name in session.SOURCE_MODULES:
            pins[str(Path(sys.modules[name].__file__).resolve())]={'mode':0o644,'gid':0,'selinux':'synthetic_t','sha256':'a'*64}
        pins[str(Path(sys.executable).resolve())]={'mode':0o755,'gid':0,'selinux':'synthetic_t','sha256':'b'*64}
        if missing_proof:obj.v['plan.json']['prior_execution']['evidence']['sha256']='0'*64
        rebind(obj.v);obj.p,obj.model,obj.full,obj.mount=session.assemble(obj.v)
        raw={k:evidence.encode(v) for k,v in obj.v.items()};p=self.directory('new-package')
        sealed=package.seal_package(str(p),contents=raw,hashes={k:hashlib.sha256(v).hexdigest() for k,v in raw.items()},
                                    context=b'synthetic_t',deadline=self.deadline())
        j=self.directory('new-journal');e=self.directory('new-evidence');private=self.directory('new-private')
        class Process:
            audit=None
            def call(self,operation,model,*,deadline,service=None):
                self.audit('PROCESS_INTENT',operation,service,{}, {},deadline)
                obj.calls.append((operation,service))
                if operation=='recreate':obj.engine.rows[service]=cb.recreated(obj.f,service)
                self.audit('PROCESS_RESULT',operation,service,{'rc':0,'reason':'COMPLETED'},{},deadline)
                return 0
        class IO:
            def __init__(self,**kw):pass
            def pinned(self,*a):pass
        # Real protected package/provenance reader, assembly, backend, sequence,
        # transport, journal and audited evidence. Only external host/Engine/
        # Compose and absent CI SELinux context are simulated.
        with patch.object(session,'ProductionReadOnly',IO),patch.object(session,'ReadOnlyEngine',return_value=obj.engine),\
             patch.object(session,'ProductionHost',return_value=obj.host),patch.object(session,'PinnedCompose',return_value=Process()),\
             patch.object(session,'Journal',side_effect=lambda path,expected_selinux,order:journal.Journal(path,expected_selinux=self.context,order=order)):
            s=session.ProtectedSession(package_path=str(p),package_sha256=sealed['manifest_sha256'],package_context=b'synthetic_t',
                journal_path=str(j),journal_context=b'synthetic_t',evidence_path=str(e),evidence_context=b'synthetic_t',
                private_path=str(private),private_context=b'synthetic_t',preparation_deadline=self.deadline())
        # One consistent injected monotonic source for the simulated host path.
        # Host observation's timestamp must belong to the real observation interval.
        original=s.sequence._backend.host
        def host(d):obj.time=time.monotonic();return original(d)
        s.sequence._backend.host=host
        return s,obj
    def test_protected_session_actual_file_pipeline_eight_only(self):
        s,obj=self.protected_session()
        result=s.run(mutation_deadline=self.deadline(),collection_deadline=time.monotonic()+60)
        self.assertEqual(result['sequence']['reason'],'COMPLETE');self.assertTrue(result['evidence_sealed'])
        self.assertEqual(obj.writes(),list(seq.ORDER[1:]))
        # Removed old IDs correctly remain read failures; this is not AC.
        self.assertFalse(result['collection']['complete']);self.assertFalse(result['runtime_acceptance'])
        summary=evidence.inspect_evidence(s.evidence.path,context=b'synthetic_t',plan_sha256=seq.fingerprint(obj.p),deadline=self.deadline())
        self.assertTrue(summary['valid']);self.assertEqual(summary['up_process_intents'],list(seq.ORDER[1:]))
    def test_bad_prior_proof_creates_no_new_claim_or_process(self):
        with self.assertRaises(ValueError):self.protected_session(missing_proof=True)
        self.assertEqual(list((self.root/'new-evidence').iterdir()),[])
        self.assertEqual(list((self.root/'new-journal').iterdir()),[])
    def rewrite_record(self,index,change):
        root=Path(self.proof['evidence']['path']);previous='0'*64
        for i,path in enumerate(sorted(root.glob('*.record.json'))):
            r=json.loads(path.read_bytes())
            if i==index:change(r,root)
            r['previous_sha256']=previous;r.pop('sha256');r['sha256']=seq.fingerprint(r);previous=r['sha256']
            path.write_bytes(evidence.encode(r))
        close=root/'evidence.closed';value=json.loads(close.read_bytes());value['last_sha256']=previous
        close.write_bytes(evidence.encode(value));self.proof['evidence']['sha256']=hashlib.sha256(close.read_bytes()).hexdigest()
    def test_validly_sealed_nonzero_or_boolean_db_result_is_not_success(self):
        for rc in (1,False,None):
            self.rewrite_record(2,lambda r,p:r.update(diagnostic={'rc':rc,'reason':'COMPLETED'}))
            with self.subTest(rc=rc),self.assertRaisesRegex(ValueError,'DB_ACK'):self.verify()
    def test_validly_sealed_success_rewrite_cannot_bless_prior_failure(self):
        def change(r,root):
            entry=r['files']['private'];p=root/entry['file'];value=json.loads(p.read_bytes());value['status']='COMPLETE'
            raw=evidence.encode(value);p.write_bytes(raw);entry.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        self.rewrite_record(4,change)
        with self.assertRaisesRegex(ValueError,'PRIOR_RESULT'):self.verify()


if __name__=='__main__':unittest.main()
