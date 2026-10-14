"""Pinned input loading and runtime assembly. No CLI, file install or auto-arm.

The bootstrap/program loading this library must already be trusted. Hash checks
here are not a verifier for Python code that was imported before this module.
Only separately reviewed/installed source may call load_bundle and build.
"""
from copy import deepcopy
from dataclasses import fields, replace
import re
import os
import time

from harbor_recovery_core import Controller, Plan, State
from harbor_recovery_docker import (DockerBackend, UnixEngine, digest, execution_binding,
                                    parse_json, remaining, require)
from harbor_recovery_executor import Executor
from harbor_recovery_control import OperatorControl, StopEngine, StopLedger
from harbor_recovery_host import HostProvider, LinuxReadOnly, absolute, validate_policy, host_provider, host_binding
from harbor_recovery_policy_backend import PolicyBackend, PolicyEngine, StoppedManager
from harbor_recovery_protected_store import ProtectedStore, label, writer_label, verify_writer_context
from harbor_recovery_transition import (Journal, Transition, TransitionPlan,
                                        observation, original_policies)

MODULES = frozenset({'harbor_recovery_core.py', 'harbor_recovery_docker.py',
                    'harbor_recovery_executor.py', 'harbor_recovery_store.py',
                    'harbor_recovery_host.py', 'harbor_recovery_policy_backend.py',
                    'harbor_recovery_transition.py', 'harbor_recovery_protected_store.py',
                    'harbor_recovery_bundle.py', 'harbor_recovery_service.py', 'harbor_recovery_control.py'})
SCHEMA = 'fds.harbor.recovery.bundle.v2'
PRODUCTION_SCHEMA = 'fds.harbor.recovery.bundle.production.v2'
LIFECYCLE_SCHEMA = 'fds.harbor.recovery.bundle.production.v3'
BOOT_SCHEMA = 'fds.harbor.recovery.bundle.production.v4'
HOST_VERSIONS = {SCHEMA: 1, PRODUCTION_SCHEMA: 2, LIFECYCLE_SCHEMA: 3, BOOT_SCHEMA: 4}


def fingerprint_version(obj):
    require(obj['schema'] in HOST_VERSIONS and
            obj['host_policy']['version'] == HOST_VERSIONS[obj['schema']], 'BUNDLE_HOST_SCOPE')
    return 2 if obj['schema'] in (LIFECYCLE_SCHEMA, BOOT_SCHEMA) else 1


def parse_bundle(raw):
    obj = parse_json(raw)
    require(isinstance(obj, dict) and set(obj) == {'schema', 'host_policy', 'plan', 'manager', 'store', 'source'} and
            obj['schema'] in HOST_VERSIONS, 'BUNDLE_SCHEMA')
    p = obj['host_policy']
    validate_policy(p)
    fingerprint_version(obj)
    require(isinstance(obj['plan'], dict) and set(obj['plan']) == {f.name for f in fields(Plan)},
            'BUNDLE_PLAN_FIELDS')
    plan = Plan(**obj['plan'])
    require(p['version'] == 1 or p['network']['ids'] == plan.ids, 'BUNDLE_NETWORK_IDS')
    require(bool(plan.execution_binding), 'BUNDLE_PLAN_BINDING_REQUIRED')
    store = obj['store']
    require(isinstance(store, dict) and set(store) == {'path', 'directory_context', 'file_context', 'writer_context'} and
            isinstance(store['path'], str) and re.fullmatch(
                '/var/lib/fds-harbor-recovery/instances/[0-9a-f]{32}', store['path']), 'BUNDLE_STORE_PATH')
    label(store['directory_context']); label(store['file_context'])
    writer_label(store['writer_context'])
    source = obj['source']
    require(isinstance(source, dict) and set(source) == {'revision', 'directory', 'files'} and
            isinstance(source['revision'], str) and re.fullmatch('[0-9a-f]{40}', source['revision']) and
            source['directory'] == '/opt/fds-harbor-recovery/versions/' + source['revision'] and
            isinstance(source['files'], dict) and set(source['files']) == MODULES, 'BUNDLE_SOURCE')
    for name, expected in source['files'].items():
        path = source['directory'] + '/' + name
        require(path in p['files'] and p['files'][path]['sha256'] == expected, 'BUNDLE_SOURCE_PIN')
    manager = obj['manager']
    require(isinstance(manager, dict) and set(manager) == {'fragment', 'dropins'}, 'BUNDLE_MANAGER')
    # Constructor validates fixed unit name and all manager/tool input pins.
    StoppedManager(p, manager['fragment'], manager['dropins'])
    require(not store['path'].startswith(p['directory'] + '/'), 'BUNDLE_PATH_OVERLAP')
    return deepcopy(obj)


def host_scope(obj):
    # Deployment identity is bound in addition to host/config: changing the
    # state namespace, code release or staged unit cannot reuse an old RUN plan.
    return {'bundle_schema': obj['schema'], 'store': obj['store'], 'source': obj['source'],
            'manager': obj['manager']}


def bound_host_digest(obj):
    base = host_binding(obj['host_policy'])
    return digest({'enrollment_version': 1, 'host': base, 'scope': host_scope(obj)})


class BoundHost:
    def __init__(self, base, obj, verify_bundle):
        self.base, self.verify_bundle = base, verify_bundle
        self.binding = bound_host_digest(obj)

    def __call__(self, deadline):
        self.verify_bundle(deadline)
        stamp = self.base(deadline)
        self.verify_bundle(deadline)
        require(stamp.binding == self.base.binding, 'BUNDLE_BASE_HOST_CHANGED')
        return replace(stamp, binding=self.binding)


class LoadedBundle:
    def __init__(self, obj, path, spec, io, *, clock):
        self._obj, self.path, self.spec = deepcopy(obj), path, deepcopy(spec)
        self.io, self.clock = io, clock
        self._canonical = digest(obj)

    @property
    def data(self):
        return deepcopy(self._obj)

    def verify(self, deadline):
        require(digest(self._obj) == self._canonical, 'BUNDLE_MEMORY_CHANGED')
        raw = self.io.pinned(self.path, self.spec, 'file', deadline)
        require(digest(parse_bundle(raw)) == self._canonical, 'BUNDLE_CHANGED')
        remaining(deadline, self.clock)


def load_bundle(path, expected_sha256, expected_context, deadline, *, io=None, clock=time.monotonic):
    """External expected hash/context are mandatory; never self-read a new hash.

    A pinned document is an integrity input, not proof of human approval. The
    caller must hold the approval for this exact bundle and operation.
    """
    require(absolute(path) and path.endswith('.json') and isinstance(expected_sha256, str) and
            re.fullmatch('[0-9a-f]{64}', expected_sha256), 'BUNDLE_EXTERNAL_PIN')
    spec = {'mode': 0o600, 'gid': 0, 'selinux': label(expected_context), 'sha256': expected_sha256}
    reader = LinuxReadOnly(clock=clock) if io is None else io
    raw = reader.pinned(path, spec, 'file', deadline)
    obj = parse_bundle(raw)
    require(path not in obj['host_policy']['files'], 'BUNDLE_SELF_REFERENCE')
    engine = UnixEngine(obj['host_policy']['api_version'], socket_path=obj['host_policy']['socket'])
    expected = execution_binding(bound_host_digest(obj), obj['host_policy']['project'], engine.binding,
                                 fingerprint_version=fingerprint_version(obj))
    require(obj['plan']['execution_binding'] == expected, 'BUNDLE_EXECUTION_BINDING')
    remaining(deadline, clock)
    return LoadedBundle(obj, path, spec, reader, clock=clock)


class Activation:
    """Arm only a verified installation in the same generation, without start.

    No manager enable/start operation and no reset of prior HOLD or claims.
    """
    def __init__(self, core, store, journal, backend, manager, *, clock=time.monotonic):
        self.core, self.store, self.journal = core, store, journal
        self.backend, self.manager, self.clock = backend, manager, clock

    def installed(self):
        record = self.journal.load()  # under the controller's same lock
        require(record['phase'] == 'INSTALLED_HOLD' and record['pending'] is None,
                'INSTALLATION_NOT_COMPLETE')
        return record

    def arm_initial(self, deadline, *, explicit=False):
        require(explicit is True, 'ACTIVATION_EXPLICIT_REQUIRED')
        with self.store.locked():
            record = self.installed()
            state = self.store.load()
            require(state == State(), 'ACTIVATION_NOT_INITIAL')
            item = self.backend.observe(deadline)
            require((item.boot, item.daemon) == (record['boot'], record['daemon']) and
                    item.logger_tcp and all(row.status == 'running' and row.health == 'healthy'
                                            for row in item.containers.values()), 'ACTIVATION_READBACK')
            require(self.manager(deadline) == self.journal.plan.manager_binding, 'ACTIVATION_MANAGER')
            remaining(deadline, self.clock)
            result = self.core.arm(state, item, self.clock()).state
            require(result.desired == 'RUN' and result.reason == 'ARMED', 'ACTIVATION_REFUSED')
            self.store.audit('initial-arm-request', state)
            self.store.save(result)
            return result


def initialize_store(components, deadline, *, clock=time.monotonic):
    """Verify target/original policies before creating even the first lock file.

    A later policy-install performs its own fresh checks. This initialization
    alone does not authorize or perform a container/manager mutation.
    """
    transition, store = components['transition'], components['store']
    require(transition.store is store, 'INITIALIZE_STORE_BINDING')
    remaining(deadline, clock)
    item = transition.backend.observe(deadline)
    observation(transition.plan, item, original_policies(), clock())
    remaining(deadline, clock)
    with store.locked():
        remaining(deadline, clock)
        store.initialize()


def verify_store_writer(bundle, deadline, *, clock=time.monotonic):
    """Read-only actor check. Does not open a Store or prove creation labels."""
    require(isinstance(bundle, LoadedBundle), 'LOADED_BUNDLE_REQUIRED')
    bundle.verify(deadline)
    verify_writer_context(bundle.data['store']['writer_context'])
    remaining(deadline, clock)


def probe_store_writer(bundle, phase, deadline, *, clock=time.monotonic):
    """Explicit scratch I/O only. No provider/Engine/manager unit construction.

    The sibling directory must already exist with approved metadata. Never
    consume the real Store, initialize a used probe, delete or repair records.
    A second process is required; PID reuse conservatively refuses the probe.
    """
    require(phase in ('probe-create', 'probe-reopen'), 'WRITER_PROBE_PHASE')
    verify_store_writer(bundle, deadline, clock=clock)
    from harbor_recovery_service import ManagerLease
    spec = bundle.data['store']
    store = ProtectedStore(spec['path'] + '.writer-probe', spec['directory_context'],
                           spec['file_context'], writer_context=spec['writer_context'])
    if phase == 'probe-create':
        with store.locked():
            remaining(deadline, clock)
            store.initialize()
    remaining(deadline, clock)
    with ManagerLease(store), store.locked():
        state = store.load()
        if phase == 'probe-create':
            require(state == State(), 'WRITER_PROBE_INITIAL')
            state = State(reason='WRITER_PROBE_CREATED', daemon=str(os.getpid()))
        else:
            require(state.daemon.isdigit() and state.daemon != str(os.getpid()) and
                    state == State(reason='WRITER_PROBE_CREATED', daemon=state.daemon), 'WRITER_PROBE_NEW_PROCESS')
            names = set(os.listdir(store.fd))
            require(len(names) == 4 and {'controller.lock', 'manager.lock', 'state.json'} <= names and
                    len([n for n in names if n.startswith('operator-hold-')]) == 1, 'WRITER_PROBE_RECORDS')
            state = replace(state, reason='WRITER_PROBE_REOPENED')
        # Exercise O_EXCL without creating a synthetic application claim.
        remaining(deadline, clock)
        before = store.load()
        try:
            store._new('state.json', b'not a state; O_EXCL must refuse')
        except FileExistsError:
            pass
        else:
            raise ValueError('WRITER_PROBE_EXCLUSIVE_CREATE')
        require(store.load() == before, 'WRITER_PROBE_CHANGED')
        remaining(deadline, clock)
        store.audit('operator-hold', state)
        remaining(deadline, clock)
        store.save(state)
        remaining(deadline, clock)
        require(store.load() == state and not store.inventory()['pending'], 'WRITER_PROBE_READBACK')
    remaining(deadline, clock)
    return {'stage': state.reason, 'probe_only': True, 'engine_io': 'NONE',
            'operational_store_io': 'NONE', 'records': 'PRESERVED', 'pid': os.getpid(),
            'probe_path': str(store.path), 'writer_context': spec['writer_context']}


def build(bundle, deadline, *, clock=time.monotonic):
    """Assemble actual Linux components, with no init/install/arm/API mutation.

    Trusted bootstrap only; the separate bootstrap provides explicit operator
    commands. Every runtime observation revalidates bundle+source pins.
    """
    require(isinstance(bundle, LoadedBundle), 'LOADED_BUNDLE_REQUIRED')
    bundle.verify(deadline)
    obj = bundle.data
    p = obj['host_policy']
    plan = Plan(**obj['plan'])
    live_engine = UnixEngine(p['api_version'], socket_path=p['socket'], clock=clock)
    host = BoundHost(host_provider(p, live_engine, clock=clock), obj, bundle.verify)
    manager = StoppedManager(p, obj['manager']['fragment'], obj['manager']['dropins'], clock=clock)
    store = ProtectedStore(obj['store']['path'], obj['store']['directory_context'], obj['store']['file_context'],
                           writer_context=obj['store']['writer_context'])
    transition_plan = TransitionPlan(plan, host.binding, manager.binding)
    journal = Journal(store, transition_plan)
    backend = DockerBackend(plan, live_engine, host, host.binding, p['project'], clock=clock,
                            fingerprint_version=fingerprint_version(obj))
    core = Controller(plan)
    activation = Activation(core, store, journal, backend, manager, clock=clock)
    executor = Executor(core, store, backend, clock=clock, gate=activation.installed)
    policy_engine = PolicyEngine(p['api_version'], [plan.ids[n] for n in plan.health_seconds],
                                 socket_path=p['socket'], clock=clock)
    policy_backend = PolicyBackend(transition_plan, policy_engine, host, manager, clock=clock,
                                   fingerprint_version=fingerprint_version(obj))
    transition = Transition(transition_plan, store, policy_backend, journal=journal, clock=clock,
                            control_gate=StopLedger(store).quiescent)
    stop_engine = StopEngine(p['api_version'], [plan.ids[n] for n in plan.health_seconds],
                             socket_path=p['socket'], clock=clock)
    control = OperatorControl(executor, manager, stop_engine, clock=clock)
    return {'store': store, 'activation': activation, 'executor': executor, 'transition': transition,
            'control': control}
