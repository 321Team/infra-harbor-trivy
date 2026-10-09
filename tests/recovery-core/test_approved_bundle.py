"""Approved input/activation simulations and Linux private file metadata tests."""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/recovery'))
import harbor_recovery_bundle as b
import harbor_recovery_core as c
import harbor_recovery_docker as d
import harbor_recovery_transition as t
from harbor_recovery_executor import Executor
from harbor_recovery_protected_store import ProtectedStore
from test_host_provider import policy, LABEL, BOOT, DAEMON
from test_policy_transition import fixture, MemoryJournal
from test_state_executor import MemoryStore


def candidate():
    host = policy()
    source = {'revision': 'a'*40, 'directory': '/opt/fds-harbor-recovery/versions/'+'a'*40,
              'files': {name: 'b'*64 for name in b.MODULES}}
    for name, sha in source['files'].items():
        host['files'][source['directory'] + '/' + name] = {
            'mode': 0o444, 'gid': 0, 'selinux': LABEL, 'sha256': sha}
    manager = {'fragment': '/etc/systemd/system/fds-harbor-recovery.service', 'dropins': []}
    host['files'][manager['fragment']] = {'mode': 0o644, 'gid': 0, 'selinux': LABEL, 'sha256': 'c'*64}
    plan, _ = fixture()
    obj = {'schema': b.SCHEMA, 'host_policy': host, 'plan': asdict(plan.recovery),
           'manager': manager, 'source': source,
           'store': {'path': '/var/lib/fds-harbor-recovery/instances/' + 'd'*32,
                     'directory_context': LABEL, 'file_context': LABEL}}
    engine = d.UnixEngine(host['api_version'], socket_path=host['socket'])
    obj['plan']['execution_binding'] = d.execution_binding(b.bound_host_digest(obj), 'harbor', engine.binding)
    return obj


class Pins:
    def __init__(self, obj):
        self.raw = json.dumps(obj).encode()
        self.sha = hashlib.sha256(self.raw).hexdigest()
        self.calls = []

    def pinned(self, path, spec, kind, deadline):
        self.calls.append((path, deepcopy(spec), kind))
        if hashlib.sha256(self.raw).hexdigest() != spec['sha256']: raise ValueError('hash')
        return self.raw


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.obj = candidate(); self.io = Pins(self.obj)

    def load(self, **kwargs):
        return b.load_bundle('/etc/fds-harbor-recovery/input.json', self.io.sha, LABEL, 20,
                             io=self.io, clock=lambda: 10, **kwargs)

    def test_exact_external_pin_complete_plan_and_no_mutation(self):
        loaded = self.load()
        self.assertEqual(loaded.data, self.obj)
        loaded.verify(20)
        self.assertEqual(len(self.io.calls), 2)
        self.assertEqual(self.io.calls[0][1]['mode'], 0o600)
        changed = loaded.data; changed['source']['revision'] = 'f'*40
        self.assertEqual(loaded.data, self.obj)

    def test_wrong_hash_source_path_and_missing_pin(self):
        with self.assertRaises(ValueError):
            b.load_bundle('/etc/input.json', 'f'*64, LABEL, 20, io=self.io, clock=lambda: 10)
        for mutate in (lambda o: o['source'].update(directory='/tmp/code'),
                       lambda o: o['source']['files'].pop('harbor_recovery_core.py'),
                       lambda o: o['plan'].pop('logger_seconds'),
                       lambda o: o['store'].update(path='/root/hbr-a3-joz3x6ya'),
                       lambda o: o['host_policy']['files'].pop(o['manager']['fragment'])):
            obj = candidate(); mutate(obj)
            with self.assertRaises(ValueError): b.parse_bundle(json.dumps(obj).encode())

    def test_namespace_source_unit_change_invalidates_old_binding(self):
        for change in (lambda o: o['store'].update(path='/var/lib/fds-harbor-recovery/instances/'+'e'*32),
                       lambda o: o['store'].update(file_context='system_u:object_r:var_lib_t:s0'),
                       lambda o: o['host_policy']['files'][o['manager']['fragment']].update(sha256='f'*64)):
            obj = candidate(); change(obj); self.io = Pins(obj)
            with self.assertRaisesRegex(ValueError, 'EXECUTION_BINDING'): self.load()

    def test_modified_bundle_after_load_rejected_before_host_observation(self):
        loaded = self.load()
        host_calls = []
        class Base:
            binding = 'c'*64
            def __call__(self, deadline):
                host_calls.append(deadline)
                return d.HostSnapshot(BOOT, DAEMON, self.binding, 10)
        wrapped = b.BoundHost(Base(), self.obj, loaded.verify)
        self.io.raw += b' '
        with self.assertRaises(ValueError): wrapped(20)
        self.assertEqual(host_calls, [])

    def test_scope_wrapper_retains_generation_and_oldest_timestamp(self):
        loaded = self.load()
        class Base:
            binding = 'c'*64
            def __call__(self, deadline): return d.HostSnapshot(BOOT, DAEMON, self.binding, 9)
        wrapped = b.BoundHost(Base(), self.obj, loaded.verify)
        stamp = wrapped(20)
        self.assertEqual((stamp.boot, stamp.daemon, stamp.at), (BOOT, DAEMON, 9))
        self.assertEqual(stamp.binding, b.bound_host_digest(self.obj))

    def test_bundle_rejects_duplicate_json_and_self_hash_reference(self):
        with self.assertRaises(ValueError): b.parse_bundle(b'{"schema":"one","schema":"two"}')
        self.obj['host_policy']['files']['/etc/fds-harbor-recovery/input.json'] = {
            'sha256': 'a'*64, 'mode': 0o600, 'gid': 0, 'selinux': LABEL}
        self.io = Pins(self.obj)
        with self.assertRaisesRegex(ValueError, 'SELF_REFERENCE'): self.load()

    def test_build_connects_real_components_without_io_or_initialize(self):
        loaded = self.load()
        with (patch.object(b, 'ProtectedStore', return_value=MemoryStore()) as store,
              patch.object(b.HostProvider, '__call__', side_effect=AssertionError('host IO forbidden'))):
            components = b.build(loaded, 20, clock=lambda: 10)
        self.assertEqual(set(components), {'store', 'activation', 'executor', 'transition', 'control'})
        self.assertIsNotNone(components['executor'].gate)
        self.assertFalse(components['executor'].opened)
        self.assertEqual(components['store'].state, c.State())
        self.assertEqual(store.call_count, 1)


class RuntimeBackend:
    def __init__(self, plan):
        self.calls = []
        self.now = 10
        rows = {n: c.Container(plan.recovery.ids[n], plan.recovery.fingerprints[n], 'running', 'healthy',
                               'always' if n == 'log' else 'no') for n in plan.recovery.ids}
        self.item = c.Observation(BOOT, DAEMON, 10, rows, True, True)

    def observe(self, deadline=None):
        self.calls.append('observe')
        return deepcopy(self.item)

    def start(self, *args, **kwargs):
        self.calls.append('start')
        raise AssertionError('No start expected')


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.plan, _ = fixture()
        self.store = MemoryStore()
        self.journal = MemoryJournal(self.store, self.plan)
        self.journal.record = {'version': 1, 'plan': self.plan.binding, 'boot': BOOT, 'daemon': DAEMON,
                               'original': t.original_policies(), 'phase': 'INSTALLED_HOLD',
                               'reason': 'ALL_POLICIES_VERIFIED', 'changed': list(c.ORDER),
                               'restored': [], 'next_token': 10, 'pending': None}
        self.backend = RuntimeBackend(self.plan)
        self.manager_ok = True
        def manager(deadline):
            if not self.manager_ok: raise ValueError('running manager')
            return self.plan.manager_binding
        self.act = b.Activation(c.Controller(self.plan.recovery), self.store, self.journal,
                                self.backend, manager, clock=lambda: 10)
        self.executor = Executor(self.act.core, self.store, self.backend, clock=lambda: 10,
                                  gate=self.act.installed)

    def arm(self): return self.act.arm_initial(20, explicit=True)

    def test_explicit_initial_arm_audit_no_container_start(self):
        with self.assertRaisesRegex(ValueError, 'EXPLICIT'): self.act.arm_initial(20)
        state = self.arm()
        self.assertEqual((state.desired, state.reason), ('RUN', 'ARMED'))
        self.assertEqual(self.store.records[0][0], 'initial-arm-request')
        self.assertNotIn('start', self.backend.calls)
        self.assertEqual(self.journal.record['phase'], 'INSTALLED_HOLD')

    def test_cannot_use_initial_arm_to_clear_hold_or_retry_history(self):
        self.store.state = c.State(reason='OPERATOR_HOLD')
        with self.assertRaisesRegex(ValueError, 'NOT_INITIAL'): self.arm()
        self.store.state = c.State(next_token=2)
        with self.assertRaisesRegex(ValueError, 'NOT_INITIAL'): self.arm()
        self.assertEqual(self.backend.calls, [])

    def test_incomplete_installation_and_boot_change_block_arm(self):
        self.journal.record['phase'] = 'HOLD'
        with self.assertRaisesRegex(ValueError, 'INSTALLATION_NOT_COMPLETE'): self.arm()
        self.journal.record['phase'] = 'INSTALLED_HOLD'
        self.backend.item = replace(self.backend.item, boot='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
        with self.assertRaisesRegex(ValueError, 'READBACK'): self.arm()
        self.assertEqual(self.store.state, c.State())

    def test_manager_active_or_unhealthy_blocks_arm(self):
        self.manager_ok = False
        with self.assertRaises(ValueError): self.arm()
        self.manager_ok = True
        self.backend.item = replace(self.backend.item, logger_tcp=False)
        with self.assertRaises(ValueError): self.arm()
        self.assertEqual(self.store.state, c.State())

    def test_arm_save_failure_keeps_audit_not_run(self):
        self.store.fail_reason = 'ARMED'
        with self.assertRaises(OSError): self.arm()
        self.assertEqual(self.store.state, c.State())
        self.assertEqual(len(self.store.records), 1)

    def test_expired_activation_has_no_audit_or_run(self):
        with self.assertRaises(ValueError): self.act.arm_initial(9, explicit=True)
        self.assertEqual(self.store.state, c.State())
        self.assertEqual(self.store.records, [])

    def test_executor_never_implicitly_arms_and_rejects_direct_initial_arm(self):
        self.executor.open()
        self.assertEqual(self.executor.tick().desired, 'HOLD')
        with self.assertRaisesRegex(RuntimeError, 'INSTALLED_ACTIVATION'): self.executor.arm_initial()
        self.assertEqual(self.backend.calls, [])

    def test_runtime_gate_failure_holds_before_observe_or_start(self):
        self.arm(); self.executor.open()
        self.backend.calls.clear()
        self.journal.record['phase'] = 'ROLLING_BACK'
        state = self.executor.tick()
        self.assertEqual(state.reason, 'INSTALLATION_GATE_FAILED')
        self.assertEqual(self.backend.calls, [])

    def test_missing_or_bad_journal_open_fails_closed(self):
        self.journal.record = None
        self.executor.open()
        self.assertEqual(self.store.state, c.State())
        self.executor.tick()
        self.assertEqual(self.backend.calls, [])

    def test_hold_before_install_preserves_initial_state_and_later_arm(self):
        record=self.journal.record;self.journal.record=None
        self.executor.open();self.executor.hold()
        self.assertEqual(self.store.state,c.State())
        self.journal.record=record
        self.assertEqual(self.arm().desired,'RUN')

    def test_gate_does_not_replace_resume_diagnosis_but_still_blocks_reconcile(self):
        self.arm();self.store.state.episode_since=10;self.store.state.health_wait=('core',50)
        self.journal.record=None;self.executor.open()
        self.assertEqual(self.store.state.reason,'INCOMPLETE_HEALTH_WAIT_ON_RESUME')
        self.executor.hold()
        self.assertEqual(self.store.state.reason,'INCOMPLETE_HEALTH_WAIT_ON_RESUME')

    def test_logger_reconcile_cannot_bypass_installation_gate(self):
        self.executor.open()
        self.store.state.reason = 'LOGGER_TIMEOUT'
        self.journal.record['phase'] = 'ROLLED_BACK'
        self.journal.record['restored'] = list(reversed(c.ORDER))
        state = self.executor.reconcile_logger(explicit=True)
        self.assertEqual(state.reason, 'INSTALLATION_GATE_FAILED')
        self.assertEqual(self.backend.calls, [])


@unittest.skipUnless(sys.platform == 'linux', 'Linux fd/ACL/xattr profile tests')
class ProtectedStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.store = ProtectedStore(self.path, LABEL, LABEL, uid=os.getuid(), gid=os.getgid())
        # CI has no enforcing SELinux: xattrs are synthetic; real fd, mode,
        # nofollow, inventory, atomic write and lock behavior stay exercised.
        self.attrs = patch('harbor_recovery_protected_store.os.listxattr', return_value=['security.selinux'])
        self.context = patch('harbor_recovery_protected_store.os.getxattr', return_value=LABEL.encode()+b'\0')
        self.attrs.start(); self.context.start()
        self.addCleanup(self.attrs.stop); self.addCleanup(self.context.stop)

    def test_initialization_save_and_inventory_with_exact_private_mode(self):
        with self.store.locked():
            self.store.initialize()
            self.store.save(c.State(reason='OPERATOR_HOLD'))
            self.assertEqual(self.store.load().reason, 'OPERATOR_HOLD')
            self.assertEqual(self.store.inventory(), {'files': 2, 'pending': []})
        self.assertEqual((self.path/'state.json').stat().st_mode & 0o777, 0o600)

    def test_pending_evidence_readable_but_blocks_all_new_writes(self):
        with self.store.locked():
            self.store.initialize()
            self.store._new('state-'+'a'*32+'.pending', b'preserved')
            self.assertEqual(self.store.load(), c.State())
            with self.assertRaisesRegex(ValueError, 'UNCOMMITTED'): self.store.save(c.State())
            with self.assertRaisesRegex(ValueError, 'UNCOMMITTED'): self.store.audit('operator-hold', c.State())
        self.assertEqual((self.path/('state-'+'a'*32+'.pending')).read_bytes(), b'preserved')

    def test_unknown_entry_symlink_and_loose_file_mode_block(self):
        with self.store.locked(): self.store.initialize()
        state = self.path/'state.json'; state.chmod(0o644)
        with self.assertRaises(ValueError), self.store.locked(): pass
        state.chmod(0o600)
        extra = self.path/'unexpected'; extra.write_text('x'); extra.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'RECORD_NAME'), self.store.locked(): pass
        extra.unlink()
        state.rename(self.path/'original'); state.symlink_to(self.path/'original')
        with self.assertRaises((OSError, ValueError)), self.store.locked(): pass

    def test_acl_unknown_xattr_and_label_reject_without_repair(self):
        with patch('harbor_recovery_protected_store.os.listxattr', return_value=['system.posix_acl_default']):
            with self.assertRaisesRegex(ValueError, 'ACL'), self.store.locked(): pass
        with patch('harbor_recovery_protected_store.os.listxattr', return_value=['security.selinux', 'user.extra']):
            with self.assertRaisesRegex(ValueError, 'XATTR'), self.store.locked(): pass
        with patch('harbor_recovery_protected_store.os.getxattr', return_value=b'wrong_context'):
            with self.assertRaisesRegex(ValueError, 'CONTEXT'), self.store.locked(): pass
        self.assertEqual(list(self.path.iterdir()), [])

    def test_parent_acl_blocks_before_lock_creation(self):
        with patch('harbor_recovery_protected_store.os.listxattr', return_value=['system.posix_acl_access']):
            with self.assertRaisesRegex(ValueError, 'ACL'), self.store.locked(): pass
        self.assertEqual(list(self.path.iterdir()), [])

    def test_wrong_new_file_label_preserves_empty_record_and_refuses_initialize(self):
        with self.store.locked():
            def new_file_context(fd, key):
                return (b'wrong_context' if os.readlink(f'/proc/self/fd/{fd}') == str(self.path/'state.json')
                        else LABEL.encode()+b'\0')
            with patch('harbor_recovery_protected_store.os.getxattr', side_effect=new_file_context):
                with self.assertRaisesRegex(ValueError, 'CONTEXT'): self.store.initialize()
        self.assertEqual((self.path/'state.json').read_bytes(), b'')
        with self.store.locked():
            with self.assertRaisesRegex(ValueError, 'NOT_EMPTY'): self.store.initialize()

    def test_real_journal_store_install_activate_hold_and_rollback(self):
        plan, item = fixture()
        store = self.store
        journal = t.Journal(store, plan)
        class Policy:
            def observe(self, deadline): return deepcopy(item)
            def update(self, action, previous, deadline):
                assert journal.load()['pending'] == action
                assert (store.path/f'policy-claim-{action["token"]:020}.json').is_file()
                item.policies[action['service']] = deepcopy(action['to'])
                return 'ack'
        with store.locked(): store.initialize()
        tx = t.Transition(plan, store, Policy(), journal=journal, clock=lambda: 10)
        self.assertEqual(tx.install(20, explicit=True)['phase'], 'INSTALLED_HOLD')
        backend = RuntimeBackend(plan)
        act = b.Activation(c.Controller(plan.recovery), store, journal, backend,
                           lambda end: plan.manager_binding, clock=lambda: 10)
        self.assertEqual(act.arm_initial(20, explicit=True).desired, 'RUN')
        executor = Executor(act.core, store, backend, clock=lambda: 10, gate=act.installed)
        executor.open()
        self.assertEqual(executor.tick().reason, 'HEALTHY')
        executor.hold()
        self.assertEqual(tx.rollback(20, explicit=True)['phase'], 'ROLLED_BACK')
        self.assertEqual(item.policies, t.original_policies())
        self.assertNotIn('start', backend.calls)
        with store.locked():
            self.assertEqual(store.load().desired, 'HOLD')
            self.assertEqual(store.inventory()['pending'], [])
            with self.assertRaisesRegex(ValueError, 'NOT_EMPTY'): store.initialize()
        self.assertEqual(len(list(self.path.glob('policy-claim-*.json'))), 18)
        self.assertEqual(len(list(self.path.glob('initial-arm-request-*.json'))), 1)

    def test_activation_replace_failure_preserves_pending_and_blocks_retry(self):
        plan, item = fixture()
        journal = t.Journal(self.store, plan)
        record = {'version': 1, 'plan': plan.binding, 'boot': BOOT, 'daemon': DAEMON,
                  'original': t.original_policies(), 'phase': 'INSTALLED_HOLD',
                  'reason': 'ALL_POLICIES_VERIFIED', 'changed': list(c.ORDER),
                  'restored': [], 'next_token': 10, 'pending': None}
        with self.store.locked():
            self.store.initialize(); journal.create(record)
        backend = RuntimeBackend(plan)
        act = b.Activation(c.Controller(plan.recovery), self.store, journal, backend,
                           lambda end: plan.manager_binding, clock=lambda: 10)
        with patch('harbor_recovery_store.os.replace', side_effect=OSError('injected')):
            with self.assertRaises(OSError): act.arm_initial(20, explicit=True)
        with self.store.locked(): self.assertEqual(self.store.load(), c.State())
        self.assertEqual(len(list(self.path.glob('*.pending'))), 1)
        self.assertEqual(len(list(self.path.glob('initial-arm-request-*.json'))), 1)
        with self.assertRaisesRegex(ValueError, 'UNCOMMITTED'): act.arm_initial(20, explicit=True)
        self.assertNotIn('start', backend.calls)


if __name__ == '__main__': unittest.main()
