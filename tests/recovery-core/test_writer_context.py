"""CLI/service handoff regression: real Linux fds, mocked process/file labels."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'scripts/recovery'))
from harbor_recovery_core import State
from harbor_recovery_protected_store import ProtectedStore, task_attribute
from harbor_recovery_service import ManagerLease
from harbor_recovery_transition import Journal, Transition
from test_policy_transition import fixture
from test_approved_bundle import candidate, Pins, LABEL
import harbor_recovery_bundle as bundle

CLI = 'unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023'
SERVICE = 'system_u:system_r:synthetic_service_t:s0'
DIRECTORY = 'unconfined_u:object_r:var_lib_t:s0'
FILE = 'system_u:object_r:var_lib_t:s0'


@unittest.skipUnless(sys.platform == 'linux', 'Linux fd/lock/SELinux attribute interface')
class WriterContextTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(tmp.cleanup); self.path = Path(tmp.name)
        self.actor, self.fscreate, self.new_label = SERVICE, '', FILE
        self.now = 10
        self.labels = {}
        actual_open = os.open
        def opened(*args, **kwargs):
            fd = actual_open(*args, **kwargs); st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode): self.labels.setdefault((st.st_dev, st.st_ino), self.new_label)
            return fd
        def context(fd, key):
            st = os.fstat(fd)
            return (self.labels.get((st.st_dev, st.st_ino), DIRECTORY)+'\0').encode()
        for mock in (patch('os.open', side_effect=opened),
                     patch('os.listxattr', return_value=['security.selinux']),
                     patch('os.getxattr', side_effect=context),
                     patch('harbor_recovery_protected_store.task_attribute',
                           side_effect=lambda name: self.actor if name == 'current' else self.fscreate)):
            mock.start(); self.addCleanup(mock.stop)
        self.store = ProtectedStore(self.path, DIRECTORY, FILE, writer_context=SERVICE,
                                    uid=os.getuid(), gid=os.getgid())

    def initialize(self):
        with self.store.locked(): self.store.initialize()

    def test_wrong_cli_context_refused_before_first_controller_file(self):
        self.actor = CLI
        with self.assertRaisesRegex(ValueError, 'STORE_WRITER_CONTEXT_CHANGED'): self.initialize()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_context_override_refused_even_when_current_context_matches(self):
        self.fscreate = FILE
        with self.assertRaisesRegex(ValueError, 'STORE_FSCREATE_OVERRIDE'): self.initialize()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_context_read_failure_refused_without_file(self):
        with patch('harbor_recovery_protected_store.task_attribute', side_effect=OSError('unavailable')):
            with self.assertRaises(OSError): self.initialize()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_other_writer_cannot_leave_bad_manager_lock_or_poison_existing_store(self):
        self.initialize(); before = (self.path/'state.json').read_bytes(); self.actor = CLI
        with self.assertRaisesRegex(ValueError, 'STORE_WRITER_CONTEXT_CHANGED'), ManagerLease(self.store): pass
        self.assertFalse((self.path/'manager.lock').exists())
        self.assertEqual((self.path/'state.json').read_bytes(), before)
        self.actor = SERVICE
        with self.store.locked(): self.assertEqual(self.store.load(), State())

    def test_writer_change_after_lock_refuses_state_audit_and_claim_without_pending(self):
        self.initialize()
        with self.store.locked():
            self.actor = CLI
            for operation in (lambda: self.store.save(State(reason='OPERATOR_HOLD')),
                              lambda: self.store.audit('operator-hold', State()),
                              lambda: self.store._new('intent-00000000000000000001.json', b'{}')):
                with self.assertRaisesRegex(ValueError, 'STORE_WRITER_CONTEXT_CHANGED'): operation()
            self.assertEqual(self.store.load(), State())
        self.assertEqual(set(os.listdir(self.path)), {'controller.lock', 'state.json'})

    def test_second_service_instance_reopens_and_updates_with_exact_same_profile(self):
        self.initialize()
        with ManagerLease(self.store), self.store.locked():
            self.store.save(State(reason='OPERATOR_HOLD'))
            self.store.audit('operator-hold', self.store.load())
        other = ProtectedStore(self.path, DIRECTORY, FILE, writer_context=SERVICE,
                               uid=os.getuid(), gid=os.getgid())
        with ManagerLease(other), other.locked():
            self.assertEqual(other.load().reason, 'OPERATOR_HOLD')
            other.save(other.load())
            self.assertEqual(other.inventory(), {'files': 4, 'pending': []})

    def test_matching_process_context_does_not_bypass_actual_wrong_file_label(self):
        self.new_label = DIRECTORY
        with self.assertRaisesRegex(ValueError, 'STORE_CONTEXT_CHANGED'): self.initialize()
        self.assertEqual((self.path/'controller.lock').read_bytes(), b'')
        self.assertFalse((self.path/'state.json').exists())

    def test_changed_writer_blocks_policy_install_before_journal_or_engine_update(self):
        self.initialize(); plan, item = fixture(); calls = []
        class Backend:
            def observe(self, deadline): calls.append('observe'); return item
            def update(self, *args): calls.append('update'); raise AssertionError('no mutation expected')
        tx = Transition(plan, self.store, Backend(), journal=Journal(self.store, plan), clock=lambda: 10)
        self.actor = CLI
        with self.assertRaisesRegex(ValueError, 'STORE_WRITER_CONTEXT_CHANGED'): tx.install(20, explicit=True)
        self.assertEqual(calls, [])
        self.assertFalse((self.path/'policy-transition.json').exists())

    def test_same_writer_still_cannot_reinitialize_or_discard_pending(self):
        self.initialize()
        with self.store.locked():
            with self.assertRaisesRegex(ValueError, 'STORE_NOT_EMPTY'): self.store.initialize()
            self.store._new('state-'+'a'*32+'.pending', b'preserve')
            with self.assertRaisesRegex(ValueError, 'STORE_UNCOMMITTED'): self.store.save(State())
        self.assertEqual((self.path/('state-'+'a'*32+'.pending')).read_bytes(), b'preserve')

    def probe(self, phase, pid, *, deadline=20):
        obj = candidate(); pins = Pins(obj)
        loaded = bundle.load_bundle('/etc/fds-harbor-recovery/probe-input.json', pins.sha, LABEL, 20,
                                    io=pins, clock=lambda: 10)
        def store(path, directory_context, file_context, *, writer_context):
            self.assertEqual(path, obj['store']['path']+'.writer-probe')
            self.assertEqual(writer_context, obj['store']['writer_context'])
            return self.store
        with patch.object(bundle, 'ProtectedStore', side_effect=store), \
             patch.object(bundle, 'build', side_effect=AssertionError('runtime construction forbidden')), \
             patch.object(bundle.os, 'getpid', return_value=pid):
            return bundle.probe_store_writer(loaded, phase, deadline, clock=lambda: self.now)

    def test_probe_two_process_protocol_reopens_without_real_claims_and_preserves_records(self):
        first = self.probe('probe-create', 123)
        self.assertTrue(first['probe_only']); self.assertEqual(first['operational_store_io'], 'NONE')
        names = set(os.listdir(self.path))
        audit = next(n for n in names if n.startswith('operator-hold-'))
        audit_raw = (self.path/audit).read_bytes()
        second = self.probe('probe-reopen', 124)
        self.assertEqual(second['stage'], 'WRITER_PROBE_REOPENED')
        self.assertEqual(len(os.listdir(self.path)), 5)
        self.assertFalse(any(n.startswith(('intent-', 'policy-claim-','stop-claim-')) for n in os.listdir(self.path)))
        self.assertEqual((self.path/audit).read_bytes(), audit_raw)
        for phase in ('probe-create', 'probe-reopen'):
            with self.assertRaises(ValueError): self.probe(phase, 125)

    def test_probe_same_process_unknown_phase_and_expiration_are_not_success(self):
        with self.assertRaisesRegex(ValueError, 'WRITER_PROBE_PHASE'): self.probe('serve', 123)
        with self.assertRaises(ValueError): self.probe('probe-create', 123, deadline=9)
        self.assertEqual(list(self.path.iterdir()), [])
        self.probe('probe-create', 123)
        before = {p.name:p.read_bytes() for p in self.path.iterdir()}
        with self.assertRaisesRegex(ValueError, 'WRITER_PROBE_NEW_PROCESS'): self.probe('probe-reopen', 123)
        self.assertEqual({p.name:p.read_bytes() for p in self.path.iterdir()}, before)

    def test_probe_reopen_wrong_context_and_extra_partial_audit_refused(self):
        self.probe('probe-create', 123); self.actor = CLI
        with self.assertRaisesRegex(ValueError, 'STORE_WRITER_CONTEXT_CHANGED'): self.probe('probe-reopen', 124)
        self.actor = SERVICE
        with self.store.locked(): self.store.audit('operator-hold', self.store.load())
        with self.assertRaisesRegex(ValueError, 'WRITER_PROBE_RECORDS'): self.probe('probe-reopen', 124)

    def test_probe_bad_creation_label_stops_before_any_policy_operation(self):
        self.new_label = DIRECTORY
        with self.assertRaisesRegex(ValueError, 'STORE_CONTEXT_CHANGED'): self.probe('probe-create', 123)
        self.assertEqual(set(os.listdir(self.path)), {'controller.lock'})

    def test_probe_atomic_save_failure_keeps_pending_and_blocks_reopen(self):
        self.probe('probe-create', 123)
        with patch.object(os, 'replace', side_effect=OSError('injected replace failure')):
            with self.assertRaises(OSError): self.probe('probe-reopen', 124)
        pending = [p for p in self.path.iterdir() if p.suffix == '.pending']
        self.assertEqual(len(pending), 1)
        raw = pending[0].read_bytes()
        with self.assertRaises(ValueError): self.probe('probe-reopen', 125)
        self.assertEqual(pending[0].read_bytes(), raw)

    def test_probe_budget_expiring_after_audit_cannot_start_state_save(self):
        self.probe('probe-create', 123)
        before = (self.path/'state.json').read_bytes(); audit = self.store.audit
        def delayed(*args):
            audit(*args); self.now = 21
        with patch.object(self.store, 'audit', side_effect=delayed), patch.object(self.store, 'save') as save:
            with self.assertRaises(ValueError): self.probe('probe-reopen', 124)
            save.assert_not_called()
        self.assertEqual((self.path/'state.json').read_bytes(), before)
        self.assertEqual(len(os.listdir(self.path)), 5)


@unittest.skipUnless(sys.platform == 'linux', 'Linux proc flags')
class AttributeReaderTests(unittest.TestCase):
    def test_read_bounded_current_and_empty_fscreate_never_writes(self):
        with patch('os.open', return_value=9) as opened, patch('os.read', return_value=(SERVICE+'\0').encode()), patch('os.close') as closed:
            self.assertEqual(task_attribute('current'), SERVICE)
            self.assertEqual(opened.call_args.args, ('/proc/thread-self/attr/current', os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW))
            closed.assert_called_once_with(9)
        with patch('os.open', return_value=9), patch('os.read', return_value=b''), patch('os.close'):
            self.assertEqual(task_attribute('fscreate'), '')

    def test_unavailable_nonascii_oversized_and_unknown_attribute_rejected(self):
        with patch('os.open', side_effect=PermissionError('private diagnostic')):
            with self.assertRaisesRegex(ValueError, '^STORE_WRITER_ATTRIBUTE_UNAVAILABLE$'): task_attribute('current')
        for raw, reason in ((b'\xff', 'UNAVAILABLE'), (b'x'*4097, 'SIZE')):
            with patch('os.open', return_value=9), patch('os.read', return_value=raw), patch('os.close') as closed:
                with self.assertRaisesRegex(ValueError, reason): task_attribute('current')
                closed.assert_called_once_with(9)
        with patch('os.open') as opened:
            with self.assertRaisesRegex(ValueError, 'STORE_WRITER_ATTRIBUTE'): task_attribute('../current')
            opened.assert_not_called()


if __name__ == '__main__': unittest.main()
