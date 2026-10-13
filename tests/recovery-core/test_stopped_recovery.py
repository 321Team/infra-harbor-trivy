"""Completed H6 recovery simulations; no production/daemon/service access."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'scripts/recovery'))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'scripts/preparation'))
import harbor_stopped_recovery as r
import test_operator_control as fixtures
from harbor_recovery_core import ORDER
from harbor_recovery_store import encode


class Journal:
    def __init__(self): self.values, self.calls, self.on_write = {}, [], lambda name: None
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def create(self, pin, name, value):
        key = (pin, name)
        if key in self.values: raise FileExistsError('spent attempt')
        self.calls.append(name)
        self.values[key] = deepcopy(value)
        self.on_write(name)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ControlTests(); self.f.setUp(); self.f.stop()
        self.before = encode(self.f.store.state)
        self.stops = deepcopy(self.f.ledger._records())
        self.pin = r.state_hash(self.f.store.state)
        with self.f.store.locked(): _, self.stop_pin = r.completed_stop(self.f.control, self.pin)
        self.journal, self.starts = Journal(), []
        self.on_start = lambda name: None
        def start(cid, deadline):
            name = next(n for n in ORDER if self.f.rows[n].id == cid)
            self.assertIn((self.pin, 'intent-'+str(len(self.starts))), self.journal.values)
            self.starts.append(cid)
            self.f.rows[name] = replace(self.f.rows[name], status='running', health='healthy')
            return self.on_start(name) or 'ok'
        self.f.backend.engine = SimpleNamespace(start=start)
        self.recovery = r.StoppedRecovery(self.f.control, receipts=lambda: self.journal,
                                         clock=lambda: self.f.now, sleep=self.advance)

    def advance(self, value): self.f.now += value
    def recover(self, **kw):
        return self.recovery.run(self.pin, self.stop_pin, 1000, explicit=True, **kw)
    def unchanged(self):
        self.assertEqual(encode(self.f.store.state), self.before)
        self.assertEqual(self.f.ledger._records(), self.stops)
        self.assertEqual(self.f.store.claims, {})

    def test_h6_stop_then_recover_nine_and_explicit_existing_reconcile(self):
        result = self.recover()
        self.assertEqual(result['stage'], 'APPS_RECOVERED_HOLD_PRESERVED')
        self.assertEqual(self.starts, [self.f.core.plan.ids[n] for n in ORDER])
        self.assertEqual(len(self.journal.values), 29)
        self.unchanged()
        # Recovery deliberately did not release HOLD; existing reconciliation
        # alone performs the explicitly requested healthy RUN transition.
        state = self.f.control.reconcile(self.pin, 1000, explicit=True)
        self.assertEqual(state.reason, 'EXPLICIT_HEALTHY_RECONCILIATION')
        self.assertEqual(state.next_token, 10)

    def test_inspection_checks_live_state_without_receipts_or_posts(self):
        result = self.recovery.inspect(self.pin, 100)
        self.assertEqual(result['stop_set_sha256'], self.stop_pin)
        self.assertEqual(self.journal.values, {}); self.assertEqual(self.starts, [])
        self.unchanged()

    def test_arbitrary_hold_not_a_completed_h6_is_refused(self):
        self.f.store.state.reason = 'OPERATOR_HOLD'; self.pin = r.state_hash(self.f.store.state)
        with self.assertRaisesRegex(ValueError, 'NOT_COMPLETED_STOP'): self.recover()
        self.assertEqual(self.starts, [])

    def test_missing_ack_despite_exited_readback_is_refused(self):
        self.f.ledger.acks.pop(9)
        with self.assertRaisesRegex(ValueError, 'RECORD_MISSING'): self.recover()
        self.assertEqual(self.starts, [])

    def test_wrong_generation_or_service_in_completed_stop_is_refused(self):
        for field, value in [('boot', 'other'), ('daemon', 'other'), ('service', 'core'), ('id', 'f'*64), ('version', True)]:
            with self.subTest(field=field):
                self.setUp()
                for records in (self.f.ledger.claims, self.f.ledger.acks, self.f.ledger.receipts):
                    records[9][field] = value
                with self.assertRaisesRegex(ValueError, 'STOP_RECORD'): self.recover()
                self.assertEqual(self.starts, [])

    def test_partial_stop_cannot_be_recovered(self):
        self.f.ledger.receipts.pop(9)
        with self.assertRaisesRegex(ValueError, 'STOP_UNRESOLVED'): self.recover()
        self.assertEqual(self.starts, [])

    def test_state_and_receipt_external_pins_required(self):
        for change in ('state', 'stop'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'state': self.pin = 'a'*64
                else: self.stop_pin = 'b'*64
                with self.assertRaises(ValueError): self.recover()
                self.assertEqual(self.starts, [])

    def test_explicit_and_finite_deadline_before_any_write(self):
        for deadline in (True, float('nan'), float('inf'), 10):
            with self.assertRaises(ValueError):
                self.recovery.run(self.pin, self.stop_pin, deadline, explicit=True)
        with self.assertRaisesRegex(ValueError, 'EXPLICIT'):
            self.recovery.run(self.pin, self.stop_pin, 100)
        self.assertEqual(self.journal.calls, [])

    def test_stopped_manager_check_failure_blocks_before_attempt(self):
        def fail(_): raise ValueError('MANAGER_NOT_DISABLED_STOPPED')
        self.f.control.manager = fail
        with self.assertRaisesRegex(ValueError, 'MANAGER'): self.recover()
        self.assertEqual(self.journal.calls, []); self.assertEqual(self.starts, [])

    def test_manager_lease_contention_blocks_before_attempt(self):
        def busy(): raise BlockingIOError('lease')
        self.f.control.lease = busy
        with self.assertRaises(BlockingIOError): self.recover()
        self.assertEqual(self.journal.calls, [])

    def test_guard_drift_immediately_after_intent_never_posts(self):
        self.journal.on_write = lambda name: setattr(self.f, 'boot', 'boot-2') if name == 'intent-0' else None
        with self.assertRaisesRegex(ValueError, 'GENERATION_OR_GUARD'): self.recover()
        self.assertEqual(self.starts, []); self.unchanged()

    def test_source_verification_failure_after_intent_never_posts(self):
        def gate(): raise ValueError('HOST_SOURCE_CHANGED')
        self.journal.on_write = lambda name: setattr(self.f.executor, 'gate', gate) if name == 'intent-0' else None
        with self.assertRaisesRegex(ValueError, 'SOURCE_CHANGED'): self.recover()
        self.assertEqual(self.starts, [])

    def test_metadata_policy_logger_and_foreign_start_drift_refused(self):
        cases = [('core', dict(fingerprint='f'*64)), ('core', dict(restart='always')),
                 ('log', dict(health='unhealthy')), ('redis', dict(status='running', health='healthy'))]
        for name, fields in cases:
            with self.subTest(name=name, fields=fields):
                self.setUp(); self.f.rows[name] = replace(self.f.rows[name], **fields)
                with self.assertRaises(ValueError): self.recover()
                self.assertEqual(self.starts, [])

    def test_attempt_or_intent_persistence_failure_prevents_posts(self):
        for broken in ('attempt', 'intent-0'):
            self.setUp()
            def fail(name):
                if name == broken: raise OSError('disk')
            self.journal.on_write = fail
            with self.assertRaises(OSError): self.recover()
            self.assertEqual(self.starts, []); self.unchanged()

    def test_ack_persistence_failure_after_post_stops_next_app(self):
        def fail(name):
            if name == 'ack-0': raise OSError('disk')
        self.journal.on_write = fail
        with self.assertRaises(OSError): self.recover()
        self.assertEqual(len(self.starts), 1); self.unchanged()

    def test_unknown_response_never_retried_even_if_container_started(self):
        self.on_start = lambda name: 'unknown'
        with self.assertRaisesRegex(ValueError, 'START_UNKNOWN'): self.recover()
        self.assertNotIn((self.pin, 'ack-0'), self.journal.values)
        self.assertEqual(len(self.starts), 1); self.unchanged()

    def test_transport_exception_leaves_intent_and_hold(self):
        def fail(name): raise TimeoutError('socket')
        self.on_start = fail
        with self.assertRaises(TimeoutError): self.recover()
        self.assertEqual(len(self.starts), 1); self.unchanged()

    def test_spent_attempt_cannot_be_reused_after_external_stop(self):
        self.on_start = lambda name: 'unknown'
        with self.assertRaises(ValueError): self.recover()
        self.f.rows['postgresql'] = replace(self.f.rows['postgresql'], status='exited')
        with self.assertRaises(FileExistsError): self.recover()
        self.assertEqual(len(self.starts), 1)

    def test_health_starting_polls_then_healthy_before_next_app(self):
        def start(name):
            self.f.rows[name] = replace(self.f.rows[name], health='starting')
        self.on_start = start
        def sleep(seconds):
            self.advance(seconds)
            self.f.rows = {n: replace(row, health='healthy') if row.status == 'running' else row
                           for n, row in self.f.rows.items()}
        self.recovery.sleep = sleep
        self.recover(); self.assertEqual(len(self.starts), 9); self.unchanged()

    def test_health_deadline_stops_before_next_app(self):
        self.on_start = lambda name: self.f.rows.update({name: replace(self.f.rows[name], health='starting')})
        with self.assertRaisesRegex(ValueError, 'DEADLINE'): self.recover()
        self.assertEqual(len(self.starts), 1); self.unchanged()

    def test_failed_earlier_app_prevents_next_start(self):
        def fail(name):
            if name == 'redis':
                self.f.rows['postgresql'] = replace(self.f.rows['postgresql'], health='unhealthy')
        self.on_start = fail
        with self.assertRaisesRegex(ValueError, 'PREFIX_CHANGED'): self.recover()
        self.assertEqual(len(self.starts), 2)

    def test_start_response_after_deadline_is_unknown_without_ack(self):
        self.on_start = lambda name: self.advance(self.f.core.plan.start_seconds)
        with self.assertRaisesRegex(ValueError, 'DEADLINE'): self.recover()
        self.assertEqual(len(self.starts), 1)
        self.assertNotIn((self.pin, 'ack-0'), self.journal.values)

    def test_overall_installed_episode_caps_large_caller_deadline(self):
        self.journal.on_write = lambda name: self.advance(self.f.core.plan.episode_seconds) if name == 'attempt' else None
        with self.assertRaisesRegex(ValueError, 'DEADLINE'): self.recover()
        self.assertEqual(self.starts, [])

    def test_state_drift_after_intent_prevents_post(self):
        def drift(name):
            if name == 'intent-0': self.f.store.state.reason = 'OTHER_HOLD'
        self.journal.on_write = drift
        with self.assertRaisesRegex(ValueError, 'STATE_CHANGED'): self.recover()
        self.assertEqual(self.starts, [])

    def test_clock_reversal_after_attempt_refused(self):
        self.f.now = 20
        self.journal.on_write = lambda name: setattr(self.f, 'now', 19) if name == 'attempt' else None
        with self.assertRaisesRegex(ValueError, 'RECOVERY_CLOCK'): self.recover()
        self.assertEqual(self.starts, [])

    def test_terminal_receipt_failure_does_not_release_hold(self):
        def fail(name):
            if name == 'complete': raise OSError('disk')
        self.journal.on_write = fail
        with self.assertRaises(OSError): self.recover()
        self.assertEqual(len(self.starts), 9); self.unchanged()


@unittest.skipUnless(sys.platform == 'linux', 'Real Linux fd with synthetic SELinux labels')
class ReceiptTests(unittest.TestCase):
    def setUp(self):
        import test_writer_context as w
        self.fixture = w.WriterContextTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture.store
        self.folder = Path(str(self.store.path)+'.stopped-recovery')
        self.folder.mkdir(mode=0o700)
        # The sibling is outside the fixture TemporaryDirectory.
        self.addCleanup(self.clean_sibling)
        self.pin = 'b'*64

    def clean_sibling(self):
        for path in self.folder.iterdir(): path.unlink()
        self.folder.rmdir()

    def test_real_create_reopen_exclusive_and_exact_fixed_path(self):
        with r.ReceiptDirectory(self.store) as d: d.create(self.pin, 'attempt', {'real_fd': True})
        with r.ReceiptDirectory(self.store) as d:
            with self.assertRaises(FileExistsError): d.create(self.pin, 'attempt', {})
        self.assertEqual(list(self.store.path.iterdir()), [])
        self.assertEqual(len(list(self.folder.iterdir())), 1)

    def test_wrong_actor_fails_without_leaving_file(self):
        self.fixture.actor = 'unconfined_u:unconfined_r:unconfined_t:s0'
        with r.ReceiptDirectory(self.store) as d:
            with self.assertRaisesRegex(ValueError, 'WRITER_CONTEXT'): d.create(self.pin, 'attempt', {})
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_wrong_creation_label_preserved_and_never_overwritten(self):
        self.fixture.new_label = self.store.directory_context
        with r.ReceiptDirectory(self.store) as d:
            with self.assertRaisesRegex(ValueError, 'STORE_CONTEXT'): d.create(self.pin, 'attempt', {})
        self.assertEqual((self.folder/(self.pin+'-attempt.json')).read_bytes(), b'')
        self.fixture.new_label = self.store.file_context
        with r.ReceiptDirectory(self.store) as d:
            with self.assertRaises(FileExistsError): d.create(self.pin, 'attempt', {})

    def test_short_write_and_failed_fsync_preserve_spent_attempt(self):
        import os
        write = os.write
        with patch('os.write', side_effect=lambda fd, raw: write(fd, raw[:1])):
            with r.ReceiptDirectory(self.store) as d: d.create(self.pin, 'intent-0', {'ok': True})
        with patch('os.fsync', side_effect=OSError('disk')):
            with r.ReceiptDirectory(self.store) as d:
                with self.assertRaises(OSError): d.create(self.pin, 'attempt', {})
        with r.ReceiptDirectory(self.store) as d:
            with self.assertRaises(FileExistsError): d.create(self.pin, 'attempt', {})

    def test_symlink_attempt_and_bad_names_refused(self):
        target = self.store.path/'untouched'; target.write_bytes(b'keep')
        (self.folder/(self.pin+'-attempt.json')).symlink_to(target)
        with r.ReceiptDirectory(self.store) as d:
            with self.assertRaises(FileExistsError): d.create(self.pin, 'attempt', {})
            for name in ('../escape', 'intent-9', 'ack--1'):
                with self.assertRaises(ValueError): d.create(self.pin, name, {})
        self.assertEqual(target.read_bytes(), b'keep')
