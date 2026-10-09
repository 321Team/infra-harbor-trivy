"""Crash-injection protocol tests and real POSIX private-store tests.

All backends are synthetic. POSIX file tests run on Ubuntu CI; Windows skips
those tests explicitly and does not pretend to have checked Linux permissions.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/recovery'))
import harbor_recovery_core as c
from harbor_recovery_executor import Executor
from harbor_recovery_store import Store, decode, encode


def fixture():
    ids = {n: f'{i+1:064x}' for i, n in enumerate((*c.ORDER, 'log'))}
    plan = c.Plan(ids, {s: 'a'*64 for s in ids}, {s: 60 for s in c.ORDER})
    rows = {s: c.Container(ids[s], 'a'*64, 'running' if s == 'log' else 'exited',
                           'healthy' if s == 'log' else 'unhealthy',
                           'always' if s == 'log' else 'no') for s in ids}
    return c.Controller(plan), rows


class MemoryStore:
    def __init__(self):
        self.state = c.State()
        self.claims, self.records = {}, []
        self.locked_now = False
        self.fail_reason = None

    @contextmanager
    def locked(self):
        if self.locked_now:
            raise BlockingIOError('busy')
        self.locked_now = True
        try:
            yield self
        finally:
            self.locked_now = False

    def load(self):
        assert self.locked_now
        return decode(encode(self.state))

    def save(self, state):
        assert self.locked_now
        if state.reason == self.fail_reason:
            raise OSError('injected persistence failure')
        self.state = decode(encode(state))

    def claim(self, action):
        assert self.locked_now and self.state.pending == action
        if action.token in self.claims:
            raise FileExistsError('spent token')
        self.claims[action.token] = action

    def audit(self, kind, state):
        assert self.locked_now
        self.records.append((kind, deepcopy(state)))


class Backend:
    def __init__(self, store, rows):
        self.store, self.rows = store, rows
        self.now, self.tcp, self.starts = 0, True, []
        self.behavior = 'ok'
        self.read_count = 0
        self.break_on_read = None

    def observe(self):
        self.read_count += 1
        if self.read_count == self.break_on_read:
            raise OSError('observation failed')
        return c.Observation('boot-1', 'daemon-1', self.now, deepcopy(self.rows), True, self.tcp)

    def start(self, action, timeout, *, stop_requested=lambda: False):
        assert self.store.locked_now and self.store.state.pending == action
        assert self.store.claims[action.token] == action
        assert 0 < timeout <= 60
        self.starts.append(action)
        if isinstance(self.behavior, BaseException):
            raise self.behavior
        return self.behavior


class CodecTests(unittest.TestCase):
    def test_initial_and_intent_roundtrip(self):
        self.assertEqual(decode(encode(c.State())), c.State())
        core, rows = fixture()
        o = c.Observation('boot-1', 'daemon-1', 0, rows, True, True)
        s = core.arm(c.State(), o, 0).state
        s = core.step(s, o, 0).state
        self.assertEqual(decode(encode(s)), s)

    def test_schema_version_nan_bool_and_extra_rejected(self):
        good = json.loads(encode(c.State()))
        for change in ('version', 'extra', 'nan', 'token', 'run'):
            obj = deepcopy(good)
            if change == 'version': obj['version'] = True
            if change == 'extra': obj['state']['ignore_me'] = 1
            if change == 'nan': obj['state']['last_now'] = float('nan')
            if change == 'token': obj['state']['next_token'] = True
            if change == 'run': obj['state']['desired'] = 'RUN'
            with self.subTest(change=change), self.assertRaises(ValueError):
                decode(json.dumps(obj).encode())

    def test_duplicate_key_rejected(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'):
            decode(b'{"version":1,"version":1,"state":{}}')

    def test_retry_future_and_invalid_intent_rejected(self):
        s = c.State(last_now=1)
        s.retries['core'] = [2]
        with self.assertRaises(ValueError): encode(s)
        s = c.State(pending=c.Action(1, 'core', 'b'*64, 'boot-1', 'daemon-1', 60))
        with self.assertRaises(ValueError): encode(s)


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.core, self.rows = fixture()
        self.store = MemoryStore()
        self.backend = Backend(self.store, self.rows)
        self.runner = self.make_runner()
        self.runner.open()
        self.runner.arm_initial()

    def make_runner(self):
        return Executor(self.core, self.store, self.backend, clock=lambda: self.backend.now)

    def test_open_required(self):
        with self.assertRaises(RuntimeError): self.make_runner().tick()

    def test_persist_then_claim_then_submit_once(self):
        s = self.runner.tick()
        self.assertEqual(len(self.backend.starts), 1)
        self.assertEqual(s.reason, 'WAIT_HEALTH')
        self.assertIsNone(s.pending)
        self.rows['postgresql'] = replace(self.rows['postgresql'], status='running', health='starting')
        self.runner.tick()
        self.assertEqual(len(self.backend.starts), 1)

    def test_intent_save_failure_prevents_submission(self):
        self.store.fail_reason = 'START_INTENT'
        with self.assertRaises(OSError): self.runner.tick()
        self.assertEqual(self.backend.starts, [])
        self.assertEqual(self.store.claims, {})

    def test_authorization_save_failure_prevents_submission(self):
        self.store.fail_reason = 'START_AUTHORIZED'
        with self.assertRaises(OSError): self.runner.tick()
        self.assertIsNotNone(self.store.state.pending)
        self.assertEqual(self.backend.starts, [])

    def test_unknown_start_no_retry(self):
        self.backend.behavior = TimeoutError('late result')
        s = self.runner.tick()
        self.assertEqual(s.desired, 'HOLD')
        self.assertIsNotNone(s.pending)
        self.runner.tick()
        self.assertEqual(len(self.backend.starts), 1)

    def test_crash_after_submission_new_process_holds(self):
        self.backend.behavior = SystemExit('crash')
        with self.assertRaises(SystemExit): self.runner.tick()
        self.assertIsNotNone(self.store.state.pending)
        fresh = self.make_runner()
        fresh.open()
        fresh.tick()
        self.assertEqual(self.store.state.reason, 'UNRESOLVED_START_ON_RESUME')
        self.assertEqual(len(self.backend.starts), 1)

    def test_ack_save_failure_leaves_pending_and_no_second_submission(self):
        self.store.fail_reason = 'WAIT_HEALTH'
        with self.assertRaises(OSError): self.runner.tick()
        self.store.fail_reason = None
        fresh = self.make_runner()
        fresh.open()
        fresh.tick()
        self.assertEqual(self.store.state.desired, 'HOLD')
        self.assertEqual(len(self.backend.starts), 1)

    def test_existing_claim_blocks_backward_state_replay(self):
        self.store.claims[1] = 'historical token'
        s = self.runner.tick()
        self.assertEqual(s.reason, 'DUPLICATE_DISPATCH_TOKEN')
        self.assertEqual(self.backend.starts, [])

    def test_second_observation_failure_prevents_dispatch(self):
        self.backend.break_on_read = self.backend.read_count + 2
        s = self.runner.tick()
        self.assertEqual(s.reason, 'DISPATCH_OBSERVATION_FAILED')
        self.assertEqual(self.backend.starts, [])

    def test_logger_lost_before_dispatch(self):
        original = self.backend.observe
        target = self.backend.read_count + 2
        def observe():
            if self.backend.read_count + 1 == target: self.backend.tcp = False
            return original()
        self.backend.observe = observe
        s = self.runner.tick()
        self.assertEqual(s.reason, 'LOGGER_LOST_BEFORE_DISPATCH')
        self.assertEqual(self.backend.starts, [])

    def test_operator_hold_audited_and_preserved(self):
        self.runner.hold()
        self.runner.tick()
        self.assertEqual(self.backend.starts, [])
        self.assertEqual(self.store.records[0][0], 'operator-hold')

    def logger_hold(self):
        for name in self.rows:
            self.rows[name] = replace(self.rows[name], status='running', health='healthy')
        self.runner.tick()
        self.backend.tcp = False
        self.backend.now = 1
        self.runner.tick()
        self.backend.now = 121
        self.runner.tick()
        self.assertEqual(self.store.state.reason, 'LOGGER_TIMEOUT')
        self.backend.tcp = True
        self.backend.now = 122

    def test_logger_reconciliation_requires_explicit_request(self):
        self.logger_hold()
        with self.assertRaisesRegex(ValueError, 'EXPLICIT'):
            self.runner.reconcile_logger()
        self.assertEqual(self.store.state.desired, 'HOLD')

    def test_logger_reconcile_no_start_no_retry_budget_reset(self):
        self.logger_hold()
        self.store.state.retries['core'] = [100]
        before = deepcopy(self.store.state)
        s = self.runner.reconcile_logger(explicit=True)
        self.assertEqual(s.desired, 'RUN')
        self.assertEqual(s.retries, before.retries)
        self.assertEqual(s.next_token, before.next_token)
        self.assertEqual(self.backend.starts, [])
        self.assertEqual(self.store.records[-1], ('logger-reconcile-request', before))

    def test_logger_reconcile_rejects_unhealthy_or_generation_drift(self):
        self.logger_hold()
        self.rows['core'] = replace(self.rows['core'], health='unhealthy')
        with self.assertRaises(ValueError): self.runner.reconcile_logger(explicit=True)
        self.assertEqual(self.store.state.desired, 'HOLD')
        self.rows['core'] = replace(self.rows['core'], health='healthy')
        original = self.backend.observe
        self.backend.observe = lambda: replace(original(), daemon='daemon-2')
        with self.assertRaises(ValueError): self.runner.reconcile_logger(explicit=True)

    def test_other_hold_reasons_not_reconciled(self):
        self.runner.hold()
        with self.assertRaisesRegex(ValueError, 'NOT_LOGGER_ONLY'):
            self.runner.reconcile_logger(explicit=True)


@unittest.skipUnless(os.name == 'posix', 'POSIX permission/locking/fsync checks run on Linux CI')
class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hbr-state-test-', dir=Path.home())
        self.path = Path(self.tmp.name)
        os.chmod(self.path, 0o700)
        self.store = Store(self.path, uid=os.getuid())

    def tearDown(self):
        self.tmp.cleanup()

    def test_explicit_init_atomic_save_and_roundtrip(self):
        with self.store.locked():
            with self.assertRaises(FileNotFoundError): self.store.load()
            self.store.initialize()
            self.assertEqual(self.store.load(), c.State())
            s = c.State(reason='OPERATOR_HOLD')
            self.store.save(s)
            self.assertEqual(self.store.load(), s)
        self.assertEqual((self.path/'state.json').stat().st_mode & 0o777, 0o600)

    def test_lock_contention(self):
        other = Store(self.path, uid=os.getuid())
        with self.store.locked():
            with self.assertRaises(BlockingIOError), other.locked(): pass

    def test_symlink_directory_and_state_rejected(self):
        link = self.path/'link'
        link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError), Store(link, uid=os.getuid()).locked(): pass
        with self.store.locked():
            (self.path/'state.json').symlink_to(self.path/'missing')
            with self.assertRaises(OSError): self.store.load()

    def test_hardlink_and_loose_permissions_rejected(self):
        with self.store.locked():
            self.store.initialize()
            os.link(self.path/'state.json', self.path/'alias')
            with self.assertRaises(ValueError): self.store.load()
            (self.path/'alias').unlink()
            os.chmod(self.path/'state.json', 0o644)
            with self.assertRaises(ValueError): self.store.load()

    def test_corrupt_or_missing_state_never_reinitialized(self):
        with self.store.locked():
            self.store.initialize()
            (self.path/'state.json').write_bytes(b'invalid')
            with self.assertRaises(ValueError): self.store.save(c.State())
            with self.assertRaises(ValueError): self.store.initialize()

    def test_partial_file_prevents_initialization(self):
        (self.path/'state-aborted.pending').write_bytes(b'partial')
        with self.store.locked(), self.assertRaises(ValueError): self.store.initialize()

    def test_claim_is_one_use(self):
        a = c.Action(1, 'core', 'a'*64, 'boot-1', 'daemon-1', 60)
        with self.store.locked():
            self.store.initialize()
            self.store.claim(a)
            with self.assertRaises(FileExistsError): self.store.claim(a)

    def test_fsync_failure_keeps_previous_state(self):
        with self.store.locked():
            self.store.initialize()
            with patch('harbor_recovery_store.os.fsync', side_effect=OSError('disk')):
                with self.assertRaises(OSError): self.store.save(c.State(reason='OPERATOR_HOLD'))
            self.assertEqual(self.store.load(), c.State())

    def test_replace_failure_keeps_previous_state(self):
        with self.store.locked():
            self.store.initialize()
            with patch('harbor_recovery_store.os.replace', side_effect=OSError('disk')):
                with self.assertRaises(OSError): self.store.save(c.State(reason='OPERATOR_HOLD'))
            self.assertEqual(self.store.load(), c.State())

    def test_insecure_directory_rejected(self):
        os.chmod(self.path, 0o755)
        with self.assertRaisesRegex(ValueError, 'PRIVATE_STORE'), self.store.locked(): pass

    def test_operations_without_lock_rejected(self):
        with self.assertRaises(ValueError): self.store.load()

    def test_fifo_state_rejected_without_blocking(self):
        os.mkfifo(self.path/'state.json', 0o600)
        with self.store.locked(), self.assertRaises(ValueError): self.store.load()

    def test_real_process_exit_after_claim_does_not_redispatch(self):
        import multiprocessing
        core, rows = fixture()
        with self.store.locked(): self.store.initialize()
        class CrashBackend:
            def observe(self):
                return c.Observation('boot-1', 'daemon-1', 0, rows, True, True)
            def start(self, action, timeout, *, stop_requested=lambda: False):
                os._exit(17)  # no Python finally/cleanup: OS releases flock
        def child():
            runner = Executor(core, Store(self.path, uid=os.getuid()), CrashBackend(), clock=lambda: 0)
            runner.open()
            runner.arm_initial()
            runner.tick()
        process = multiprocessing.get_context('fork').Process(target=child)
        process.start()
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join()
            self.fail('child did not terminate')
        self.assertEqual(process.exitcode, 17)
        class NoDispatchBackend(CrashBackend):
            def start(self, action, timeout, *, stop_requested=lambda: False):
                raise AssertionError('must not dispatch again')
        runner = Executor(core, self.store, NoDispatchBackend(), clock=lambda: 1)
        runner.open()
        self.assertEqual(runner.tick().reason, 'UNRESOLVED_START_ON_RESUME')
        with self.store.locked(): self.assertIsNotNone(self.store.load().pending)
        self.assertEqual(len(list(self.path.glob('intent-*.json'))), 1)


if __name__ == '__main__':
    unittest.main()
