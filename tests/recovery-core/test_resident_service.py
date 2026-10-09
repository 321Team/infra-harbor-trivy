"""Resident lifecycle and signal boundaries; no systemd/Docker mutation."""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest

import harbor_recovery_service as s
import harbor_recovery_core as c
import harbor_recovery_docker as d
from harbor_recovery_executor import Executor
from harbor_recovery_store import Store
from test_state_executor import MemoryStore, Backend, fixture
from test_approved_bundle import candidate


class ShutdownBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.core, self.rows = fixture()
        self.store = MemoryStore()
        self.backend = Backend(self.store, self.rows)
        self.executor = Executor(self.core, self.store, self.backend, clock=lambda: self.backend.now)
        self.executor.open(); self.executor.arm_initial()

    def test_stop_before_tick_does_not_observe_or_change_run(self):
        before = deepcopy(self.store.state); reads = self.backend.read_count
        self.assertEqual(self.executor.tick(stop_requested=lambda: True), before)
        self.assertEqual(self.backend.read_count, reads)
        self.assertEqual(self.backend.starts, [])

    def test_stop_during_first_observation_preserves_clean_run(self):
        original = self.backend.observe
        stopped = [False]
        def observe():
            item = original(); stopped[0] = True; return item
        self.backend.observe = observe
        state = self.executor.tick(stop_requested=lambda: stopped[0])
        self.assertEqual(state.desired, 'RUN'); self.assertIsNone(state.pending)
        self.assertEqual(self.backend.starts, [])

    def test_stop_after_intent_keeps_pending_without_claim_or_submission(self):
        save = self.store.save
        stopped = [False]
        def saving(state):
            save(state)
            if state.reason == 'START_INTENT': stopped[0] = True
        self.store.save = saving
        state = self.executor.tick(stop_requested=lambda: stopped[0])
        self.assertEqual(state.reason, 'MANAGER_STOP_WITH_INTENT')
        self.assertIsNotNone(state.pending)
        self.assertEqual(self.store.claims, {})
        self.assertEqual(self.backend.starts, [])

    def test_stop_after_claim_keeps_spent_claim_without_submission(self):
        claim = self.store.claim
        stopped = [False]
        def claiming(action): claim(action); stopped[0] = True
        self.store.claim = claiming
        state = self.executor.tick(stop_requested=lambda: stopped[0])
        self.assertEqual(state.desired, 'HOLD')
        self.assertEqual(len(self.store.claims), 1)
        self.assertEqual(self.backend.starts, [])
        self.executor.open()
        self.assertIsNotNone(self.store.state.pending)

    def test_signal_after_submission_keeps_health_wait_not_false_cancellation(self):
        start = self.backend.start
        stopped = [False]
        def submit(*args, **kwargs):
            outcome = start(*args, **kwargs); stopped[0] = True; return outcome
        self.backend.start = submit
        state = self.executor.tick(stop_requested=lambda: stopped[0])
        self.assertEqual(len(self.backend.starts), 1)
        self.assertIsNotNone(state.health_wait)
        fresh = Executor(self.core, self.store, self.backend, clock=lambda: self.backend.now)
        fresh.open()
        self.assertEqual(self.store.state.reason, 'INCOMPLETE_HEALTH_WAIT_ON_RESUME')


class ResidentTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.reports = [], []
        self.event = SimpleNamespace(stopped=False)
        self.event.is_set = lambda: self.event.stopped
        def wait(seconds): self.calls.append(('wait', seconds)); self.event.stopped = True
        self.event.wait = wait
        self.executor = SimpleNamespace(store=None, open=lambda: self.calls.append('open'))
        def tick(**kw):
            self.calls.append('tick'); self.assertFalse(kw['stop_requested']())
            return c.State(desired='RUN', reason='HEALTHY')
        self.executor.tick = tick
        self.executor.hold = lambda **kw: self.calls.append(('hold', kw))
        self.verify = lambda: self.calls.append('verify')

    def run_loop(self):
        return s.run(self.executor, self.event, poll_seconds=1, verify_launch=self.verify,
                     report=self.reports.append, lease=nullcontext())

    def test_clean_shutdown_preserves_run_and_stops_no_apps(self):
        self.assertEqual(self.run_loop(), 0)
        self.assertEqual(self.calls, ['verify', 'open', 'verify', 'tick', ('wait', 1)])
        self.assertEqual(self.reports[-1], {'stage': 'MANAGER_EXITED', 'containers': 'NOT_STOPPED'})

    def test_hold_exits_without_wait_retry_or_implicit_arm(self):
        self.executor.tick = lambda **kw: c.State(reason='OPERATOR_HOLD')
        self.assertEqual(self.run_loop(), 2)
        self.assertEqual(self.calls, ['verify', 'open', 'verify'])

    def test_launch_drift_audited_as_manager_hold_not_operator_request(self):
        def verify():
            if 'open' in self.calls: raise ValueError('changed')
            self.calls.append('verify')
        self.verify = verify
        self.assertEqual(self.run_loop(), 2)
        self.assertEqual(self.calls[-1], ('hold', {'reason': 'LAUNCH_INPUT_CHANGED'}))
        self.assertNotIn('tick', self.calls)

    def test_startup_verifier_failure_prevents_open(self):
        self.verify = lambda: (_ for _ in ()).throw(ValueError('bad'))
        with self.assertRaises(ValueError): self.run_loop()
        self.assertEqual(self.calls, [])

    def test_poll_nan_zero_and_unbounded_rejected(self):
        for value in (float('nan'), 0, True, 31):
            with self.assertRaises(ValueError):
                s.run(self.executor, self.event, poll_seconds=value, verify_launch=self.verify,
                      report=self.reports.append, lease=nullcontext())

    def test_signals_only_set_flag_and_restore_previous_handlers(self):
        old = signal.getsignal(signal.SIGTERM)
        with s.shutdown_event() as event:
            handler = signal.getsignal(signal.SIGTERM)
            handler(signal.SIGTERM, None)
            self.assertTrue(event.is_set())
        self.assertEqual(signal.getsignal(signal.SIGTERM), old)

    def test_signal_during_wait_has_no_lock_and_returns_after_short_slice(self):
        now=[0]; waits=[]
        with s.shutdown_event() as event:
            def sleep(seconds):
                waits.append(seconds);now[0]+=seconds
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
            self.assertTrue(event.wait(30,clock=lambda:now[0],sleep=sleep))
        self.assertEqual(waits,[0.1])

    def test_tick_exception_attempts_hold_and_reports_failed_persistence_truthfully(self):
        def fail(**kw):raise OSError('IO')
        self.executor.tick=fail
        self.assertEqual(self.run_loop(),2)
        self.assertEqual(self.reports[-1],{'stage':'MANAGER_TICK_FAILED','hold_persisted':True})
        self.executor.hold=fail
        self.assertEqual(self.run_loop(),2)
        self.assertEqual(self.reports[-1],{'stage':'MANAGER_TICK_FAILED','hold_persisted':False})


class OwnerTests(unittest.TestCase):
    def setUp(self):
        obj = candidate()
        self.row = dict(LoadState='loaded', ActiveState='active', SubState='running', MainPID='123',
                       FragmentPath=obj['manager']['fragment'], DropInPaths='', NeedDaemonReload='no',
                       Transient='no', InvocationID='a'*32, Requires='docker.service fds-harbor-ac04-guard.service',
                       After='docker.service fds-harbor-ac04-guard.service', PartOf='docker.service')
        def run(*args): return '\n'.join(k+'='+v for k,v in self.row.items()).encode()
        self.owner = s.ActiveOwner(obj['host_policy'], obj['manager'], pid=123,
                                  io=SimpleNamespace(run=run), clock=lambda: 10)

    def test_exact_pid_source_dependencies_and_stable_invocation(self):
        self.owner(20)
        for key, value in [('MainPID','124'), ('NeedDaemonReload','yes'), ('PartOf',''),
                           ('After','docker.service'), ('InvocationID','b'*32), ('SubState','dead')]:
            old = self.row[key]; self.row[key] = value
            with self.assertRaises(ValueError): self.owner(20)
            self.row[key] = old

    def test_startup_active_transition_is_not_false_drift(self):
        self.row.update(ActiveState='activating', SubState='start')
        self.owner(20)
        self.row.update(ActiveState='active', SubState='running')
        self.owner(20)

    def test_host_failure_never_executes_owner_command(self):
        calls = []
        class Host:
            binding = 'a'*64
            def __call__(self, deadline): raise ValueError('pin failed')
        wrapped = s.RuntimeHost(Host(), lambda d: calls.append(d))
        with self.assertRaises(ValueError): wrapped(20)
        self.assertEqual(calls, [])


class UnitTests(unittest.TestCase):
    def test_lifecycle_dependencies_and_no_implicit_container_stop(self):
        unit = s.unit_text('/usr/bin/python3', '/opt/trusted/bootstrap.py',
                           'system_u:object_r:etc_t:s0', startup_seconds=30, shutdown_seconds=90)
        self.assertIn('PartOf=docker.service\n', unit)
        self.assertIn('WantedBy=docker.service multi-user.target\n', unit)
        self.assertIn('RestartPreventExitStatus=2 130\n', unit)
        self.assertIn('TimeoutStopSec=90\n', unit)
        self.assertIn(' -I -S -B ', unit)
        self.assertNotIn('ExecStop=', unit)
        self.assertNotIn('--sha256', unit)

    def test_unit_injection_and_invalid_budgets_rejected(self):
        for python, bootstrap, context, start, stop in [
            ('/usr/bin/python3;evil','/opt/a.py','etc_t',30,90),
            ('/usr/bin/python3','/opt/%n.py','etc_t',30,90),
            ('/usr/bin/python3','/opt/a.py','etc_t\nExecStart=x',30,90),
            ('/usr/bin/python3','/opt/a.py','etc_t',True,90),
            ('/usr/bin/python3','/opt/a.py','etc_t',30,601)]:
            with self.assertRaises(ValueError):
                s.unit_text(python,bootstrap,context,startup_seconds=start,shutdown_seconds=stop)


@unittest.skipUnless(sys.platform == 'linux', 'Linux lifetime flock')
class LeaseTests(unittest.TestCase):
    def test_second_manager_blocked_but_controller_lock_still_available(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as path:
            store = Store(path, uid=os.getuid())
            with store.locked(): store.initialize()
            with s.ManagerLease(store):
                with self.assertRaises(BlockingIOError), s.ManagerLease(store): pass
                with store.locked(): self.assertEqual(store.load(), c.State())
            with s.ManagerLease(store): pass
            self.assertEqual((Path(path)/'manager.lock').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
