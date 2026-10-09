"""Synthetic state-machine tests; no guest, Docker or command execution."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/recovery'))
import harbor_recovery_core as c


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.ids = {n: f'{i + 1:064x}' for i, n in enumerate((*c.ORDER, 'log'))}
        self.plan = c.Plan(self.ids, {s: 'f' * 64 for s in self.ids},
                           {s: 60 for s in c.ORDER})
        self.core = c.Controller(self.plan)
        self.rows = {n: c.Container(v, 'f' * 64, 'running' if n == 'log' else 'exited',
                                  'healthy' if n == 'log' else 'unhealthy',
                                  'always' if n == 'log' else 'no') for n, v in self.ids.items()}
        self.state = self.core.arm(c.State(), self.obs(0), 0).state

    def obs(self, now, **changes):
        return replace(c.Observation('boot-1', 'daemon-1', now,
                                     deepcopy(self.rows), True, True), **changes)

    def update(self, name, **changes):
        self.rows[name] = replace(self.rows[name], **changes)

    def all_healthy(self):
        for s in c.ORDER:
            self.update(s, status='running', health='healthy')

    def test_initial_hold_never_starts(self):
        t = self.core.step(c.State(), self.obs(0), 0)
        self.assertIsNone(t.action)
        self.assertEqual(t.state.desired, 'HOLD')

    def test_exact_order_and_ids_no_duplicate_intents(self):
        state, emitted = self.state, []
        for i, service in enumerate(c.ORDER):
            now = i * 5
            t = self.core.step(state, self.obs(now), now)
            self.assertEqual((t.action.service, t.action.container_id), (service, self.ids[service]))
            self.assertIsNone(self.core.step(t.state, self.obs(now), now).action)
            emitted.append(t.action.token)
            state = self.core.acknowledge(t.state, t.action, 'ok', now + 0.1).state
            self.update(service, status='running', health='healthy')
        done = self.core.step(state, self.obs(50), 50)
        self.assertEqual(done.state.reason, 'HEALTHY')
        self.assertEqual(len(set(emitted)), 9)
        self.assertIsNone(done.action)

    def test_healthy_apps_adopted_without_restart(self):
        self.all_healthy()
        t = self.core.step(self.state, self.obs(1), 1)
        self.assertEqual(t.state.reason, 'HEALTHY')
        self.assertIsNone(t.action)

    def test_logger_must_be_healthy_and_tcp_ready(self):
        for mutation in ({'logger_tcp': False}, {'containers': {
                **self.rows, 'log': replace(self.rows['log'], health='starting')}}):
            with self.subTest(mutation=mutation):
                t = self.core.step(self.state, self.obs(1, **mutation), 1)
                self.assertIsNone(t.action)
                t = self.core.step(t.state, self.obs(121, **mutation), 121)
                self.assertEqual(t.state.reason, 'LOGGER_TIMEOUT')

    def test_logger_recovers_before_deadline(self):
        t = self.core.step(self.state, self.obs(1, logger_tcp=False), 1)
        t = self.core.step(t.state, self.obs(10), 10)
        self.assertEqual(t.action.service, 'postgresql')

    def test_logger_loss_does_not_stop_running_apps(self):
        self.all_healthy()
        t = self.core.step(self.state, self.obs(1), 1)
        t = self.core.step(t.state, self.obs(2, logger_tcp=False), 2)
        self.assertEqual(t.state.reason, 'WAIT_LOGGER')
        self.assertIsNone(t.action)

    def test_all_guard_failures_emit_no_actions(self):
        bad = [self.obs(0, guards_ok=False), self.obs(0, at=-10), self.obs(0, at=1),
               self.obs(0, boot=''), self.obs(0, daemon=''), self.obs(0, guards_ok=1),
               self.obs(0, containers={})]
        for o in bad:
            with self.subTest(o=o):
                t = self.core.step(self.state, o, 0)
                self.assertIsNone(t.action)
                self.assertEqual(t.state.desired, 'HOLD')

    def test_drift_in_any_container_blocks_first_start(self):
        for service, changes in [('proxy', {'id': 'a'*64}), ('core', {'fingerprint': 'b'*64}),
                                 ('redis', {'restart': 'always'}), ('log', {'restart': 'no'}),
                                 ('registry', {'endpoint': 'tcp://localhost:1514'}),
                                 ('portal', {'health': None}), ('core', {'status': 'paused'})]:
            with self.subTest(service=service, changes=changes):
                rows = {**self.rows, service: replace(self.rows[service], **changes)}
                t = self.core.step(self.state, self.obs(1, containers=rows), 1)
                self.assertEqual(t.state.desired, 'HOLD')
                self.assertIsNone(t.action)

    def test_failed_and_unknown_start_never_retried(self):
        for outcome in ('failed', 'unknown'):
            with self.subTest(outcome=outcome):
                t = self.core.step(self.state, self.obs(0), 0)
                a = t.action
                t = self.core.acknowledge(t.state, a, outcome, 1)
                t = self.core.step(t.state, self.obs(100), 100)
                self.assertEqual(t.state.pending, a)
                self.assertEqual(t.state.desired, 'HOLD')
                self.assertIsNone(t.action)

    def test_late_success_does_not_clear_uncertain_intent(self):
        t = self.core.step(self.state, self.obs(0), 0)
        t = self.core.acknowledge(t.state, t.action, 'ok', 60)
        self.update('postgresql', status='running', health='healthy')
        t = self.core.step(t.state, self.obs(61), 61)
        self.assertEqual(t.state.desired, 'HOLD')
        self.assertIsNotNone(t.state.pending)

    def test_pending_timeout(self):
        t = self.core.step(self.state, self.obs(0), 0)
        t = self.core.step(t.state, self.obs(60), 60)
        self.assertEqual(t.state.reason, 'START_RESULT_UNKNOWN')

    def test_wrong_ack_rejected(self):
        t = self.core.step(self.state, self.obs(0), 0)
        with self.assertRaisesRegex(ValueError, 'ACK_MISMATCH'):
            self.core.acknowledge(t.state, replace(t.action, token=2), 'ok', 1)

    def test_health_timeout_including_late_healthy(self):
        for health in ('starting', 'healthy'):
            t = self.core.step(self.state, self.obs(0), 0)
            t = self.core.acknowledge(t.state, t.action, 'ok', 1)
            self.update('postgresql', status='running', health=health)
            t = self.core.step(t.state, self.obs(61), 61)
            self.assertEqual(t.state.reason, 'HEALTH_TIMEOUT')
            self.update('postgresql', status='exited', health='unhealthy')

    def test_exit_during_startup_is_not_automatic_retry(self):
        t = self.core.step(self.state, self.obs(0), 0)
        t = self.core.acknowledge(t.state, t.action, 'ok', 1)
        t = self.core.step(t.state, self.obs(2), 2)
        self.assertEqual(t.state.reason, 'EXIT_DURING_STARTUP')

    def test_running_unhealthy_no_kill_or_restart(self):
        self.all_healthy()
        self.update('core', health='unhealthy')
        t = self.core.step(self.state, self.obs(1), 1)
        self.assertEqual(t.state.reason, 'RUNNING_UNHEALTHY')
        self.assertIsNone(t.action)

    def test_existing_starting_wait_is_bounded(self):
        self.update('postgresql', status='running', health='starting')
        t = self.core.step(self.state, self.obs(1), 1)
        self.assertEqual(t.state.reason, 'WAIT_EXISTING_START')
        self.assertIsNone(t.action)
        t = self.core.step(t.state, self.obs(61), 61)
        self.assertEqual(t.state.reason, 'HEALTH_TIMEOUT')

    def test_restart_budget_and_backoff(self):
        self.all_healthy()
        t = self.core.step(self.state, self.obs(0), 0)
        self.update('core', status='exited', health='unhealthy')
        for now in (5, 10, 15):
            t = self.core.step(t.state, self.obs(now), now)
            self.assertEqual(t.action.service, 'core')
            t = self.core.acknowledge(t.state, t.action, 'ok', now + .1)
            self.update('core', status='running', health='healthy')
            t = self.core.step(t.state, self.obs(now + 1), now + 1)
            self.update('core', status='exited', health='unhealthy')
            t = self.core.step(t.state, self.obs(now + 2), now + 2)
            self.assertIsNone(t.action)
        self.assertEqual(t.state.reason, 'RETRY_BUDGET_EXHAUSTED')
        self.assertEqual(self.core.resume(t.state).state.desired, 'HOLD')

    def test_retry_window_ages_out_in_same_boot(self):
        self.all_healthy()
        t = self.core.step(self.state, self.obs(0), 0)
        t.state.retries['core'] = [1, 2, 3]
        t = self.core.step(t.state, self.obs(304), 304)
        self.assertEqual(t.state.retries['core'], [])
        self.update('core', status='exited', health='unhealthy')
        self.assertIsNotNone(self.core.step(t.state, self.obs(305), 305).action)

    def test_manual_hold_survives_boot_and_late_ack(self):
        t = self.core.step(self.state, self.obs(0), 0)
        a = t.action
        held = self.core.hold(t.state).state
        t = self.core.acknowledge(held, a, 'ok', 1)
        t = self.core.step(t.state, self.obs(0, boot='boot-2'), 0)
        self.assertEqual(t.state.desired, 'HOLD')
        self.assertIsNotNone(t.state.pending)

    def test_clean_new_boot_can_start(self):
        self.all_healthy()
        t = self.core.step(self.state, self.obs(100), 100)
        self.update('postgresql', status='exited', health='unhealthy')
        t = self.core.step(t.state, self.obs(0, boot='boot-2', daemon='daemon-2'), 0)
        self.assertEqual(t.action.service, 'postgresql')

    def test_new_boot_cannot_erase_retry_budget(self):
        self.all_healthy()
        t = self.core.step(self.state, self.obs(1), 1)
        t.state.retries['core'] = [1]
        t = self.core.step(t.state, self.obs(0, boot='boot-2'), 0)
        self.assertEqual(t.state.reason, 'BOOT_CHANGED_WITH_UNSETTLED_BUDGET')

    def test_generation_change_with_pending_or_wait_is_hold(self):
        pending = self.core.step(self.state, self.obs(0), 0)
        waiting = self.core.acknowledge(pending.state, pending.action, 'ok', 1)
        for t in (pending, waiting):
            with self.subTest(reason=t.state.reason):
                t = self.core.step(t.state, self.obs(2, daemon='daemon-2'), 2)
                self.assertEqual(t.state.reason, 'GENERATION_CHANGED_WITH_WORK')

    def test_executor_restart_with_uncertain_work_is_hold(self):
        t = self.core.step(self.state, self.obs(0), 0)
        self.assertEqual(self.core.resume(t.state).state.desired, 'HOLD')
        t = self.core.acknowledge(t.state, t.action, 'ok', 1)
        self.assertEqual(self.core.resume(t.state).state.desired, 'HOLD')

    def test_episode_deadline_caps_start(self):
        self.state.episode_since = 0
        t = self.core.step(self.state, self.obs(899), 899)
        self.assertEqual(t.action.deadline, 900)
        t = self.core.step(self.state, self.obs(900), 900)
        self.assertEqual(t.state.reason, 'EPISODE_DEADLINE')

    def test_inputs_not_mutated(self):
        old_state, old_rows = deepcopy(self.state), deepcopy(self.rows)
        self.core.step(self.state, self.obs(1), 1)
        self.assertEqual(self.state, old_state)
        self.assertEqual(self.rows, old_rows)

    def test_nonfinite_bool_and_negative_budgets_rejected(self):
        for value in (True, False, 0, -1, float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(self.plan, start_seconds=value)

    def test_bad_plan_sets_ids_and_health_map(self):
        for changes in ({'ids': {}}, {'fingerprints': {}}, {'health_seconds': {}},
                        {'ids': {n: 'a'*64 for n in self.ids}}, {'retry_limit': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.plan, **changes)

    def test_clock_reversal_is_hold(self):
        self.state.last_now = 10
        t = self.core.step(self.state, self.obs(9), 9)
        self.assertEqual(t.state.reason, 'MONOTONIC_CLOCK_REVERSED')

    def test_rearm_cannot_clear_hold_or_unknown_work(self):
        for state in (self.core.hold(self.state).state,
                      self.core.step(self.state, self.obs(0), 0).state):
            t = self.core.arm(state, self.obs(1), 1)
            self.assertEqual(t.state.reason, 'RECONCILIATION_REQUIRED')

    def test_changed_plan_cannot_reuse_run_state(self):
        other = c.Controller(replace(self.plan, retry_limit=4))
        self.assertEqual(other.step(self.state, self.obs(1), 1).state.reason, 'PLAN_CHANGED')
        self.assertEqual(other.resume(self.state).state.reason, 'PLAN_CHANGED')

    def test_per_service_health_budget(self):
        core = c.Controller(replace(self.plan, health_seconds={**self.plan.health_seconds,
                                                             'postgresql': 10}))
        s = core.arm(c.State(), self.obs(0), 0).state
        t = core.step(s, self.obs(0), 0)
        t = core.acknowledge(t.state, t.action, 'ok', 1)
        self.update('postgresql', status='running', health='starting')
        t = core.step(t.state, self.obs(11), 11)
        self.assertEqual(t.state.reason, 'HEALTH_TIMEOUT')

    def test_episode_includes_logger_wait(self):
        t = self.core.step(self.state, self.obs(0, logger_tcp=False), 0)
        t = self.core.step(t.state, self.obs(100), 100)
        self.assertEqual(t.state.episode_since, 0)

    def test_fresh_dispatch_authorization(self):
        t = self.core.step(self.state, self.obs(0), 0)
        approved = self.core.authorize(t.state, t.action, self.obs(1), 1)
        self.assertEqual(approved.state.reason, 'START_AUTHORIZED')
        self.assertIsNone(approved.action)
        self.assertEqual(approved.state.pending, t.action)

    def test_dispatch_races_fail_closed(self):
        t = self.core.step(self.state, self.obs(0), 0)
        for changes in ({'logger_tcp': False}, {'guards_ok': False}, {'boot': 'boot-2'},
                        {'daemon': 'daemon-2'}, {'at': -10},
                        {'containers': {**self.rows, 'postgresql':
                                        replace(self.rows['postgresql'], status='running')}}):
            with self.subTest(changes=changes):
                checked = self.core.authorize(t.state, t.action, self.obs(1, **changes), 1)
                self.assertEqual(checked.state.desired, 'HOLD')
                self.assertIsNone(checked.action)

    def test_stop_wins_before_dispatch(self):
        t = self.core.step(self.state, self.obs(0), 0)
        checked = self.core.authorize(self.core.hold(t.state).state, t.action, self.obs(1), 1)
        self.assertEqual(checked.state.reason, 'HOLD_BEFORE_DISPATCH')

    def test_dependency_lost_after_intent(self):
        self.all_healthy()
        t = self.core.step(self.state, self.obs(0), 0)
        self.update('core', status='exited', health='unhealthy')
        t = self.core.step(t.state, self.obs(1), 1)
        self.update('postgresql', status='exited', health='unhealthy')
        checked = self.core.authorize(t.state, t.action, self.obs(2), 2)
        self.assertEqual(checked.state.reason, 'DEPENDENCY_LOST_BEFORE_DISPATCH')


if __name__ == '__main__':
    unittest.main()
