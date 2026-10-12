"""SYNTHETIC only: no Docker, guest access, credentials or real disk journal."""
from contextlib import contextmanager
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('address_sequence',
    Path(__file__).resolve().parents[2] / 'scripts/production/harbor_address_sequence.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    rows = {}
    for i, service in enumerate(m.SERVICES):
        rows[service] = dict(id=f'{i+1:064x}', image='sha256:' + f'{i+11:064x}',
            preservation_sha256=f'{i+21:064x}',
            logging={'Type': 'json-file', 'Config': {}} if service == 'log' else
                {'Type': 'syslog', 'Config': {'syslog-address': m.OLD_ADDRESS, 'tag': service}},
            restart={'Name': 'always', 'MaximumRetryCount': 0},
            status='running' if service == 'log' else 'exited',
            health='healthy' if service == 'log' else 'unhealthy',
            exit_code=0 if service == 'log' else 128, error_sha256='a'*64)
    return dict(schema='fds.harbor.production-address-sequence.v1',
                binding_sha256='b'*64, inputs_sha256='c'*64, baseline=rows,
                health_seconds={s: 20 for s in m.ORDER}, io_seconds=5,
                poll_seconds=1, observation_max_age=3)


class MemoryJournal:
    def __init__(self):
        self.records, self.spent, self.held = [], False, False
        self.on_append = lambda event: None
        self.fail_kind = None
        self.poisoned = False
        self.append_calls = []

    @contextmanager
    def locked(self):
        if self.held:
            raise BlockingIOError('busy')
        self.held = True
        try:
            yield self
        finally:
            self.held = False

    def begin(self, pin):
        assert self.held
        if self.spent:
            raise FileExistsError('existing history')
        self.spent = True
        self.append(dict(kind='BEGIN', plan_sha256=pin))

    def append(self, event):
        assert self.held
        self.append_calls.append(event['kind'])
        if self.poisoned or event['kind'] == self.fail_kind:
            self.poisoned = True
            raise OSError('injected storage failure SECRET')
        self.records.append(deepcopy(event))
        self.on_append(event)


class Backend:
    def __init__(self, plan, journal):
        self.plan, self.journal = deepcopy(plan), journal
        self.rows = deepcopy(plan['baseline'])
        self.time, self.calls, self.reads = 10.0, [], 0
        self.on_read = lambda obs: None
        self.on_recreate = lambda service: None
        self.rc, self.health = 0, 'healthy'
        self.exception = None
        self.delay = 0

    def clock(self):
        return self.time

    def sleep(self, seconds):
        self.time += seconds

    def observe(self, deadline):
        assert self.journal.held and self.journal.spent
        self.reads += 1
        result = dict(binding_sha256=self.plan['binding_sha256'], inputs_sha256=self.plan['inputs_sha256'],
                      observed_mono=self.time, logger_ipv4=True, rows=deepcopy(self.rows))
        self.on_read(result)
        return result

    def recreate(self, *, service, expected_id, plan_sha256, deadline_mono):
        assert self.journal.held
        assert self.rows[service]['id'] == expected_id
        assert plan_sha256 == m.fingerprint(self.plan)
        assert self.journal.records[-1]['kind'] == 'RECREATE_INTENT'
        assert self.journal.records[-1]['service'] == service
        assert deadline_mono > self.time
        self.calls.append(service)
        self.on_recreate(service)
        if self.exception is not None:
            raise self.exception
        row = self.rows[service]
        row.update(id=f'{m.ORDER.index(service)+101:064x}', logging=m.logging_candidate(row['logging']),
                   status='running', health=self.health, exit_code=0, error_sha256='e'*64)
        self.time += self.delay
        return self.rc


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self.p = fixture()
        self.j = MemoryJournal()
        self.b = Backend(self.p, self.j)
        self.s = m.Sequence(self.p, self.b, self.j, clock=self.b.clock, sleep=self.b.sleep)

    def run_it(self, deadline=200):
        return self.s.run(deadline_mono=deadline)

    def maintenance(self):
        self.p['schema']=m.HEALTHY_SCHEMA
        for row in self.p['baseline'].values():
            row.update(status='running',health='healthy',exit_code=0,error_sha256=m.hashlib.sha256(b'').hexdigest())
        self.b=Backend(self.p,self.j)
        self.s=m.Sequence(self.p,self.b,self.j,clock=self.b.clock,sleep=self.b.sleep)

    def test_healthy_baseline_requires_explicit_schema_old_schema_stays_strict(self):
        self.maintenance()
        p=deepcopy(self.p);p['schema']=m.STOPPED_SCHEMA
        with self.assertRaisesRegex(m.Stop,'BASE_APP_STATE'):m.validate_plan(p)
        self.assertEqual(self.run_it()['status'],'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')

    def test_maintenance_refuses_mixed_initial_state_and_previous_error(self):
        self.maintenance()
        for changes in [dict(status='exited'),dict(health='unhealthy'),dict(exit_code=128),dict(error_sha256='e'*64)]:
            p=deepcopy(self.p);p['baseline']['core'].update(changes)
            with self.assertRaisesRegex(m.Stop,'BASE_APP_STATE'):m.validate_plan(p)

    def test_maintenance_waits_for_untouched_dependency_health_without_changing_it(self):
        self.maintenance()
        def change(s):
            if s=='postgresql':self.b.rows['core']['health']='unhealthy'
        self.b.on_recreate=change
        def recover(obs):
            if self.b.time>=12:
                self.b.rows['core']['health']='healthy'
                obs['rows']['core']['health']='healthy'
            if len(self.b.calls)>1:self.assertGreaterEqual(self.b.time,12)
        self.b.on_read=recover
        self.assertEqual(self.run_it()['status'],'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        self.assertEqual(self.b.calls,list(m.ORDER))

    def test_maintenance_dependency_health_timeout_never_advances(self):
        self.maintenance()
        self.b.on_recreate=lambda s:self.b.rows['core'].update(health='unhealthy')
        self.assertEqual(self.run_it()['reason'],'DEADLINE')
        self.assertEqual(self.b.calls,['postgresql'])

    def test_maintenance_never_ignores_untouched_identity_status_or_error(self):
        for changes in [dict(id='f'*64),dict(status='exited'),dict(error_sha256='f'*64),dict(preservation_sha256='f'*64)]:
            self.setUp();self.maintenance()
            self.b.on_recreate=lambda s:self.b.rows['core'].update(changes)
            self.assertEqual(self.run_it()['status'],'STOP_RECOVERY_REQUIRED')
            self.assertEqual(self.b.calls,['postgresql'])

    def test_maintenance_never_ignores_logger_health(self):
        self.maintenance()
        self.b.on_recreate=lambda s:self.b.rows['log'].update(health='unhealthy')
        self.assertEqual(self.run_it()['reason'],'UNTOUCHED_CONTAINER_CHANGED')
        self.assertEqual(self.b.calls,['postgresql'])

    def test_success_nine_ordered_calls_no_logger_and_no_acceptance(self):
        result = self.run_it()
        self.assertEqual(result['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        self.assertEqual(self.b.calls, list(m.ORDER))
        self.assertEqual(result['healthy_services'], list(m.ORDER))
        self.assertFalse(result['runtime_acceptance'])
        self.assertFalse(result['autostart_tested'])
        self.assertTrue(result['journal_recorded'])

    def test_spent_object_and_persisted_claim_refuse_retry(self):
        self.run_it()
        with self.assertRaisesRegex(m.Stop, 'SEQUENCE_SPENT'):
            self.run_it()
        other = m.Sequence(self.p, self.b, self.j, clock=self.b.clock)
        result = other.run(deadline_mono=200)
        self.assertEqual(result['status'], 'STOP_EXISTING_HISTORY_REQUIRES_REVIEW')
        self.assertEqual(len(self.b.calls), 9)

    def test_baseexception_leaves_claim_no_result_no_automatic_resume(self):
        self.b.exception = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_it()
        self.assertTrue(self.j.spent)
        self.assertEqual(self.j.records[-1]['kind'], 'RECREATE_INTENT')
        other = m.Sequence(self.p, self.b, self.j, clock=self.b.clock)
        self.assertEqual(other.run(deadline_mono=200)['status'], 'STOP_EXISTING_HISTORY_REQUIRES_REVIEW')
        self.assertEqual(self.b.calls, ['postgresql'])

    def test_intent_fsync_failure_no_callback(self):
        self.j.fail_kind = 'RECREATE_INTENT'
        r = self.run_it()
        self.assertEqual(self.b.calls, [])
        self.assertEqual(r['status'], 'STOP_BEFORE_CHANGE')
        self.assertFalse(r['journal_recorded'])
        self.assertNotIn('SECRET', str(r))
        self.assertEqual(self.j.append_calls, ['BEGIN', 'RECREATE_INTENT'])

    def test_result_persistence_failure_stops_after_first_attempt(self):
        self.j.fail_kind = 'RECREATE_RESULT'
        r = self.run_it()
        self.assertEqual(self.b.calls, ['postgresql'])
        self.assertEqual(r['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertFalse(r['journal_recorded'])

    def test_untrusted_exception_messages_never_escape(self):
        self.b.on_read = lambda obs: (_ for _ in ()).throw(m.Stop('SECRET-TOKEN'))
        r = self.run_it()
        self.assertEqual(r['reason'], 'IO_OR_ADAPTER_FAILURE')
        self.assertNotIn('SECRET', str(r) + str(self.j.records))

    def test_post_intent_generation_change_is_not_a_response_loss(self):
        self.j.on_append = lambda e: self.b.plan.update(binding_sha256='d'*64) if e['kind'] == 'RECREATE_INTENT' else None
        r = self.run_it()
        self.assertEqual(r['reason'], 'GENERATION_OR_PROTECTION_CHANGED')
        self.assertEqual(r['claimed_services'], ['postgresql'])
        self.assertEqual(r['transport_entered_services'], [])
        self.assertFalse(any(e['kind'] == 'RECREATE_RESULT' for e in self.j.records))

    def test_post_intent_deadline_no_callback(self):
        self.j.on_append = lambda e: setattr(self.b, 'time', 200) if e['kind'] == 'RECREATE_INTENT' else None
        self.assertEqual(self.run_it()['reason'], 'DEADLINE')
        self.assertEqual(self.b.calls, [])

    def test_post_intent_backward_clock_no_callback(self):
        self.j.on_append = lambda e: setattr(self.b, 'time', 1) if e['kind'] == 'RECREATE_INTENT' else None
        self.assertEqual(self.run_it()['reason'], 'CLOCK_INVALID')
        self.assertEqual(self.b.calls, [])

    def test_unknown_recreate_no_retry_or_next_service(self):
        self.b.exception = TimeoutError('SECRET')
        r = self.run_it()
        self.assertEqual(self.b.calls, ['postgresql'])
        self.assertEqual(r['reason'], 'RECREATE_OUTCOME_UNKNOWN')
        self.assertEqual(self.j.records[-2]['outcome'], 'UNKNOWN')

    def test_late_ack_no_next_service(self):
        self.b.delay = 5
        r = self.run_it()
        self.assertEqual(r['reason'], 'DEADLINE')
        self.assertEqual(r['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertEqual(self.b.calls, ['postgresql'])
        self.assertEqual(self.j.records[-2], dict(kind='RECREATE_RESULT', service='postgresql', outcome='LATE'))

    def test_slow_complete_append_does_not_reclassify_terminal_record(self):
        self.j.on_append = lambda e: setattr(self.b, 'time', 205) if e['kind'] == 'COMPLETE' else None
        r = self.run_it()
        self.assertEqual(r['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        self.assertEqual(self.j.records[-1]['kind'], 'COMPLETE')
        self.assertFalse(any(e['kind'] == 'STOP' for e in self.j.records))

    def test_expired_final_observation_cannot_commit_complete(self):
        def final_time(obs):
            if len(self.s._completed) == 9:
                self.b.time = 200
        self.b.on_read = final_time
        r = self.run_it()
        self.assertEqual(r['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertEqual(r['reason'], 'DEADLINE')
        self.assertFalse(any(e['kind'] == 'COMPLETE' for e in self.j.records))

    def test_late_diagnostic_persistence_failure_poisons_writer(self):
        self.b.delay = 5
        self.j.fail_kind = 'RECREATE_RESULT'
        r = self.run_it()
        self.assertEqual(r['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertFalse(r['journal_recorded'])
        self.assertEqual(self.b.calls, ['postgresql'])
        self.assertNotIn('STOP', self.j.append_calls)

    def test_nonzero_rc_no_health_success_or_next(self):
        self.b.rc = 2
        r = self.run_it()
        self.assertEqual(r['reason'], 'RECREATE_COMMAND_FAILED')
        self.assertEqual(r['healthy_services'], [])
        self.assertEqual(self.b.calls, ['postgresql'])

    def test_partial_failure_at_each_service_preserves_prefix_no_later_call(self):
        for failed in m.ORDER:
            with self.subTest(service=failed):
                self.setUp()
                self.b.on_recreate = lambda service: setattr(self.b, 'rc', 2 if service == failed else 0)
                r = self.run_it()
                index = m.ORDER.index(failed)
                self.assertEqual(self.b.calls, list(m.ORDER[:index+1]))
                self.assertEqual(r['healthy_services'], list(m.ORDER[:index]))
                self.assertEqual(r['status'], 'STOP_RECOVERY_REQUIRED')

    def test_remaining_scope_is_still_checked_after_first_app(self):
        for victim in ('log', 'proxy'):
            with self.subTest(victim=victim):
                self.setUp()
                def drift_after_first(event):
                    if event['kind'] == 'APP_HEALTHY':
                        self.b.rows[victim]['id'] = 'f'*64
                self.j.on_append = drift_after_first
                self.assertEqual(self.run_it()['reason'], 'UNTOUCHED_CONTAINER_CHANGED')
                self.assertEqual(self.b.calls, ['postgresql'])

    def test_noninteger_rc_not_treated_as_success(self):
        self.b.rc = False
        self.assertEqual(self.run_it()['reason'], 'RECREATE_OUTCOME_UNKNOWN')
        self.assertEqual(self.b.calls, ['postgresql'])

    def test_health_wait_is_bounded_no_next_service(self):
        self.b.health = 'starting'
        r = self.run_it()
        self.assertEqual(r['reason'], 'DEADLINE')
        self.assertEqual(self.b.calls, ['postgresql'])
        self.assertEqual(self.b.time, 30)

    def test_transient_starting_then_healthy(self):
        self.b.health = 'starting'
        def healthy_after_poll(obs):
            if self.b.time > 10:
                for service in self.b.calls:
                    self.b.rows[service]['health'] = 'healthy'
                    obs['rows'][service]['health'] = 'healthy'
        self.b.on_read = healthy_after_poll
        self.assertEqual(self.run_it()['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')

    def test_complete_write_failure_not_success(self):
        self.j.fail_kind = 'COMPLETE'
        r = self.run_it()
        self.assertEqual(r['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertEqual(len(r['healthy_services']), 9)
        self.assertFalse(r['journal_recorded'])

    def test_lock_contention_no_begin_or_callback(self):
        self.j.held = True
        r = self.run_it()
        self.assertEqual(r['reason'], 'JOURNAL_UNAVAILABLE')
        self.assertEqual(self.j.records, [])
        self.assertEqual(self.b.calls, [])

    def test_fork_and_concurrent_call_rejected(self):
        with patch.object(m.os, 'getpid', return_value=-1):
            with self.assertRaisesRegex(m.Stop, 'FORKED_SEQUENCE'):
                self.run_it()
        self.s._lock.acquire()
        try:
            with self.assertRaisesRegex(m.Stop, 'SEQUENCE_BUSY'):
                self.run_it()
        finally:
            self.s._lock.release()

    def test_original_plan_mutation_does_not_change_private_plan(self):
        self.p['baseline']['postgresql']['id'] = '0'*64
        self.assertEqual(self.run_it()['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')

    def test_preservation_drift_per_service_stops_next_action(self):
        for field, value in [('image', 'sha256:'+'f'*64), ('preservation_sha256', 'f'*64),
                             ('restart', {'Name': 'no', 'MaximumRetryCount': 0}),
                             ('logging', {'Type': 'json-file', 'Config': {}})]:
            with self.subTest(field=field):
                self.setUp()
                def drift(obs):
                    if self.b.calls:
                        obs['rows']['postgresql'][field] = value
                self.b.on_read = drift
                self.assertEqual(self.run_it()['status'], 'STOP_RECOVERY_REQUIRED')
                self.assertEqual(self.b.calls, ['postgresql'])

    def test_pending_app_external_start_is_detected(self):
        self.b.on_read = lambda obs: obs['rows']['proxy'].update(status='running', health='healthy')
        self.assertEqual(self.run_it()['reason'], 'UNTOUCHED_CONTAINER_CHANGED')
        self.assertEqual(self.b.calls, [])

    def test_completed_app_loses_health_stops_next(self):
        def changed(e):
            if e['kind'] == 'APP_HEALTHY':
                self.b.rows[e['service']]['health'] = 'unhealthy'
        self.j.on_append = changed
        self.assertEqual(self.run_it()['reason'], 'PRIOR_APP_UNHEALTHY')
        self.assertEqual(self.b.calls, ['postgresql'])

    def test_logger_id_listener_and_protected_input_failure(self):
        for mutation in [lambda o: o['rows']['log'].update(id='f'*64),
                         lambda o: o.update(logger_ipv4=False),
                         lambda o: o.update(inputs_sha256='f'*64),
                         lambda o: o['rows']['log'].update(health='unhealthy')]:
            with self.subTest(mutation=mutation):
                self.setUp()
                self.b.on_read = mutation
                self.assertEqual(self.run_it()['status'], 'STOP_BEFORE_CHANGE')
                self.assertEqual(self.b.calls, [])

    def test_freshness_past_future_and_slow_observation(self):
        for offset in (-1, 1):
            with self.subTest(offset=offset):
                self.setUp()
                self.b.on_read = lambda o: o.update(observed_mono=self.b.time + offset)
                self.assertEqual(self.run_it()['reason'], 'OBSERVATION_STALE')
        self.setUp()
        self.b.on_read = lambda o: setattr(self.b, 'time', self.b.time + 4)
        self.assertEqual(self.run_it()['reason'], 'OBSERVATION_STALE')

    def test_row_set_and_duplicate_current_id(self):
        self.b.on_read = lambda o: o['rows'].pop('core')
        self.assertEqual(self.run_it()['reason'], 'OBSERVATION_SERVICES')

    def test_recreated_app_old_id_not_accepted(self):
        def old_id(o):
            if self.b.calls:
                o['rows']['postgresql']['id'] = self.p['baseline']['postgresql']['id']
        self.b.on_read = old_id
        self.assertEqual(self.run_it()['reason'], 'APP_NOT_RECREATED')

    def test_replacement_during_health_wait_rejected(self):
        self.b.health = 'starting'
        def replacement(o):
            if self.b.time > 10:
                o['rows']['postgresql']['id'] = 'f'*64
        self.b.on_read = replacement
        self.assertEqual(self.run_it()['reason'], 'NEW_CONTAINER_REPLACED')

    def test_address_is_the_only_logging_delta(self):
        before = self.p['baseline']['core']['logging']
        after = m.logging_candidate(before)
        self.assertEqual(after['Config']['tag'], before['Config']['tag'])
        self.assertEqual(before['Config']['syslog-address'], m.OLD_ADDRESS)
        self.assertEqual(after['Config']['syslog-address'], m.NEW_ADDRESS)

    def test_invalid_plan_shapes_and_synthetic_budgets(self):
        mutations = [lambda p: p.update(io_seconds=True), lambda p: p.update(poll_seconds=0),
            lambda p: p.update(observation_max_age=float('nan')), lambda p: p['health_seconds'].pop('core'),
            lambda p: p['baseline']['core'].update(status='running'),
            lambda p: p['baseline']['log'].update(health='unhealthy'),
            lambda p: p['baseline']['core'].update(id=p['baseline']['redis']['id']),
            lambda p: p.update(binding_sha256='not-a-hash'),
            lambda p: p['baseline']['core']['logging']['Config'].update({'syslog-address': m.NEW_ADDRESS})]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                p = fixture(); mutation(p)
                with self.assertRaises(m.Stop):
                    m.Sequence(p, self.b, self.j)


if __name__ == '__main__':
    unittest.main()
