"""Policy transaction failure/crash tests. No real Engine or service changes."""
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/recovery'))
import harbor_recovery_core as c
import harbor_recovery_docker as d
import harbor_recovery_transition as t
import harbor_recovery_policy_backend as b
from harbor_recovery_store import Store
from test_docker_adapter import FakeEngine
from test_state_executor import MemoryStore
from test_host_provider import BOOT, DAEMON, policy as host_policy


def fixture():
    ids = {n: f'{i+1:064x}' for i, n in enumerate((*c.ORDER, 'log'))}
    plan = t.TransitionPlan(c.Plan(ids, {n: 'a'*64 for n in ids}, {n: 60 for n in c.ORDER},
                                  execution_binding='b'*64), 'c'*64, 'd'*64)
    item = t.PolicyObservation(BOOT, DAEMON, 10, plan.host_binding, plan.manager_binding,
                               ids, plan.recovery.fingerprints, t.original_policies(), True)
    return plan, item


class MemoryJournal:
    def __init__(self, store, plan):
        self.store, self.plan, self.record = store, plan, None
        self.claims, self.history = {}, []
        self.fail_save = lambda _: False
        self.fail_claim = None

    def create(self, record):
        assert self.store.locked_now
        if self.record is not None: raise FileExistsError('exists')
        self.save(record)

    def load(self):
        assert self.store.locked_now
        return t.validate(deepcopy(self.record), self.plan)

    def save(self, record):
        assert self.store.locked_now
        t.validate(record, self.plan)
        if self.fail_save(record): raise OSError('injected save failure')
        self.record = deepcopy(record)
        self.history.append(deepcopy(record))

    def claim(self, action):
        assert self.store.locked_now and self.record['pending'] == action
        if self.fail_claim: raise self.fail_claim
        if action['token'] in self.claims: raise FileExistsError('spent')
        self.claims[action['token']] = deepcopy(action)


class Backend:
    def __init__(self, item, journal):
        self.item, self.journal = deepcopy(item), journal
        self.updates = []
        self.observe_hook = lambda: None
        self.behavior = lambda _: 'ack'

    def observe(self, deadline):
        self.observe_hook()
        return deepcopy(self.item)

    def update(self, action, expected, deadline):
        assert self.journal.record['pending'] == action
        assert action['token'] in self.journal.claims
        outcome = self.behavior(action)
        if outcome == 'not_submitted': return outcome
        self.updates.append(deepcopy(action))
        self.item.policies[action['service']] = deepcopy(action['to'])
        if isinstance(outcome, BaseException): raise outcome
        return outcome


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.plan, item = fixture()
        self.store = MemoryStore()
        self.journal = MemoryJournal(self.store, self.plan)
        self.backend = Backend(item, self.journal)
        self.now = 10
        self.tx = t.Transition(self.plan, self.store, self.backend, journal=self.journal, clock=lambda: self.now)

    def install(self): return self.tx.install(20, explicit=True)
    def rollback(self): return self.tx.rollback(20, explicit=True)

    def test_complete_install_leaves_hold_no_logger_and_no_arm(self):
        row = self.install()
        self.assertEqual(row['phase'], 'INSTALLED_HOLD')
        self.assertEqual(row['changed'], list(c.ORDER))
        self.assertEqual([a['service'] for a in self.backend.updates], list(c.ORDER))
        self.assertEqual(self.store.state, c.State())
        self.assertEqual(self.backend.item.policies['log'], t.ORIGINAL)
        self.assertEqual(len(self.journal.claims), 9)

    def test_rollback_reverse_verified_only_and_preserve_claims(self):
        self.install()
        row = self.rollback()
        self.assertEqual(row['phase'], 'ROLLED_BACK')
        self.assertEqual(row['restored'], list(reversed(c.ORDER)))
        self.assertEqual([a['service'] for a in self.backend.updates[9:]], list(reversed(c.ORDER)))
        self.assertEqual(self.backend.item.policies, t.original_policies())
        self.assertEqual(len(self.journal.claims), 18)
        self.assertEqual(self.store.state, c.State())

    def test_explicit_required_and_no_repeat_install(self):
        with self.assertRaisesRegex(ValueError, 'EXPLICIT'): self.tx.install(20)
        self.install()
        with self.assertRaises(Exception): self.install()
        self.assertEqual(len(self.backend.updates), 9)
        with self.assertRaisesRegex(ValueError, 'EXPLICIT'): self.tx.rollback(20)

    def test_controller_running_pending_or_used_state_rejected(self):
        for state in (c.State(desired='HOLD', reason='OPERATOR_HOLD'), c.State(next_token=2)):
            self.store.state = state
            with self.assertRaisesRegex(ValueError, 'INITIAL_STORE'): self.install()
        self.assertEqual(self.backend.updates, [])

    def test_identity_metadata_policy_health_stale_preflight(self):
        original = self.backend.item
        for change in ({'ids': dict(original.ids, core='e'*64)},
                       {'fingerprints': dict(original.fingerprints, core='e'*64)},
                       {'host_binding': 'f'*64}, {'manager_binding': 'f'*64},
                       {'healthy': False}, {'at': 0},
                       {'policies': dict(original.policies, core=t.TARGET)}):
            self.backend.item = replace(original, **change)
            with self.assertRaises(ValueError): self.install()
        self.assertEqual(self.backend.updates, [])

    def test_intent_save_failure_zero_updates(self):
        self.journal.fail_save = lambda row: row['pending'] is not None
        with self.assertRaises(OSError): self.install()
        self.assertEqual(self.backend.updates, [])
        self.assertEqual(self.journal.claims, {})

    def test_claim_failure_never_submits(self):
        self.journal.fail_claim = OSError('disk')
        with self.assertRaises(OSError): self.install()
        self.assertEqual(self.backend.updates, [])
        self.journal.fail_claim = None
        self.assertEqual(self.tx.resume()['phase'], 'HOLD')

    def test_duplicate_claim_preserved_no_submission(self):
        self.journal.claims[1] = {'old': 'evidence'}
        row = self.install()
        self.assertEqual(row['reason'], 'DUPLICATE_POLICY_CLAIM')
        self.assertIsNotNone(row['pending'])
        self.assertEqual(self.backend.updates, [])

    def test_response_loss_preserves_pending_no_blind_rollback(self):
        self.backend.behavior = lambda _: 'unknown'
        row = self.install()
        self.assertEqual(row['reason'], 'UPDATE_UNCERTAIN')
        self.assertEqual(row['changed'], [])
        self.assertEqual(len(self.backend.updates), 1)
        with self.assertRaisesRegex(ValueError, 'NO_BLIND'): self.rollback()
        self.tx.resume()
        self.assertEqual(len(self.backend.updates), 1)

    def test_crash_after_mutation_before_ack_never_replays(self):
        self.backend.behavior = lambda _: SystemExit(99)
        with self.assertRaises(SystemExit): self.install()
        row = self.tx.resume()
        self.assertEqual(row['phase'], 'HOLD')
        self.assertIsNotNone(row['pending'])
        self.assertEqual(len(self.backend.updates), 1)

    def test_ack_save_failure_pending_preserved(self):
        self.journal.fail_save = lambda row: bool(row['changed'])
        with self.assertRaises(OSError): self.install()
        self.assertIsNotNone(self.journal.record['pending'])
        self.assertEqual(len(self.backend.updates), 1)

    def test_ack_but_wrong_readback_is_uncertain(self):
        def hook():
            if self.backend.updates:
                self.backend.item.policies['postgresql'] = deepcopy(t.ORIGINAL)
        self.backend.observe_hook = hook
        row = self.install()
        self.assertEqual(row['reason'], 'READBACK_UNCERTAIN')
        self.assertIsNotNone(row['pending'])
        self.assertEqual(len(self.backend.updates), 1)

    def test_not_submitted_allows_explicit_known_partial_rollback(self):
        self.backend.behavior = lambda a: 'not_submitted' if a['service'] == 'redis' else 'ack'
        row = self.install()
        self.assertEqual(row['changed'], ['postgresql'])
        self.assertIsNone(row['pending'])
        self.assertEqual(row['phase'], 'HOLD')
        row = self.rollback()
        self.assertEqual(row['phase'], 'ROLLED_BACK')
        self.assertEqual([a['service'] for a in self.backend.updates], ['postgresql', 'postgresql'])
        self.assertEqual(len(self.journal.claims), 3)

    def test_generation_change_blocks_next_update_and_rollback(self):
        def hook():
            if self.backend.updates: self.backend.item = replace(self.backend.item, daemon='e'*32)
        self.backend.observe_hook = hook
        self.assertEqual(self.install()['phase'], 'HOLD')
        self.assertEqual(len(self.backend.updates), 1)
        with self.assertRaises(ValueError): self.rollback()

    def test_deadline_before_or_after_submit_never_retries(self):
        self.now = 21
        with self.assertRaises(ValueError): self.install()
        self.now = 10
        def hook():
            if self.backend.updates: self.now = 21
        self.backend.observe_hook = hook
        self.assertEqual(self.install()['reason'], 'READBACK_UNCERTAIN')
        self.assertEqual(len(self.backend.updates), 1)

    def test_rollback_response_loss_does_not_retry_or_change_more(self):
        self.install()
        self.backend.behavior = lambda _: 'unknown'
        row = self.rollback()
        self.assertEqual(row['phase'], 'HOLD')
        self.assertEqual(row['restored'], [])
        self.assertEqual(len(self.backend.updates), 10)
        with self.assertRaises(ValueError): self.rollback()

    def test_record_tampering_rejected(self):
        base = self.install()
        for update in (lambda r: r.update(plan='f'*64), lambda r: r['original']['core'].update(Name='no'),
                       lambda r: r.update(changed=['redis']), lambda r: r.update(restored=['core']),
                       lambda r: r.update(next_token=True)):
            row = deepcopy(base); update(row)
            with self.assertRaises(ValueError): t.validate(row, self.plan)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeEngine()
        for row in self.fake.rows.values():
            row['HostConfig']['RestartPolicy'] = deepcopy(t.ORIGINAL)
            row['State'].update(Status='running', Running=True, Health={'Status': 'healthy'})
        self.engine = b.PolicyEngine('1.53', [self.fake.ids[n] for n in c.ORDER])
        self.engine.inventory = self.fake.inventory
        self.engine.inspect = self.fake.inspect
        self.host_binding, self.manager_binding = 'c'*64, 'd'*64
        recovery = c.Plan(self.fake.ids, {n: d.project(row, n, row['Id'], 'harbor', expected_restart='always').fingerprint
                           for n, row in self.fake.rows.items()}, {n: 60 for n in c.ORDER},
                           execution_binding=d.execution_binding(self.host_binding, 'harbor', self.engine.binding))
        self.plan = t.TransitionPlan(recovery, self.host_binding, self.manager_binding)
        def host(_): return d.HostSnapshot(BOOT, DAEMON, self.host_binding, 10)
        host.binding = self.host_binding
        self.manager_ok = True
        def manager(_):
            if not self.manager_ok: raise ValueError('active')
            return self.manager_binding
        manager.binding = self.manager_binding
        self.backend = b.PolicyBackend(self.plan, self.engine, host, manager, clock=lambda: 10, probe=lambda _: True)
        self.calls = []
        self.engine.update = lambda cid, value, deadline: self.calls.append((cid, value)) or 'ack'

    def test_observe_both_policy_states_without_blessing_metadata(self):
        item = self.backend.observe(20)
        self.assertEqual(item.policies, t.original_policies())
        self.fake.rows['core']['HostConfig']['RestartPolicy'] = deepcopy(t.TARGET)
        self.assertEqual(self.backend.observe(20).fingerprints, item.fingerprints)
        self.fake.rows['core']['HostConfig']['LogConfig']['Config']['tag'] = 'drift'
        self.assertNotEqual(self.backend.observe(20).fingerprints, item.fingerprints)

    def action(self):
        return {'token': 1, 'service': 'postgresql', 'id': self.fake.ids['postgresql'],
                'from': deepcopy(t.ORIGINAL), 'to': deepcopy(t.TARGET), 'direction': 'install'}

    def test_single_update_and_manager_gate_failure_zero_calls(self):
        item = self.backend.observe(20)
        self.assertEqual(self.backend.update(self.action(), item, 20), 'ack')
        self.assertEqual(len(self.calls), 1)
        self.manager_ok = False
        self.assertEqual(self.backend.update(self.action(), item, 20), 'not_submitted')
        self.assertEqual(len(self.calls), 1)

    def test_metadata_drift_between_intent_and_submit_zero_calls(self):
        item = self.backend.observe(20)
        self.fake.rows['core']['HostConfig']['LogConfig']['Config']['tag'] = 'drift'
        self.assertEqual(self.backend.update(self.action(), item, 20), 'not_submitted')
        self.assertEqual(self.calls, [])

    def test_policy_engine_and_runtime_engine_mutation_boundaries(self):
        cid = self.fake.ids['postgresql']; path = '/containers/' + cid + '/update'
        body = json.dumps({'RestartPolicy': t.TARGET}).encode()
        self.engine._validate_request('POST', path, body)
        for engine, method, endpoint, payload in [
            (d.UnixEngine('1.53'), 'POST', path, body),
            (self.engine, 'POST', '/containers/' + cid + '/start', b''),
            (self.engine, 'POST', '/containers/' + self.fake.ids['log'] + '/update', body),
            (self.engine, 'POST', path, b'{"RestartPolicy":{"Name":"no","MaximumRetryCount":false}}'),
            (self.engine, 'POST', path, b'{"RestartPolicy":{},"Memory":1}')]:
            with self.assertRaises(ValueError): engine._validate_request(method, endpoint, payload)

    def test_policy_http_warnings_status_and_invalid_json(self):
        # Call the real class method; only transport is mocked.
        for status, raw, wanted in [(200, b'{"Warnings":[]}', 'ack'),
                                    (200, b'{"Warnings":null}', 'ack'),
                                    (200, b'{"Warnings":["warning"]}', 'unknown'),
                                    (500, b'error', 'unknown')]:
            with patch.object(self.engine, '_request', return_value=(status, raw)):
                self.assertEqual(b.PolicyEngine.update(self.engine, self.fake.ids['core'], t.TARGET, 20), wanted)
        with patch.object(self.engine, '_request', return_value=(200, b'not-json')):
            with self.assertRaises(ValueError):
                b.PolicyEngine.update(self.engine, self.fake.ids['core'], t.TARGET, 20)


class ManagerTests(unittest.TestCase):
    def test_loaded_disabled_inactive_exact_unit_only(self):
        p = host_policy(); path = '/etc/systemd/system/fds-harbor-recovery.service'
        p['files'][path] = deepcopy(next(iter(p['files'].values())))
        row = dict(LoadState='loaded', ActiveState='inactive', SubState='dead', UnitFileState='disabled',
                   MainPID='0', ControlPID='0', FragmentPath=path, DropInPaths='', NeedDaemonReload='no',
                   Job='', TriggeredBy='', Transient='no')
        class IO:
            def run(self, argv, cwd, deadline):
                assert argv[1:3] == ['show', b.MANAGER]
                return '\n'.join(k+'='+v for k,v in row.items()).encode()
        probe = b.StoppedManager(p, path, [], io=IO(), clock=lambda: 10)
        self.assertEqual(probe(20), probe.binding)
        for key, value in [('UnitFileState', 'enabled'), ('ActiveState', 'activating'), ('MainPID', '123'),
                           ('NeedDaemonReload', 'yes'), ('Job', '1'), ('TriggeredBy', 'timer.service'),
                           ('DropInPaths', '/injected')]:
            old = row[key]; row[key] = value
            with self.assertRaises(ValueError): probe(20)
            row[key] = old


@unittest.skipUnless(os.name == 'posix', 'POSIX durable journal and lock')
class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name, uid=os.getuid())
        self.plan, item = fixture()
        self.journal = t.Journal(self.store, self.plan)
        self.record = {'version': 1, 'plan': self.plan.binding, 'boot': item.boot, 'daemon': item.daemon,
                       'original': t.original_policies(), 'phase': 'INSTALLING', 'reason': 'PREPARED',
                       'changed': [], 'restored': [], 'next_token': 1, 'pending': None}
        with self.store.locked(): self.store.initialize()

    def test_durable_roundtrip_no_reinitialization(self):
        with self.store.locked():
            self.journal.create(self.record)
            self.assertEqual(self.journal.load(), self.record)
            with self.assertRaises(ValueError): self.journal.create(self.record)
            self.record.update(phase='HOLD', reason='OPERATOR_REQUEST')
            self.journal.save(self.record)
            self.assertEqual(self.journal.load(), self.record)
        self.assertEqual((Path(self.temp.name)/'policy-transition.json').stat().st_mode & 0o777, 0o600)

    def test_replace_failure_preserves_pending_and_blocks_resume(self):
        with self.store.locked():
            self.journal.create(self.record)
            before = (Path(self.temp.name)/'policy-transition.json').read_bytes()
            self.record.update(phase='HOLD')
            with patch.object(t.os, 'replace', side_effect=OSError('injected')):
                with self.assertRaises(OSError): self.journal.save(self.record)
            self.assertEqual((Path(self.temp.name)/'policy-transition.json').read_bytes(), before)
            self.assertEqual(len(list(Path(self.temp.name).glob('*.pending'))), 1)
            with self.assertRaisesRegex(ValueError, 'UNCOMMITTED'): self.journal.load()

    def test_claim_exact_intent_unique_and_old_state_partial_blocks(self):
        with self.store.locked():
            self.record['pending'] = {'token': 1, 'service': 'postgresql', 'id': self.plan.recovery.ids['postgresql'],
                                      'from': deepcopy(t.ORIGINAL), 'to': deepcopy(t.TARGET), 'direction': 'install'}
            self.record['next_token'] = 2
            self.journal.create(self.record)
            self.journal.claim(self.record['pending'])
            with self.assertRaises(FileExistsError): self.journal.claim(self.record['pending'])
            self.store._new('state-old.pending', b'original evidence')
            with self.assertRaisesRegex(ValueError, 'UNCOMMITTED'): self.journal.load()


@unittest.skipUnless(sys.platform == 'linux', 'Linux fake Unix HTTP server')
class PolicyWireTests(unittest.TestCase):
    def test_exact_id_policy_only_body_and_no_retry(self):
        with tempfile.TemporaryDirectory() as work:
            path = os.path.join(work, 'engine.sock')
            seen, errors = [], []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path); server.listen(); server.settimeout(3)
                def serve():
                    try:
                        with server.accept()[0] as connection:
                            connection.settimeout(3)
                            raw = b''
                            while b'\r\n\r\n' not in raw: raw += connection.recv(4096)
                            head, body = raw.split(b'\r\n\r\n', 1)
                            length = int(next(line.split(b':', 1)[1] for line in head.split(b'\r\n')
                                              if line.startswith(b'Content-Length:')))
                            while len(body) < length: body += connection.recv(4096)
                            seen.append((head, body))
                            reply = b'{"Warnings":[]}'
                            connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(reply)).encode()+
                                               b'\r\nConnection: close\r\n\r\n'+reply)
                    except Exception as error: errors.append(type(error).__name__)
                thread = threading.Thread(target=serve, daemon=True); thread.start()
                ids = [f'{i+1:064x}' for i in range(9)]
                engine = b.PolicyEngine('1.53', ids, socket_path=path, peer_uid=os.getuid())
                self.assertEqual(engine.update(ids[0], t.TARGET, time.monotonic()+2), 'ack')
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
                self.assertEqual(len(seen), 1)
                self.assertTrue(seen[0][0].startswith(('POST /v1.53/containers/'+ids[0]+'/update HTTP/1.1').encode()))
                self.assertEqual(json.loads(seen[0][1]), {'RestartPolicy': t.TARGET})


if __name__ == '__main__': unittest.main()
