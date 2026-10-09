"""Synthetic Engine/host inputs and local fake Unix HTTP server; no Docker."""
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/recovery'))
import harbor_recovery_core as c
import harbor_recovery_docker as d
from harbor_recovery_executor import Executor
from test_state_executor import MemoryStore

BOOT = '12345678-1234-1234-1234-123456789abc'
DAEMON = 'a' * 32
BINDING = 'b' * 64


def inspect_row(service, cid):
    return {'Id': cid, 'Name': '/' + service, 'Image': 'sha256:' + 'a'*64,
            'Config': {'Labels': {'com.docker.compose.service': service,
                                  'com.docker.compose.project': 'harbor'},
                       'Env': ['SYNTHETIC_SECRET=never-report-this'], 'User': '',
                       'Entrypoint': ['/entrypoint'], 'Cmd': None,
                       'Healthcheck': {'Test': ['CMD', '/health'], 'Interval': 30000000000}},
            'HostConfig': {'RestartPolicy': {'Name': 'always' if service == 'log' else 'no',
                                            'MaximumRetryCount': 0},
                           'LogConfig': {'Type': 'json-file' if service == 'log' else 'syslog',
                                         'Config': {} if service == 'log' else {
                                             'syslog-address': c.ENDPOINT, 'tag': service}},
                           'NetworkMode': 'harbor_harbor', 'PortBindings': None,
                           'Privileged': False, 'ReadonlyRootfs': False, 'SecurityOpt': None,
                           'CapAdd': None, 'CapDrop': None, 'Binds': []},
            'Mounts': [{'Type': 'bind', 'Source': '/data/' + service, 'Destination': '/data',
                        'Mode': 'z', 'RW': True}], 'MountLabel': '', 'ProcessLabel': '',
            'State': {'Status': 'running' if service == 'log' else 'exited',
                      'Running': service == 'log', 'Paused': False, 'Restarting': False, 'Dead': False,
                      'Health': {'Status': 'healthy' if service == 'log' else 'unhealthy'}}}


class FakeEngine:
    def __init__(self):
        self.binding = 'c' * 64
        self.ids = {s: f'{i+1:064x}' for i, s in enumerate((*c.ORDER, 'log'))}
        self.rows = {s: inspect_row(s, cid) for s, cid in self.ids.items()}
        self.listed = [{'Id': cid, 'Labels': deepcopy(self.rows[s]['Config']['Labels'])}
                       for s, cid in self.ids.items()]
        self.posts, self.behavior = [], 'ok'
        self.inventory_count = 0
        self.on_inventory = lambda: None
        self.on_inspect = lambda: None

    def inventory(self, deadline):
        self.inventory_count += 1
        self.on_inventory()
        return deepcopy(self.listed)

    def inspect(self, cid, deadline):
        self.on_inspect()
        return deepcopy(next(r for r in self.rows.values() if r['Id'] == cid))

    def start(self, cid, deadline):
        self.posts.append((cid, deadline))
        if isinstance(self.behavior, BaseException):
            raise self.behavior
        return self.behavior


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.now, self.tcp = FakeEngine(), 10, True
        self.stamp = d.HostSnapshot(BOOT, DAEMON, BINDING, self.now)
        self.plan = c.Plan(self.engine.ids, {s: d.project(r, s, r['Id'], 'harbor').fingerprint
                          for s, r in self.engine.rows.items()}, {s: 60 for s in c.ORDER},
                          execution_binding=d.execution_binding(BINDING, 'harbor', self.engine.binding))
        self.host_calls = 0
        self.on_host = lambda: None
        def host(deadline):
            self.host_calls += 1
            self.on_host()
            return self.stamp
        self.backend = d.DockerBackend(self.plan, self.engine, host, BINDING, 'harbor',
                                       clock=lambda: self.now, probe=lambda deadline: self.tcp)
        self.action = c.Action(1, 'postgresql', self.plan.ids['postgresql'], BOOT, DAEMON, 70)

    def project(self, row, service='postgresql'):
        return d.project(row, service, self.plan.ids[service], 'harbor')

    def healthy(self, service):
        row = self.engine.rows[service]['State']
        row.update(Status='running', Running=True, Health={'Status': 'healthy'})

    def test_observe_exact_services_private_projection(self):
        o = self.backend.observe()
        self.assertEqual(set(o.containers), set(self.plan.ids))
        self.assertEqual(o.at, 10)
        self.assertTrue(o.guards_ok and o.logger_tcp)
        self.assertNotIn('SYNTHETIC_SECRET', repr(o))
        self.assertEqual(self.host_calls, 2)
        self.assertEqual(self.engine.posts, [])

    def test_adapter_binding_required_and_transport_changes_rejected(self):
        with self.assertRaisesRegex(ValueError, 'BINDING'):
            d.DockerBackend(replace(self.plan, execution_binding=''), self.engine,
                            lambda _: self.stamp, BINDING, 'harbor')
        self.engine.binding = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'BINDING'): self.backend.observe()
        self.assertEqual(self.backend.start(self.action, 60), 'failed')
        self.assertEqual(self.engine.posts, [])

    def test_host_contract_change_cannot_reuse_saved_run(self):
        core = c.Controller(self.plan)
        state = core.arm(c.State(), self.backend.observe(), self.now).state
        new = c.Controller(replace(self.plan, execution_binding='e'*64))
        self.assertEqual(new.resume(state).state.reason, 'PLAN_CHANGED')
        with self.assertRaises(ValueError): replace(self.plan, execution_binding=True)

    def test_fingerprint_binds_security_logging_health_env_mount_image(self):
        original = self.engine.rows['postgresql']
        changes = [lambda r: r['Config']['Env'].append('X=changed'),
                   lambda r: r['Config']['Healthcheck'].update(Interval=1),
                   lambda r: r['HostConfig']['LogConfig']['Config'].update(tag='changed'),
                   lambda r: r['HostConfig'].update(Privileged=True),
                   lambda r: r['HostConfig'].update(CapAdd=['SYS_ADMIN']),
                   lambda r: r['Mounts'][0].update(Mode='ro', RW=False),
                   lambda r: r.update(Image='sha256:'+'e'*64),
                   lambda r: r.update(ProcessLabel='changed')]
        for change in changes:
            row = deepcopy(original)
            change(row)
            with self.subTest(change=change):
                self.assertNotEqual(self.project(row).fingerprint, self.project(original).fingerprint)

    def test_runtime_changes_do_not_change_fingerprint(self):
        row = deepcopy(self.engine.rows['postgresql'])
        old = self.project(row).fingerprint
        row['State'].update(Status='running', Running=True, Health={'Status': 'starting', 'Log': ['private']})
        row['NetworkSettings'] = {'runtime': 'changes'}
        self.assertEqual(old, self.project(row).fingerprint)

    def test_mount_order_normalized_but_duplicate_target_rejected(self):
        row = deepcopy(self.engine.rows['postgresql'])
        row['Mounts'].append(dict(row['Mounts'][0], Destination='/other'))
        before = self.project(row).fingerprint
        row['Mounts'].reverse()
        self.assertEqual(before, self.project(row).fingerprint)
        row['Mounts'].append(deepcopy(row['Mounts'][0]))
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'): self.project(row)

    def test_missing_health_security_or_ambiguous_state_rejected(self):
        for change in (lambda r: r['Config'].pop('Healthcheck'),
                       lambda r: r['HostConfig'].pop('SecurityOpt'),
                       lambda r: r['State'].update(Paused=True),
                       lambda r: r['State'].update(Running=True),
                       lambda r: r['State'].pop('Health')):
            row = deepcopy(self.engine.rows['postgresql']); change(row)
            with self.assertRaises(ValueError): self.project(row)

    def test_id_project_and_service_substitution_rejected(self):
        for mutation in ('id', 'project', 'service'):
            row = deepcopy(self.engine.rows['postgresql'])
            if mutation == 'id': row['Id'] = 'e'*64
            else: row['Config']['Labels']['com.docker.compose.' + mutation] = 'other'
            with self.assertRaises(ValueError): self.project(row)

    def test_restart_full_object_and_syslog_endpoint_rejected(self):
        for change in (lambda r: r['HostConfig']['RestartPolicy'].update(Name='always'),
                       lambda r: r['HostConfig']['RestartPolicy'].update(MaximumRetryCount=True),
                       lambda r: r['HostConfig']['RestartPolicy'].update(MaximumRetryCount=3),
                       lambda r: r['HostConfig']['LogConfig'].update(Type='json-file'),
                       lambda r: r['HostConfig']['LogConfig']['Config'].update(**{'syslog-address': 'udp://127.0.0.1:1514'})):
            row = deepcopy(self.engine.rows['postgresql']); change(row)
            with self.assertRaises(ValueError): self.project(row)

    def test_metadata_drift_rejected_before_start(self):
        self.engine.rows['postgresql']['Config']['Env'].append('changed')
        self.assertEqual(self.backend.start(self.action, 60), 'failed')
        self.assertEqual(self.engine.posts, [])

    def test_inventory_extra_duplicate_missing_replacement_rejected(self):
        original = deepcopy(self.engine.listed)
        for mutation in ('extra', 'duplicate', 'missing', 'replacement'):
            self.engine.listed = deepcopy(original)
            if mutation == 'extra': self.engine.listed.append({'Id': 'e'*64, 'Labels': {
                'com.docker.compose.project': 'harbor', 'com.docker.compose.service': 'extra'}})
            if mutation == 'duplicate': self.engine.listed.append(deepcopy(original[0]))
            if mutation == 'missing': self.engine.listed.pop()
            if mutation == 'replacement': self.engine.listed[0]['Id'] = 'e'*64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.backend.observe()

    def test_other_project_inventory_does_not_expand_target(self):
        self.engine.listed.append({'Id': 'e'*64, 'Labels': {'com.docker.compose.project': 'other'}})
        self.assertEqual(set(self.backend.observe().containers), set(self.plan.ids))

    def test_inventory_changes_during_collection_rejected(self):
        def change():
            if self.engine.inventory_count == 2: self.engine.listed.pop()
        self.engine.on_inventory = change
        with self.assertRaises(ValueError): self.backend.observe()

    def test_generation_changes_during_collection_rejected(self):
        def change():
            if self.host_calls == 2: self.stamp = replace(self.stamp, daemon='c'*32)
        self.on_host = change
        with self.assertRaisesRegex(ValueError, 'GENERATION'): self.backend.observe()

    def test_wrong_or_stale_host_binding_rejected(self):
        for change in ({'binding': 'c'*64}, {'at': 4}, {'at': 11}, {'daemon': 'not-an-invocation'}):
            self.stamp = replace(d.HostSnapshot(BOOT, DAEMON, BINDING, 10), **change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.backend.observe()

    def test_collection_time_not_hidden_by_completion_timestamp(self):
        def delay(): self.now += 0.1
        self.engine.on_inspect = delay
        o = self.backend.observe()
        self.assertEqual(o.at, 10)
        self.assertGreater(self.now, o.at)

    def test_collection_deadline_includes_all_io(self):
        def delay(): self.now += 1
        self.engine.on_inspect = delay
        with self.assertRaisesRegex(ValueError, 'DEADLINE'): self.backend.observe()

    def test_tcp_not_ready_is_observation_but_not_start(self):
        self.tcp = False
        self.assertFalse(self.backend.observe().logger_tcp)
        self.assertEqual(self.backend.start(self.action, 60), 'failed')
        self.assertEqual(self.engine.posts, [])

    def test_start_exact_id_once_under_remaining_deadline(self):
        self.assertEqual(self.backend.start(self.action, 7), 'ok')
        self.assertEqual(self.engine.posts, [(self.action.container_id, 17)])

    def test_start_rejects_logger_wrong_id_token_or_elapsed_deadline(self):
        for action in (replace(self.action, service='log'), replace(self.action, container_id='x'),
                       replace(self.action, token=True), replace(self.action, deadline=10)):
            self.assertEqual(self.backend.start(action, 60), 'failed')
        self.assertEqual(self.engine.posts, [])

    def test_signal_during_final_fresh_observation_prevents_post(self):
        stopped = [False]
        self.engine.on_inspect = lambda: stopped.__setitem__(0, True)
        self.assertEqual(self.backend.start(self.action, 60, stop_requested=lambda: stopped[0]), 'stopped')
        self.assertEqual(self.engine.posts, [])

    def test_executor_passes_signal_to_last_preflight_and_preserves_claim(self):
        store = MemoryStore()
        executor = Executor(c.Controller(self.plan), store, self.backend, clock=lambda: self.now)
        executor.open(); executor.arm_initial()
        stopped = [False]
        original = self.backend.start
        def start(*args, **kw):
            self.engine.on_inspect = lambda: stopped.__setitem__(0, True)
            return original(*args, **kw)
        self.backend.start = start
        state = executor.tick(stop_requested=lambda: stopped[0])
        self.assertEqual(state.desired, 'HOLD')
        self.assertEqual(state.reason, 'MANAGER_STOP_BEFORE_POST')
        self.assertIsNotNone(state.pending)
        self.assertEqual(len(store.claims), 1)
        self.assertEqual(self.engine.posts, [])

    def test_start_generation_or_dependency_change_no_post(self):
        self.assertEqual(self.backend.start(replace(self.action, daemon='c'*32), 60), 'failed')
        later = replace(self.action, service='redis', container_id=self.plan.ids['redis'])
        self.assertEqual(self.backend.start(later, 60), 'failed')
        self.assertEqual(self.engine.posts, [])

    def test_start_already_running_no_post(self):
        self.healthy('postgresql')
        self.assertEqual(self.backend.start(self.action, 60), 'failed')
        self.assertEqual(self.engine.posts, [])

    def test_post_exception_or_unexpected_result_unknown_no_retry(self):
        for behavior in (TimeoutError(), OSError(), 'failed', 'unexpected'):
            self.engine.posts = []; self.engine.behavior = behavior
            self.assertEqual(self.backend.start(self.action, 60), 'unknown')
            self.assertEqual(len(self.engine.posts), 1)

    def test_late_ack_is_unknown(self):
        original = self.engine.start
        def late(cid, deadline):
            result = original(cid, deadline); self.now = deadline
            return result
        self.engine.start = late
        self.assertEqual(self.backend.start(self.action, 60), 'unknown')
        self.assertEqual(len(self.engine.posts), 1)

    def test_executor_integration_unknown_preserves_claim_on_resume(self):
        store = MemoryStore()
        executor = Executor(c.Controller(self.plan), store, self.backend, clock=lambda: self.now)
        executor.open(); executor.arm_initial()
        original = self.engine.start
        def checked(cid, deadline):
            self.assertTrue(store.locked_now)
            self.assertEqual(store.state.pending, store.claims[1])
            return original(cid, deadline)
        self.engine.start = checked
        self.engine.behavior = TimeoutError()
        self.assertEqual(executor.tick().reason, 'START_FAILED_OR_UNKNOWN')
        executor.open(); executor.tick()
        self.assertEqual(len(self.engine.posts), 1)
        self.assertIsNotNone(store.state.pending)

    def test_json_duplicate_nonfinite_invalid_and_size_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'{' , b' '* (d.MAX_BODY+1)):
            with self.assertRaises(ValueError): d.parse_json(raw)

    def test_engine_path_and_operation_reject_arbitrary_commands(self):
        engine = d.UnixEngine('1.53')
        with self.assertRaises(ValueError): engine.inspect('../evil', 20)
        with self.assertRaises(ValueError): engine.start('--help', 20)
        with self.assertRaises(ValueError): engine._request('POST', '/containers/create', 20)
        with self.assertRaises(ValueError): d.UnixEngine('1.53\r\nInjected: true')


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux Unix socket/peer-credential tests')
class UnixTransportTests(unittest.TestCase):
    def request(self, wire, operation='inventory', *, delay=0, peer_uid=None, budget=2):
        with tempfile.TemporaryDirectory(prefix='hbr-uds-') as directory:
            path = os.path.join(directory, 'engine.sock')
            received, errors = [], []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path); server.listen(1); server.settimeout(3)
                def respond():
                    try:
                        conn, _ = server.accept()
                        with conn:
                            conn.settimeout(2)
                            data = b''
                            while b'\r\n\r\n' not in data:
                                chunk = conn.recv(4096)
                                if not chunk: break
                                data += chunk
                            received.append(data)
                            if delay: time.sleep(delay)
                            conn.sendall(wire)
                    except (BrokenPipeError, ConnectionResetError): pass
                    except Exception as exc: errors.append(exc)
                worker = threading.Thread(target=respond)
                worker.start()
                from harbor_recovery_control import StopEngine
                engine_cls = StopEngine if operation == 'stop' else d.UnixEngine
                extra = {'ids': [f'{i:064x}' for i in range(1,9)]+['a'*64]} if operation == 'stop' else {}
                engine = engine_cls('1.53', socket_path=path,
                                      peer_uid=os.getuid() if peer_uid is None else peer_uid, **extra)
                try:
                    if operation == 'inventory': result = engine.inventory(time.monotonic()+budget)
                    elif operation == 'stop': result = engine.stop('a'*64, time.monotonic()+budget)
                    else: result = engine.start('a'*64, time.monotonic()+budget)
                    return result, received
                finally:
                    worker.join(4)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(errors, [])

    def test_get_exact_versioned_path(self):
        result, requests = self.request(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]')
        self.assertEqual(result, [])
        self.assertTrue(requests[0].startswith(b'GET /v1.53/containers/json?all=true HTTP/1.1\r\n'))

    def test_post_exact_id_empty_body(self):
        result, requests = self.request(b'HTTP/1.1 204 No Content\r\n\r\n', 'start')
        self.assertEqual(result, 'ok')
        self.assertEqual(len(requests), 1)
        self.assertIn(('/containers/'+'a'*64+'/start HTTP/1.1').encode(), requests[0])
        self.assertIn(b'Content-Length: 0\r\n', requests[0])

    def test_stop_wire_never_uses_default_kill_timeout_or_other_signal(self):
        result, requests = self.request(b'HTTP/1.1 204 No Content\r\n\r\n','stop')
        self.assertEqual(result,'ack')
        self.assertEqual(len(requests),1)
        self.assertIn(('/containers/'+'a'*64+'/stop?signal=SIGTERM&t=-1 HTTP/1.1').encode(),requests[0])

    def test_stop_304_is_uncertain_not_our_ack(self):
        result, requests = self.request(b'HTTP/1.1 304 Not Modified\r\n\r\n','stop')
        self.assertEqual(result,'unknown'); self.assertEqual(len(requests),1)

    def test_chunked_json(self):
        result, _ = self.request(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n')
        self.assertEqual(result, [])

    def test_already_running_and_server_error_are_unknown(self):
        for status in (304, 404, 500):
            result, requests = self.request(f'HTTP/1.1 {status} Result\r\nContent-Length: 0\r\n\r\n'.encode(), 'start')
            self.assertEqual(result, 'unknown')
            self.assertEqual(len(requests), 1)

    def test_no_redirect_or_retry(self):
        with self.assertRaisesRegex(ValueError, 'READ_FAILED'):
            self.request(b'HTTP/1.1 302 Redirect\r\nLocation: http://external/\r\nContent-Length: 0\r\n\r\n')

    def test_truncated_body_rejected(self):
        with self.assertRaises((ValueError, d.http.client.IncompleteRead)):
            self.request(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n[]')

    def test_oversized_body_declared_rejected(self):
        with self.assertRaisesRegex(ValueError, 'BODY_LIMIT'):
            self.request(f'HTTP/1.1 200 OK\r\nContent-Length: {d.MAX_BODY+1}\r\n\r\n'.encode())

    def test_duplicate_or_ambiguous_framing_rejected(self):
        for headers in (b'Content-Length: 2\r\nContent-Length: 2',
                        b'Content-Length: 2\r\nTransfer-Encoding: chunked'):
            with self.assertRaisesRegex(ValueError, 'FRAMING'):
                self.request(b'HTTP/1.1 200 OK\r\n'+headers+b'\r\n\r\n[]')

    def test_wrong_peer_uid_rejected(self):
        with self.assertRaisesRegex(ValueError, 'PEER_UID'):
            self.request(b'', peer_uid=os.getuid()+1)

    def test_total_deadline(self):
        with self.assertRaises((TimeoutError, ValueError)):
            self.request(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]', delay=0.3, budget=0.05)


if __name__ == '__main__':
    unittest.main()
