"""Phase 1 Docker adapter; no CLI, installer, or default host-guard provider.

Only the executor may call start after durable intent and claim. The required
host provider must freshly verify identity/isolation, SELinux, AC04, effective
Compose, engine/storage profile and input ownership. Synthetic providers are
for tests only. This module alone is NOT a deployable recovery service.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import http.client
import io
import json
import math
import os
import re
import socket
import struct
import time

from harbor_recovery_core import Action, Container, Controller, ENDPOINT, Observation, ORDER

MAX_BODY = 8 * 1024 * 1024
HEX = re.compile('[0-9a-f]{64}')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def remaining(deadline, clock):
    now = clock()
    require(finite(deadline) and finite(now) and now < deadline, 'IO_DEADLINE')
    return deadline - now


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def execution_binding(host_binding, project_name, engine_binding):
    require(all(isinstance(v, str) and HEX.fullmatch(v) for v in (host_binding, engine_binding)),
            'ADAPTER_BINDING')
    return digest({'adapter_version': 1, 'host': host_binding, 'project': project_name,
                   'engine': engine_binding})


def parse_json(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_BODY, 'ENGINE_BODY_LIMIT')
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, 'ENGINE_DUPLICATE_KEY')
            obj[key] = value
        return obj
    def invalid(_):
        raise ValueError('ENGINE_NONFINITE_JSON')
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('ENGINE_JSON_INVALID') from None


def project(row, service, cid, project_name):
    """Hash private immutable metadata; never return env, secrets, or health logs.

    RestartPolicy is checked separately, so policy-only installation does not
    require blessing a different immutable fingerprint. Runtime State and
    NetworkSettings are excluded; host/network guards remain mandatory.
    """
    require(isinstance(row, dict) and row.get('Id') == cid, 'INSPECT_ID')
    config, host, state = (row.get(k) for k in ('Config', 'HostConfig', 'State'))
    require(all(isinstance(v, dict) for v in (config, host, state)), 'INSPECT_SCHEMA')
    labels = config.get('Labels')
    require(isinstance(labels, dict) and labels.get('com.docker.compose.service') == service and
            labels.get('com.docker.compose.project') == project_name, 'INSPECT_LABELS')
    require(isinstance(row.get('Name'), str) and row['Name'].startswith('/') and
            isinstance(row.get('Image'), str) and
            re.fullmatch('sha256:[0-9a-f]{64}', row['Image']), 'INSPECT_IMAGE_NAME')
    for key in ('Env', 'Entrypoint', 'Cmd', 'User', 'Healthcheck'):
        require(key in config, 'INSPECT_CONFIG_FIELD')
    healthcheck = config['Healthcheck']
    require(isinstance(healthcheck, dict) and isinstance(healthcheck.get('Test'), list) and
            len(healthcheck['Test']) >= 2 and healthcheck['Test'][0] in ('CMD', 'CMD-SHELL'),
            'INSPECT_HEALTHCHECK')
    for key in ('LogConfig', 'RestartPolicy', 'NetworkMode', 'PortBindings', 'Privileged',
                'SecurityOpt', 'ReadonlyRootfs', 'CapAdd', 'CapDrop', 'Binds'):
        require(key in host, 'INSPECT_HOST_FIELD')
    policy = host['RestartPolicy']
    require(isinstance(policy, dict) and set(policy) == {'Name', 'MaximumRetryCount'} and
            policy['Name'] == ('always' if service == 'log' else 'no') and
            type(policy['MaximumRetryCount']) is int and policy['MaximumRetryCount'] == 0,
            'INSPECT_RESTART_POLICY')
    logging = host['LogConfig']
    require(isinstance(logging, dict) and isinstance(logging.get('Type'), str) and
            isinstance(logging.get('Config'), dict), 'INSPECT_LOGGING')
    endpoint = logging['Config'].get('syslog-address', '')
    if service != 'log':
        require(logging['Type'] == 'syslog' and endpoint == ENDPOINT, 'INSPECT_LOGGING')
    mounts = row.get('Mounts')
    require(isinstance(mounts, list) and all(isinstance(m, dict) and
            all(isinstance(m.get(k), str) for k in ('Type', 'Source', 'Destination', 'Mode')) and
            type(m.get('RW')) is bool for m in mounts), 'INSPECT_MOUNTS')
    require(len({m['Destination'] for m in mounts}) == len(mounts), 'INSPECT_MOUNT_DUPLICATE')
    require(all(isinstance(row.get(k), str) for k in ('MountLabel', 'ProcessLabel')),
            'INSPECT_SECURITY_LABELS')
    require(isinstance(state.get('Health'), dict), 'INSPECT_HEALTH_STATE')
    status, health = state.get('Status'), state['Health'].get('Status')
    require(status in ('running', 'exited', 'created') and
            health in ('healthy', 'starting', 'unhealthy'), 'INSPECT_STATE')
    for key in ('Running', 'Paused', 'Restarting', 'Dead'):
        require(type(state.get(key)) is bool, 'INSPECT_STATE_FLAG')
    require(state['Running'] == (status == 'running') and
            not any(state[k] for k in ('Paused', 'Restarting', 'Dead')), 'INSPECT_STATE_CONFLICT')
    metadata_host = deepcopy(host)
    del metadata_host['RestartPolicy']
    metadata = {'projection_version': 1, 'Id': cid, 'Name': row['Name'], 'Image': row['Image'],
                'Config': config, 'HostConfig': metadata_host,
                'Mounts': sorted(mounts, key=lambda m: m['Destination']),
                'MountLabel': row['MountLabel'], 'ProcessLabel': row['ProcessLabel']}
    return Container(cid, digest(metadata), status, health, policy['Name'], endpoint)


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline, clock):
        self.sock, self.deadline, self.clock = sock, deadline, clock
        self.count = 0

    def readable(self):
        return True

    def readinto(self, buf):
        self.sock.settimeout(remaining(self.deadline, self.clock))
        size = self.sock.recv_into(buf)
        self.count += size
        # Includes HTTP framing, preventing a stream of tiny chunks from using
        # unlimited memory/wire input even when decoded body remains small.
        require(self.count <= MAX_BODY * 2, 'ENGINE_WIRE_LIMIT')
        return size


class _ResponseSocket:
    def __init__(self, sock, deadline, clock):
        self.sock, self.deadline, self.clock = sock, deadline, clock

    def makefile(self, mode):
        return io.BufferedReader(_DeadlineReader(self.sock, self.deadline, self.clock))


class UnixEngine:
    """Linux AF_UNIX only, root peer by default, no redirects or retries.

    Installation must validate the socket path and approved API version. The
    peer_uid override exists for unprivileged local fake-server tests only.
    """
    def __init__(self, api_version, *, socket_path='/run/docker.sock', peer_uid=0,
                 clock=time.monotonic):
        require(isinstance(api_version, str) and re.fullmatch(r'1\.\d{2}', api_version), 'API_VERSION')
        require(os.path.isabs(socket_path) and '\0' not in socket_path, 'SOCKET_PATH')
        self.prefix, self.path = '/v' + api_version, socket_path
        self.peer_uid, self.clock = peer_uid, clock

    @property
    def binding(self):
        return digest({'transport_version': 1, 'api_prefix': self.prefix,
                       'socket_path': self.path, 'peer_uid': self.peer_uid})

    def _request(self, method, path, deadline):
        require((method == 'GET' and (path == '/containers/json?all=true' or
                re.fullmatch('/containers/[0-9a-f]{64}/json', path))) or
                (method == 'POST' and re.fullmatch('/containers/[0-9a-f]{64}/start', path)),
                'ENGINE_OPERATION_NOT_ALLOWED')
        require(hasattr(socket, 'SO_PEERCRED'), 'LINUX_PEERCRED_REQUIRED')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(remaining(deadline, self.clock))
            sock.connect(self.path)
            _, uid, _ = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == self.peer_uid, 'ENGINE_PEER_UID')
            sock.settimeout(remaining(deadline, self.clock))
            request = (f'{method} {self.prefix}{path} HTTP/1.1\r\nHost: localhost\r\n'
                       'Connection: close\r\nContent-Length: 0\r\n\r\n').encode('ascii')
            sock.sendall(request)
            with http.client.HTTPResponse(_ResponseSocket(sock, deadline, self.clock)) as response:
                response.begin()
                lengths = response.headers.get_all('Content-Length', [])
                transfers = response.headers.get_all('Transfer-Encoding', [])
                require(len(lengths) <= 1 and len(transfers) <= 1 and not (lengths and transfers),
                        'ENGINE_FRAMING')
                require(not transfers or transfers[0].lower() == 'chunked', 'ENGINE_FRAMING')
                require(not lengths or (lengths[0].isascii() and lengths[0].isdigit() and
                        int(lengths[0]) <= MAX_BODY), 'ENGINE_BODY_LIMIT')
                raw = response.read(MAX_BODY + 1)
                require(len(raw) <= MAX_BODY, 'ENGINE_BODY_LIMIT')
                require(not lengths or response.status in (204, 304) or len(raw) == int(lengths[0]),
                        'ENGINE_TRUNCATED_BODY')
                remaining(deadline, self.clock)
                return response.status, raw

    def _json(self, path, deadline):
        status, raw = self._request('GET', path, deadline)
        require(status == 200, 'ENGINE_READ_FAILED')
        return parse_json(raw)

    def inventory(self, deadline):
        return self._json('/containers/json?all=true', deadline)

    def inspect(self, cid, deadline):
        require(isinstance(cid, str) and HEX.fullmatch(cid), 'ENGINE_ID')
        return self._json('/containers/' + cid + '/json', deadline)

    def start(self, cid, deadline):
        require(isinstance(cid, str) and HEX.fullmatch(cid), 'ENGINE_ID')
        status, _ = self._request('POST', '/containers/' + cid + '/start', deadline)
        # 304/already-running indicates competing activity; never acknowledge
        # it as our successful start. Any other HTTP result stays uncertain.
        return 'ok' if status == 204 else 'unknown'


@dataclass(frozen=True)
class HostSnapshot:
    boot: str
    daemon: str  # Docker systemd InvocationID, not a constant daemon ID
    binding: str  # digest of verified host/config/security/engine/storage inputs
    at: float


def logger_tcp(deadline, clock=time.monotonic):
    try:
        with socket.create_connection(('127.0.0.1', 1514), timeout=min(1, remaining(deadline, clock))):
            pass
        remaining(deadline, clock)
        return True
    except OSError:
        return False


class DockerBackend:
    def __init__(self, plan, engine, host_provider, host_binding, project_name, *,
                 clock=time.monotonic, probe=None):
        require(isinstance(host_binding, str) and HEX.fullmatch(host_binding), 'HOST_BINDING')
        require(isinstance(project_name, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,62}', project_name),
                'PROJECT_NAME')
        require(callable(host_provider), 'HOST_PROVIDER_REQUIRED')
        self.core = Controller(plan)
        self.engine, self.host_provider, self.binding = engine, host_provider, host_binding
        self.project_name, self.clock = project_name, clock
        self.probe = probe if probe is not None else lambda deadline: logger_tcp(deadline, clock)
        self._binding()

    def _binding(self):
        require(self.core.plan.execution_binding == execution_binding(
            self.binding, self.project_name, self.engine.binding), 'PLAN_ADAPTER_BINDING')

    def _host(self, deadline):
        stamp = self.host_provider(deadline)
        now = self.clock()
        remaining(deadline, self.clock)
        require(isinstance(stamp, HostSnapshot) and stamp.binding == self.binding and
                isinstance(stamp.boot, str) and re.fullmatch('[0-9a-f-]{36}', stamp.boot) and
                isinstance(stamp.daemon, str) and re.fullmatch('[0-9a-f]{32}', stamp.daemon) and
                finite(stamp.at) and 0 <= now - stamp.at <= self.core.plan.max_age_seconds,
                'HOST_VERIFICATION_FAILED')
        return stamp

    def _inventory(self, deadline):
        rows = self.engine.inventory(deadline)
        require(isinstance(rows, list), 'INVENTORY_SCHEMA')
        actual = {}
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get('Labels'), dict), 'INVENTORY_SCHEMA')
            if row['Labels'].get('com.docker.compose.project') != self.project_name:
                continue
            service = row['Labels'].get('com.docker.compose.service')
            require(isinstance(service, str) and service not in actual, 'INVENTORY_DUPLICATE')
            actual[service] = row.get('Id')
        require(actual == self.core.plan.ids, 'PROJECT_INVENTORY_CHANGED')

    def observe(self, deadline=None):
        self._binding()
        started = self.clock()
        end = started + self.core.plan.max_age_seconds
        if deadline is not None:
            require(finite(deadline), 'IO_DEADLINE')
            end = min(end, deadline)
        first = self._host(end)
        self._inventory(end)
        rows = {name: project(self.engine.inspect(cid, end), name, cid, self.project_name)
                for name, cid in self.core.plan.ids.items()}
        tcp = self.probe(end)
        require(type(tcp) is bool, 'LOGGER_PROBE_INVALID')
        self._inventory(end)
        last = self._host(end)
        require((first.boot, first.daemon) == (last.boot, last.daemon), 'OBSERVATION_GENERATION_CHANGED')
        now = self.clock()
        remaining(end, self.clock)
        # Oldest input, not completion time: slow collection cannot refresh old
        # evidence merely by assigning a new timestamp at the end.
        observation = Observation(last.boot, last.daemon, min(started, first.at, last.at), rows, True, tcp)
        issue = self.core.problem(observation, now)
        require(issue is None, issue or 'INVALID_OBSERVATION')
        return observation

    def start(self, action, timeout):
        # This is not a standalone action API: only Executor may own durable
        # intent/claims. Recheck immediately before the one mutating request.
        try:
            require(isinstance(action, Action) and action.service in ORDER and
                    action.container_id == self.core.plan.ids[action.service] and
                    type(action.token) is int and action.token > 0 and
                    finite(action.deadline) and finite(timeout) and timeout > 0, 'START_ACTION')
            deadline = min(action.deadline, self.clock() + timeout)
            o = self.observe(deadline)
            require((o.boot, o.daemon) == (action.boot, action.daemon), 'START_GENERATION')
            require(o.logger_tcp and o.containers['log'].status == 'running' and
                    o.containers['log'].health == 'healthy', 'START_LOGGER')
            require(o.containers[action.service].status in ('created', 'exited'), 'START_TARGET')
            require(all(o.containers[n].status == 'running' and o.containers[n].health == 'healthy'
                        for n in ORDER[:ORDER.index(action.service)]), 'START_DEPENDENCY')
            remaining(deadline, self.clock)
        except Exception:
            return 'failed'  # no POST submitted
        try:
            outcome = self.engine.start(action.container_id, deadline)
            remaining(deadline, self.clock)
            return outcome if outcome in ('ok', 'unknown') else 'unknown'
        except Exception:
            return 'unknown'  # submission may have reached daemon; never retry
