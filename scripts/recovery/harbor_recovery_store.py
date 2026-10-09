"""Strict state codec and POSIX private storage. No server command execution."""
from contextlib import contextmanager
from dataclasses import asdict, fields
import json
import math
import os
from pathlib import Path
import re
import stat
import uuid

from harbor_recovery_core import Action, ORDER, State

if os.name == 'posix':
    import fcntl

MAX_BYTES = 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= MAX_BYTES, 'STATE_TOO_LARGE')
    obj = json.loads(raw, object_pairs_hook=pairs_unique)
    require(isinstance(obj, dict) and set(obj) == {'version', 'state'} and
            type(obj['version']) is int and obj['version'] == 1, 'STATE_VERSION')
    d = obj['state']
    require(isinstance(d, dict) and set(d) == {f.name for f in fields(State)}, 'STATE_SCHEMA')
    require(d['desired'] in ('RUN', 'HOLD'), 'STATE_DESIRED')
    require(isinstance(d['reason'], str) and re.fullmatch('[A-Z0-9_]{1,128}', d['reason']), 'STATE_REASON')
    for key in ('boot', 'daemon'):
        require(isinstance(d[key], str) and re.fullmatch('[A-Za-z0-9-]{0,128}', d[key]), 'STATE_GENERATION')
    require(isinstance(d['plan_digest'], str) and
            re.fullmatch('(?:[0-9a-f]{64})?', d['plan_digest']), 'STATE_PLAN')
    require(type(d['next_token']) is int and 1 <= d['next_token'] < 2**63, 'STATE_TOKEN')
    for key in ('last_now', 'episode_since', 'logger_since'):
        require(d[key] is None or number(d[key]), 'STATE_TIME')
    if d['desired'] == 'RUN':
        require(d['boot'] and d['daemon'] and d['plan_digest'] and d['last_now'] is not None, 'STATE_RUN_BINDING')
    require(isinstance(d['seen_healthy'], list) and all(s in ORDER for s in d['seen_healthy']) and
            len(d['seen_healthy']) == len(set(d['seen_healthy'])), 'STATE_SEEN')
    require(isinstance(d['retries'], dict) and set(d['retries']) == set(ORDER), 'STATE_RETRIES')
    for ts in d['retries'].values():
        require(isinstance(ts, list) and len(ts) <= 512 and all(number(t) for t in ts) and
                ts == sorted(ts), 'STATE_RETRY_TIMES')
        require(not ts or (d['last_now'] is not None and ts[-1] <= d['last_now']), 'STATE_FUTURE_RETRY')
    for key in ('episode_since', 'logger_since'):
        require(d[key] is None or (d['last_now'] is not None and d[key] <= d['last_now']), 'STATE_TIME_ORDER')
    if d['pending'] is not None:
        p = d['pending']
        require(isinstance(p, dict) and set(p) == {f.name for f in fields(Action)}, 'STATE_INTENT_SCHEMA')
        require(type(p['token']) is int and p['token'] == d['next_token'] - 1 and p['token'] > 0,
                'STATE_INTENT_TOKEN')
        require(p['service'] in ORDER and isinstance(p['container_id'], str) and
                re.fullmatch('[0-9a-f]{64}', p['container_id']), 'STATE_INTENT_TARGET')
        require(p['boot'] == d['boot'] and p['daemon'] == d['daemon'] and
                p['boot'] and p['daemon'] and number(p['deadline']) and d['last_now'] is not None,
                'STATE_INTENT_BINDING')
        require(d['episode_since'] is not None, 'STATE_INTENT_EPISODE')
        d['pending'] = Action(**p)
    if d['health_wait'] is not None:
        wait = d['health_wait']
        require(isinstance(wait, list) and len(wait) == 2 and wait[0] in ORDER and
                number(wait[1]) and d['episode_since'] is not None and d['pending'] is None,
                'STATE_WAIT')
        d['health_wait'] = tuple(wait)
    d['seen_healthy'] = set(d['seen_healthy'])
    return State(**d)


def encode(state):
    d = asdict(state)
    d['seen_healthy'] = sorted(state.seen_healthy)
    raw = (json.dumps({'version': 1, 'state': d}, sort_keys=True, allow_nan=False) + '\n').encode()
    decode(raw)  # never persist a schema-invalid transition
    return raw


class Store:
    """Pre-created private directory only; initialization is explicit.

    Production integrations must use uid=0 (the default). Tests use their
    unprivileged uid in private directories beneath their own home directory.
    """
    def __init__(self, directory, *, uid=0):
        if os.name != 'posix':
            raise OSError('POSIX_STORE_REQUIRED')
        self.path = Path(directory)
        require(self.path.is_absolute() and '..' not in self.path.parts, 'ABSOLUTE_STORE_REQUIRED')
        self.uid = uid
        self.fd = None

    def _directory(self):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open('/', flags)
        try:
            for part in self.path.parts[1:]:
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                st = os.fstat(fd)
                require(st.st_uid in (0, self.uid) and not st.st_mode & 0o022, 'UNTRUSTED_STORE_PARENT')
            st = os.fstat(fd)
            require(st.st_uid == self.uid and not st.st_mode & 0o077, 'PRIVATE_STORE_REQUIRED')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _file(self, name, flags):
        require(self.fd is not None, 'STORE_LOCK_REQUIRED')
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                    st.st_uid == self.uid and not st.st_mode & 0o077 and st.st_size <= MAX_BYTES,
                    'UNTRUSTED_STORE_FILE')
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextmanager
    def locked(self):
        require(self.fd is None, 'NESTED_STORE_LOCK')
        directory = self._directory()
        self.fd = directory
        lock = None
        try:
            lock = self._file('controller.lock', os.O_CREAT | os.O_RDWR)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield self
        finally:
            if lock is not None:
                os.close(lock)
            self.fd = None
            os.close(directory)

    def load(self):
        with os.fdopen(self._file('state.json', os.O_RDONLY), 'rb') as stream:
            return decode(stream.read(MAX_BYTES + 1))

    def _new(self, name, raw):
        require(len(raw) <= MAX_BYTES, 'RECORD_TOO_LARGE')
        fd = self._file(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)

    def initialize(self):
        # A surviving claim/audit/partial file means this is not a fresh store.
        require(set(os.listdir(self.fd)) <= {'controller.lock'}, 'STORE_NOT_EMPTY')
        self._new('state.json', encode(State()))

    def save(self, state):
        self.load()  # missing/corrupt/symlink state is never silently replaced
        pending = 'state-' + uuid.uuid4().hex + '.pending'
        self._new(pending, encode(state))
        os.replace(pending, 'state.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def claim(self, action):
        require(isinstance(action, Action) and type(action.token) is int and action.token > 0,
                'INVALID_CLAIM')
        # Same token cannot be dispatched again even if state is restored backwards.
        self._new(f'intent-{action.token:020}.json',
                  (json.dumps(asdict(action), sort_keys=True, allow_nan=False) + '\n').encode())

    def audit(self, kind, state):
        require(kind in ('logger-reconcile-request', 'operator-hold', 'initial-arm-request', 'manager-hold'), 'AUDIT_KIND')
        self._new(kind + '-' + uuid.uuid4().hex + '.json', encode(state))
