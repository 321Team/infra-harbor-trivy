"""Linux, single-use durable journal for the production address sequence.

No installer, permission/label repair, replay or default path/context. The caller
must supply an empty protected directory and its independently reviewed context.
An existing/partial claim is preserved and refused, including after an I/O fault.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import threading

ORDER = ('postgresql', 'redis', 'registry', 'registryctl', 'core', 'portal',
         'jobservice', 'trivy-adapter', 'proxy')
REASONS = frozenset('''CLOCK_INVALID DEADLINE OBSERVATION_SCHEMA
GENERATION_OR_PROTECTION_CHANGED PROTECTED_INPUT_CHANGED OBSERVATION_STALE
LOGGER_LISTENER OBSERVATION_SERVICES ROW_SCHEMA PRESERVATION_CHANGED LOGGING_CHANGED
APP_NOT_RECREATED NEW_CONTAINER_REPLACED APP_NOT_RUNNING PRIOR_APP_UNHEALTHY
UNTOUCHED_CONTAINER_CHANGED DUPLICATE_CURRENT_ID BASE_LOGGING
RECREATE_OUTCOME_UNKNOWN RECREATE_COMMAND_FAILED EXISTING_HISTORY
IO_OR_ADAPTER_FAILURE'''.split())


def require(ok):
    if not ok:
        raise ValueError('JOURNAL_CONTRACT')


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def prefix(value):
    return type(value) is list and value == list(ORDER[:len(value)]) and len(value) <= 9


def validate_event(event):
    require(type(event) is dict)
    kind = event.get('kind')
    fields = {
        'BEGIN': {'kind', 'plan_sha256'},
        'RECREATE_INTENT': {'kind', 'service', 'old_id'},
        'RECREATE_RESULT': {'kind', 'service', 'outcome'},
        'APP_HEALTHY': {'kind', 'service', 'new_id'},
        'COMPLETE': {'kind', 'healthy_services'},
        'STOP': {'kind', 'reason', 'claimed_services', 'transport_entered_services', 'healthy_services'},
    }
    require(kind in fields and set(event) == fields[kind])
    for key in ('plan_sha256', 'old_id', 'new_id'):
        if key in event:
            require(digest(event[key]))
    if 'service' in event:
        require(event['service'] in ORDER)
    if 'outcome' in event:
        require(event['outcome'] in ('ACK', 'FAILED', 'UNKNOWN', 'LATE'))
    if 'reason' in event:
        require(event['reason'] in REASONS)
    for key in ('claimed_services', 'transport_entered_services', 'healthy_services'):
        if key in event:
            require(prefix(event[key]))
    if kind == 'COMPLETE':
        require(event['healthy_services'] == list(ORDER))
    if kind == 'STOP':
        require(len(event['healthy_services']) <= len(event['transport_entered_services']) <= len(event['claimed_services']))
    return json.loads(encode(event))


class Journal:
    """Root-only fd-relative O_EXCL claim, flock, hash chain and fsync.

    expected_selinux is explicit: exact bytes without NUL, or None only for a
    separately reviewed platform without SELinux xattrs (e.g. CI temp storage).
    None never disables SELinux or accepts a present context. No default exists.
    The parent directory tree must be root-owned and not group/other writable;
    the final directory must be root:root 0700, files root:root 0600/nlink1.
    Independent privileged writers are outside flock's enforcement boundary.
    """
    def __init__(self, path, *, expected_selinux):
        p = PurePosixPath(path)
        require(str(p) == path and p.is_absolute() and '..' not in p.parts and len(p.parts) > 2)
        require(expected_selinux is None or (type(expected_selinux) is bytes and
                expected_selinux and b'\0' not in expected_selinux))
        self.path, self.context = p, expected_selinux
        self.pid, self.mutex = os.getpid(), threading.Lock()
        self.used, self.failed, self.held = False, False, False
        self.directory = self.lockfd = self.claimfd = self.eventsfd = None
        self.parents = []
        self.records, self.previous, self.length = 0, '0'*64, 0
        self.stage, self.completed = 'NEW', []

    def _metadata(self, fd, *, directory=False, final=False):
        s = os.fstat(fd)
        require(s.st_uid == s.st_gid == 0)
        require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
        require(stat.S_IMODE(s.st_mode) == (0o700 if directory else 0o600) if final or not directory
                else not (s.st_mode & 0o022))
        if not directory:
            require(s.st_nlink == 1)
        attrs = set(os.listxattr(fd))
        require(attrs <= {'security.selinux'})
        if final or not directory:
            actual = os.getxattr(fd, 'security.selinux').rstrip(b'\0') if 'security.selinux' in attrs else None
            require(actual == self.context)
        return s

    def _same(self, fd, name):
        a = self._metadata(fd)
        b = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
        require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))
        return a

    def _owned(self):
        require(os.getpid() == self.pid and self.held and not self.failed)
        self._metadata(self.directory, directory=True, final=True)
        self._same(self.lockfd, 'writer.lock')
        if self.claimfd is not None:
            self._same(self.claimfd, 'run.claim')
        if self.eventsfd is not None:
            require(self._same(self.eventsfd, 'events.jsonl').st_size == self.length)

    def _new(self, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_APPEND,
                     0o600, dir_fd=self.directory)
        try:
            self._same(fd, name)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _write(fd, raw):
        while raw:
            n = os.write(fd, raw)
            require(n > 0)
            raw = raw[n:]
        os.fsync(fd)

    @contextmanager
    def locked(self):
        import fcntl  # Linux only; importing the module remains safe on Windows.
        require(os.geteuid() == 0 and os.getpid() == self.pid)
        require(self.mutex.acquire(blocking=False))
        try:
            require(not self.used)
            self.used = True
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.parents.append(fd)
            self._metadata(fd, directory=True)
            for component in self.path.parts[1:]:
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=fd)
                self.parents.append(fd)
                self._metadata(fd, directory=True)
            self.directory = fd
            self._metadata(fd, directory=True, final=True)
            try:
                self.lockfd = self._new('writer.lock')
                os.fsync(self.directory)
            except FileExistsError:
                self.lockfd = os.open('writer.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=self.directory)
                self._same(self.lockfd, 'writer.lock')
            require(os.fstat(self.lockfd).st_size == 0)
            fcntl.flock(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.held = True
            self._owned()
            yield self
        finally:
            self.held = False
            for name in ('eventsfd', 'claimfd', 'lockfd'):
                fd = getattr(self, name)
                if fd is not None:
                    os.close(fd)
                    setattr(self, name, None)
            for fd in reversed(self.parents):
                os.close(fd)
            self.parents = []
            self.directory = None
            self.mutex.release()

    def begin(self, plan_sha256):
        try:
            self._owned()
            require(self.stage == 'NEW' and digest(plan_sha256))
            if set(os.listdir(self.directory)) != {'writer.lock'}:
                raise FileExistsError('EXISTING_HISTORY')
            self.claimfd = self._new('run.claim')
            self._write(self.claimfd, encode(dict(schema='fds.harbor.address-claim.v1', plan_sha256=plan_sha256))+b'\n')
            os.fsync(self.directory)
            self.eventsfd = self._new('events.jsonl')
            os.fsync(self.directory)
            self._append(dict(kind='BEGIN', plan_sha256=plan_sha256))
            self.stage = 'READY'
        except BaseException:
            self.failed = True
            raise

    def _append(self, event):
        self._owned()
        record = dict(sequence=self.records, previous_sha256=self.previous, event=validate_event(event))
        body = encode(record)
        record['sha256'] = hashlib.sha256(body).hexdigest()
        raw = encode(record)+b'\n'
        require(len(raw) <= 4096)
        self._write(self.eventsfd, raw)
        self.length += len(raw)
        self.records += 1
        self.previous = record['sha256']

    def append(self, event):
        try:
            self._owned()
            event = validate_event(event)
            kind = event['kind']
            require(self.stage not in ('NEW', 'TERMINAL') and kind != 'BEGIN')
            service = ORDER[len(self.completed)] if len(self.completed) < 9 else None
            stage = self.stage
            if kind == 'RECREATE_INTENT':
                require(stage == 'READY' and event['service'] == service)
                stage = 'INTENT'
            elif kind == 'RECREATE_RESULT':
                require(stage == 'INTENT' and event['service'] == service)
                stage = 'ACK' if event['outcome'] == 'ACK' else 'FAILED'
            elif kind == 'APP_HEALTHY':
                require(stage == 'ACK' and event['service'] == service)
                stage = 'READY'
            elif kind == 'COMPLETE':
                require(stage == 'READY' and self.completed == list(ORDER))
                stage = 'TERMINAL'
            elif kind == 'STOP':
                require(event['healthy_services'] == self.completed)
                count = len(self.completed) + (stage != 'READY')
                require(event['claimed_services'] == list(ORDER[:count]))
                stage = 'TERMINAL'
            self._append(event)
            self.stage = stage
            if kind == 'APP_HEALTHY':
                self.completed.append(service)
        except BaseException:
            self.failed = True
            raise
