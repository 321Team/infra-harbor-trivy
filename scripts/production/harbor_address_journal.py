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
RECREATE_OUTCOME_UNKNOWN RECREATE_COMMAND_FAILED RECREATE_PREPARATION_FAILED NETWORK_NOT_READY EXISTING_HISTORY
IO_OR_ADAPTER_FAILURE'''.split())


def require(ok):
    if not ok:
        raise ValueError('JOURNAL_CONTRACT')


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def prefix(value, order=ORDER):
    return type(value) is list and value == list(order[:len(value)]) and len(value) <= len(order)


def validate_event(event, order=ORDER):
    require(type(order) is tuple and order in (ORDER, ORDER[1:]))
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
        require(event['service'] in order)
    if 'outcome' in event:
        require(event['outcome'] in ('ACK', 'FAILED', 'UNKNOWN', 'LATE'))
    if 'reason' in event:
        require(event['reason'] in REASONS)
    for key in ('claimed_services', 'transport_entered_services', 'healthy_services'):
        if key in event:
            require(prefix(event[key], order))
    if kind == 'COMPLETE':
        require(event['healthy_services'] == list(order))
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
    def __init__(self, path, *, expected_selinux, order=ORDER):
        require(type(order) is tuple and order in (ORDER, ORDER[1:]))
        self.order = order
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
        record = dict(sequence=self.records, previous_sha256=self.previous, event=validate_event(event, self.order))
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
            event = validate_event(event, self.order)
            kind = event['kind']
            require(self.stage not in ('NEW', 'TERMINAL') and kind != 'BEGIN')
            service = self.order[len(self.completed)] if len(self.completed) < len(self.order) else None
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
                require(stage == 'READY' and self.completed == list(self.order))
                stage = 'TERMINAL'
            elif kind == 'STOP':
                require(event['healthy_services'] == self.completed)
                count = len(self.completed) + (stage != 'READY')
                require(event['claimed_services'] == list(self.order[:count]))
                stage = 'TERMINAL'
            self._append(event)
            self.stage = stage
            if kind == 'APP_HEALTHY':
                self.completed.append(service)
        except BaseException:
            self.failed = True
            raise


def _parse_unique(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('JOURNAL_CONTRACT')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def inspect_bytes(claim_raw, events_raw, *, expected_plan_sha256, order=ORDER):
    """Offline forensic parse, without repair, replay or actual runtime judgment.

    None means a missing file, distinct from an empty/torn file. A valid prefix
    remains diagnostic only. A hash chain cannot authenticate against an actor
    who can rewrite the complete history; retain external collection hashes.
    """
    require(digest(expected_plan_sha256) and type(order) is tuple and order in (ORDER, ORDER[1:]))
    for raw, limit in ((claim_raw, 4096), (events_raw, 128 * 1024)):
        require(raw is None or (type(raw) is bytes and len(raw) <= limit))
    result = dict(status='UNCLASSIFIED', valid_records=0, last_valid_stage='NEW',
                  recorded_healthy_services=[], terminal=None, invalid_record_index=None,
                  claim_sha256=hashlib.sha256(claim_raw).hexdigest() if claim_raw is not None else None,
                  events_sha256=hashlib.sha256(events_raw).hexdigest() if events_raw is not None else None,
                  runtime_outcome='NOT_INFERRED', may_resume=False)
    if claim_raw is None:
        result['status'] = 'EMPTY_UNCLAIMED' if events_raw is None else 'EVENTS_WITHOUT_CLAIM'
        return result
    try:
        require(claim_raw.endswith(b'\n'))
        claim = _parse_unique(claim_raw)
        require(type(claim) is dict and set(claim) == {'schema', 'plan_sha256'} and
                claim['schema'] == 'fds.harbor.address-claim.v1' and digest(claim['plan_sha256']))
    except Exception:
        result['status'] = 'INVALID_OR_PARTIAL_CLAIM'
        return result
    if claim['plan_sha256'] != expected_plan_sha256:
        result['status'] = 'PLAN_MISMATCH'
        return result
    if not events_raw:
        result['status'] = 'CLAIM_WITHOUT_EVENT_RECORD'
        return result
    stage, completed, previous = 'NEW', [], '0' * 64
    # At most 30 records: BEGIN + (INTENT/RESULT/HEALTHY)*9 + COMPLETE/STOP.
    for index, raw in enumerate(events_raw.splitlines(keepends=True)):
        if not raw.endswith(b'\n'):
            result.update(status='TORN_EVENT_TAIL', invalid_record_index=index)
            return result
        try:
            require(index < 30 and len(raw) <= 4096 and stage != 'TERMINAL')
            record = _parse_unique(raw)
            require(type(record) is dict and set(record) == {'sequence', 'previous_sha256', 'event', 'sha256'} and
                    type(record['sequence']) is int and record['sequence'] == index and
                    record['previous_sha256'] == previous and digest(record['sha256']))
            body = {key: record[key] for key in ('sequence', 'previous_sha256', 'event')}
            require(hashlib.sha256(encode(body)).hexdigest() == record['sha256'])
            event = validate_event(record['event'], order)
            kind = event['kind']
            service = order[len(completed)] if len(completed) < len(order) else None
            new_stage = stage
            if index == 0:
                require(kind == 'BEGIN' and event['plan_sha256'] == expected_plan_sha256)
                new_stage = 'READY'
            else:
                require(kind != 'BEGIN')
                if kind == 'RECREATE_INTENT':
                    require(stage == 'READY' and event['service'] == service)
                    new_stage = 'INTENT'
                elif kind == 'RECREATE_RESULT':
                    require(stage == 'INTENT' and event['service'] == service)
                    new_stage = 'ACK' if event['outcome'] == 'ACK' else 'FAILED'
                elif kind == 'APP_HEALTHY':
                    require(stage == 'ACK' and event['service'] == service)
                    new_stage = 'READY'
                elif kind == 'COMPLETE':
                    require(stage == 'READY' and completed == list(order))
                    new_stage = 'TERMINAL'
                elif kind == 'STOP':
                    require(event['healthy_services'] == completed and
                            event['claimed_services'] == list(order[:len(completed)+(stage != 'READY')]))
                    # RESULT proves callback return was recorded. A STOP which
                    # claims it was never entered contradicts that evidence.
                    require(stage not in ('ACK', 'FAILED') or
                            event['transport_entered_services'] == event['claimed_services'])
                    new_stage = 'TERMINAL'
            stage, previous = new_stage, record['sha256']
            if kind == 'APP_HEALTHY':
                completed.append(service)
            if stage == 'TERMINAL':
                result['terminal'] = kind
            result.update(valid_records=index+1, last_valid_stage=stage,
                          recorded_healthy_services=list(completed))
        except Exception:
            result.update(status='INVALID_EVENT_RECORD', invalid_record_index=index)
            return result
    result['status'] = 'VALID_TERMINAL_HISTORY' if stage == 'TERMINAL' else 'VALID_INCOMPLETE_HISTORY'
    return result


def inspect_history(path, *, expected_selinux, expected_plan_sha256, order=ORDER):
    """Linux root read-only existing history under a shared, nonblocking lock.

    Never calls Journal.locked/begin/append: those can create files. No O_CREAT,
    truncation, permission repair, relabel or fsync. Busy/unsafe/replaced/oversize
    inputs raise a fixed contract error; original bytes remain untouched.
    """
    import fcntl
    require(os.geteuid() == 0 and digest(expected_plan_sha256))
    check = Journal(path, expected_selinux=expected_selinux, order=order)
    parents, opened = [], {}
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    def signature(s):
        return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        fd = os.open('/', flags | os.O_DIRECTORY)
        parents.append((fd, None, '/'))
        check._metadata(fd, directory=True)
        for component in check.path.parts[1:]:
            child = os.open(component, flags | os.O_DIRECTORY, dir_fd=fd)
            parents.append((child, fd, component))
            check._metadata(child, directory=True)
            fd = child
        check.directory = fd
        check._metadata(fd, directory=True, final=True)
        inventory = set(os.listdir(fd))
        require(inventory <= {'writer.lock', 'run.claim', 'events.jsonl'})
        if not inventory:
            # Return only after the same directory chain was revalidated below.
            result = inspect_bytes(None, None, expected_plan_sha256=expected_plan_sha256, order=order)
        else:
            require('writer.lock' in inventory)
            lock = os.open('writer.lock', flags, dir_fd=fd)
            opened['writer.lock'] = lock
            require(check._same(lock, 'writer.lock').st_size == 0)
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            snapshots, contents = {}, {}
            for name, limit in (('run.claim', 4096), ('events.jsonl', 128*1024)):
                if name not in inventory:
                    contents[name] = None
                    continue
                filefd = os.open(name, flags, dir_fd=fd)
                opened[name] = filefd
                before = check._same(filefd, name)
                require(before.st_size <= limit)
                raw = bytearray()
                while len(raw) <= limit:
                    chunk = os.read(filefd, min(65536, limit+1-len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                require(len(raw) <= limit)
                require(signature(before) == signature(check._same(filefd, name)))
                snapshots[name] = signature(before)
                contents[name] = bytes(raw)
            result = inspect_bytes(contents['run.claim'], contents['events.jsonl'],
                                   expected_plan_sha256=expected_plan_sha256, order=order)
            for name, before in snapshots.items():
                require(before == signature(check._same(opened[name], name)))
            require(check._same(lock, 'writer.lock').st_size == 0)
        require(set(os.listdir(fd)) == inventory)
        for filefd, parentfd, name in parents:
            a = check._metadata(filefd, directory=True, final=(filefd == fd))
            if parentfd is not None:
                b = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
                require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))
        result['protected_read'] = 'VERIFIED_EXISTING_FILES'
        return result
    except Exception:
        raise ValueError('JOURNAL_HISTORY_UNAVAILABLE') from None
    finally:
        for fd in opened.values():
            os.close(fd)
        for fd, _, _ in reversed(parents):
            os.close(fd)
