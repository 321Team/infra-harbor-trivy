"""Exclusive root evidence; partial writes are retained and never resumed.

No default path, context or budget. Private payloads are never returned. A
process intent means the client MAY have run, never that Docker accepted it.
"""
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import threading
import time

from harbor_address_compose import MAX_OUTPUT, _signature, parse, protected_path, remaining, require
from harbor_address_sequence import SERVICES, fingerprint


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def context_check(fd, context):
    actual = os.getxattr(fd, 'security.selinux').rstrip(b'\0') if 'security.selinux' in os.listxattr(fd) else None
    require((context is None or (type(context) is bytes and context and b'\0' not in context)) and
            actual == context, 'EVIDENCE_CONTEXT')


def write_all(fd, raw, deadline, clock):
    while raw:
        remaining(deadline, clock)
        n = os.write(fd, raw[:65536])
        require(n > 0, 'EVIDENCE_WRITE')
        raw = raw[n:]
    os.fsync(fd)
    remaining(deadline, clock)


class Evidence:
    def __init__(self, path, *, context, plan_sha256, clock=time.monotonic):
        require(type(plan_sha256) is str and re.fullmatch('[0-9a-f]{64}', plan_sha256), 'EVIDENCE_PLAN')
        self.path, self.context, self.plan_sha, self.clock = path, context, plan_sha256, clock
        self.pid, self.mutex = os.getpid(), threading.Lock()
        self.save_mutex = threading.Lock()
        self.used = self.failed = self.held = False
        self.directory = None
        self.deadline = None
        self.inventory = {}
        self.previous, self.sequence, self.records = '0'*64, 0, []

    def _same(self, name, fd):
        a, b = os.fstat(fd), os.stat(name, dir_fd=self.directory, follow_symlinks=False)
        require(stat.S_ISREG(a.st_mode) and a.st_uid == a.st_gid == 0 and
                stat.S_IMODE(a.st_mode) == 0o600 and a.st_nlink == 1 and
                (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and
                set(os.listxattr(fd)) <= {'security.selinux'}, 'EVIDENCE_FILE')
        context_check(fd, self.context)
        return _signature(a)

    def _owned(self):
        require(self.held and not self.failed and os.getpid() == self.pid, 'EVIDENCE_SPENT')
        with protected_path(self.path, directory=True, exact_mode=0o700) as current:
            require((os.fstat(current).st_dev, os.fstat(current).st_ino) ==
                    (os.fstat(self.directory).st_dev, os.fstat(self.directory).st_ino), 'EVIDENCE_PATH_CHANGED')
        require(set(os.listdir(self.directory)) == set(self.inventory), 'EVIDENCE_INVENTORY_CHANGED')
        context_check(self.directory, self.context)
        for name, signature in self.inventory.items():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.directory)
            try:
                require(self._same(name, fd) == signature, 'EVIDENCE_CHANGED')
            finally:
                os.close(fd)

    def _new(self, name, raw, deadline):
        remaining(deadline, self.clock)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.directory)
        try:
            self._same(name, fd)
            write_all(fd, raw, deadline, self.clock)
            self.inventory[name] = self._same(name, fd)
        finally:
            os.close(fd)
        os.fsync(self.directory)
        remaining(deadline, self.clock)

    @contextmanager
    def locked(self, deadline):
        require(self.mutex.acquire(blocking=False), 'EVIDENCE_BUSY')
        try:
            require(not self.used and os.getpid() == self.pid, 'EVIDENCE_SPENT')
            self.used = True
            self.deadline = deadline
            with protected_path(self.path, directory=True, exact_mode=0o700) as directory:
                self.directory = directory
                context_check(directory, self.context)
                require(os.listdir(directory) == [], 'EVIDENCE_EXISTING')
                # O_EXCL claim excludes a second instance, including one that
                # inspected an empty directory before this instance claimed it.
                self._new('evidence.claim', encode(dict(schema='fds.harbor.address-evidence.v1',
                          plan_sha256=self.plan_sha)), deadline)
                self.held = True
                yield self
                self._owned()
                self._new('evidence.closed', encode(dict(plan_sha256=self.plan_sha, records=self.sequence,
                          last_sha256=self.previous)), deadline)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.held = False
            self.directory = None
            self.mutex.release()

    def save(self, *, kind, operation=None, service=None, payloads=None, diagnostic=None, deadline):
        """Metadata is fixed-schema; all arbitrary bytes go into private files."""
        require(self.save_mutex.acquire(blocking=False), 'EVIDENCE_BUSY')
        try:
            self._owned()
            remaining(deadline, self.clock)
            require(kind in ('CALL_INTENT', 'PROCESS_INTENT', 'PROCESS_RESULT', 'CALL_END',
                             'INVENTORY', 'INSPECT', 'COLLECTION_END', 'READ_FAILED', 'SEQUENCE_RESULT'), 'EVIDENCE_KIND')
            require(operation in (None, 'render', 'recreate') and service in (None, *SERVICES), 'EVIDENCE_SCOPE')
            require(type(payloads) is dict and set(payloads) <= {'stdout', 'stderr', 'private'} and
                    all(type(v) is bytes and len(v) <= MAX_OUTPUT for v in payloads.values()), 'EVIDENCE_PAYLOAD')
            require(type(diagnostic) is dict and set(diagnostic) <= {'rc', 'reason', 'stdin_sha256', 'binary_sha256', 'id'},
                    'EVIDENCE_DIAGNOSTIC')
            for k, v in diagnostic.items():
                if k == 'rc': require(v is None or type(v) is int, 'EVIDENCE_RC')
                elif k == 'reason': require(type(v) is str and re.fullmatch('[A-Z_]{1,80}', v), 'EVIDENCE_REASON')
                else: require(type(v) is str and re.fullmatch('[0-9a-f]{64}', v), 'EVIDENCE_DIGEST')
            prefix = f'{self.sequence:06d}'
            files = {}
            for name, raw in sorted(payloads.items()):
                filename = prefix+'.'+name+'.bin'
                self._new(filename, raw, deadline)
                files[name] = dict(file=filename, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            record = dict(sequence=self.sequence, previous_sha256=self.previous, plan_sha256=self.plan_sha,
                          kind=kind, operation=operation, service=service, diagnostic=diagnostic,
                          files=files, monotonic=self.clock())
            record['sha256'] = fingerprint(record)
            self._new(prefix+'.record.json', encode(record), deadline)
            self.previous, self.sequence = record['sha256'], self.sequence+1
            self.records.append(record)
            return json.loads(encode(record))
        except BaseException:
            self.failed = True
            raise
        finally:
            self.save_mutex.release()


class AuditedCompose:
    """Durable operation records around a PinnedCompose, with no retry."""
    def __init__(self, process, evidence, *, clock=time.monotonic):
        require(process.audit is None, 'COMPOSE_AUDIT_ALREADY_BOUND')
        self.process, self.evidence, self.clock = process, evidence, clock
        self.pid, self.busy, self.failed = os.getpid(), threading.Lock(), False
        process.audit = self._process_event

    def _process_event(self, kind, operation, service, diagnostic, payloads, deadline):
        self.evidence.save(kind=kind, operation=operation, service=service,
                           diagnostic=diagnostic, payloads=payloads,
                           deadline=self.evidence.deadline if kind == 'PROCESS_RESULT' else deadline)

    def call(self, operation, model, *, deadline, service=None):
        require(self.busy.acquire(blocking=False), 'COMPOSE_AUDIT_BUSY')
        try:
            require(not self.failed and os.getpid() == self.pid, 'COMPOSE_AUDIT_SPENT')
            self.evidence.save(kind='CALL_INTENT', operation=operation, service=service,
                               diagnostic={}, payloads={}, deadline=deadline)
            try:
                rc = self.process.call(operation, model, deadline=deadline, service=service)
            except BaseException:
                # If the deadline or disk has failed, do not manufacture an END
                # record or retry writing. Existing intent is conservatively open.
                if not self.evidence.failed and self.clock() < self.evidence.deadline:
                    self.evidence.save(kind='CALL_END', operation=operation, service=service,
                                       diagnostic={'reason': 'CALL_FAILED'}, payloads={}, deadline=self.evidence.deadline)
                raise
            self.evidence.save(kind='CALL_END', operation=operation, service=service,
                               diagnostic={'rc': rc, 'reason': 'CALL_RETURNED'}, payloads={}, deadline=self.evidence.deadline)
            return rc
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy.release()


def collect_partial(engine, evidence, *, baseline_ids, deadline, clock=time.monotonic):
    """Bounded READ ONLY handoff, including old IDs and current/duplicate rows.

    Caller supplies a separate authorized collection deadline, never extends the
    mutation deadline. Missing old IDs are failures in evidence, not empty data.
    """
    require(type(baseline_ids) is dict and set(baseline_ids) == set(SERVICES) and
            all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in baseline_ids.values()), 'COLLECT_BASELINE')
    inspected, failures = [], 0
    first_ids = None
    def inventory():
        rows = engine.inventory(deadline)
        require(type(rows) is list, 'COLLECT_INVENTORY')
        scoped = [r for r in rows if type(r) is dict and type(r.get('Labels')) is dict and
                  r['Labels'].get('com.docker.compose.project') == 'harbor']
        require(len(scoped) <= 32 and all(type(r.get('Id')) is str and re.fullmatch('[0-9a-f]{64}',r['Id'])
                                        for r in scoped), 'COLLECT_LIMIT')
        evidence.save(kind='INVENTORY', payloads={'private':encode(scoped)}, diagnostic={}, deadline=deadline)
        return {r['Id'] for r in scoped}
    try:
        first_ids = inventory()
    except Exception:
        failures += 1
        if evidence.failed or clock() >= deadline: return dict(complete=False, failures=failures, inspected=inspected)
        evidence.save(kind='READ_FAILED', payloads={}, diagnostic={'reason':'INVENTORY_FAILED'}, deadline=deadline)
    for cid in sorted(set(baseline_ids.values()) | (first_ids or set())):
        if clock() >= deadline: return dict(complete=False, failures=failures, inspected=inspected)
        try:
            row = engine.inspect(cid, deadline)
            require(type(row) is dict and row.get('Id') == cid, 'COLLECT_ID')
            evidence.save(kind='INSPECT', payloads={'private':encode(row)}, diagnostic={'id':cid}, deadline=deadline)
            inspected.append(cid)
        except Exception:
            failures += 1
            if evidence.failed or clock() >= deadline: return dict(complete=False, failures=failures, inspected=inspected)
            evidence.save(kind='READ_FAILED', payloads={}, diagnostic={'id':cid,'reason':'INSPECT_FAILED'}, deadline=deadline)
    try:
        final_ids = inventory()
    except Exception:
        failures += 1; final_ids = None
    complete = not failures and first_ids == final_ids
    if not evidence.failed and clock() < deadline:
        evidence.save(kind='COLLECTION_END', payloads={}, diagnostic={'reason':'READ_COMPLETE' if complete else 'READ_INCOMPLETE'}, deadline=deadline)
    return dict(complete=complete, failures=failures, inspected=inspected)


def inspect_evidence(path, *, context, plan_sha256, deadline, clock=time.monotonic):
    """Read-only verification. Missing close/torn files never prove no up call.

    Payloads are hashed as streams and never returned, even on validation error.
    This identifies this audited client only, not other actors or Docker state.
    """
    result = dict(valid=False, sealed=False, may_resume=False, runtime_outcome='NOT_INFERRED',
                  up_process_intents=[], this_client_up='UNKNOWN', reason='EVIDENCE_UNAVAILABLE')
    try:
        require(type(plan_sha256) is str and re.fullmatch('[0-9a-f]{64}', plan_sha256), 'EVIDENCE_PLAN')
        with protected_path(path, directory=True, exact_mode=0o700) as directory:
            context_check(directory, context)
            names = set(os.listdir(directory)); require(1 <= len(names) <= 2048, 'EVIDENCE_COUNT')
            require('evidence.claim' in names, 'EVIDENCE_NO_CLAIM')
            signatures, observed = {}, set()
            def read(name, *, private=False):
                require(name in names and re.fullmatch(r'(evidence\.(claim|closed)|[0-9]{6}\.(record\.json|(private|stdout|stderr)\.bin))',name), 'EVIDENCE_NAME')
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                try:
                    s = os.fstat(fd)
                    require(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and
                            stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and
                            s.st_size <= (MAX_OUTPUT if private else 16384) and
                            set(os.listxattr(fd)) <= {'security.selinux'}, 'EVIDENCE_FILE')
                    context_check(fd, context)
                    hashed, raw, size = hashlib.sha256(), bytearray(), 0
                    while True:
                        remaining(deadline, clock)
                        block = os.read(fd, 65536)
                        if not block: break
                        hashed.update(block); size += len(block)
                        require(size <= (MAX_OUTPUT if private else 16384), 'EVIDENCE_SIZE')
                        if not private: raw.extend(block)
                    require(_signature(s) == _signature(os.fstat(fd)) and size == s.st_size, 'EVIDENCE_CHANGED')
                    signatures[name] = _signature(s); observed.add(name)
                    return (hashed.hexdigest(), size) if private else parse(bytes(raw))
                finally: os.close(fd)
            claim = read('evidence.claim')
            require(claim == dict(schema='fds.harbor.address-evidence.v1',plan_sha256=plan_sha256), 'EVIDENCE_PLAN')
            record_names = sorted(n for n in names if n.endswith('.record.json'))
            require(len(record_names) <= 400, 'EVIDENCE_RECORD_LIMIT')
            previous, up, active = '0'*64, [], None
            for index, name in enumerate(record_names):
                require(name == f'{index:06d}.record.json', 'EVIDENCE_RECORD_SEQUENCE')
                record = read(name)
                require(type(record) is dict and set(record) == {'sequence','previous_sha256','plan_sha256',
                        'kind','operation','service','diagnostic','files','monotonic','sha256'}, 'EVIDENCE_SCHEMA')
                supplied = record.pop('sha256')
                require(record['sequence']==index and record['previous_sha256']==previous and
                        record['plan_sha256']==plan_sha256 and fingerprint(record)==supplied, 'EVIDENCE_CHAIN')
                previous=supplied
                require(type(record['files']) is dict and set(record['files']) <= {'stdout','stderr','private'}, 'EVIDENCE_PAYLOAD')
                for key, value in record['files'].items():
                    require(type(value) is dict and set(value)=={'file','size','sha256'} and
                            value['file']==f'{index:06d}.{key}.bin', 'EVIDENCE_PAYLOAD')
                    digest,size=read(value['file'],private=True)
                    require(digest==value['sha256'] and size==value['size'], 'EVIDENCE_PAYLOAD_CHANGED')
                kind, operation, service = record['kind'], record['operation'], record['service']
                require(operation in (None,'render','recreate') and service in (None,*SERVICES), 'EVIDENCE_SCOPE')
                if kind == 'CALL_INTENT':
                    require(active is None and operation in ('render','recreate') and
                            ((operation=='render' and service is None) or (operation=='recreate' and service in SERVICES[:-1])), 'EVIDENCE_CALL_ORDER')
                    active=[operation,service,'CALL']
                elif kind == 'PROCESS_INTENT':
                    require(active == [operation,service,'CALL'], 'EVIDENCE_PROCESS_ORDER')
                    active[-1]='PROCESS'
                    if operation=='recreate': up.append(service)
                elif kind == 'PROCESS_RESULT':
                    require(active == [operation,service,'PROCESS'], 'EVIDENCE_PROCESS_ORDER')
                    active[-1]='RESULT'
                elif kind == 'CALL_END':
                    require(active is not None and active[:2]==[operation,service], 'EVIDENCE_CALL_ORDER')
                    active=None
                else:
                    require(kind in ('INVENTORY','INSPECT','COLLECTION_END','READ_FAILED','SEQUENCE_RESULT') and
                            operation is None, 'EVIDENCE_KIND')
            sealed='evidence.closed' in names
            if sealed:
                require(read('evidence.closed') == dict(plan_sha256=plan_sha256,records=len(record_names),
                        last_sha256=previous), 'EVIDENCE_CLOSE')
            require(observed==names and set(os.listdir(directory))==names, 'EVIDENCE_UNREFERENCED_FILES')
            for name, signature in signatures.items():
                require(_signature(os.stat(name,dir_fd=directory,follow_symlinks=False))==signature, 'EVIDENCE_CHANGED')
            remaining(deadline, clock)
            verified=dict(valid=True,sealed=sealed,up_process_intents=up,
                          this_client_up=('MAY_HAVE_RUN' if up else ('NOT_INVOKED' if sealed else 'UNKNOWN')),
                          reason='SEALED' if sealed else 'INCOMPLETE')
        result.update(verified)  # path-context exit must also succeed
    except Exception:
        pass
    return result
