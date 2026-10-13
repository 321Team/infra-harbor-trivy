"""Explicit same-generation recovery after a completely acknowledged H6 stop.

This is a separately reviewed operator helper, not part of the resident bundle.
The trusted caller verifies this file and the installed bootstrap/bundle, builds
the installed components, and uses their service writer context. No CLI, bundle
replacement, state editing, automatic retry, unit change, or reconciliation.
"""
from copy import deepcopy
import hashlib
import json
import math
import os
import re
import stat
import time

from harbor_recovery_control import state_hash
from harbor_recovery_core import ORDER
from harbor_recovery_docker import require
from harbor_recovery_protected_store import ProtectedStore


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def completed_stop(control, pin):
    """Caller holds manager lease/controller lock. Reads only, including gate."""
    state = control._state(pin)
    require(state.desired == 'HOLD' and state.reason == 'APPS_STOPPED_LOGGER_PRESERVED',
            'RECOVERY_NOT_COMPLETED_STOP')
    require(state.pending is None and state.health_wait is None and
            state.episode_since is None and state.logger_since is None,
            'RECOVERY_UNSETTLED_STATE')
    records = control.ledger._records()
    last = state.next_token - 1
    require(last >= len(ORDER) and max(records['claim'], default=0) == last,
            'RECOVERY_STOP_TAIL')
    proof = []
    for index, service in enumerate(reversed(ORDER)):
        token = last-len(ORDER)+1+index
        expected = dict(version=1, plan=state.plan_digest, boot=state.boot,
                        daemon=state.daemon, token=token, service=service,
                        id=control.core.plan.ids[service])
        require(token in records['claim'] and
                type(records['claim'][token][0].get('version')) is int and
                type(records['claim'][token][0].get('token')) is int,
                'RECOVERY_STOP_RECORD_TYPES')
        for kind in ('claim', 'ack', 'done'):
            require(token in records[kind], 'RECOVERY_STOP_RECORD_MISSING')
            value, raw = records[kind][token]
            target = expected if kind == 'claim' else dict(
                claim=expected, result='HTTP_204' if kind == 'ack' else 'EXITED_READBACK')
            require(value == target, 'RECOVERY_STOP_RECORD_MISMATCH')
            proof.append(dict(kind=kind, token=token,
                              sha256=hashlib.sha256(raw).hexdigest()))
    return state, digest(proof)


class ReceiptDirectory:
    """Pre-created, exact-label sibling only; deterministic O_EXCL attempt pin.

    No files are added to the resident Store's closed record namespace. Failed
    or partial attempts remain in this fixed sibling, never a caller-selected
    fresh directory. No chmod, chcon, unlink, mkdir or record overwrite.
    """
    def __init__(self, store):
        self.guard = ProtectedStore(str(store.path)+'.stopped-recovery',
                                    store.directory_context, store.file_context,
                                    writer_context=store.writer_context,
                                    uid=store.uid, gid=store.gid)
        self.fd = None

    def __enter__(self):
        self.fd = self.guard._directory()
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def create(self, pin, name, value):
        require(re.fullmatch('[0-9a-f]{64}', pin) is not None and
                re.fullmatch(r'(?:attempt|complete|(?:intent|ack|healthy)-[0-8])', name) is not None,
                'RECOVERY_RECEIPT_NAME')
        require(self.fd is not None, 'RECOVERY_RECEIPT_DIRECTORY')
        raw = (json.dumps(value, sort_keys=True, allow_nan=False)+'\n').encode()
        require(len(raw) <= 1048576, 'RECOVERY_RECEIPT_SIZE')
        self.guard._writer()
        fd = os.open(pin+'-'+name+'.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        try:
            row = os.fstat(fd)
            require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and
                    row.st_uid == self.guard.uid and row.st_gid == self.guard.gid and
                    stat.S_IMODE(row.st_mode) == 0o600, 'RECOVERY_RECEIPT_METADATA')
            self.guard._attrs(fd, self.guard.file_context)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                require(count > 0, 'RECOVERY_RECEIPT_WRITE')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)


class StoppedRecovery:
    """Start exactly nine exited, proven-stopped IDs; retain the original HOLD.

    Both bounds and metadata are from the installed Plan. The external deadline
    can only shorten its episode limit. No implicit continuation on failure.
    All earlier healthy and later exited apps are checked before every POST and
    throughout health polling. Engine outcomes other than a real 204 are unknown.
    """
    def __init__(self, control, *, receipts=None, clock=time.monotonic, sleep=time.sleep):
        self.control = control
        self.store, self.core = control.store, control.core
        self.backend = control.backend
        self.clock, self.sleep = clock, sleep
        self.last_clock = None
        self.receipts = receipts or (lambda: ReceiptDirectory(self.store))

    def _time(self, deadline):
        now = self.clock()
        require(type(now) in (int, float) and math.isfinite(now) and
                (self.last_clock is None or now >= self.last_clock), 'RECOVERY_CLOCK')
        self.last_clock = now
        require(now < deadline, 'RECOVERY_DEADLINE')

    def inspect(self, pin, deadline):
        """Completed-stop readiness only; no receipts/POST/state rewrite."""
        require(type(deadline) in (int, float) and math.isfinite(deadline), 'RECOVERY_DEADLINE')
        self._time(deadline)
        with self.control.lease(), self.store.locked():
            state, proof = completed_stop(self.control, pin)
            self._observe(pin, proof, state, (), deadline)
            return dict(stage='COMPLETED_STOP_VERIFIED', state_sha256=pin,
                        stop_set_sha256=proof, engine_post='NONE', state_write='NONE')

    def _observe(self, pin, stop_pin, state, completed, deadline, current=None):
        self._time(deadline)
        again, proof = completed_stop(self.control, pin)
        require(again == state and proof == stop_pin, 'RECOVERY_INPUT_CHANGED')
        item = self.backend.observe(deadline)
        self.control.manager(deadline)
        now = self.clock()
        self._time(deadline)
        require(self.core.problem(item, now) is None and state.last_now is not None and
                now >= state.last_now and (item.boot, item.daemon) == (state.boot, state.daemon),
                'RECOVERY_GENERATION_OR_GUARD')
        logger = item.containers['log']
        require(item.logger_tcp and logger.status == 'running' and logger.health == 'healthy',
                'RECOVERY_LOGGER')
        for name in ORDER:
            row = item.containers[name]
            if name in completed:
                require(row.status == 'running' and row.health == 'healthy', 'RECOVERY_PREFIX_CHANGED')
            elif name == current:
                require(row.status == 'running' and row.health in ('starting', 'healthy'),
                        'RECOVERY_STARTED_APP_FAILED')
            else:
                require(row.status == 'exited', 'RECOVERY_UNEXPECTED_APP_STATE')
        return item

    def run(self, pin, stop_pin, deadline, *, explicit=False):
        require(explicit is True, 'RECOVERY_EXPLICIT_REQUIRED')
        require(isinstance(stop_pin, str) and re.fullmatch('[0-9a-f]{64}', stop_pin),
                'RECOVERY_STOP_PIN')
        require(type(deadline) in (int, float) and math.isfinite(deadline), 'RECOVERY_DEADLINE')
        end = min(deadline, self.clock()+self.core.plan.episode_seconds)
        self._time(end)
        with self.control.lease(), self.store.locked():
            state, proof = completed_stop(self.control, pin)
            require(proof == stop_pin, 'RECOVERY_STOP_CHANGED')
            self._observe(pin, stop_pin, state, (), end)
            with self.receipts() as journal:
                # Deterministic state pin prevents a second attempt, including a
                # different nonce or a client timeout after the first POST.
                journal.create(pin, 'attempt', dict(schema='fds.harbor.stopped-recovery.v1',
                    state_sha256=pin, stop_set_sha256=stop_pin, boot=state.boot, daemon=state.daemon,
                    plan=state.plan_digest, ids=deepcopy(self.core.plan.ids),
                    start_seconds=self.core.plan.start_seconds,
                    health_seconds=self.core.plan.health_seconds,
                    episode_seconds=self.core.plan.episode_seconds))
                completed = []
                for index, name in enumerate(ORDER):
                    start_end = min(end, self.clock()+self.core.plan.start_seconds)
                    self._observe(pin, stop_pin, state, completed, start_end)
                    intent = dict(service=name, id=self.core.plan.ids[name],
                                  state_sha256=pin, stop_set_sha256=stop_pin,
                                  boot=state.boot, daemon=state.daemon)
                    journal.create(pin, 'intent-'+str(index), intent)
                    self._observe(pin, stop_pin, state, completed, start_end)
                    self._time(start_end)
                    outcome = self.backend.engine.start(intent['id'], start_end)
                    require(outcome == 'ok', 'RECOVERY_START_UNKNOWN')
                    # A late but actually received 204 remains a known fact.
                    # Persist it before deadline/readback checks, as H6 stop
                    # does. This never authorizes another POST or auto-resume.
                    journal.create(pin, 'ack-'+str(index), dict(intent=intent, result='HTTP_204'))
                    self._time(start_end)
                    health_end = min(end, self.clock()+self.core.plan.health_seconds[name])
                    while True:
                        item = self._observe(pin, stop_pin, state, completed, health_end, current=name)
                        if item.containers[name].health == 'healthy':
                            break
                        self.sleep(min(self.core.plan.retry_interval_seconds,
                                       max(0, health_end-self.clock())))
                    journal.create(pin, 'healthy-'+str(index), dict(intent=intent, result='HEALTHY_READBACK'))
                    completed.append(name)
                self._observe(pin, stop_pin, state, completed, end)
                require(state_hash(self.store.load()) == pin, 'RECOVERY_HOLD_CHANGED')
                result = dict(stage='APPS_RECOVERED_HOLD_PRESERVED', services=completed,
                              state_sha256=pin, stop_set_sha256=stop_pin,
                              manager='NOT_STARTED', reconciliation='NOT_PERFORMED')
                journal.create(pin, 'complete', result)
                self._time(end)
                return result
