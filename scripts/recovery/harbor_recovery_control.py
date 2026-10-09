"""Explicit same-generation HOLD reconciliation and graceful reverse stop.

No implicit retry, unit change, force kill, rollback or new approval enrollment.
Unknown stop outcomes retain unmatched claims and block further control writes.
"""
from copy import deepcopy
import hashlib
import json
import os
import re
import time

from harbor_recovery_core import ORDER
from harbor_recovery_docker import UnixEngine, remaining, require, parse_json
from harbor_recovery_store import encode, MAX_BYTES
from harbor_recovery_service import ManagerLease


def state_hash(state):
    return hashlib.sha256(encode(state)).hexdigest()


class StopEngine(UnixEngine):
    """Separate transport capability: exact approved app IDs, graceful only."""
    def __init__(self, api_version, ids, **kw):
        super().__init__(api_version, **kw)
        require(len(ids) == 9 and len(set(ids)) == 9 and
                all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in ids), 'STOP_IDS')
        self.ids = frozenset(ids)

    def _validate_request(self, method, path, body):
        match = re.fullmatch(r'/containers/([0-9a-f]{64})/stop\?signal=SIGTERM&t=-1', path)
        require(method == 'POST' and body == b'' and match and match[1] in self.ids,
                'STOP_OPERATION_FORBIDDEN')

    def stop(self, cid, deadline):
        require(cid in self.ids, 'STOP_ID')
        code, _ = self._request('POST', '/containers/'+cid+'/stop?signal=SIGTERM&t=-1', deadline)
        return 'ack' if code == 204 else 'unknown'


class StopLedger:
    def __init__(self, store): self.store = store

    def _read(self, name):
        with os.fdopen(self.store._file(name, os.O_RDONLY), 'rb') as stream:
            return parse_json(stream.read(MAX_BYTES+1))

    def quiescent(self):
        names = os.listdir(self.store.fd)
        require(not any(n.endswith('.pending') for n in names), 'CONTROL_UNCOMMITTED')
        claims = sorted(n for n in names if re.fullmatch(r'stop-claim-[0-9]{20}\.json', n))
        receipts = {n for n in names if re.fullmatch(r'stop-done-[0-9]{20}\.json', n)}
        require(len(claims) == len(receipts), 'STOP_UNRESOLVED')
        for name in claims:
            other = name.replace('stop-claim-','stop-done-')
            require(other in receipts, 'STOP_UNRESOLVED')
            claim = self._read(name); done = self._read(other)
            require(done == {'claim':claim,'result':'EXITED_READBACK'}, 'STOP_RECEIPT_MISMATCH')

    def claim(self, value):
        self.store._new(f'stop-claim-{value["token"]:020}.json',
                        (json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode())

    def done(self, value):
        self.store._new(f'stop-done-{value["token"]:020}.json',
                        (json.dumps({'claim':value,'result':'EXITED_READBACK'},sort_keys=True)+'\n').encode())


class OperatorControl:
    def __init__(self, executor, manager, stop_engine, *, ledger=None, lease=None, clock=time.monotonic):
        self.executor, self.store, self.core = executor, executor.store, executor.core
        self.backend, self.manager, self.stop_engine = executor.backend, manager, stop_engine
        self.ledger = StopLedger(self.store) if ledger is None else ledger
        self.lease = (lambda: ManagerLease(self.store)) if lease is None else lease
        self.clock = clock

    def inspect_state(self):
        # No Executor.open(): this must not rewrite pending/health-wait state.
        with self.store.locked():
            state = self.store.load()
            return {'state_sha256':state_hash(state),'desired':state.desired,'reason':state.reason,
                    'pending_start':state.pending is not None,'health_wait':state.health_wait is not None}

    def _state(self, pin):
        require(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin), 'CONTROL_STATE_PIN')
        state = self.store.load()
        require(state_hash(state) == pin, 'CONTROL_STATE_CHANGED')
        require(state.plan_digest == self.core.plan_digest(), 'CONTROL_PLAN_CHANGED')
        require(self.executor.gate is not None, 'CONTROL_INSTALLATION_GATE_REQUIRED')
        self.executor.gate()
        self.ledger.quiescent()
        return state

    def _observe(self, state, deadline, stopped=()):
        item = self.backend.observe(deadline)
        self.manager(deadline)  # host/tool pins were verified by backend first
        now = self.clock(); remaining(deadline,self.clock)
        require(self.core.problem(item,now) is None and state.last_now is not None and now >= state.last_now and
                (item.boot,item.daemon) == (state.boot,state.daemon), 'CONTROL_GENERATION_OR_GUARD')
        require(item.logger_tcp and item.containers['log'].status == 'running' and
                item.containers['log'].health == 'healthy', 'CONTROL_LOGGER')
        for name in ORDER:
            row = item.containers[name]
            require(row.status == 'exited' if name in stopped else
                    row.status == 'running' and row.health == 'healthy', 'CONTROL_APP_STATE')
        return item

    def reconcile(self, pin, deadline, *, explicit=False):
        require(explicit is True, 'CONTROL_EXPLICIT_REQUIRED')
        with self.lease(), self.store.locked():
            state = self._state(pin)
            require(state.desired == 'HOLD', 'CONTROL_NOT_HOLD')
            self._observe(state,deadline)
            result = deepcopy(state)
            # An observed settled state, never a fabricated ACK of the old POST.
            result.desired, result.reason = 'RUN', 'EXPLICIT_HEALTHY_RECONCILIATION'
            result.pending = result.health_wait = result.episode_since = result.logger_since = None
            result.last_now = self.clock()
            result.seen_healthy.update(ORDER)
            self.store.audit('healthy-reconcile-request',state)
            self.store.save(result)
            return result

    def stop(self, pin, deadline, *, per_container_seconds, explicit=False):
        require(explicit is True, 'CONTROL_EXPLICIT_REQUIRED')
        require(type(per_container_seconds) in (int,float) and 0 < per_container_seconds <= 600,
                'CONTROL_STOP_BUDGET')
        with self.lease(), self.store.locked():
            state = self._state(pin)
            require(state.pending is None and state.health_wait is None and state.episode_since is None,
                    'STOP_START_NOT_QUIESCENT')
            self._observe(state,deadline)
            self.store.audit('graceful-stop-request',state)
            state = self.core.hold(state,'OPERATOR_STOP').state
            self.store.save(state)  # manager HOLD before the first stop intent
            stopped = []
            for name in reversed(ORDER):
                end = min(deadline,self.clock()+per_container_seconds)
                try:
                    self._observe(state,end,stopped)
                    claim = {'version':1,'plan':state.plan_digest,'boot':state.boot,'daemon':state.daemon,
                             'token':state.next_token,'service':name,'id':self.core.plan.ids[name]}
                    state.next_token += 1
                    state.reason, state.last_now = 'STOP_INTENT', self.clock()
                    self.store.save(state)
                    self.ledger.claim(claim)
                    self._observe(state,end,stopped)
                    remaining(end,self.clock)
                    outcome = self.stop_engine.stop(claim['id'],end)
                    require(outcome == 'ack','STOP_OUTCOME_UNKNOWN')
                    self._observe(state,end,[*stopped,name])
                    self.ledger.done(claim)
                except Exception:
                    state.reason = 'STOP_INTERRUPTED_OR_UNKNOWN'
                    self.store.save(state)
                    return state
                stopped.append(name)
            state.reason, state.last_now = 'APPS_STOPPED_LOGGER_PRESERVED', self.clock()
            self.store.save(state)
            return state
