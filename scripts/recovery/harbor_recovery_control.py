"""Explicit same-generation HOLD reconciliation and graceful reverse stop.

No implicit retry, unit change, force kill, rollback or new approval enrollment.
Unknown stop outcomes retain unmatched claims and block further control writes.
Received HTTP204 may be durably recorded, never inferred from later exit.
"""
from copy import deepcopy
import hashlib
import json
import math
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
    """Exact approved IDs; preserve their checked, fingerprint-bound StopSignal.

    OperatorControl checks signal suitability before any stop intent. No signal
    override or finite daemon kill timeout is available on this transport.
    """
    def __init__(self, api_version, ids, **kw):
        super().__init__(api_version, **kw)
        require(len(ids) == 9 and len(set(ids)) == 9 and
                all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in ids), 'STOP_IDS')
        self.ids = frozenset(ids)

    def _validate_request(self, method, path, body):
        match = re.fullmatch(r'/containers/([0-9a-f]{64})/stop\?t=-1', path)
        require(method == 'POST' and body == b'' and match and match[1] in self.ids,
                'STOP_OPERATION_FORBIDDEN')

    def stop(self, cid, deadline):
        require(cid in self.ids, 'STOP_ID')
        code, _ = self._request('POST', '/containers/'+cid+'/stop?t=-1', deadline)
        return 'ack' if code == 204 else 'unknown'


class StopLedger:
    def __init__(self, store): self.store = store

    def _bytes(self, name):
        with os.fdopen(self.store._file(name, os.O_RDONLY), 'rb') as stream:
            raw = stream.read(MAX_BYTES+1)
        require(len(raw) <= MAX_BYTES, 'STOP_RECORD_TOO_LARGE')
        return raw

    def _read(self, name): return parse_json(self._bytes(name))

    def _records(self):
        names = os.listdir(self.store.fd)
        require(not any(n.endswith('.pending') for n in names), 'CONTROL_UNCOMMITTED')
        records = {}
        for kind in ('claim', 'done', 'ack'):
            records[kind] = {}
            for name in names:
                match = re.fullmatch(r'stop-'+kind+r'-([0-9]{20})\.json', name)
                if match:
                    token = int(match[1]); raw = self._bytes(name)
                    require(token > 0, 'CONTROL_CLAIM_TOKEN')
                    records[kind][token] = (parse_json(raw), raw)
        claims = records['claim']
        require(set(records['done']) <= set(claims) and set(records['ack']) <= set(claims),
                'STOP_ORPHAN_RECORD')
        for kind, result in (('done', 'EXITED_READBACK'), ('ack', 'HTTP_204')):
            for token, (record, _) in records[kind].items():
                require(record == {'claim':claims[token][0], 'result':result},
                        'STOP_RECEIPT_MISMATCH')
        return records

    def quiescent(self):
        records = self._records()
        # Legacy completed claims remain valid; missing ACK never resolves an
        # unfinished legacy claim. New ACKs are validated whenever present.
        require(set(records['claim']) == set(records['done']), 'STOP_UNRESOLVED')

    def claim(self, value):
        self.store._new(f'stop-claim-{value["token"]:020}.json',
                        (json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode())

    def ack(self, value):
        self.store._new(f'stop-ack-{value["token"]:020}.json',
                        (json.dumps({'claim':value,'result':'HTTP_204'},sort_keys=True)+'\n').encode())

    def acknowledged_pending(self, state, plan, claim_pin, ack_pin):
        for pin in (claim_pin, ack_pin):
            require(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin), 'STOP_RECORD_PIN')
        records = self._records()
        claims, done, ack = (records[key] for key in ('claim', 'done', 'ack'))
        pending = set(claims) - set(done)
        require(len(pending) == 1, 'STOP_RESOLUTION_SINGLE_PENDING_REQUIRED')
        token = next(iter(pending))
        require(token == max(claims) == state.next_token-1, 'STOP_RESOLUTION_TAIL_REQUIRED')
        value, raw = claims[token]
        require(hashlib.sha256(raw).hexdigest() == claim_pin, 'STOP_CLAIM_CHANGED')
        require(token in ack, 'STOP_ACK_NOT_RECORDED')
        require(hashlib.sha256(ack[token][1]).hexdigest() == ack_pin, 'STOP_ACK_CHANGED')
        reverse = tuple(reversed(ORDER))
        require(isinstance(value,dict) and value.get('service') in reverse,
                'STOP_RESOLUTION_CLAIM')
        count = reverse.index(value['service'])+1
        prefix = reverse[:count]
        for index, service in enumerate(prefix):
            previous = token-count+1+index
            expected = {'version':1,'plan':state.plan_digest,'boot':state.boot,'daemon':state.daemon,
                        'token':previous,'service':service,'id':plan.ids[service]}
            require(previous > 0 and previous in claims and claims[previous][0] == expected and
                    type(claims[previous][0].get('version')) is int and
                    type(claims[previous][0].get('token')) is int,
                    'STOP_RESOLUTION_CLAIM')
            require(previous in ack, 'STOP_ACK_NOT_RECORDED')
            require(previous == token or previous in done, 'STOP_RESOLUTION_PREFIX')
        return value, prefix

    def max_token(self):
        highest = 0
        for name in os.listdir(self.store.fd):
            match = re.fullmatch(r'(?:intent|stop-claim)-([0-9]{20})\.json',name)
            if match:
                value = self._read(name)
                token = int(match[1])
                require(isinstance(value,dict) and type(value.get('token')) is int and
                        value['token'] == token and token > 0,'CONTROL_CLAIM_TOKEN')
                highest = max(highest,token)
        return highest

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

    def _state(self, pin, *, unfinished_stop=False):
        require(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin), 'CONTROL_STATE_PIN')
        state = self.store.load()
        require(state_hash(state) == pin, 'CONTROL_STATE_CHANGED')
        require(state.plan_digest == self.core.plan_digest(), 'CONTROL_PLAN_CHANGED')
        require(self.executor.gate is not None, 'CONTROL_INSTALLATION_GATE_REQUIRED')
        self.executor.gate()
        if not unfinished_stop: self.ledger.quiescent()
        require(state.next_token > self.ledger.max_token(),'CONTROL_TOKEN_HISTORY_REGRESSED')
        return state

    def settle_acknowledged_stop(self, pin, claim_pin, ack_pin, deadline, *, explicit=False):
        """Only record fresh readback for an already received, pinned ACK.

        No Engine POST, RUN transition, retry, policy change or record deletion.
        A missing ACK, uncertain transport, generation change or legacy pending
        claim is intentionally outside this operation.
        """
        require(explicit is True, 'CONTROL_EXPLICIT_REQUIRED')
        with self.lease(), self.store.locked():
            state = self._state(pin, unfinished_stop=True)
            require(state.desired == 'HOLD' and state.reason in ('STOP_INTERRUPTED_OR_UNKNOWN','STOP_INTENT'),
                    'STOP_RESOLUTION_NOT_INTERRUPTED_HOLD')
            require(state.pending is None and state.health_wait is None and state.episode_since is None,
                    'STOP_START_NOT_QUIESCENT')
            claim, prefix = self.ledger.acknowledged_pending(state,self.core.plan,claim_pin,ack_pin)
            self._observe(state,deadline,prefix)
            self.store.audit('stop-readback-request',state)
            # Audit can consume budget or fail. Recheck host and all target
            # states before creating the sole missing readback receipt.
            self._observe(state,deadline,prefix)
            self.ledger.done(claim)
            result = deepcopy(state)
            result.reason, result.last_now = 'ACKED_STOP_READBACK_SETTLED_HOLD', self.clock()
            self.store.save(result)
            return result

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
        require(type(per_container_seconds) in (int,float) and math.isfinite(per_container_seconds) and
                0 < per_container_seconds <= 600,
                'CONTROL_STOP_BUDGET')
        with self.lease(), self.store.locked():
            state = self._state(pin)
            require(state.pending is None and state.health_wait is None and state.episode_since is None,
                    'STOP_START_NOT_QUIESCENT')
            self._stop_observe(state,deadline)
            self.store.audit('graceful-stop-request',state)
            state = self.core.hold(state,'OPERATOR_STOP').state
            self.store.save(state)  # manager HOLD before the first stop intent
            stopped = []
            for name in reversed(ORDER):
                end = min(deadline,self.clock()+per_container_seconds)
                try:
                    self._stop_observe(state,end,stopped)
                    claim = {'version':1,'plan':state.plan_digest,'boot':state.boot,'daemon':state.daemon,
                             'token':state.next_token,'service':name,'id':self.core.plan.ids[name]}
                    state.next_token += 1
                    state.reason, state.last_now = 'STOP_INTENT', self.clock()
                    self.store.save(state)
                    self.ledger.claim(claim)
                    self._stop_observe(state,end,stopped)
                    remaining(end,self.clock)
                    outcome = self.stop_engine.stop(claim['id'],end)
                    require(outcome == 'ack','STOP_OUTCOME_UNKNOWN')
                    self.ledger.ack(claim)  # durable received fact before fragile readback
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

    def _stop_observe(self, state, deadline, stopped=()):
        item = self._observe(state, deadline, stopped)
        # QUIT is graceful for the two nginx services, but immediate shutdown
        # for PostgreSQL. Never generalize its use to the other app IDs.
        for name in ORDER:
            allowed = ('SIGQUIT', '3') if name in ('proxy', 'portal') else ('SIGTERM', '15')
            require(item.containers[name].stop_signal in allowed, 'CONTROL_STOP_SIGNAL')
        return item
