"""Durable, explicit policy-only installation/rollback transaction.

No CLI, unit installation/enable/start, state reset or automatic resume. Store
must already be prepared and initialized in HOLD by a reviewed installer. A
deployment still needs approved input loading and full ACL/xattr verification.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass
import json
import os
import re
import time
import uuid

from harbor_recovery_core import ORDER, Plan, State
from harbor_recovery_docker import digest, parse_json, remaining, require
from harbor_recovery_store import MAX_BYTES

NAMES = (*ORDER, 'log')
ORIGINAL = {'Name': 'always', 'MaximumRetryCount': 0}
TARGET = {'Name': 'no', 'MaximumRetryCount': 0}


@dataclass(frozen=True)
class TransitionPlan:
    recovery: Plan
    host_binding: str
    manager_binding: str

    def __post_init__(self):
        require(isinstance(self.recovery, Plan) and self.recovery.execution_binding,
                'TRANSITION_RECOVERY_PLAN')
        require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                    for v in (self.host_binding, self.manager_binding)), 'TRANSITION_BINDING')
        object.__setattr__(self, 'recovery', deepcopy(self.recovery))

    @property
    def binding(self):
        return digest({'transition_version': 1, 'plan': asdict(self),
                       'original': ORIGINAL, 'target': TARGET})


@dataclass(frozen=True)
class PolicyObservation:
    boot: str
    daemon: str
    at: float
    host_binding: str
    manager_binding: str
    ids: dict
    fingerprints: dict
    policies: dict
    healthy: bool  # all ten healthy/running; logger TCP ready


def observation(plan, item, expected, now):
    require(isinstance(item, PolicyObservation) and
            isinstance(item.boot, str) and str(uuid.UUID(item.boot)) == item.boot and
            isinstance(item.daemon, str) and re.fullmatch('[0-9a-f]{32}', item.daemon) and
            item.daemon != '0' * 32,
            'TRANSITION_OBSERVATION')
    require(type(item.at) in (int, float) and 0 <= now - item.at <= plan.recovery.max_age_seconds,
            'TRANSITION_STALE')
    require(item.host_binding == plan.host_binding and item.manager_binding == plan.manager_binding and
            item.ids == plan.recovery.ids and item.fingerprints == plan.recovery.fingerprints and
            item.policies == expected and item.healthy is True, 'TRANSITION_GUARD')
    require(all(type(v.get('MaximumRetryCount')) is int for v in item.policies.values()),
            'TRANSITION_POLICY_TYPE')


def original_policies():
    return {name: deepcopy(ORIGINAL) for name in NAMES}


def policies(record):
    result = deepcopy(record['original'])
    for name in record['changed']:
        if name not in record['restored']:
            result[name] = deepcopy(TARGET)
    return result


def validate(record, plan):
    keys = {'version', 'plan', 'boot', 'daemon', 'original', 'phase', 'reason',
            'changed', 'restored', 'next_token', 'pending'}
    require(isinstance(record, dict) and set(record) == keys and type(record['version']) is int and
            record['version'] == 1 and record['plan'] == plan.binding, 'TRANSITION_RECORD_BINDING')
    require(isinstance(record['boot'], str) and str(uuid.UUID(record['boot'])) == record['boot'] and
            isinstance(record['daemon'], str) and re.fullmatch('[0-9a-f]{32}', record['daemon']) and
            record['daemon'] != '0' * 32,
            'TRANSITION_RECORD_GENERATION')
    require(record['original'] == original_policies(), 'TRANSITION_ORIGINAL')
    # Enforce exact policy types, not Python's bool/int equality.
    require(all(type(v.get('MaximumRetryCount')) is int for v in record['original'].values()),
            'TRANSITION_POLICY_TYPE')
    require(record['phase'] in ('INSTALLING', 'INSTALLED_HOLD', 'ROLLING_BACK', 'ROLLED_BACK', 'HOLD') and
            isinstance(record['reason'], str) and re.fullmatch('[A-Z_]{1,64}', record['reason']),
            'TRANSITION_RECORD_PHASE')
    require(isinstance(record['changed'], list) and
            record['changed'] == list(ORDER[:len(record['changed'])]) and len(record['changed']) <= 9,
            'TRANSITION_CHANGE_ORDER')
    require(isinstance(record['restored'], list) and
            record['restored'] == list(reversed(record['changed']))[:len(record['restored'])] and
            len(record['restored']) <= len(record['changed']), 'TRANSITION_RESTORE_ORDER')
    require(type(record['next_token']) is int and 1 <= record['next_token'] <= 40, 'TRANSITION_TOKEN')
    require(record['next_token'] > len(record['changed']) + len(record['restored']), 'TRANSITION_TOKEN_HISTORY')
    require(record['phase'] != 'INSTALLED_HOLD' or (len(record['changed']) == 9 and not record['restored']),
            'TRANSITION_INSTALL_INCOMPLETE')
    require(record['phase'] != 'ROLLED_BACK' or len(record['changed']) == len(record['restored']),
            'TRANSITION_RESTORE_INCOMPLETE')
    require(record['phase'] != 'INSTALLING' or not record['restored'], 'TRANSITION_PHASE_ORDER')
    if record['pending'] is not None:
        action = record['pending']
        require(isinstance(action, dict) and set(action) == {'token', 'service', 'id', 'from', 'to', 'direction'},
                'TRANSITION_INTENT_SCHEMA')
        require(type(action['token']) is int and action['token'] == record['next_token'] - 1 and
                action['token'] > 0 and action['service'] in ORDER and
                action['id'] == plan.recovery.ids[action['service']], 'TRANSITION_INTENT_ID')
        require(action['direction'] in ('install', 'rollback'), 'TRANSITION_INTENT_DIRECTION')
        installing = action['direction'] == 'install'
        queue = list(ORDER[len(record['changed']):]) if installing else [
            n for n in reversed(record['changed']) if n not in record['restored']]
        require(queue and action['service'] == queue[0] and
                action['from'] == (ORIGINAL if installing else TARGET) and
                action['to'] == (TARGET if installing else ORIGINAL) and
                all(type(action[k].get('MaximumRetryCount')) is int for k in ('from', 'to')),
                'TRANSITION_INTENT_POLICY')
        require(record['phase'] in (('INSTALLING', 'HOLD') if installing else ('ROLLING_BACK', 'HOLD')),
                'TRANSITION_INTENT_PHASE')
    return record


class Journal:
    """Uses the controller Store's same lock and durable private file primitives.

    Pending temporary files are uncommitted evidence. Any such residue blocks
    transactions; it is never auto-promoted or removed. Existing journal/claims
    cannot be reinitialized, including after a successful rollback.
    """
    def __init__(self, store, plan):
        self.store, self.plan = store, plan

    def _check(self):
        require(self.store.fd is not None, 'TRANSITION_LOCK_REQUIRED')
        require(not any(name.endswith('.pending') for name in os.listdir(self.store.fd)),
                'TRANSITION_UNCOMMITTED_EVIDENCE')

    def load(self):
        self._check()
        with os.fdopen(self.store._file('policy-transition.json', os.O_RDONLY), 'rb') as stream:
            return validate(parse_json(stream.read(MAX_BYTES + 1)), self.plan)

    def _encode(self, record):
        validate(record, self.plan)
        return (json.dumps(record, sort_keys=True, allow_nan=False) + '\n').encode()

    def create(self, record):
        self._check()
        require(not any(n.startswith('policy-') for n in os.listdir(self.store.fd)), 'TRANSITION_ALREADY_EXISTS')
        self.store._new('policy-transition.json', self._encode(record))

    def save(self, record):
        self.load()
        name = 'policy-' + uuid.uuid4().hex + '.pending'
        self.store._new(name, self._encode(record))
        os.replace(name, 'policy-transition.json', src_dir_fd=self.store.fd, dst_dir_fd=self.store.fd)
        os.fsync(self.store.fd)

    def claim(self, action):
        record = self.load()
        require(action == record['pending'] and action is not None, 'TRANSITION_CLAIM_MISMATCH')
        self.store._new(f'policy-claim-{action["token"]:020}.json',
                        (json.dumps({'plan': self.plan.binding, 'boot': record['boot'],
                                     'daemon': record['daemon'], 'action': action},
                                    sort_keys=True, allow_nan=False) + '\n').encode())


class Transition:
    """Call only with disabled manager, prepared HOLD store and approved plan.

    backend.observe(deadline) must verify host+manager+all containers freshly.
    backend.update(action, expected_observation, deadline) rechecks those gates
    before its one policy-only request. Return ack/not_submitted/unknown.
    """
    def __init__(self, plan, store, backend, *, journal=None, clock=time.monotonic):
        self.plan, self.store, self.backend = deepcopy(plan), store, backend
        self.journal = journal if journal is not None else Journal(store, self.plan)
        self.clock = clock

    def _hold_state(self):
        state = self.store.load()
        require(state.desired == 'HOLD' and state.pending is None and state.health_wait is None,
                'TRANSITION_CONTROLLER_NOT_QUIESCENT')
        return state

    def _observe(self, expected, deadline, record=None):
        self._hold_state()
        remaining(deadline, self.clock)
        item = self.backend.observe(deadline)
        remaining(deadline, self.clock)
        observation(self.plan, item, expected, self.clock())
        if record:
            require((item.boot, item.daemon) == (record['boot'], record['daemon']), 'TRANSITION_GENERATION_CHANGED')
        return item

    def _hold(self, record, reason):
        record['phase'], record['reason'] = 'HOLD', reason
        self.journal.save(record)
        return record

    def install(self, deadline, *, explicit=False):
        require(explicit is True, 'TRANSITION_EXPLICIT_REQUIRED')
        with self.store.locked():
            state = self._hold_state()
            require(state == State(), 'TRANSITION_INITIAL_STORE_REQUIRED')
            item = self._observe(original_policies(), deadline)
            record = {'version': 1, 'plan': self.plan.binding, 'boot': item.boot, 'daemon': item.daemon,
                      'original': original_policies(), 'phase': 'INSTALLING', 'reason': 'PREPARED',
                      'changed': [], 'restored': [], 'next_token': 1, 'pending': None}
            self.journal.create(record)
            return self._walk(record, 'install', deadline)

    def rollback(self, deadline, *, explicit=False):
        require(explicit is True, 'TRANSITION_EXPLICIT_REQUIRED')
        with self.store.locked():
            record = self.journal.load()
            require(record['phase'] != 'ROLLED_BACK' and record['pending'] is None,
                    'TRANSITION_NO_BLIND_ROLLBACK')
            try:
                self._observe(policies(record), deadline, record)
            except Exception:
                return self._hold(record, 'ROLLBACK_PREFLIGHT_FAILED')
            record['phase'], record['reason'] = 'ROLLING_BACK', 'EXPLICIT_ROLLBACK'
            self.journal.save(record)
            return self._walk(record, 'rollback', deadline)

    def resume(self):
        # Never continue a partially executed transaction from disk automatically.
        with self.store.locked():
            record = self.journal.load()
            if record['phase'] in ('INSTALLING', 'ROLLING_BACK') or record['pending'] is not None:
                return self._hold(record, 'INTERRUPTED_TRANSACTION')
            return record

    def _walk(self, record, direction, deadline):
        queue = list(ORDER) if direction == 'install' else [
            n for n in reversed(record['changed']) if n not in record['restored']]
        for name in queue:
            try:
                item = self._observe(policies(record), deadline, record)
            except Exception:
                return self._hold(record, 'PREFLIGHT_FAILED')
            require(record['next_token'] < 40, 'TRANSITION_TOKEN_BUDGET')
            action = {'token': record['next_token'], 'service': name,
                      'id': self.plan.recovery.ids[name], 'from': deepcopy(item.policies[name]),
                      'to': deepcopy(TARGET if direction == 'install' else ORIGINAL), 'direction': direction}
            record['pending'] = action
            record['next_token'] += 1
            self.journal.save(record)  # durable intent precedes claim and request
            try:
                self.journal.claim(action)
            except FileExistsError:
                return self._hold(record, 'DUPLICATE_POLICY_CLAIM')
            remaining(deadline, self.clock)
            try:
                result = self.backend.update(deepcopy(action), item, deadline)
            except Exception:
                result = 'unknown'
            if result == 'not_submitted':
                record['pending'] = None
                return self._hold(record, 'UPDATE_NOT_SUBMITTED')
            if result != 'ack':
                return self._hold(record, 'UPDATE_UNCERTAIN')
            expected = policies(record)
            expected[name] = deepcopy(action['to'])
            try:
                self._observe(expected, deadline, record)
            except Exception:
                return self._hold(record, 'READBACK_UNCERTAIN')
            record['changed' if direction == 'install' else 'restored'].append(name)
            record['pending'], record['reason'] = None, 'POLICY_VERIFIED'
            self.journal.save(record)
        record['phase'] = 'INSTALLED_HOLD' if direction == 'install' else 'ROLLED_BACK'
        record['reason'] = 'ALL_POLICIES_VERIFIED'
        self.journal.save(record)
        return record
