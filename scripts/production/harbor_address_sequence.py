"""One serialized production address migration, with injected trusted I/O.

Not a CLI or a deployable bundle. No default host policy, journal, Compose
transport or real execution inputs. The concrete adapter must enforce the
runbook's complete preservation/protected-input and absolute-deadline contract.
"""
from copy import deepcopy
import hashlib
import json
import math
import os
import re
import threading
import time

ORDER = ('postgresql', 'redis', 'registry', 'registryctl', 'core', 'portal',
         'jobservice', 'trivy-adapter', 'proxy')
SERVICES = (*ORDER, 'log')
OLD_ADDRESS = 'tcp://localhost:1514'
NEW_ADDRESS = 'tcp://127.0.0.1:1514'
ROW_FIELDS = {'id', 'image', 'preservation_sha256', 'logging', 'restart',
              'status', 'health', 'exit_code', 'error_sha256'}
PLAN_FIELDS = {'schema', 'binding_sha256', 'inputs_sha256', 'baseline',
               'health_seconds', 'io_seconds', 'poll_seconds', 'observation_max_age'}
STOPPED_SCHEMA = 'fds.harbor.production-address-sequence.v1'
HEALTHY_SCHEMA = 'fds.harbor.production-address-maintenance.v1'
TRANSITION_SCHEMA = 'fds.harbor.production-address-maintenance.v2'
MAINTENANCE_SCHEMAS = (HEALTHY_SCHEMA, TRANSITION_SCHEMA)
RUNTIME_REASONS = frozenset('''CLOCK_INVALID DEADLINE OBSERVATION_SCHEMA
GENERATION_OR_PROTECTION_CHANGED PROTECTED_INPUT_CHANGED OBSERVATION_STALE
LOGGER_LISTENER OBSERVATION_SERVICES ROW_SCHEMA PRESERVATION_CHANGED LOGGING_CHANGED
APP_NOT_RECREATED NEW_CONTAINER_REPLACED APP_NOT_RUNNING PRIOR_APP_UNHEALTHY
UNTOUCHED_CONTAINER_CHANGED DUPLICATE_CURRENT_ID BASE_LOGGING
RECREATE_OUTCOME_UNKNOWN RECREATE_COMMAND_FAILED RECREATE_PREPARATION_FAILED NETWORK_NOT_READY EXISTING_HISTORY'''.split())


class Stop(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Stop(reason)


def number(value):
    return type(value) in (float, int) and math.isfinite(value) and value >= 0


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def logging_candidate(value):
    require(isinstance(value, dict) and set(value) == {'Type', 'Config'} and
            value['Type'] == 'syslog' and isinstance(value['Config'], dict) and
            value['Config'].get('syslog-address') == OLD_ADDRESS and
            all(isinstance(k, str) and isinstance(v, str) for k, v in value['Config'].items()),
            'BASE_LOGGING')
    result = deepcopy(value)
    result['Config']['syslog-address'] = NEW_ADDRESS
    return result


def row_schema(row):
    require(isinstance(row, dict) and set(row) == ROW_FIELDS and digest(row['id']) and
            isinstance(row['image'], str) and row['image'].startswith('sha256:') and
            digest(row['image'][7:]) and digest(row['preservation_sha256']) and
            isinstance(row['logging'], dict) and
            row['restart'] == {'Name': 'always', 'MaximumRetryCount': 0} and
            type(row['restart'].get('MaximumRetryCount')) is int and
            row['status'] in ('exited', 'created', 'running') and
            row['health'] in ('starting', 'unhealthy', 'healthy') and
            type(row['exit_code']) is int and row['exit_code'] >= 0 and
            digest(row['error_sha256']), 'ROW_SCHEMA')


def validate_plan(plan):
    fields = PLAN_FIELDS | ({'recreate_seconds', 'db_shutdown'} if
                           isinstance(plan, dict) and plan.get('schema') == TRANSITION_SCHEMA else set())
    require(isinstance(plan, dict) and set(plan) == fields and
            plan['schema'] in (STOPPED_SCHEMA, *MAINTENANCE_SCHEMAS) and
            digest(plan['binding_sha256']) and digest(plan['inputs_sha256']), 'PLAN_SCHEMA')
    require(isinstance(plan['baseline'], dict) and set(plan['baseline']) == set(SERVICES), 'PLAN_SERVICES')
    for name, row in plan['baseline'].items():
        row_schema(row)
        if name == 'log':
            require(row['status'] == 'running' and row['health'] == 'healthy', 'BASE_LOGGER')
        else:
            if plan['schema'] in MAINTENANCE_SCHEMAS:
                require(row['status'] == 'running' and row['health'] == 'healthy' and
                        row['exit_code'] == 0 and row['error_sha256'] == hashlib.sha256(b'').hexdigest(),
                        'BASE_APP_STATE')
            else:
                require(row['status'] == 'exited' and row['health'] == 'unhealthy' and
                        row['exit_code'] == 128, 'BASE_APP_STATE')
            logging_candidate(row['logging'])
    require(len({r['id'] for r in plan['baseline'].values()}) == 10, 'PLAN_DUPLICATE_ID')
    require(isinstance(plan['health_seconds'], dict) and set(plan['health_seconds']) == set(ORDER), 'PLAN_BUDGETS')
    values = [*plan['health_seconds'].values(), plan['io_seconds'], plan['poll_seconds'], plan['observation_max_age']]
    require(all(number(v) and v > 0 for v in values) and
            plan['poll_seconds'] < min(plan['health_seconds'].values()), 'PLAN_BUDGETS')
    if plan['schema'] == TRANSITION_SCHEMA:
        require(isinstance(plan['recreate_seconds'], dict) and
                set(plan['recreate_seconds']) == set(ORDER) and
                all(number(v) and v > 0 for v in plan['recreate_seconds'].values()), 'PLAN_RECREATE_BUDGETS')
        # An explicit reviewed strategy, not a default or a signal override.
        # Smart shutdown may wait indefinitely for existing clients. A bounded
        # CLI wait never promises cancellation of an accepted Docker request.
        require(plan['db_shutdown'] == {
            'strategy': 'preserve-smart', 'effective_signal': 'SIGTERM',
            'on_timeout': 'stop-and-handoff-no-retry'}, 'PLAN_DB_SHUTDOWN')
    # Also rejects non-JSON, NaN or cyclic data without ever logging raw inputs.
    fingerprint(plan)
    return deepcopy(plan)


class Sequence:
    """Call run exactly once. A new object cannot reuse a spent journal.

    journal.locked(): nonblocking exclusive ownership through the whole run.
    journal.begin(plan_sha256): durable exclusive NEW claim, refusing any prior
      or partial history; success only after file+directory fsync.
    journal.append(event): append-only durable event; poison writer after failure.
    backend.observe(deadline_mono): fresh validated, secret-free 10-row projection.
    backend.recreate(service, expected_id, plan_sha256, deadline_mono): validate
      protected candidate + exact current ID, recreate that service once; no
      internal retries/dependency changes. Returns process rc, never proof of health.
      maintenance.v2 additionally calls on_dispatch(deadline) exactly once after
      read-only preparation, before entering the mutation-capable transport.
    """
    def __init__(self, plan, backend, journal, *, clock=time.monotonic, sleep=time.sleep):
        self._plan = validate_plan(plan)
        self._plan_sha = fingerprint(self._plan)
        self._backend, self._journal = backend, journal
        self._clock, self._sleep = clock, sleep
        self._pid, self._lock = os.getpid(), threading.Lock()
        self._used, self._owned = False, False
        self._journal_failed = False
        self._last = None
        self._completed, self._new_ids = [], {}
        self._entered, self._claimed = [], []
        self._may_have_changed = False
        self._network_pending = []
        self._maintenance = self._plan['schema'] in MAINTENANCE_SCHEMAS

    def _now(self, deadline):
        now = self._clock()
        require(number(now) and number(deadline) and
                (self._last is None or now >= self._last), 'CLOCK_INVALID')
        self._last = now
        require(now < deadline, 'DEADLINE')
        return now

    def _append(self, kind, **fields):
        # Only fixed codes, counters, service names, identities and hashes.
        try:
            self._journal.append(dict(kind=kind, **fields))
        except Exception:
            self._journal_failed = True
            raise

    def _observe(self, deadline, current=None):
        started = self._now(deadline)
        obs = self._backend.observe(min(deadline, started + self._plan['io_seconds']))
        now = self._now(min(deadline, started + self._plan['io_seconds']))
        fields={'binding_sha256', 'inputs_sha256', 'observed_mono', 'logger_ipv4', 'rows'}
        if self._plan['schema']==TRANSITION_SCHEMA:fields.add('network_pending')
        require(isinstance(obs, dict) and set(obs)==fields, 'OBSERVATION_SCHEMA')
        pending=obs.get('network_pending',[])
        require(type(pending) is list and all(type(s) is str and s in SERVICES for s in pending) and
                pending==sorted(set(pending)), 'OBSERVATION_SCHEMA')
        require(set(pending)<=({current} if current is not None else set()), 'NETWORK_NOT_READY')
        self._network_pending=pending
        require(obs['binding_sha256'] == self._plan['binding_sha256'], 'GENERATION_OR_PROTECTION_CHANGED')
        require(obs['inputs_sha256'] == self._plan['inputs_sha256'], 'PROTECTED_INPUT_CHANGED')
        require(number(obs['observed_mono']) and started <= obs['observed_mono'] <= now and
                now - obs['observed_mono'] <= self._plan['observation_max_age'], 'OBSERVATION_STALE')
        require(obs['logger_ipv4'] is True, 'LOGGER_LISTENER')
        rows = obs['rows']
        require(isinstance(rows, dict) and set(rows) == set(SERVICES), 'OBSERVATION_SERVICES')
        for service, row in rows.items():
            row_schema(row)
            old = self._plan['baseline'][service]
            changed = service in self._completed or service == current
            for key in ('image', 'preservation_sha256', 'restart'):
                require(row[key] == old[key], 'PRESERVATION_CHANGED')
            expected_logging = logging_candidate(old['logging']) if changed else old['logging']
            require(row['logging'] == expected_logging, 'LOGGING_CHANGED')
            if changed:
                require(row['id'] not in {r['id'] for r in self._plan['baseline'].values()}, 'APP_NOT_RECREATED')
                if service in self._new_ids:
                    require(row['id'] == self._new_ids[service], 'NEW_CONTAINER_REPLACED')
                else:
                    self._new_ids[service] = row['id']
                require(row['status'] == 'running', 'APP_NOT_RUNNING')
                if service in self._completed and not (self._maintenance and current is not None):
                    require(row['health'] == 'healthy', 'PRIOR_APP_UNHEALTHY')
            else:
                if self._maintenance and current is not None and service != 'log':
                    # A dependency replacement may temporarily fail an existing
                    # app's health probe. Identity/status/error and all other
                    # fields remain exact; wait for EVERY app before advancing.
                    stable = deepcopy(row)
                    stable['health'] = old['health']
                    require(stable == old, 'UNTOUCHED_CONTAINER_CHANGED')
                else:
                    require(row == old, 'UNTOUCHED_CONTAINER_CHANGED')
        require(len({r['id'] for r in rows.values()}) == 10, 'DUPLICATE_CURRENT_ID')
        return deepcopy(rows)

    def _result(self, status, reason, recorded):
        return dict(status=status, reason=reason, plan_sha256=self._plan_sha,
                    claimed_services=list(self._claimed), transport_entered_services=list(self._entered),
                    healthy_services=list(self._completed), this_invocation_may_have_changed=self._may_have_changed,
                    journal_recorded=recorded, runtime_acceptance=False, autostart_tested=False)

    def run(self, *, deadline_mono):
        require(os.getpid() == self._pid, 'FORKED_SEQUENCE')
        require(self._lock.acquire(blocking=False), 'SEQUENCE_BUSY')
        try:
            require(not self._used, 'SEQUENCE_SPENT')
            self._used = True
            try:
                self._now(deadline_mono)
                with self._journal.locked():
                    try:
                        try:
                            self._journal.begin(self._plan_sha)
                        except FileExistsError:
                            raise Stop('EXISTING_HISTORY') from None
                        self._owned = True
                        self._observe(deadline_mono)
                        for service in ORDER:
                            self._observe(deadline_mono)
                            self._append('RECREATE_INTENT', service=service,
                                         old_id=self._plan['baseline'][service]['id'])
                            self._claimed.append(service)
                            # Recheck after durable intent; failure here means no
                            # callback for this service, not an uncertain response.
                            self._observe(deadline_mono)
                            start = self._now(deadline_mono)
                            transition=self._plan['schema']==TRANSITION_SCHEMA
                            call_deadline = None if transition else min(deadline_mono,start+self._plan['io_seconds'])
                            health_deadline = (None if transition else
                                min(deadline_mono, start + self._plan['health_seconds'][service]))
                            def dispatch(deadline):
                                nonlocal call_deadline
                                require(call_deadline is None and number(deadline) and deadline<=deadline_mono,
                                        'RECREATE_OUTCOME_UNKNOWN')
                                self._now(deadline)
                                call_deadline=deadline
                                self._entered.append(service)
                                self._may_have_changed=True
                            if not transition:
                                self._entered.append(service)
                                self._may_have_changed=True
                            try:
                                kwargs=dict(service=service,
                                    expected_id=self._plan['baseline'][service]['id'],
                                    plan_sha256=self._plan_sha, deadline_mono=deadline_mono if transition else call_deadline)
                                if transition:kwargs['on_dispatch']=dispatch
                                rc = self._backend.recreate(**kwargs)
                            except Exception:
                                if transition and call_deadline is None:
                                    # Durable intent stays spent; known preparation failure never called up.
                                    raise Stop('RECREATE_PREPARATION_FAILED') from None
                                self._append('RECREATE_RESULT', service=service, outcome='UNKNOWN')
                                raise Stop('RECREATE_OUTCOME_UNKNOWN') from None
                            if call_deadline is None:
                                # A broken adapter's ACK cannot prove no dispatch.
                                self._entered.append(service);self._may_have_changed=True
                                self._append('RECREATE_RESULT', service=service, outcome='UNKNOWN')
                                raise Stop('RECREATE_OUTCOME_UNKNOWN')
                            # A late response cannot authorize the next service.
                            try:
                                self._now(call_deadline)
                            except Stop as exc:
                                if str(exc) == 'DEADLINE':
                                    self._append('RECREATE_RESULT', service=service, outcome='LATE')
                                raise
                            require(type(rc) is int, 'RECREATE_OUTCOME_UNKNOWN')
                            self._append('RECREATE_RESULT', service=service,
                                         outcome='ACK' if rc == 0 else 'FAILED')
                            require(rc == 0, 'RECREATE_COMMAND_FAILED')
                            if self._plan['schema'] == TRANSITION_SCHEMA:
                                # Health receives its own budget AFTER timely ACK.
                                # Neither phase can extend the absolute mutation end.
                                health_deadline = min(deadline_mono,
                                    self._now(deadline_mono) + self._plan['health_seconds'][service])
                            while True:
                                rows = self._observe(health_deadline, current=service)
                                ready = (all(r['health'] == 'healthy' for r in rows.values())
                                         if self._maintenance else rows[service]['health'] == 'healthy')
                                if ready and not self._network_pending:
                                    break
                                remaining = health_deadline - self._now(health_deadline)
                                self._sleep(min(self._plan['poll_seconds'], remaining))
                            self._append('APP_HEALTHY', service=service, new_id=self._new_ids[service])
                            self._completed.append(service)
                        self._observe(deadline_mono)
                        # COMPLETE commits the final timely observation. A slow
                        # durable append cannot turn it into COMPLETE + STOP.
                        self._now(deadline_mono)
                        self._append('COMPLETE', healthy_services=list(self._completed))
                        return self._result('ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED', 'COMPLETE', True)
                    except Exception as exc:
                        reason = str(exc) if isinstance(exc, Stop) and str(exc) in RUNTIME_REASONS else 'IO_OR_ADAPTER_FAILURE'
                        recorded = False
                        if self._owned and not self._journal_failed:
                            try:
                                self._append('STOP', reason=reason,
                                    claimed_services=list(self._claimed),
                                    transport_entered_services=list(self._entered),
                                    healthy_services=list(self._completed))
                                recorded = True
                            except Exception:
                                pass  # Do not repair/retry a failed durable writer.
                        status = 'STOP_RECOVERY_REQUIRED' if self._may_have_changed else 'STOP_BEFORE_CHANGE'
                        if reason == 'EXISTING_HISTORY':
                            status = 'STOP_EXISTING_HISTORY_REQUIRES_REVIEW'
                        return self._result(status, reason, recorded)
            except Exception as exc:
                # Includes lock/open failure; never append to somebody else's run.
                return self._result('STOP_RECOVERY_REQUIRED' if self._may_have_changed else 'STOP_BEFORE_CHANGE',
                                    str(exc) if isinstance(exc, Stop) and str(exc) in RUNTIME_REASONS else 'JOURNAL_UNAVAILABLE', False)
        finally:
            self._lock.release()
