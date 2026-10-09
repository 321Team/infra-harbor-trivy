"""Phase 1 recovery decisions only: no Docker, filesystem, socket or process I/O.

The executor must durably commit Transition.state before submitting its Action.
An Action is never permission to bypass fresh host/configuration guards. See the
adapter contract in docs/runbooks/harbor-recovery-core.md before integrating.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import re

ORDER = ('postgresql', 'redis', 'registry', 'registryctl', 'core', 'portal',
         'jobservice', 'trivy-adapter', 'proxy')
ENDPOINT = 'tcp://127.0.0.1:1514'


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


@dataclass(frozen=True)
class Plan:
    # fingerprints bind complete immutable container metadata, including logging
    # driver/tag/options and healthcheck configuration, not just the endpoint.
    ids: dict
    fingerprints: dict
    health_seconds: dict
    start_seconds: float = 60
    logger_seconds: float = 120
    episode_seconds: float = 900
    max_age_seconds: float = 5
    retry_window_seconds: float = 300
    retry_interval_seconds: float = 5
    retry_limit: int = 3
    execution_binding: str = ''  # adapter/host/config/transport contract; empty for pure mock only

    def __post_init__(self):
        names = set(ORDER) | {'log'}
        if set(self.ids) != names or set(self.fingerprints) != names:
            raise ValueError('PLAN_SERVICE_SET')
        if (len(set(self.ids.values())) != 10 or
                not all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                        for v in (*self.ids.values(), *self.fingerprints.values()))):
            raise ValueError('PLAN_ID_OR_FINGERPRINT')
        if set(self.health_seconds) != set(ORDER):
            raise ValueError('PLAN_HEALTH_SET')
        values = (*self.health_seconds.values(), self.start_seconds,
                  self.logger_seconds, self.episode_seconds, self.max_age_seconds,
                  self.retry_window_seconds, self.retry_interval_seconds)
        if not all(positive(v) for v in values):
            raise ValueError('PLAN_BUDGET')
        if type(self.retry_limit) is not int or self.retry_limit < 1:
            raise ValueError('PLAN_RETRY_LIMIT')
        if not isinstance(self.execution_binding, str) or not re.fullmatch(
                '(?:[0-9a-f]{64})?', self.execution_binding):
            raise ValueError('PLAN_EXECUTION_BINDING')
        # Own copies prevent callers mutating approved mappings after creation.
        object.__setattr__(self, 'ids', deepcopy(self.ids))
        object.__setattr__(self, 'fingerprints', deepcopy(self.fingerprints))
        object.__setattr__(self, 'health_seconds', deepcopy(self.health_seconds))


@dataclass(frozen=True)
class Container:
    id: str
    fingerprint: str
    status: str
    health: str
    restart: str
    endpoint: str = ENDPOINT


@dataclass(frozen=True)
class Observation:
    boot: str
    daemon: str
    at: float  # monotonic observation completion, from the current boot
    containers: dict
    guards_ok: bool  # root/identity/SELinux/AC04/configuration checks all passed
    logger_tcp: bool


@dataclass(frozen=True)
class Action:
    token: int
    service: str
    container_id: str
    boot: str
    daemon: str
    deadline: float


@dataclass
class State:
    desired: str = 'HOLD'
    reason: str = 'NOT_ARMED'
    boot: str = ''
    daemon: str = ''
    last_now: float | None = None
    episode_since: float | None = None
    logger_since: float | None = None
    pending: Action | None = None
    health_wait: tuple | None = None  # (service, absolute monotonic deadline)
    seen_healthy: set = field(default_factory=set)
    retries: dict = field(default_factory=lambda: {s: [] for s in ORDER})
    next_token: int = 1
    plan_digest: str = ''


@dataclass(frozen=True)
class Transition:
    state: State
    action: Action | None = None


class Controller:
    def __init__(self, plan):
        self.plan = deepcopy(plan)

    def plan_digest(self):
        return hashlib.sha256(json.dumps(asdict(self.plan), sort_keys=True,
                                         separators=(',', ':')).encode()).hexdigest()

    @staticmethod
    def hold(state, reason='OPERATOR_HOLD'):
        s = deepcopy(state)
        s.desired, s.reason = 'HOLD', reason
        # Never discard unresolved intent, evidence, or retry budget.
        return Transition(s)

    def resume(self, state):
        """Call once on executor restart, before step; no implicit re-arm."""
        if state.desired == 'RUN' and state.plan_digest != self.plan_digest():
            return self.hold(state, 'PLAN_CHANGED')
        if state.pending is not None:
            return self.hold(state, 'UNRESOLVED_START_ON_RESUME')
        if state.health_wait is not None:
            return self.hold(state, 'INCOMPLETE_HEALTH_WAIT_ON_RESUME')
        return Transition(deepcopy(state))

    def problem(self, o, now):
        if (type(now) not in (int, float) or not math.isfinite(now) or
                type(o.at) not in (int, float) or not math.isfinite(o.at) or
                o.at > now or now - o.at > self.plan.max_age_seconds):
            return 'STALE_OR_INVALID_OBSERVATION'
        if not o.boot or not o.daemon or o.guards_ok is not True:
            return 'GUARD_FAILED'
        if set(o.containers) != set(self.plan.ids):
            return 'SERVICE_SET_CHANGED'
        for name, c in o.containers.items():
            if c.id != self.plan.ids[name] or c.fingerprint != self.plan.fingerprints[name]:
                return 'CONTAINER_METADATA_DRIFT'
            if c.restart != ('always' if name == 'log' else 'no'):
                return 'RESTART_POLICY_DRIFT'
            if name != 'log' and c.endpoint != ENDPOINT:
                return 'LOGGER_ENDPOINT_DRIFT'
            if c.status not in ('running', 'exited', 'created'):
                return 'UNSUPPORTED_CONTAINER_STATE'
            if c.health not in ('healthy', 'starting', 'unhealthy'):
                return 'HEALTH_STATE_MISSING'
        return None

    def arm(self, state, observation, now):
        """Explicit operator intent. Never erase uncertain work or failure budget."""
        if state.pending or state.health_wait:
            return self.hold(state, 'RECONCILIATION_REQUIRED')
        if state.reason != 'NOT_ARMED':
            # Non-initial HOLD release needs a separately reviewed reconciliation
            # transaction; toggling RUN must not reset exhausted budgets.
            return self.hold(state, 'RECONCILIATION_REQUIRED')
        issue = self.problem(observation, now)
        if issue:
            return self.hold(state, issue)
        s = deepcopy(state)
        s.desired, s.reason = 'RUN', 'ARMED'
        s.plan_digest = self.plan_digest()
        s.boot, s.daemon = observation.boot, observation.daemon
        s.last_now = now
        return Transition(s)

    def step(self, state, o, now):
        s = deepcopy(state)
        if s.desired != 'RUN':
            return Transition(s)
        if s.plan_digest != self.plan_digest():
            return self.hold(s, 'PLAN_CHANGED')
        issue = self.problem(o, now)
        if issue:
            return self.hold(s, issue)
        new_boot = o.boot != s.boot
        new_generation = new_boot or o.daemon != s.daemon
        if not new_boot and s.last_now is not None and now < s.last_now:
            return self.hold(s, 'MONOTONIC_CLOCK_REVERSED')
        if new_generation:
            if s.pending or s.health_wait:
                return self.hold(s, 'GENERATION_CHANGED_WITH_WORK')
            # Never carry monotonic retry timestamps across boots or silently
            # forgive a failed episode. Clean completed RUN may auto-start.
            if new_boot and (s.episode_since is not None or any(s.retries.values())):
                return self.hold(s, 'BOOT_CHANGED_WITH_UNSETTLED_BUDGET')
            s.boot, s.daemon = o.boot, o.daemon
            s.episode_since = None
            s.logger_since = None
            s.seen_healthy.clear()
        s.last_now = now
        for service in ORDER:
            s.retries[service] = [t for t in s.retries[service]
                                  if now - t < self.plan.retry_window_seconds]
        if s.pending:
            if now >= s.pending.deadline:
                return self.hold(s, 'START_RESULT_UNKNOWN')
            return Transition(s)  # never emit the same action twice
        if s.episode_since is None and any(
                o.containers[n].status != 'running' or o.containers[n].health != 'healthy'
                for n in ORDER):
            s.episode_since = now  # include logger wait in this recovery episode
        if s.episode_since is not None and now - s.episode_since >= self.plan.episode_seconds:
            return self.hold(s, 'EPISODE_DEADLINE')
        log = o.containers['log']
        if not (log.status == 'running' and log.health == 'healthy' and o.logger_tcp is True):
            if s.logger_since is None:
                s.logger_since = now
            if now - s.logger_since >= self.plan.logger_seconds:
                return self.hold(s, 'LOGGER_TIMEOUT')
            s.reason = 'WAIT_LOGGER'
            return Transition(s)
        s.logger_since = None
        if s.health_wait:
            service, deadline = s.health_wait
            c = o.containers[service]
            if now >= deadline:
                return self.hold(s, 'HEALTH_TIMEOUT')
            if c.status != 'running':
                return self.hold(s, 'EXIT_DURING_STARTUP')
            if c.health != 'healthy':
                s.reason = 'WAIT_HEALTH'
                return Transition(s)
            s.seen_healthy.add(service)
            s.health_wait = None
        for service in ORDER:
            c = o.containers[service]
            if c.status == 'running' and c.health == 'healthy':
                s.seen_healthy.add(service)
        if any(c.status == 'running' and c.health == 'unhealthy'
               for name, c in o.containers.items() if name != 'log'):
            return self.hold(s, 'RUNNING_UNHEALTHY')
        for service in ORDER:
            c = o.containers[service]
            if c.status == 'running' and c.health == 'healthy':
                continue
            if s.episode_since is None:
                s.episode_since = now
            if c.status == 'running':
                s.health_wait = (service, min(now + self.plan.health_seconds[service],
                                            s.episode_since + self.plan.episode_seconds))
                s.reason = 'WAIT_EXISTING_START'
                return Transition(s)
            attempts = s.retries[service]
            if len(attempts) >= self.plan.retry_limit:
                return self.hold(s, 'RETRY_BUDGET_EXHAUSTED')
            if attempts and now - attempts[-1] < self.plan.retry_interval_seconds:
                s.reason = 'RETRY_BACKOFF'
                return Transition(s)
            if service in s.seen_healthy:
                attempts.append(now)
            action = Action(s.next_token, service, c.id, s.boot, s.daemon,
                            min(now + self.plan.start_seconds,
                                s.episode_since + self.plan.episode_seconds))
            s.next_token += 1
            s.pending, s.reason = action, 'START_INTENT'
            return Transition(s, action)
        s.episode_since = None
        s.reason = 'HEALTHY'
        return Transition(s)

    def authorize(self, state, action, observation, now):
        """Recheck immediately before dispatch, after intent persistence.

        Returns no Action. Only RUN/START_AUTHORIZED for the exact pending
        intent permits the executor's single submission. All other outcomes
        must be persisted without executing the command.
        """
        if state.pending != action:
            raise ValueError('ACTION_MISMATCH')
        if state.desired != 'RUN':
            return self.hold(state, 'HOLD_BEFORE_DISPATCH')
        if state.plan_digest != self.plan_digest():
            return self.hold(state, 'PLAN_CHANGED')
        issue = self.problem(observation, now)
        if issue:
            return self.hold(state, issue)
        if now < state.last_now or now >= action.deadline:
            return self.hold(state, 'DISPATCH_DEADLINE')
        if (observation.boot, observation.daemon) != (action.boot, action.daemon):
            return self.hold(state, 'GENERATION_CHANGED_BEFORE_DISPATCH')
        log = observation.containers['log']
        if not (log.status == 'running' and log.health == 'healthy' and
                observation.logger_tcp is True):
            return self.hold(state, 'LOGGER_LOST_BEFORE_DISPATCH')
        if observation.containers[action.service].status not in ('created', 'exited'):
            return self.hold(state, 'TARGET_CHANGED_BEFORE_DISPATCH')
        for name in ORDER[:ORDER.index(action.service)]:
            c = observation.containers[name]
            if c.status != 'running' or c.health != 'healthy':
                return self.hold(state, 'DEPENDENCY_LOST_BEFORE_DISPATCH')
        s = deepcopy(state)
        s.last_now, s.reason = now, 'START_AUTHORIZED'
        return Transition(s)

    def acknowledge(self, state, action, outcome, now):
        """Acknowledge only the exact saved intent; timeout is not cancellation."""
        s = deepcopy(state)
        if s.pending != action or outcome not in ('ok', 'failed', 'unknown'):
            raise ValueError('ACK_MISMATCH')
        if (type(now) not in (int, float) or not math.isfinite(now) or
                now < s.last_now):
            return self.hold(s, 'INVALID_ACK_TIME')
        if s.desired != 'RUN':
            return self.hold(s, 'ACK_DURING_HOLD')
        if outcome != 'ok' or now >= action.deadline:
            return self.hold(s, 'START_FAILED_OR_UNKNOWN')
        s.pending = None
        s.health_wait = (action.service, min(now + self.plan.health_seconds[action.service],
                                           s.episode_since + self.plan.episode_seconds))
        s.last_now, s.reason = now, 'WAIT_HEALTH'
        return Transition(s)

    def reconcile_logger(self, state, observation, now, *, explicit=False):
        """Explicit release of logger-only HOLD; never start a container here."""
        if explicit is not True:
            raise ValueError('EXPLICIT_RECONCILIATION_REQUIRED')
        if (state.desired != 'HOLD' or state.reason != 'LOGGER_TIMEOUT' or
                state.pending is not None or state.health_wait is not None or
                state.episode_since is not None):
            raise ValueError('NOT_LOGGER_ONLY_HOLD')
        if state.plan_digest != self.plan_digest():
            raise ValueError('PLAN_CHANGED')
        issue = self.problem(observation, now)
        if issue:
            raise ValueError(issue)
        if ((observation.boot, observation.daemon) != (state.boot, state.daemon) or
                state.last_now is None or now < state.last_now):
            raise ValueError('RECONCILIATION_GENERATION_OR_CLOCK_CHANGED')
        if (observation.logger_tcp is not True or
                not all(row.status == 'running' and row.health == 'healthy'
                        for row in observation.containers.values())):
            raise ValueError('RECONCILIATION_NOT_HEALTHY')
        s = deepcopy(state)
        s.desired, s.reason = 'RUN', 'LOGGER_RECONCILED'
        s.logger_since, s.last_now = None, now
        # Retry history and token sequence deliberately remain unchanged.
        return Transition(s)
