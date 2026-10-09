"""Serialized execution protocol. Backend is injected; no default Docker client.

backend.observe() must perform bounded fresh host/config/engine/log checks.
backend.start(action, remaining_seconds) must submit exactly the specified ID
once with a bounded timeout and return ok/failed/unknown. No retries are allowed.
"""
import time


class Executor:
    def __init__(self, core, store, backend, *, clock=time.monotonic, gate=None):
        self.core, self.store, self.backend, self.clock = core, store, backend, clock
        if gate is not None and not callable(gate):
            raise TypeError('EXECUTOR_GATE')
        self.gate = gate
        self.opened = False

    def _gated(self, state):
        if self.gate is not None:
            try:
                self.gate()  # same Store lock; must raise on incomplete installation
            except Exception:
                return self.core.hold(state, 'INSTALLATION_GATE_FAILED').state
        return state

    def open(self):
        with self.store.locked():
            state = self._gated(self.core.resume(self.store.load()).state)
            self.store.save(state)
        self.opened = True

    def _require_open(self):
        if not self.opened:
            raise RuntimeError('EXECUTOR_NOT_OPEN')

    def tick(self, *, stop_requested=lambda: False):
        self._require_open()
        with self.store.locked():
            state = self.store.load()
            if state.desired != 'RUN':
                return state
            if stop_requested():
                return state  # clean manager shutdown preserves desired RUN
            state = self._gated(state)
            if state.desired != 'RUN':
                self.store.save(state)
                return state
            # This process never resumes a saved pending/wait state for the first
            # time without open(). Normal acknowledged health_wait may continue.
            try:
                observation = self.backend.observe()
            except Exception:
                if stop_requested():
                    return state  # nothing new was submitted in this tick
                state = self.core.hold(state, 'OBSERVATION_FAILED').state
                self.store.save(state)
                return state
            if stop_requested():
                return state
            transition = self.core.step(state, observation, self.clock())
            self.store.save(transition.state)  # commit intent before any submission
            action = transition.action
            if action is None:
                return transition.state
            def stopping(current):
                if stop_requested():
                    held = self.core.hold(current, 'MANAGER_STOP_WITH_INTENT').state
                    self.store.save(held)
                    return held
                return None
            held = stopping(transition.state)
            if held is not None:
                return held
            try:
                observation = self.backend.observe()
            except Exception:
                state = self.core.hold(transition.state, 'DISPATCH_OBSERVATION_FAILED').state
                self.store.save(state)
                return state
            state = self.core.authorize(transition.state, action, observation, self.clock()).state
            self.store.save(state)
            if state.desired != 'RUN' or state.reason != 'START_AUTHORIZED':
                return state
            held = stopping(state)
            if held is not None:
                return held
            try:
                self.store.claim(action)
            except FileExistsError:
                state = self.core.hold(state, 'DUPLICATE_DISPATCH_TOKEN').state
                self.store.save(state)
                return state
            held = stopping(state)
            if held is not None:
                return held
            remaining = action.deadline - self.clock()
            if remaining <= 0:
                state = self.core.hold(state, 'DISPATCH_DEADLINE').state
                self.store.save(state)
                return state
            try:
                outcome = self.backend.start(action, remaining, stop_requested=stop_requested)
                if outcome not in ('ok', 'failed', 'unknown'):
                    outcome = 'unknown'
            except Exception:
                outcome = 'unknown'
            # BaseException (SIGINT/SystemExit/test crash) deliberately leaves
            # saved intent+claim. A new process enters HOLD through open().
            state = self.core.acknowledge(state, action, outcome, self.clock()).state
            self.store.save(state)
            return state

    def arm_initial(self):
        self._require_open()
        if self.gate is not None:
            raise RuntimeError('USE_INSTALLED_ACTIVATION')
        with self.store.locked():
            state = self.store.load()
            observation = self.backend.observe()
            state = self.core.arm(state, observation, self.clock()).state
            self.store.save(state)
            return state

    def hold(self, *, reason='OPERATOR_HOLD'):
        self._require_open()
        with self.store.locked():
            state = self.store.load()
            self.store.audit('operator-hold' if reason == 'OPERATOR_HOLD' else 'manager-hold', state)
            state = self.core.hold(state, reason).state
            self.store.save(state)
            return state

    def reconcile_logger(self, *, explicit=False):
        self._require_open()
        with self.store.locked():
            state = self.store.load()
            gated = self._gated(state)
            if gated.reason == 'INSTALLATION_GATE_FAILED':
                self.store.save(gated)
                return gated
            observation = self.backend.observe()
            result = self.core.reconcile_logger(state, observation, self.clock(), explicit=explicit).state
            # The old HOLD is preserved before changing state; this audit is a
            # request record, not proof that subsequent state persistence worked.
            self.store.audit('logger-reconcile-request', state)
            self.store.save(result)
            return result
