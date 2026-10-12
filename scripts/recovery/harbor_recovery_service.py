"""One resident manager, cooperative shutdown, exact loaded systemd ownership.

No unit installation or automatic arm. Manager shutdown never stops containers.
An uncertain in-flight start remains evidence and prevents implicit recovery.
"""
from contextlib import contextmanager
from copy import deepcopy
import os
import re
import signal
import sys
import time

from harbor_recovery_docker import require, remaining
from harbor_recovery_host import LinuxReadOnly, absolute
from harbor_recovery_policy_backend import StoppedManager, MANAGER

if sys.platform == 'linux':
    import fcntl

OWNER_PROPERTIES = ('LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,'
                    'NeedDaemonReload,Transient,InvocationID,Requires,After,PartOf')


class ManagerLease:
    """Process-lifetime flock distinct from short controller transaction locks."""
    def __init__(self, store): self.store, self.fd = store, None

    def __enter__(self):
        require(sys.platform == 'linux' and self.fd is None, 'MANAGER_LEASE_STATE')
        with self.store.locked():
            fd = self.store._file('manager.lock', os.O_CREAT | os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.fd = fd
            except BaseException:
                os.close(fd)
                raise
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class ActiveOwner:
    """Read-only unit ownership check; input hashes are checked by host first."""
    def __init__(self, policy, manager, *, pid=None, io=None, clock=time.monotonic):
        staged = StoppedManager(policy, manager['fragment'], manager['dropins'], clock=clock)
        self.spec = deepcopy(staged.spec)
        self.pid = os.getpid() if pid is None else pid
        require(type(self.pid) is int and self.pid > 0, 'MANAGER_PID')
        self.io = LinuxReadOnly(clock=clock) if io is None else io
        self.clock, self.invocation = clock, None

    def __call__(self, deadline):
        raw = self.io.run([self.spec['systemctl'], 'show', MANAGER, '--no-pager',
                           '--property='+OWNER_PROPERTIES], self.spec['directory'], deadline)
        row = {}
        for line in raw.decode('utf-8').splitlines():
            require('=' in line, 'MANAGER_OWNER_FORMAT')
            key, value = line.split('=', 1)
            require(key not in row, 'MANAGER_OWNER_DUPLICATE')
            row[key] = value
        require(set(row) == set(OWNER_PROPERTIES.split(',')), 'MANAGER_OWNER_FIELDS')
        require(row['LoadState'] == 'loaded' and
                (row['ActiveState'], row['SubState']) in (('active', 'running'), ('activating', 'start')) and
                row['MainPID'] == str(self.pid) and
                row['NeedDaemonReload'] == row['Transient'] == 'no' and
                row['FragmentPath'] == self.spec['fragment'] and
                row['DropInPaths'].split() == self.spec['dropins'] and
                {'docker.service', 'fds-harbor-ac04-guard.service'} <= set(row['Requires'].split()) and
                {'docker.service', 'fds-harbor-ac04-guard.service'} <= set(row['After'].split()) and
                'docker.service' in row['PartOf'].split(), 'MANAGER_OWNER_DRIFT')
        invocation = row['InvocationID']
        require(re.fullmatch('[0-9a-f]{32}', invocation) and invocation != '0'*32 and
                (self.invocation is None or self.invocation == invocation), 'MANAGER_INVOCATION_CHANGED')
        remaining(deadline, self.clock)
        self.invocation = invocation


class RuntimeHost:
    """Do pinned host checks before running systemctl for the resident owner."""
    def __init__(self, base, owner, verify_launch=None):
        self.base, self.owner, self.binding = base, owner, base.binding
        self.verify_launch = verify_launch

    def __call__(self, deadline):
        if self.verify_launch is not None: self.verify_launch(deadline)
        stamp = self.base(deadline)
        self.owner(deadline)
        if self.verify_launch is not None: self.verify_launch(deadline)
        require(stamp.binding == self.binding, 'MANAGER_HOST_BINDING')
        return stamp


class SignalFlag:
    """Main-thread signal state, no Condition/lock acquisition in the handler."""
    def __init__(self): self.stopped = False
    def set(self): self.stopped = True
    def is_set(self): return self.stopped
    def wait(self, seconds, *, clock=time.monotonic, sleep=time.sleep):
        end = clock() + seconds
        while not self.stopped:
            left = end - clock()
            if left <= 0: break
            sleep(min(0.1, left))
        return self.stopped


@contextmanager
def shutdown_event():
    """Signals set a flag only; persistence/API calls stay at safe boundaries."""
    event = SignalFlag()
    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: event.set())
        yield event
    finally:
        for signum, handler in previous.items(): signal.signal(signum, handler)


def run(executor, event, *, poll_seconds, verify_launch, report, lease=None):
    """Return 2 for HOLD/errors, 0 for cooperative manager-only shutdown.

    No implicit state creation/arm/reconciliation. Event wait is interruptible.
    Exceptions preserve evidence; systemd may restart only through resume gates.
    """
    require(type(poll_seconds) in (int, float) and 0.25 <= poll_seconds <= 30, 'MANAGER_POLL')
    lease = ManagerLease(executor.store) if lease is None else lease
    with lease:
        verify_launch()
        executor.open()
        last = None
        while not event.is_set():
            try:
                verify_launch()
            except Exception:
                executor.hold(reason='LAUNCH_INPUT_CHANGED')
                report({'stage': 'MANAGER_HOLD', 'reason': 'LAUNCH_INPUT_CHANGED'})
                return 2
            try:
                state = executor.tick(stop_requested=event.is_set)
            except Exception:
                # A persistence failure cannot guarantee a durable HOLD. Never
                # report one unless the separate locked write actually succeeds.
                try:
                    executor.hold(reason='MANAGER_TICK_FAILED')
                    persisted = True
                except Exception:
                    persisted = False
                report({'stage':'MANAGER_TICK_FAILED','hold_persisted':persisted})
                return 2
            summary = {'desired': state.desired, 'reason': state.reason}
            if summary != last:
                report(dict(summary, stage='MANAGER_STATE'))
                last = summary
            if state.desired == 'HOLD':
                return 2
            event.wait(poll_seconds)
        report({'stage': 'MANAGER_EXITED', 'containers': 'NOT_STOPPED'})
        return 0


def unit_text(python, bootstrap, launch_context, *, startup_seconds, shutdown_seconds, production=False):
    """Render only. Explicit input budgets; no file writes/enable/start/stop.

    launch.json is an externally approved protected root trust anchor. Its hash
    is intentionally outside the unit, avoiding unit<->bundle hash recursion.
    """
    require(absolute(python) and absolute(bootstrap) and bootstrap.endswith('.py'), 'MANAGER_UNIT_PATH')
    require(isinstance(launch_context, str) and re.fullmatch('[A-Za-z0-9_:.,-]+', launch_context),
            'MANAGER_UNIT_CONTEXT')
    require(all(type(v) is int and 1 <= v <= 600 for v in (startup_seconds, shutdown_seconds)),
            'MANAGER_UNIT_BUDGET')
    require(type(production) is bool, 'MANAGER_UNIT_SCOPE')
    network = 'Wants=network-online.target\nAfter=network-online.target\n' if production else ''
    return ('[Unit]\nDescription=Phase 1 Harbor recovery manager\n'
            'Requires=docker.service fds-harbor-ac04-guard.service\n'
            'After=docker.service fds-harbor-ac04-guard.service\nPartOf=docker.service\n'
            + network +
            'StartLimitIntervalSec=300\nStartLimitBurst=3\n\n[Service]\nType=exec\n'
            'User=root\nGroup=root\nUMask=0077\n'
            f'ExecStart={python} -I -S -B {bootstrap} serve '
            f'--launch /etc/fds-harbor-recovery/launch.json --context {launch_context} '
            f'--timeout {startup_seconds} --execute\n'
            'Restart=on-failure\nRestartSec=5\nRestartPreventExitStatus=2 130\n'
            f'TimeoutStartSec={startup_seconds+5}\nTimeoutStopSec={shutdown_seconds}\n'
            'KillMode=control-group\n\n[Install]\nWantedBy=docker.service multi-user.target\n')
