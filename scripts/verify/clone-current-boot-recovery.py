#!/usr/bin/env python3
"""One reviewed recovery for the fixed 2026-10-11 boot after proven prior completion.

Preserve both historical claims. No restart, recreate, policy change or retry.
This is an explicit manual recovery, never an autostart or AC acceptance test.
"""
import argparse
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import types

BOOT = '4b622c3c-4dec-4493-9ff2-8d5de74325d8'
INVOCATION = '6fd1b238bedf4dceb5ee3b991e58a89a'
CUTOFF = datetime(2026, 10, 11, 15, 0, tzinfo=timezone.utc).timestamp()
LATEST_START = CUTOFF - 960  # Existing 900s change budget + 3 independent 20s captures.
PRIOR_WORK = Path('/root/hbr-app-recovery-ik0dm4a1')
PRIOR_RESULT_SHA = '793ce1ff0e5cfadbdc66450da28d2c66d4365a8cfe0c5df0f8ee508163b06677'
PRIOR_CLAIM = Path('/root/hbr-a3-app-recovery.claim')
PRIOR_CLAIM_SHA = 'b7e6225dcdde9f16bf9624d9e08b1f740a19469eb5c2068ff9597334f4a52e72'
PARENT_SHA = '2178a40b948ccc87ee00b3aad29f0b6c4b7054ac4485f0cd588d75d46b46cb0c'
TRIAL_SHA = '0a79b3b70d18211fcacb94903332b81e71168ade18225909ed4d53e26be3d8c4'
CLAIM = Path('/root/hbr-boot-' + BOOT + '-app-recovery.claim')
LOCK = Path('/root/hbr-a3-driver.lock')
MANAGER = ['systemctl', 'show', '--no-pager', 'fds-harbor-recovery.service',
           '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID']


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted(path):
    require(path.is_absolute(), 'ABSOLUTE_PATH_REQUIRED')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022, 'UNTRUSTED_PARENT')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022 and info.st_size <= 16 * 1024 * 1024,
                'UNTRUSTED_FILE')
        return stream.read()


def pinned(path, digest):
    raw = trusted(path)
    require(sha(raw) == digest, 'PIN_MISMATCH')
    return raw


def load_module(path, digest, name):
    raw = pinned(path, digest)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    # Execute the verified bytes rather than reopening a mutable path via a loader.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def completed_prior(result, claim, order):
    require(result.get('status') == 'MANUAL_RECOVERY_HEALTHY_REVIEW_REQUIRED' and
            result.get('started_services') == list(order) and
            result.get('source_sha256') == PARENT_SHA and
            result.get('trial_sha256') == TRIAL_SHA, 'PRIOR_NOT_COMPLETED')
    require(set(result.get('after', {})) == set(order) | {'log'} and
            all(r.get('status') == 'running' and r.get('health') == 'healthy'
                for r in result['after'].values()), 'PRIOR_NOT_ALL_HEALTHY')
    require(result.get('commands') and all(type(c.get('rc')) is int and c['rc'] == 0 for c in result['commands']) and
            type(result.get('finished_epoch')) in (int, float) and
            result['finished_epoch'] < time.time(), 'PRIOR_INCOMPLETE_COMMANDS')
    require(claim.get('work') == str(PRIOR_WORK) and claim.get('source_sha256') == PARENT_SHA,
            'PRIOR_CLAIM_NOT_LINKED')


def recovery_class(parent):
    class CurrentBootRecovery(parent.Recovery):
        def __init__(self, work, trial, prior, candidate, bundle):
            history = {'after': copy.deepcopy(prior['after']), 'boot_after': BOOT,
                       'unit_after': {'InvocationID': INVOCATION}}
            super().__init__(work, trial, history, candidate)
            self.prior = prior
            self.bundle = bundle
            self.source_path = Path(__file__)
            self.source_sha = sha(trusted(self.source_path))
            self.result.update(source_sha256=self.source_sha, expected_boot=BOOT,
                               expected_invocation=INVOCATION,
                               dependency_source_sha256=PARENT_SHA,
                               prior_result_sha256=PRIOR_RESULT_SHA,
                               prior_claim_sha256=PRIOR_CLAIM_SHA, claim_path=str(CLAIM))

        def guard(self):
            require(time.time() < CUTOFF, 'FIELD_WINDOW_ENDED')
            self.trial.clone_guard()
            require('hgfs' not in Path('/proc/self/mountinfo').read_text().lower(), 'HGFS_MOUNT')
            require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT, 'BOOT_CHANGED')
            require(self.read('selinux', ['getenforce']).strip() == 'Enforcing', 'SELINUX_CHANGED')
            pinned(self.source_path, self.source_sha)
            pinned(self.bundle / 'clone-app-recovery.py', PARENT_SHA)
            pinned(self.bundle / 'trial.py', TRIAL_SHA)
            prior = json.loads(pinned(PRIOR_WORK / 'result.json', PRIOR_RESULT_SHA))
            claim = json.loads(pinned(PRIOR_CLAIM, PRIOR_CLAIM_SHA))
            completed_prior(prior, claim, parent.ORDER)
            old = json.loads(parent.pinned(parent.A3 / 'result.json', parent.PINS['result.json']))
            require(old['boot_after'] != BOOT, 'NOT_A_NEW_BOOT')
            parent.pinned(parent.OLD_CLAIM, parent.OLD_CLAIM_SHA)
            parent.pinned(parent.A3 / 'candidate-check-result.json', parent.PINS['candidate-check-result.json'])
            require(time.monotonic() < self.deadline, 'RECOVERY_DEADLINE')

        def ready(self):
            rows = super().ready()
            require(self.firewall == self.prior['firewall_before'], 'AC04_SHAPE_CHANGED')
            fields = dict(line.split('=', 1) for line in self.read('manager', MANAGER).splitlines() if line)
            require(fields.get('LoadState') == 'not-found' and fields.get('ActiveState') == 'inactive' and
                    fields.get('SubState') == 'dead' and fields.get('MainPID') == '0', 'MANAGER_PRESENT')
            return rows

        def read(self, name, argv, timeout=20):
            if argv[:-2] == self.trial.DOCKER and argv[-2:-1] == ['start']:
                require(time.time() < CUTOFF, 'FIELD_WINDOW_ENDED')
                require(time.monotonic() < self.deadline, 'RECOVERY_DEADLINE')
            return super().read(name, argv, timeout)

        def preflight(self):
            require(not os.path.lexists(CLAIM), 'CURRENT_BOOT_ALREADY_CLAIMED')
            require(json.loads(parent.trusted(Path('/var/lib/hbr-ssh-control/state.json')))['status']
                    == 'ROLLED_BACK', 'SSH_NOT_ROLLED_BACK')
            rows = self.ready()
            require(all(rows[s]['status'] == 'exited' and rows[s]['health'] == 'unhealthy'
                        for s in parent.ORDER), 'NOT_ORIGINAL_FAILED_APPS')
            ids = {rows[s]['id'] for s in parent.ORDER}
            errors = [json.loads(line) for line in self.read('app-errors', self.trial.DOCKER +
                      ['inspect', '--type', 'container', '--format', parent.ERROR_FORMAT,
                       *sorted(ids)]).splitlines()]
            require(len(errors) == 9 and {r['id'] for r in errors} == ids and
                    all(r['exit'] == 128 and sha(r['error'].encode()) == parent.ERROR_SHA for r in errors),
                    'APP_FAILURE_CHANGED')
            self.result['profile_before'] = self.profile(rows)
            require(self.result['profile_before'] == self.prior['profile_after'], 'PRIOR_PROFILE_CHANGED')
            self.result['before'] = rows
            self.result['firewall_before'] = self.firewall
            self.save()

        def claim(self):
            rows = self.ready()
            require(rows == self.result['before'], 'STATE_CHANGED_BEFORE_CLAIM')
            require(time.time() < CUTOFF, 'FIELD_WINDOW_ENDED')
            require(time.monotonic() < self.deadline, 'RECOVERY_DEADLINE')
            fd = os.open(CLAIM, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump({'work': str(self.work), 'epoch': time.time(), 'boot': BOOT,
                           'invocation': INVOCATION, 'source_sha256': self.source_sha,
                           'prior_result_sha256': PRIOR_RESULT_SHA,
                           'prior_claim_sha256': PRIOR_CLAIM_SHA}, stream)
                stream.flush(); os.fsync(stream.fileno())
            dfd = os.open(CLAIM.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            self.result['status'] = 'CURRENT_BOOT_RECOVERY_CLAIMED'
            self.save()

        def finish(self):
            super().finish()
            self.result['status'] = 'MANUAL_BOOT_RECOVERY_HEALTHY_REVIEW_REQUIRED'

        def execute(self):
            claimed = False
            try:
                self.preflight()
                self.claim()
                claimed = True
                self.recover()
                self.finish()
                return 0
            except (Exception, KeyboardInterrupt) as exc:
                self.result['status'] = 'STOP_RECOVERY_REQUIRED' if claimed or os.path.lexists(CLAIM) else 'STOP_BEFORE_CHANGE'
                self.result['error'] = str(exc) if re.fullmatch('[A-Z0-9_]+', str(exc)) else type(exc).__name__
                self.result['failure_capture'] = {}
                for name, action in (('state', self.state),
                                     ('unit', lambda: self.read('failure-unit', parent.UNIT)),
                                     ('ac04', lambda: self.read('failure-ac04', parent.NFT))):
                    try:
                        self.result['failure_capture'][name] = {'value': action()}
                    except (Exception, KeyboardInterrupt) as error:
                        self.result['failure_capture'][name] = {'error': type(error).__name__}
                return 2
            finally:
                self.result['finished_epoch'] = time.time()
                self.save()
    return CurrentBootRecovery


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--confirm-host-gate', choices=['a3-evidence-preserved-no-nic-no-hgfs'], required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(time.time() < LATEST_START, 'INSUFFICIENT_FIELD_WINDOW')
    require(args.bundle.is_absolute() and args.bundle.parent == Path('/root'), 'BUNDLE_PATH')
    require(Path(__file__).parent == args.bundle, 'SOURCE_OUTSIDE_BUNDLE')
    os.umask(0o077)
    parent = load_module(args.bundle / 'clone-app-recovery.py', PARENT_SHA, 'approved_prior_recovery')
    trial = load_module(args.bundle / 'trial.py', TRIAL_SHA, 'approved_readonly_trial')
    prior = json.loads(pinned(PRIOR_WORK / 'result.json', PRIOR_RESULT_SHA))
    claim = json.loads(pinned(PRIOR_CLAIM, PRIOR_CLAIM_SHA))
    completed_prior(prior, claim, parent.ORDER)
    candidate = json.loads(parent.pinned(parent.A3 / 'candidate-check-result.json',
                                        parent.PINS['candidate-check-result.json']))
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'UNTRUSTED_SHARED_LOCK')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not os.path.lexists(CLAIM), 'CURRENT_BOOT_ALREADY_CLAIMED')
        work = Path(tempfile.mkdtemp(prefix='hbr-current-boot-recovery-', dir='/root'))
        session = recovery_class(parent)(work, trial, prior, candidate, args.bundle)
        rc = session.execute()
        print(session.result['status'] + ' PRIVATE=' + str(work))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())
