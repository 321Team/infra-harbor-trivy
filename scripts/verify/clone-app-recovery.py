#!/usr/bin/env python3
"""One explicit recovery of the sealed A3 apps; never an autostart test.

No daemon restart, recreate, update, pull, firewall change or automatic retry.
Use only on the fixed disconnected clone after exact-source review.
"""
import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time

A3 = Path('/root/hbr-a3-joz3x6ya')
PINS = {
    'result.json': '5df896fd9f501cbac82e1091c6368160d79dbca34baf651681f766f331102fa7',
    'candidate-check-result.json': 'efff85d306350d62ca5ff58f2ae0d4a49ae7d2e6fd4ff2b558bde433c4680664',
}
TRIAL_SHA = '0a79b3b70d18211fcacb94903332b81e71168ade18225909ed4d53e26be3d8c4'
OLD_CLAIM = Path('/root/hbr-a3-docker-restart.claim')
OLD_CLAIM_SHA = 'fc00ce44c9aaa35b3cb15d150db208a560f0873532736fb4daafe870c3afa175'
CLAIM = Path('/root/hbr-a3-app-recovery.claim')
LOCK = Path('/root/hbr-a3-driver.lock')
ORDER = ('postgresql', 'redis', 'registry', 'registryctl', 'core', 'portal',
         'jobservice', 'trivy-adapter', 'proxy')
HOST_GATE = 'a3-evidence-preserved-no-nic-no-hgfs'
ERROR_SHA = 'af8467c764dce9ff2e620a0ea090e216b10d67949b0112cbf5c059a63ed9a9d3'
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
UNIT = ['systemctl', 'show', 'docker.service', '--no-pager',
        '--property=ActiveState,SubState,InvocationID,Requires,After']
NFT = ['nft', '-j', 'list', 'table', 'inet', 'p1_hbr_ac04']
ERROR_FORMAT = '{"id":{{json .Id}},"error":{{json .State.Error}},"exit":{{json .State.ExitCode}}}'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted(path):
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'UNTRUSTED_PARENT')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022 and info.st_size <= 16 * 1024 * 1024, 'UNTRUSTED_FILE')
        return stream.read()


def pinned(path, digest):
    raw = trusted(path)
    require(sha(raw) == digest, 'PIN_MISMATCH')
    return raw


def metadata(rows):
    result = copy.deepcopy(rows)
    for row in result.values():
        row.pop('status', None)
        row.pop('health', None)
        row['mounts'] = sorted(row['mounts'], key=lambda m: (m['Destination'], m['Source']))
    return result


def nft_shape(text):
    def clean(value):
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if key == 'handle':
                    continue
                if key == 'counter' and isinstance(child, dict):
                    child = {k: v for k, v in child.items() if k not in ('packets', 'bytes')}
                result[key] = clean(child)
            return result
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value
    rows = json.loads(text)['nftables']
    require(any(r.get('table', {}).get('family') == 'inet' and
                r.get('table', {}).get('name') == 'p1_hbr_ac04' for r in rows), 'AC04_TABLE_MISSING')
    return clean([r for r in rows if 'metainfo' not in r])


def unit(text, expected):
    fields = dict(line.split('=', 1) for line in text.splitlines() if line)
    require(fields.get('ActiveState') == 'active' and fields.get('SubState') == 'running' and
            fields.get('InvocationID') == expected, 'DOCKER_UNIT_CHANGED')
    require(all('fds-harbor-ac04-guard.service' in fields.get(k, '').split()
                for k in ('Requires', 'After')), 'GUARD_DEPENDENCY_MISSING')
    return fields


class Recovery:
    def __init__(self, work, trial, history, candidate):
        self.work, self.trial, self.history, self.candidate = work, trial, history, candidate
        self.before = history['after']
        self.done = set()
        self.deadline = time.monotonic() + 900
        self.result = {'status': 'PRECHECK', 'started_epoch': time.time(), 'commands': [],
                       'source_sha256': sha(Path(__file__).read_bytes()),
                       'historical_pins': PINS, 'trial_sha256': TRIAL_SHA,
                       'HOST_GATE': 'OPERATOR_CONFIRMED_NOT_GUEST_VERIFIED',
                       'AUTOSTART': 'NOT_TESTED', 'SYSLOG_INGESTION': 'NOT_TESTED',
                       'AC_CLOSE': 'NOT_EVALUATED', 'started_services': []}

    def save(self):
        pending = self.work / 'result.pending'
        with pending.open('w', encoding='utf-8') as stream:
            json.dump(self.result, stream, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        pending.replace(self.work / 'result.json')

    def read(self, name, argv, timeout=20):
        # Durable intent, including ambiguous timeout/interrupt, before each command.
        prefix = f'{len(self.result["commands"]):03}-{name}'
        record = {'name': name, 'argv': argv, 'started_epoch': time.time(),
                  'stdout_file': prefix + '.stdout', 'stderr_file': prefix + '.stderr', 'rc': None}
        self.result['commands'].append(record); self.save()
        with (self.work / record['stdout_file']).open('xb') as out, \
                (self.work / record['stderr_file']).open('xb') as err:
            try:
                rc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    env=ENV, cwd='/', timeout=timeout, check=False).returncode
            except subprocess.TimeoutExpired:
                rc = 124
            except KeyboardInterrupt:
                rc = 130
            except OSError:
                rc = 127
        record.update(rc=rc, finished_epoch=time.time()); self.save()
        require(rc == 0, 'COMMAND_FAILED_' + name.upper().replace('-', '_'))
        return (self.work / record['stdout_file']).read_text(encoding='utf-8')

    def guard(self):
        self.trial.clone_guard()
        require('hgfs' not in Path('/proc/self/mountinfo').read_text().lower(), 'HGFS_MOUNT')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == self.history['boot_after'],
                'BOOT_CHANGED')
        require(self.read('selinux', ['getenforce']).strip() == 'Enforcing', 'SELINUX_CHANGED')
        pinned(A3 / 'result.json', PINS['result.json'])
        pinned(OLD_CLAIM, OLD_CLAIM_SHA)
        require(time.monotonic() < self.deadline, 'RECOVERY_DEADLINE')

    def state(self):
        return self.trial.decode_state(self.read('state', self.trial.DOCKER +
            ['inspect', '--type', 'container', '--format', self.trial.FORMAT, *self.trial.NAMES]))

    def ready(self):
        self.guard()
        unit(self.read('docker-unit', UNIT), self.history['unit_after']['InvocationID'])
        require(self.read('guard-active', ['systemctl', 'is-active', 'fds-harbor-ac04-guard.service']).strip()
                == 'active', 'GUARD_NOT_ACTIVE')
        shape = nft_shape(self.read('ac04', NFT))
        if hasattr(self, 'firewall'):
            require(shape == self.firewall, 'AC04_DRIFT')
        else:
            self.firewall = shape
        rows = self.state()
        require(metadata(rows) == metadata(self.before), 'CONTAINER_METADATA_DRIFT')
        require(rows['log']['status'] == 'running' and rows['log']['health'] == 'healthy', 'LOGGER_NOT_READY')
        # TCP connect demonstrates accept readiness, not durable syslog ingestion.
        with socket.create_connection(('127.0.0.1', 1514), timeout=3):
            pass
        return rows

    def profile(self, rows):
        result = self.trial.profile_runtime(self.read, rows, self.candidate['before'])
        for mount in self.trial.volume_mounts(self.candidate['before']).values():
            raw = self.read('volume', self.trial.DOCKER + ['volume', 'inspect', '--format',
                           self.trial.VOLUME_FORMAT, mount['Name']])
            self.trial.validate_volume_inventory(mount, json.loads(raw))
        return result

    def preflight(self):
        require(not os.path.lexists(CLAIM), 'RECOVERY_ALREADY_CLAIMED')
        require(json.loads(trusted(Path('/var/lib/hbr-ssh-control/state.json')))['status'] == 'ROLLED_BACK',
                'SSH_NOT_ROLLED_BACK')
        rows = self.ready()
        require(all(rows[s]['status'] == 'exited' and rows[s]['health'] == 'unhealthy' for s in ORDER),
                'NOT_ORIGINAL_FAILED_APPS')
        ids = {rows[s]['id'] for s in ORDER}
        errors = [json.loads(line) for line in self.read('app-errors', self.trial.DOCKER +
                  ['inspect', '--type', 'container', '--format', ERROR_FORMAT, *sorted(ids)]).splitlines()]
        require(len(errors) == 9 and {r['id'] for r in errors} == ids and
                all(r['exit'] == 128 and sha(r['error'].encode()) == ERROR_SHA for r in errors),
                'APP_FAILURE_CHANGED')
        self.result['profile_before'] = self.profile(rows)
        self.result['before'] = rows
        self.result['firewall_before'] = self.firewall
        self.save()

    def claim(self):
        rows = self.ready()
        require(rows == self.result['before'], 'STATE_CHANGED_BEFORE_CLAIM')
        with CLAIM.open('x', encoding='utf-8') as stream:
            json.dump({'work': str(self.work), 'epoch': time.time(),
                       'source_sha256': self.result['source_sha256']}, stream)
            stream.flush(); os.fsync(stream.fileno())
        self.result['status'] = 'RECOVERY_CLAIMED'; self.save()

    def recover(self):
        for service in ORDER:
            rows = self.ready()
            for name in ORDER:
                expected = ('running', 'healthy') if name in self.done else ('exited', 'unhealthy')
                require((rows[name]['status'], rows[name]['health']) == expected, 'APP_STATE_DRIFT')
            cid = rows[service]['id']
            self.read('start-' + service, self.trial.DOCKER + ['start', cid], timeout=60)
            self.result['started_services'].append(service); self.save()
            until = min(self.deadline, time.monotonic() + 60)
            while True:
                require(time.monotonic() < until, 'APP_HEALTH_TIMEOUT')
                observed = self.state()
                require(time.monotonic() < until, 'APP_HEALTH_TIMEOUT')
                require(metadata(observed) == metadata(self.before), 'CONTAINER_METADATA_DRIFT')
                require(observed['log']['status'] == 'running' and observed['log']['health'] == 'healthy',
                        'LOGGER_LOST')
                require(observed[service]['status'] == 'running', 'APP_EXITED')
                if observed[service]['health'] == 'healthy':
                    break
                require(time.monotonic() < until, 'APP_HEALTH_TIMEOUT')
                time.sleep(2)
            self.done.add(service)

    def finish(self):
        rows = self.ready()
        require(all(r['status'] == 'running' and r['health'] == 'healthy' for r in rows.values()),
                'NOT_ALL_HEALTHY')
        self.result['profile_after'] = self.profile(rows)
        require(self.result['profile_after'] == self.result['profile_before'], 'PROFILE_DRIFT')
        self.result['after'] = rows
        self.result['status'] = 'MANUAL_RECOVERY_HEALTHY_REVIEW_REQUIRED'

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
            # Independent failure captures; a failed query must not erase others.
            self.result['failure_capture'] = {}
            for name, action in (('state', self.state), ('unit', lambda: self.read('failure-unit', UNIT)),
                                 ('ac04', lambda: self.read('failure-ac04', NFT))):
                try:
                    self.result['failure_capture'][name] = {'value': action()}
                except (Exception, KeyboardInterrupt) as capture_error:
                    self.result['failure_capture'][name] = {'error': type(capture_error).__name__}
            return 2
        finally:
            self.result['finished_epoch'] = time.time(); self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--confirm-host-gate', choices=[HOST_GATE], required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    require(args.bundle.is_absolute() and args.bundle.parent == Path('/root'), 'BUNDLE_PATH')
    raw = pinned(args.bundle / 'trial.py', TRIAL_SHA)
    history = json.loads(pinned(A3 / 'result.json', PINS['result.json']))
    candidate = json.loads(pinned(A3 / 'candidate-check-result.json', PINS['candidate-check-result.json']))
    pinned(OLD_CLAIM, OLD_CLAIM_SHA)
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not os.path.lexists(CLAIM), 'RECOVERY_ALREADY_CLAIMED')
        work = Path(tempfile.mkdtemp(prefix='hbr-app-recovery-', dir='/root'))
        (work / 'trial.py').write_bytes(raw)
        spec = importlib.util.spec_from_file_location('approved_trial', work / 'trial.py')
        trial = importlib.util.module_from_spec(spec); spec.loader.exec_module(trial)
        recovery = Recovery(work, trial, history, candidate)
        rc = recovery.execute()
        print(recovery.result['status'] + ' PRIVATE=' + str(work))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())
