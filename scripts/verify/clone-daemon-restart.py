#!/usr/bin/env python3
"""A3: one Docker restart on the fixed disconnected Harbor clone; no recovery.

Requires separate exact-source review and an operator-confirmed host gate.
Raw journal and any private precheck output remain under /root.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

PINS = {
    'trial.py': '0a79b3b70d18211fcacb94903332b81e71168ade18225909ed4d53e26be3d8c4',
    'observer.py': 'ac9d42efbcd4f18effc2bcd7a819af29d7cc6aaa5cbd13c94fbd05e37f39e1e1',
}
SNAPSHOT = 'before-address-A2-20261008-1500'
CLAIM = Path('/root/hbr-a3-docker-restart.claim')
LOCK = Path('/root/hbr-a3-driver.lock')
OLD_WORK = '/root/hbr-address-trial-20261008-1607'
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
RESTART = ['systemctl', 'restart', 'docker.service']
UNIT = ['systemctl', 'show', 'docker.service', '--no-pager',
        '--property=ActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic']
SAMPLES, INTERVAL, OBSERVER_LIMIT = 37, 5, 500


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch('[0-9a-f-]{36}', value), 'BOOT_ID_INVALID')
    return value


def no_hgfs(text):
    for line in text.splitlines():
        parts = line.split(' - ', 1)
        require(len(parts) == 2, 'MOUNTINFO_INVALID')
        require('hgfs' not in parts[1].split()[0].lower(), 'HGFS_MOUNT_PRESENT')


def unit_state(text):
    rows = [line.split('=', 1) for line in text.splitlines() if line]
    require(all(len(row) == 2 for row in rows), 'UNIT_OUTPUT_INVALID')
    value = dict(rows)
    require(len(rows) == len(value) == 5, 'UNIT_FIELDS_INVALID')
    require(value['ActiveState'] == 'active' and value['SubState'] == 'running', 'DOCKER_UNIT_NOT_RUNNING')
    require(value['MainPID'].isdigit() and int(value['MainPID']) > 0, 'DOCKER_PID_INVALID')
    require(re.fullmatch('[0-9a-f]{32}', value['InvocationID']), 'DOCKER_INVOCATION_INVALID')
    require(value['ExecMainStartTimestampMonotonic'].isdigit(), 'DOCKER_START_TIME_INVALID')
    return value


def preserved(before, after):
    require(set(before) == set(after), 'POST_CONTAINER_SET_CHANGED')
    for service, old in before.items():
        new = after[service]
        require(new['status'] == 'running' and new['health'] == 'healthy', 'POST_NOT_ALL_HEALTHY')
        for key in ('id', 'name', 'service', 'project', 'image', 'restart', 'ports', 'logging'):
            require(old[key] == new[key], 'POST_PRESERVATION_' + key.upper())
        order = lambda mounts: sorted(mounts, key=lambda m: (m['Destination'], m['Source']))
        require(order(old['mounts']) == order(new['mounts']), 'POST_MOUNTS_CHANGED')


def ready_sample(records, observer, current):
    require(len(records) >= 2, 'OBSERVER_NOT_READY')
    header, row = records[:2]
    require(header['kind'] == 'header' and header['source_sha256'] == PINS['observer.py'] and
            header['host'] == 'harbor01' and header['uid'] == 0 and
            header['samples'] == SAMPLES and header['interval_seconds'] == INTERVAL and
            header['commands'] == {'docker': observer.DOCKER, 'listener': observer.LISTENER}, 'OBSERVER_HEADER_CHANGED')
    require(row['kind'] == 'sample' and row['index'] == 0, 'OBSERVER_FIRST_SAMPLE_INVALID')
    require(all('error' not in row[k] and row[k]['rc'] == 0 for k in ('docker', 'listener')), 'OBSERVER_FIRST_SAMPLE_FAILED')
    rows = observer.containers('\n'.join(json.dumps(r) for r in row['docker']['value']))
    require(all(r['status'] == 'running' and r['health'] == 'healthy' for r in rows), 'OBSERVER_FIRST_NOT_HEALTHY')
    require({r['name']: r['id'] for r in rows} == {r['name']: r['id'] for r in current.values()}, 'OBSERVER_ID_DRIFT')
    require(row['listener']['value'] is True, 'OBSERVER_FIRST_NO_LISTENER')
    return row


class Session:
    def __init__(self, work, trial, observer):
        self.work, self.trial, self.observer = work, trial, observer
        self.process = None
        self.result = {'source_sha256': digest(Path(__file__).read_bytes()), 'started_epoch': time.time(),
                       'status': 'PRECHECK', 'commands': [], 'AUTOSTART': 'NOT_EVALUATED',
                       'SYSLOG_INGESTION': 'NOT_TESTED', 'AC_CLOSE': 'NOT_EVALUATED',
                       'HOST_GATE': 'OPERATOR_CONFIRMED_NOT_GUEST_VERIFIED', 'snapshot': SNAPSHOT,
                       'automatic_recovery': 'NONE', 'pinned_sources': PINS}

    def save(self):
        target = self.work / 'result.json'
        temporary = self.work / 'result.pending'
        with temporary.open('w', encoding='utf-8') as f:
            json.dump(self.result, f, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, target)

    def command(self, name, argv, timeout=20, required=True):
        prefix = str(len(self.result['commands'])) + '-' + name
        output = self.work / (prefix + '.stdout')
        record = {'name': name, 'argv': argv, 'started_epoch': time.time(),
                  'begin_ns': time.monotonic_ns(), 'stdout_file': output.name}
        with output.open('xb') as out, (self.work / (prefix + '.stderr')).open('xb') as err:
            try:
                rc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    env=ENV, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                rc = 124  # systemd job may still be running; never retry/cancel it.
            except KeyboardInterrupt:
                rc = 130
            except OSError:
                rc = 127
        record.update(rc=rc, finished_epoch=time.time(), end_ns=time.monotonic_ns())
        self.result['commands'].append(record); self.save()
        if required:
            require(rc == 0, 'COMMAND_FAILED_' + name.upper().replace('-', '_'))
        return rc, output.read_text(encoding='utf-8')

    def read(self, name, argv):
        return self.command(name, argv)[1]

    def guard(self):
        self.trial.clone_guard()
        no_hgfs(Path('/proc/self/mountinfo').read_text())

    def preflight(self):
        self.guard()
        require(not CLAIM.exists(), 'RESTART_ALREADY_CLAIMED')
        self.result['boot_before'] = boot_id()
        # The pinned source has 29 bounded read-only queries; give the entire subprocess 180s.
        _, raw = self.command('candidate-check', ['python3', '-I', str(self.work/'trial.py'), 'check-current',
                             '--bundle', str(self.work), '--work', OLD_WORK, '--a2r1-mode-profile'], timeout=180)
        match = re.fullmatch(r'CANDIDATE_METADATA_VERIFIED PRIVATE=(/root/hbr-a2r1-check-[a-z0-9_]+)\n', raw)
        require(match is not None, 'FRESH_CANDIDATE_CHECK_FAILED')
        path = Path(match[1]); require(not path.is_symlink(), 'PRECHECK_PATH_SYMLINK')
        raw_result = (path/'check-current-result.json').read_bytes()
        precheck = json.loads(raw_result)
        require(precheck['source_sha256'] == PINS['trial.py'] and precheck['status'] == 'CANDIDATE_METADATA_VERIFIED', 'PRECHECK_SOURCE_OR_STATUS')
        require(precheck['started_epoch'] >= self.result['started_epoch'], 'STALE_PRECHECK')
        (self.work/'candidate-check-result.json').write_bytes(raw_result)
        self.current, self.historical = precheck['current'], precheck['before']
        self.result['candidate_private'] = str(path)
        self.result['live_restore_before'] = json.loads(self.read('live-restore-before', self.trial.DOCKER +
            ['info', '--format', '{{json .LiveRestoreEnabled}}']))
        require(self.result['live_restore_before'] is False, 'LIVE_RESTORE_NOT_DISABLED')
        self.result['unit_before'] = unit_state(self.read('unit-before', UNIT))
        self.save()

    def start_observer(self):
        self.capture = self.work/'observation.jsonl'
        self.observer_started_ns = time.monotonic_ns()
        self.observer_deadline = time.monotonic() + OBSERVER_LIMIT
        with (self.work/'observer.stdout').open('xb') as out, (self.work/'observer.stderr').open('xb') as err:
            self.process = subprocess.Popen(['python3', '-I', str(self.work/'observer.py'), 'collect',
                '--output', str(self.capture), '--expected-host', 'harbor01', '--samples', str(SAMPLES),
                '--interval', str(INTERVAL)], env=ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                start_new_session=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.capture.exists():
                # Ignore the last partial line while the append-only observer is writing.
                lines = self.capture.read_bytes().split(b'\n')[:-1]
                if len(lines) >= 2:
                    sample = ready_sample([json.loads(line) for line in lines[:2]], self.observer, self.current)
                    self.result['first_sample'] = sample
                    require(self.process.poll() is None, 'OBSERVER_EXITED_BEFORE_RESTART')
                    return
            require(self.process.poll() is None, 'OBSERVER_EXITED_BEFORE_READY')
            time.sleep(0.2)
        raise ValueError('OBSERVER_READY_TIMEOUT')

    def claim(self):
        self.guard()
        require(boot_id() == self.result['boot_before'], 'BOOT_CHANGED_BEFORE_RESTART')
        current = self.trial.decode_state(self.read('state-immediate', self.trial.DOCKER +
            ['inspect', '--type', 'container', '--format', self.trial.FORMAT, *self.trial.NAMES]))
        require(current == self.current, 'CANDIDATE_CHANGED_BEFORE_RESTART')
        require(unit_state(self.read('unit-immediate', UNIT)) == self.result['unit_before'], 'UNIT_CHANGED_BEFORE_RESTART')
        require(self.process.poll() is None, 'OBSERVER_EXITED_BEFORE_RESTART')
        with CLAIM.open('x') as f:
            json.dump({'work': str(self.work), 'source_sha256': self.result['source_sha256'],
                       'epoch': time.time()}, f); f.flush(); os.fsync(f.fileno())
        self.result['status'] = 'RESTART_CLAIMED_REQUIRES_REVIEW'
        self.result['t0'] = {'epoch': time.time(), 'monotonic_ns': time.monotonic_ns(), 'boot_id': boot_id()}
        self.save()  # durable intent before submitting the only mutating command

    def restart(self):
        self.result['restart_rc'] = self.command('restart-once', RESTART, timeout=90, required=False)[0]
        self.save()

    def finish_observer(self):
        require(self.process is not None, 'NO_OBSERVER')
        timeout = max(0.01, self.observer_deadline - time.monotonic())
        try:
            rc = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.stop_observer(); raise ValueError('OBSERVER_TIMEOUT')
        self.result['observer_rc'] = rc
        summary = self.observer.summarize(self.capture)
        require(summary['source_sha256'] == PINS['observer.py'], 'OBSERVER_SOURCE_CHANGED')
        require(rc == (2 if summary['error_sample_indices'] else 0), 'OBSERVER_RC_MISMATCH')
        self.result['observation_summary'] = summary
        self.save()

    def postcheck(self):
        self.result['boot_after'] = boot_id()
        require(self.result['boot_after'] == self.result['boot_before'], 'BOOT_CHANGED')
        unit_rc, unit_raw = self.command('unit-after', UNIT, required=False)
        state_rc, state_raw = self.command('state-after', self.trial.DOCKER +
            ['inspect', '--type', 'container', '--format', self.trial.FORMAT, *self.trial.NAMES], required=False)
        require(state_rc == 0, 'POST_STATE_QUERY_FAILED')
        after = self.trial.decode_state(state_raw)
        self.result['after'] = after; self.save()
        require(unit_rc == 0, 'POST_UNIT_QUERY_FAILED')
        after_unit = unit_state(unit_raw); self.result['unit_after'] = after_unit
        require(after_unit['InvocationID'] != self.result['unit_before']['InvocationID'], 'DOCKER_NOT_RESTARTED')
        require(int(after_unit['ExecMainStartTimestampMonotonic'])*1000 >= self.result['t0']['monotonic_ns'], 'DOCKER_START_BEFORE_TZERO')
        preserved(self.current, after)
        self.result['profile_after'] = self.trial.profile_runtime(self.read, after, self.historical)
        for name, mount in self.trial.volume_mounts(self.historical).items():
            actual = json.loads(self.read('volume-'+name, self.trial.DOCKER +
                ['volume', 'inspect', '--format', self.trial.VOLUME_FORMAT, name]))
            self.trial.validate_volume_inventory(mount, actual)
        require(self.observer.listener(self.read('listener-after', self.observer.LISTENER)), 'POST_IPV4_LISTENER_ABSENT')
        self.result['live_restore_after'] = json.loads(self.read('live-restore-after', self.trial.DOCKER +
            ['info', '--format', '{{json .LiveRestoreEnabled}}']))
        require(self.result['live_restore_after'] is False, 'LIVE_RESTORE_CHANGED')
        self.guard()
        self.result['postchecks'] = 'PASS'

    def journal(self):
        if 't0' not in self.result:
            return
        until = int(time.time())+1
        self.result['journal_window'] = {'since_epoch_floor': int(self.result['t0']['epoch']), 'until_epoch': until}
        rc, raw = self.command('docker-journal-private', ['journalctl', '--no-pager', '-u', 'docker.service',
            '-b', self.result['boot_before'], '--since', '@'+str(int(self.result['t0']['epoch'])),
            '--until', '@'+str(until), '-o', 'short-iso-precise'], timeout=30, required=False)
        require(rc == 0, 'JOURNAL_COLLECTION_FAILED')
        require(raw.strip() and raw.strip() != '-- No entries --', 'JOURNAL_EMPTY')

    def stop_observer(self):
        if self.process is not None and self.process.poll() is None:
            # Only our private observer process group; never kill Docker/systemd jobs.
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL); self.process.wait(timeout=5)


def execute(session):
    """After submitting a restart, attempt each independent capture even on failure."""
    attempted = False
    errors = []
    try:
        session.preflight(); session.start_observer(); session.claim()
        attempted = True
        session.restart()
        for action in (session.finish_observer, session.postcheck, session.journal):
            try:
                action()
            except (Exception, KeyboardInterrupt) as exc:
                errors.append(str(exc) if re.fullmatch('[A-Z_]+', str(exc)) else 'CAPTURE_OR_POSTCHECK_FAILED')
        if session.result.get('restart_rc') != 0:
            errors.append('RESTART_COMMAND_FAILED_OR_UNCERTAIN')
    except (Exception, KeyboardInterrupt) as exc:
        errors.append(str(exc) if re.fullmatch('[A-Z_]+', str(exc)) else 'INPUT_OR_EXECUTION_FAILED')
    finally:
        try:
            session.stop_observer()
        except (Exception, KeyboardInterrupt):
            errors.append('OBSERVER_CLEANUP_FAILED')
        session.result.update(finished_epoch=time.time(), errors=errors)
        session.result['status'] = ('STOP_RECOVERY_REQUIRED' if attempted or session.result.get('status') == 'RESTART_CLAIMED_REQUIRES_REVIEW'
                                    else 'STOP_BEFORE_RESTART') if errors else 'OBSERVATION_COMPLETE_REVIEW_REQUIRED'
        session.save()
    return 2 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--confirm-host-gate', required=True, choices=[SNAPSHOT],
                        help='Operator verified host share disabled, NIC disconnected, snapshot completion and evidence preservation')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    import fcntl
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not CLAIM.exists(), 'RESTART_ALREADY_CLAIMED')
        bundle = Path(args.bundle).resolve()
        require(bundle.parent == Path('/root') and not Path(args.bundle).is_symlink(), 'BUNDLE_PATH_INVALID')
        work = Path(tempfile.mkdtemp(prefix='hbr-a3-', dir='/root'))
        modules = {}
        for name, expected in PINS.items():
            path = bundle/name
            require(not path.is_symlink(), 'SOURCE_SYMLINK')
            raw = path.read_bytes(); require(digest(raw) == expected, 'SOURCE_HASH_MISMATCH')
            local = work/name; local.write_bytes(raw)
            spec = importlib.util.spec_from_file_location('pinned_'+name.replace('.', '_'), local)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            modules[name] = module
        session = Session(work, modules['trial.py'], modules['observer.py'])
        rc = execute(session)
        print(session.result['status']+' PRIVATE='+str(work))
        return rc


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        print('STOP_INPUT_OR_SESSION_ERROR; preserve the private A3 result and claim before any retry')
        raise SystemExit(2)
