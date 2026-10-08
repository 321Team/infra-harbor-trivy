"""Actual Docker mechanism experiment on a disposable GitHub-hosted Linux runner.

Never restart a daemon, contact Harbor, use credentials or change host policy.
This does not test Harbor services, automatic restart, or AC04.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
import time
import uuid

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
LABEL = 'fds.syslog-lab.run'


def permitted(env):
    return (env.get('GITHUB_ACTIONS') == 'true'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('RUNNER_OS') == 'Linux'
            and env.get('GITHUB_REPOSITORY') == '321Team/infra-harbor-trivy')


def owned(obj, identity, image=False):
    labels = obj.get('Config', {}).get('Labels') or {}
    return labels.get(LABEL) == identity and bool(re.fullmatch(
        r'(sha256:)?[a-f0-9]{64}', obj.get('Id', '')))


def refused(result):
    return (result['rc'] != 0 and 'failed to initialize logging driver' in result['stderr']
            and 'connection refused' in result['stderr'])


class Receiver:
    def __init__(self, port=0):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('127.0.0.1', port))
        self.port = self.socket.getsockname()[1]
        self.socket.listen(8)
        self.socket.settimeout(.1)
        self.stop = threading.Event()
        self.messages = bytearray()
        self.error = None
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def collect(self):
        try:
            while not self.stop.is_set():
                try:
                    client, _ = self.socket.accept()
                except socket.timeout:
                    continue
                with client:
                    client.settimeout(.1)
                    while not self.stop.is_set():
                        try:
                            data = client.recv(4096)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        self.messages.extend(data)
                        if len(self.messages) > 65536:
                            raise RuntimeError('RECEIVER_LIMIT')
        except Exception as exc:
            self.error = type(exc).__name__ + ':' + str(exc)

    def received(self, marker):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.error:
                raise RuntimeError(self.error)
            if marker.encode() in self.messages:
                return True
            time.sleep(.05)
        return False

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError('RECEIVER_NOT_STOPPED')


class Lab:
    def __init__(self, output):
        if not permitted(os.environ):
            raise RuntimeError('DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED')
        self.output = output
        output.mkdir(parents=True, exist_ok=False)
        self.runid = uuid.uuid4().hex
        self.names = []
        self.image = None
        self.receivers = []
        self.events = []
        self.results = []

    def command(self, args, timeout=20):
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            result = {'utc': start, 'argv': args, 'rc': p.returncode,
                      'stdout': p.stdout, 'stderr': p.stderr}
        except subprocess.TimeoutExpired as exc:
            def decode(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
            result = {'utc': start, 'argv': args, 'rc': 124,
                      'stdout': decode(exc.stdout), 'stderr': decode(exc.stderr)}
        self.events.append(result)
        with (self.output/'commands.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(result) + '\n')
        return result

    def checked(self, args, timeout=20):
        r = self.command(args, timeout)
        if r['rc']:
            raise RuntimeError('COMMAND_FAILED:' + str(args[:4]))
        return r['stdout'].strip()

    def receiver(self, port=0):
        r = Receiver(port)
        self.receivers.append(r)
        return r

    def create(self, case, address):
        name = 'fds-syslog-lab-' + self.runid + '-' + case
        self.names.append(name)  # Recover exact label/ID if create response is lost.
        marker = 'FDS_LAB_' + self.runid + '_' + case
        cid = self.checked(DOCKER + ['create', '--pull=never', '--name', name,
            '--label', LABEL+'='+self.runid, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '32', '--memory', '32m', '--cpus', '.2', '--restart', 'no',
            '--log-driver', 'syslog', '--log-opt', 'syslog-address='+address,
            '--log-opt', 'syslog-format=rfc5424micro', '--log-opt', 'tag='+marker,
            self.image, marker])
        if not re.fullmatch('[a-f0-9]{64}', cid):
            raise RuntimeError('INVALID_CONTAINER_ID')
        return cid, marker

    def start(self, cid, marker, receiver=None):
        result = self.command(DOCKER + ['start', cid])
        if result['rc'] == 0:
            exitcode = self.checked(DOCKER + ['wait', cid])
            if exitcode != '0':
                raise RuntimeError('EMITTER_FAILED:'+exitcode)
            if receiver is None or not receiver.received(marker):
                raise RuntimeError('NO_ACTUAL_LOG_RECEIPT')
        return result

    def cleanup(self):
        errors = []
        for name in self.names:
            r = self.command(DOCKER+['container', 'inspect', name])
            if r['rc']:
                if 'No such container' not in r['stderr']:
                    errors.append('INSPECT_UNKNOWN:'+name)
                continue
            obj = json.loads(r['stdout'])[0]
            if not owned(obj, self.runid):
                errors.append('FOREIGN:'+name)
                continue
            cid = obj['Id']
            r = self.command(DOCKER+['rm', '-f', cid])
            if r['rc']:
                errors.append('REMOVE_FAILED:'+cid)
        for i, receiver in enumerate(self.receivers):
            try:
                receiver.close()
                (self.output/f'receiver-{i}.log').write_bytes(bytes(receiver.messages))
                if receiver.error:
                    errors.append(receiver.error)
            except Exception as exc:
                errors.append(str(exc))
        if self.image:
            r = self.command(DOCKER+['image', 'inspect', self.image])
            if not r['rc'] and owned(json.loads(r['stdout'])[0], self.runid, image=True):
                if self.command(DOCKER+['image', 'rm', self.image])['rc']:
                    errors.append('IMAGE_REMOVE_FAILED')
            else:
                errors.append('IMAGE_OWNERSHIP_UNKNOWN')
        r = self.command(DOCKER+['ps', '-aq', '--filter', 'label='+LABEL+'='+self.runid])
        if r['rc'] or r['stdout'].strip():
            errors.append('CONTAINERS_NOT_CONFIRMED_ABSENT')
        return errors

    def run(self):
        failure = None
        try:
            # A disposable runner is required; do not experiment beside workloads.
            if self.checked(DOCKER+['ps', '-aq']):
                raise RuntimeError('NONEMPTY_DAEMON')
            self.checked(DOCKER+['version', '--format', '{{json .}}'])
            here = Path(__file__).resolve().parents[2]/'tests/syslog-lab'
            build = self.output/'build'; build.mkdir()
            (build/'Dockerfile').write_bytes((here/'Dockerfile').read_bytes())
            self.checked(['cc', '-static', '-O2', '-o', str(build/'emit'), str(here/'emit.c')], 30)
            self.checked(DOCKER+['build', '--network=none', '--pull=false',
                '--label', LABEL+'='+self.runid, '--iidfile', str(build/'image-id.txt'), str(build)], 60)
            self.image = (build/'image-id.txt').read_text().strip()
            if not re.fullmatch('sha256:[a-f0-9]{64}', self.image):
                raise RuntimeError('INVALID_IMAGE_ID')
            ready = self.receiver()
            cid, marker = self.create('ipv4-ready', f'tcp://127.0.0.1:{ready.port}')
            assert self.start(cid, marker, ready)['rc'] == 0
            self.results.append({'case': 'ipv4-ready', 'result': 'START_AND_LOG_RECEIPT'})
            cid, marker = self.create('ipv6-mismatch', f'tcp://[::1]:{ready.port}')
            assert refused(self.start(cid, marker)), 'IPV6_EXPECTED_LOGGER_REFUSAL'
            self.results.append({'case': 'ipv6-mismatch', 'result': 'LOGGING_DRIVER_REFUSED'})
            cid, marker = self.create('localhost', f'tcp://localhost:{ready.port}')
            local = self.start(cid, marker, ready)
            if local['rc'] and not refused(local):
                raise RuntimeError('UNEXPECTED_LOCALHOST_ERROR')
            self.results.append({'case': 'localhost', 'rc': local['rc'],
                                 'result': 'ENVIRONMENT_DEPENDENT_OBSERVATION'})
            # Reserve an IPv4 port without listening: start must fail before ready.
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
                cid, marker = self.create('late-logger', f'tcp://127.0.0.1:{port}')
                assert refused(self.start(cid, marker)), 'ABSENT_LOGGER_MUST_FAIL'
            late = self.receiver(port)
            assert self.start(cid, marker, late)['rc'] == 0
            self.results.append({'case': 'late-logger', 'result': 'REFUSED_THEN_EXPLICIT_START_AND_RECEIPT',
                                 'automatic_recovery': 'NOT_TESTED'})
        except Exception as exc:
            failure = type(exc).__name__+':'+str(exc)
        finally:
            # Finish exact-ID cleanup even if another interrupt arrives.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            errors = self.cleanup()
            result = {'schema': 'fds.harbor.syslog-mechanism.v1', 'run_id': self.runid,
                'source_commit': os.environ.get('GITHUB_SHA'), 'results': self.results,
                'failure': failure, 'cleanup_errors': errors,
                'rc': 1 if failure or errors else 0, 'HARBOR_AUTOSTART': 'NOT_TESTED',
                'AC04': 'NOT_EVALUATED', 'production_changes': False}
            (self.output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
            files = sorted(p for p in self.output.rglob('*') if p.is_file())
            (self.output/'SHA256SUMS').write_text(''.join(
                hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(self.output).as_posix()+'\n'
                for p in files))
        return result['rc']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def interrupted(sig, frame):
        raise RuntimeError('INTERRUPTED:'+str(sig))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    return Lab(args.output.resolve()).run()


if __name__ == '__main__':
    raise SystemExit(main())
