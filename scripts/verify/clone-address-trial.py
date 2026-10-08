#!/usr/bin/env python3
"""One address-only trial on the explicitly identified, disconnected working clone.

Never restart Docker, reboot, pull, run prepare/down, or remove data. Results and
private Compose renderings remain under /root. No automatic retry or rollback.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import time
import uuid

BASE = Path('/home/server08/harbor/docker-compose.yml')
BASE_SHA = '0a84f57692268335eeedf45411e025d784e520bf749fa3501a3800cdfcb14ef0'
CLONE_UUID = bytes.fromhex('564d9e38f024efe2b68f137a5047788a')
UUIDS = {str(uuid.UUID(bytes=CLONE_UUID)), str(uuid.UUID(bytes_le=CLONE_UUID))}
SERVICES = ('core', 'jobservice', 'portal', 'postgresql', 'proxy', 'redis', 'registry', 'registryctl', 'trivy-adapter')
NAMES = ('harbor-core', 'harbor-jobservice', 'harbor-portal', 'harbor-db', 'nginx', 'redis', 'registry', 'registryctl', 'trivy-adapter', 'harbor-log')
# Observed clone A2: preserve these existing local volumes; no arbitrary volumes.
VOLUME_TARGETS = {
    'portal': {'/run', '/var/cache/nginx', '/var/log/nginx'},
    'proxy': {'/run', '/var/cache/nginx', '/var/log/nginx'},
    'registryctl': {'/var/lib/registry'},
    'log': {'/run', '/etc/logrotate.d'},
}
VOLUME_FORMAT = ('{"name":{{json .Name}},"driver":{{json .Driver}},'
                 '"mountpoint":{{json .Mountpoint}},"scope":{{json .Scope}},'
                 '"has_options":{{if .Options}}true{{else}}false{{end}}}')
CHECKER_SHA = '97c03cf62554eddbb36c0e5fdd2fa560d013d1821df6afb5ca6c189f47fce997'
OVERRIDE_SHA = 'c67d8a652b94f9f142534d87adce70974f1f72bfe9863181a971b16f12b61d9b'
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
DOCKER = ['docker', '--host=unix:///var/run/docker.sock']
FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
          '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
          '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
          '"status":{{json .State.Status}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},'
          '"restart":{{json .HostConfig.RestartPolicy}},"mounts":{{json .Mounts}},'
          '"ports":{{json .HostConfig.PortBindings}},"logging":{{json .HostConfig.LogConfig}}}')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clone_guard():
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(socket.gethostname().split('.')[0] == 'harbor01', 'HOST_MISMATCH')
    require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() in UUIDS, 'CLONE_UUID_MISMATCH')
    require(not any(p.exists() for p in Path('/sys/class/net').glob('*/device')), 'PHYSICAL_NIC_PRESENT')
    require(BASE.is_file() and not BASE.is_symlink() and digest(BASE) == BASE_SHA, 'BASE_CHANGED')


def decode_state(text):
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    require(len(rows) == 10 and {r['name'] for r in rows} == {'/' + n for n in NAMES}, 'CONTAINER_SET_CHANGED')
    require({r['service'] for r in rows} == set(SERVICES) | {'log'}, 'SERVICE_SET_CHANGED')
    require(all(r['project'] == 'harbor' for r in rows), 'PROJECT_CHANGED')
    return {r['service']: r for r in rows}


def volume_mounts(rows):
    found = {}
    for service, row in rows.items():
        targets = set()
        for mount in row['mounts']:
            require(mount['Destination'] not in targets, 'DUPLICATE_MOUNT_TARGET')
            targets.add(mount['Destination'])
            if mount['Type'] == 'bind':
                continue
            require(mount['Type'] == 'volume' and mount['Destination'] in VOLUME_TARGETS.get(service, set()), 'UNEXPECTED_NON_BIND_DATA')
            name = mount.get('Name', '')
            require(re.fullmatch(r'[0-9a-f]{64}', name) is not None, 'VOLUME_NAME_INVALID')
            require(mount.get('Driver') == 'local' and mount.get('Source') == '/var/lib/docker/volumes/' + name + '/_data', 'VOLUME_LOCATION_INVALID')
            require(mount.get('RW') is True and mount.get('Mode') == '' and mount.get('Propagation') == '', 'VOLUME_OPTIONS_CHANGED')
            require(name not in found, 'UNEXPECTED_SHARED_VOLUME')
            found[name] = mount
    return found


def validate_volume_inventory(mount, actual):
    require(actual == {'name': mount['Name'], 'driver': 'local', 'mountpoint': mount['Source'],
                       'scope': 'local', 'has_options': False}, 'VOLUME_INVENTORY_CHANGED')


def validate_restore_current(before, current):
    # Compose can inherit anonymous volumes only from containers still present.
    # Never attempt reconstruction from a missing container; use sealed recovery.
    for service, old in before.items():
        new = current[service]
        for key in ('image', 'restart', 'ports'):
            require(old[key] == new[key], 'RESTORE_PRESERVATION_' + key.upper())
        require(sorted(old['mounts'], key=lambda m: m['Destination']) ==
                sorted(new['mounts'], key=lambda m: m['Destination']), 'RESTORE_MOUNTS_CHANGED')
        expected = json.loads(json.dumps(old['logging']))
        if service != 'log':
            address = new['logging'].get('Config', {}).get('syslog-address')
            require(address in ('tcp://localhost:1514', 'tcp://127.0.0.1:1514'), 'RESTORE_LOGGING_CHANGED')
            expected['Config']['syslog-address'] = address
        require(new['logging'] == expected, 'RESTORE_LOGGING_CHANGED')
    require(current['log']['id'] == before['log']['id'], 'LOGGER_ID_CHANGED')


def validate_before(rows, images, address):
    require(all(r['status'] == 'running' and r['health'] == 'healthy' for r in rows.values()), 'NOT_ALL_HEALTHY')
    for service, row in rows.items():
        require(row['image'] == images[service], 'LOCAL_IMAGE_DRIFT')
        require(row['restart']['Name'] == 'always', 'RESTART_POLICY_CHANGED')
        if service != 'log':
            require(row['logging']['Type'] == 'syslog' and row['logging']['Config']['syslog-address'] == address, 'LOGGING_STATE_CHANGED')
    volume_mounts(rows)


def validate_after(before, after, address):
    require(all(r['status'] == 'running' and r['health'] == 'healthy' for r in after.values()), 'NOT_ALL_HEALTHY')
    for service, old in before.items():
        new = after[service]
        for key in ('image', 'restart', 'ports'):
            require(old[key] == new[key], 'PRESERVATION_' + key.upper())
        mounts = lambda r: sorted(r['mounts'], key=lambda m: (m['Destination'], m['Source']))
        require(mounts(old) == mounts(new), 'PRESERVATION_MOUNTS')
        wanted = json.loads(json.dumps(old['logging']))
        if service == 'log':
            require(new['id'] == old['id'], 'LOGGER_RECREATED')
        else:
            require(new['id'] != old['id'], 'APP_NOT_RECREATED')
            wanted['Config']['syslog-address'] = address
        require(new['logging'] == wanted, 'PRESERVATION_LOGGING')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('apply', 'restore'))
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--work', required=True)
    args = parser.parse_args(argv)
    clone_guard()
    bundle = Path(args.bundle).resolve()
    work = Path(args.work)
    require(work.parent == Path('/root') and work.name.startswith('hbr-address-trial-') and not work.is_symlink(), 'WORK_PATH_INVALID')
    os.umask(0o077)
    if args.mode == 'apply':
        work.mkdir(mode=0o700, exist_ok=False)
        require(digest(bundle / 'checker.py') == CHECKER_SHA, 'CHECKER_HASH')
        require(digest(bundle / 'override.json') == OVERRIDE_SHA, 'OVERRIDE_HASH')
        for name in ('checker.py', 'override.json'):
            require(not (bundle / name).is_symlink(), 'SOURCE_SYMLINK')
            (work / name).write_bytes((bundle / name).read_bytes())
    else:
        require(work.is_dir() and (work / 'apply.claim').exists(), 'NO_APPLY_RECORD')
        require(digest(work / 'checker.py') == CHECKER_SHA and digest(work / 'override.json') == OVERRIDE_SHA, 'SOURCE_CHANGED')
        prior = json.loads((work / 'apply-result.json').read_text())
        require(prior.get('status') in ('ADDRESS_APPLIED_HEALTHY', 'STOP_RECOVERY_REQUIRED'), 'NO_CHANGE_TO_RESTORE')
    claim = work / (args.mode + '.claim')
    with claim.open('x') as f:
        f.write(str(time.time()) + '\n')
    result = {'mode': args.mode, 'started_epoch': time.time(), 'source_sha256': digest(Path(__file__)),
              'commands': [], 'status': 'PRECHECK', 'DOCKER_RESTART': 'NOT_RUN', 'AUTOSTART': 'NOT_TESTED'}
    def save():
        (work / (args.mode + '-result.json')).write_text(json.dumps(result, indent=2) + '\n')
    def run(name, cmd, timeout=35):
        prefix = args.mode + '-' + str(len(result['commands'])) + '-' + name
        out = work / (prefix + '.stdout')
        with out.open('xb') as stdout, (work / (prefix + '.stderr')).open('xb') as stderr:
            try:
                rc = subprocess.run(cmd, cwd=BASE.parent, env=ENV, stdout=stdout, stderr=stderr, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                rc = 124
        result['commands'].append({'name': name, 'argv': cmd, 'rc': rc, 'stdout_file': out.name})
        save()
        require(rc == 0, 'COMMAND_FAILED_' + name)
        return out.read_text()
    def inspect():
        return decode_state(run('state', DOCKER + ['inspect', '--type', 'container', '--format', FORMAT, *NAMES]))
    try:
        compose = DOCKER + ['compose', '--project-directory', str(BASE.parent), '-f', str(BASE)]
        base_raw = run('base', compose + ['config', '--format', 'json', '--no-env-resolution']).encode()
        effective_raw = run('effective', compose + ['-f', str(work / 'override.json'), 'config', '--format', 'json', '--no-env-resolution']).encode()
        spec = importlib.util.spec_from_file_location('approved_checker', work / 'checker.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        rc, delta = checker.check(base_raw, effective_raw)
        require(rc == 0, 'CONFIG_DELTA_FAILED')
        result['delta'] = delta
        base = json.loads(base_raw)
        images = {s: run('image-' + s, DOCKER + ['image', 'inspect', '--format', '{{.Id}}', c['image']]).strip()
                  for s, c in base['services'].items()}
        if args.mode == 'apply':
            before = inspect()
            result['before'] = before
            save()
            validate_before(before, images, 'tcp://localhost:1514')
            logger = before['log']
        else:
            before = prior['before']
            require(set(before) == set(SERVICES) | {'log'}, 'BEFORE_STATE_INVALID')
            for s, row in before.items():
                require(row['image'] == images[s], 'LOCAL_IMAGE_DRIFT')
            current = inspect()
            validate_restore_current(before, current)
            logger = current['log']
        result['before'] = before
        for name, mount in volume_mounts(before).items():
            inventory = json.loads(run('volume-' + name, DOCKER + ['volume', 'inspect', '--format', VOLUME_FORMAT, name]))
            validate_volume_inventory(mount, inventory)
        require(logger['status'] == 'running' and logger['health'] == 'healthy', 'LOGGER_NOT_HEALTHY')
        listener = run('listener', ['ss', '-H', '-ltn4', 'sport', '=', ':1514'])
        require(any('127.0.0.1:1514' in line for line in listener.splitlines()), 'LOGGER_IPV4_NOT_LISTENING')
        clone_guard()
        result['status'] = 'CHANGE_ATTEMPTED'
        save()
        candidate = compose + (['-f', str(work / 'override.json')] if args.mode == 'apply' else [])
        run('recreate-apps', candidate + ['up', '-d', '--no-deps', '--force-recreate', '--pull', 'never', *SERVICES], 120)
        deadline = time.monotonic() + 180
        while True:
            after = inspect()
            result['after'] = after
            if all(r['status'] == 'running' and r['health'] == 'healthy' for r in after.values()):
                break
            require(time.monotonic() < deadline, 'HEALTH_TIMEOUT')
            time.sleep(5)
        validate_after(before, after, 'tcp://127.0.0.1:1514' if args.mode == 'apply' else 'tcp://localhost:1514')
        require(digest(BASE) == BASE_SHA, 'BASE_CHANGED')
        result['status'] = 'ADDRESS_APPLIED_HEALTHY' if args.mode == 'apply' else 'ORIGINAL_ADDRESS_RESTORED_HEALTHY'
    except (ValueError, OSError, KeyError) as exc:
        code = str(exc)
        result['error_code'] = code if code and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_-' for c in code) else 'INPUT_OR_COMMAND_DATA_INVALID'
        result['status'] = 'STOP_RECOVERY_REQUIRED' if result['status'] == 'CHANGE_ATTEMPTED' else 'STOP_BEFORE_CHANGE'
    finally:
        result['finished_epoch'] = time.time()
        save()
    print(result['status'] + ' PRIVATE=' + str(work))
    return 0 if result['status'] in ('ADDRESS_APPLIED_HEALTHY', 'ORIGINAL_ADDRESS_RESTORED_HEALTHY') else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('STOP_INPUT_OR_IO_ERROR; inspect the private result before any retry')
        raise SystemExit(2)
