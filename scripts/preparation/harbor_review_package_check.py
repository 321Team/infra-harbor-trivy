#!/usr/bin/env python3
"""Read-only receipt check on a trusted private workstation, never a guest installer.

An external INSTALL_PLAN hash is mandatory. Matching bytes establish integrity,
not approval, current host compatibility, installation or Runtime success.
Candidate source bytes are compiled after validation but never imported/executed.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'scripts/recovery'))
from harbor_recovery_bundle import MODULES, parse_bundle, bound_host_digest, fingerprint_version
from harbor_recovery_docker import UnixEngine, execution_binding, parse_json, require
from harbor_recovery_host import absolute
from harbor_recovery_protected_store import label
from harbor_recovery_service import unit_text

PAYLOADS = MODULES | {'harbor_recovery_bootstrap.py', 'manager.service', 'bundle.json', 'launch.json'}
FILES = PAYLOADS | {'INSTALL_PLAN.json'}
PLAN_FIELDS = {'schema', 'status', 'input_sha256', 'source_revision', 'files', 'store',
               'external_existing_inputs', 'prerequisites', 'apply', 'rollback',
               'automatic_deletion', 'runtime_go'}
ENTRY_FIELDS = {'file', 'target', 'sha256', 'bytes', 'uid', 'gid', 'mode', 'selinux', 'existing_target'}
MAX_TOTAL = 32 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def limit(name):
    if name in ('INSTALL_PLAN.json', 'bundle.json'):
        return 8 * 1024 * 1024
    if name in ('manager.service', 'launch.json'):
        return 16 * 1024
    return 1024 * 1024


def verify_bytes(files, expected_plan_sha256):
    """Verify one bounded byte snapshot. No I/O, candidate import or auto-baseline."""
    require(digest(expected_plan_sha256), 'PACKAGE_CHECK_EXTERNAL_HASH')
    require(isinstance(files, dict) and set(files) == FILES and
            all(isinstance(raw, bytes) and 0 < len(raw) <= limit(name)
                for name, raw in files.items()) and
            sum(map(len, files.values())) <= MAX_TOTAL, 'PACKAGE_CHECK_FILE_SET_OR_SIZE')
    require(sha(files['INSTALL_PLAN.json']) == expected_plan_sha256, 'PACKAGE_CHECK_PLAN_HASH')
    plan = parse_json(files['INSTALL_PLAN.json'])
    require(isinstance(plan, dict) and set(plan) == PLAN_FIELDS and
            plan['schema'] == 'fds.harbor.review-package.v1' and
            plan['status'] == 'PREPARED_NOT_APPROVED_NOT_INSTALLED' and
            digest(plan['input_sha256']) and plan['runtime_go'] is False and
            plan['automatic_deletion'] is False and
            plan['apply'] == 'NOT_IMPLEMENTED_REQUIRES_TARGET_INPUT_REVIEW', 'PACKAGE_CHECK_PLAN')
    entries = plan['files']
    require(isinstance(entries, list) and len(entries) == len(PAYLOADS) and
            all(isinstance(e, dict) and set(e) == ENTRY_FIELDS for e in entries),
            'PACKAGE_CHECK_ENTRIES')
    require(all(isinstance(e['file'], str) and e['file'] in PAYLOADS for e in entries) and
            len({e['file'] for e in entries}) == len(PAYLOADS), 'PACKAGE_CHECK_NAMES')
    entries = {e['file']: deepcopy(e) for e in entries}
    for name, entry in entries.items():
        require(type(entry['bytes']) is int and entry['bytes'] == len(files[name]) and
                digest(entry['sha256']) and entry['sha256'] == sha(files[name]), 'PACKAGE_CHECK_BYTES')
        require(type(entry['uid']) is type(entry['gid']) is int and
                entry['uid'] == entry['gid'] == 0 and type(entry['mode']) is int and
                0 <= entry['mode'] <= 0o777 and not entry['mode'] & 0o022 and
                entry['existing_target'] == 'STOP_NO_OVERWRITE' and absolute(entry['target']),
                'PACKAGE_CHECK_METADATA')
        label(entry['selinux'])
    require(len({e['target'] for e in entries.values()}) == len(entries), 'PACKAGE_CHECK_TARGET_COLLISION')
    bundle = parse_bundle(files['bundle.json'])
    require(plan['source_revision'] == bundle['source']['revision'] and
            plan['store'] == bundle['store'], 'PACKAGE_CHECK_SCOPE')
    p = bundle['host_policy']
    require(bundle['manager'] == {'fragment': '/etc/systemd/system/fds-harbor-recovery.service',
                                  'dropins': []}, 'PACKAGE_CHECK_MANAGER')
    engine = UnixEngine(p['api_version'], socket_path=p['socket'])
    require(bundle['plan']['execution_binding'] == execution_binding(
        bound_host_digest(bundle), p['project'], engine.binding,
        fingerprint_version=fingerprint_version(bundle)), 'PACKAGE_CHECK_EXECUTION_BINDING')
    for name in MODULES:
        path = bundle['source']['directory'] + '/' + name
        entry = entries[name]
        require(entry['target'] == path and entry['sha256'] == bundle['source']['files'][name] and
                {k: entry[k] for k in ('sha256', 'mode', 'gid', 'selinux')} == p['files'][path],
                'PACKAGE_CHECK_SOURCE_PIN')
    boot = entries['harbor_recovery_bootstrap.py']
    require(boot['target'] == '/opt/fds-harbor-recovery/bootstrap/' + boot['sha256'] +
            '/harbor_recovery_bootstrap.py' and boot['mode'] == 0o444, 'PACKAGE_CHECK_BOOTSTRAP')
    manager = entries['manager.service']
    require(manager['target'] == bundle['manager']['fragment'] and
            {k: manager[k] for k in ('sha256', 'mode', 'gid', 'selinux')} == p['files'][manager['target']],
            'PACKAGE_CHECK_UNIT_PIN')
    launch = parse_json(files['launch.json'])
    require(isinstance(launch, dict) and set(launch) == {'version', 'bundle', 'sha256', 'context'} and
            type(launch['version']) is int and launch['version'] == 1, 'PACKAGE_CHECK_LAUNCH')
    b = entries['bundle.json']
    require(b['target'].startswith('/etc/fds-harbor-recovery/bundles/') and
            b['target'].endswith('.json') and b['mode'] == 0o600 and
            launch['bundle'] == b['target'] and launch['sha256'] == b['sha256'] and
            launch['context'] == b['selinux'], 'PACKAGE_CHECK_LAUNCH_BINDING')
    anchor = entries['launch.json']
    require(anchor['target'] == '/etc/fds-harbor-recovery/launch.json' and anchor['mode'] == 0o400,
            'PACKAGE_CHECK_ANCHOR')
    unit = files['manager.service'].decode('utf-8')
    starts = [line for line in unit.splitlines() if line.startswith('ExecStart=')]
    stops = [line for line in unit.splitlines() if line.startswith('TimeoutStopSec=')]
    require(len(starts) == len(stops) == 1, 'PACKAGE_CHECK_UNIT_FORMAT')
    start = re.fullmatch(r'ExecStart=(/[A-Za-z0-9_./-]+) -I -S -B ' + re.escape(boot['target']) +
                        r' serve --launch /etc/fds-harbor-recovery/launch.json --context ' +
                        re.escape(anchor['selinux']) + r' --timeout ([0-9]+) --execute', starts[0])
    stop = re.fullmatch(r'TimeoutStopSec=([0-9]+)', stops[0])
    require(start is not None and stop is not None, 'PACKAGE_CHECK_UNIT_LAUNCH_BINDING')
    startup, shutdown = int(start[2]), int(stop[1])
    require(unit == unit_text(start[1], boot['target'], anchor['selinux'],
                              startup_seconds=startup, shutdown_seconds=shutdown, production=p['version'] in (2, 3, 4)),
            'PACKAGE_CHECK_UNIT_BYTES')
    require(shutdown >= bundle['plan']['start_seconds'] + 3 * bundle['plan']['max_age_seconds'] + 5,
            'PACKAGE_CHECK_SHUTDOWN_BUDGET')
    targets = {e['target'] for e in entries.values()}
    require(plan['external_existing_inputs'] == {k: v for k, v in p['files'].items() if k not in targets},
            'PACKAGE_CHECK_EXTERNAL_INPUTS')
    # Compilation does not execute/import candidate code or emit bytecode.
    for name in sorted(MODULES | {'harbor_recovery_bootstrap.py'}):
        compile(files[name].decode('utf-8'), name, 'exec', dont_inherit=True)
    return {'schema': 'fds.harbor.review-package-check.v1', 'status': 'PACKAGE_BYTES_VERIFIED',
            'plan_sha256': expected_plan_sha256, 'input_sha256': plan['input_sha256'],
            'source_revision': plan['source_revision'], 'files': len(FILES),
            'approval': 'NOT_VERIFIED', 'original_input_bytes': 'NOT_INCLUDED_NOT_VERIFIED',
            'target_metadata': 'NOT_VERIFIED', 'external_existing_inputs': 'NOT_VERIFIED',
            'installation': 'NOT_RUN', 'runtime': 'NOT_RUN'}


def stamp(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_uid, row.st_gid,
            row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def ordinary(row):
    return not stat.S_ISLNK(row.st_mode) and not getattr(row, 'st_file_attributes', 0) & \
        getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)


def read_package(directory, deadline, *, clock=time.monotonic):
    """Read only exact package members; reject replaced, linked or special files.

    Caller supplies a trusted private workstation path and excludes other
    writers. This is a byte receipt check, not a target owner/ACL/SELinux audit.
    """
    require(type(deadline) in (int, float) and math.isfinite(deadline), 'PACKAGE_CHECK_DEADLINE')
    def budget():
        require(clock() < deadline, 'PACKAGE_CHECK_DEADLINE')
    path = Path(directory)
    require(path.is_absolute(), 'PACKAGE_CHECK_DIRECTORY')
    budget()
    for parent in (*reversed(path.parents), path):
        row = parent.lstat()
        require(ordinary(row) and stat.S_ISDIR(row.st_mode), 'PACKAGE_CHECK_DIRECTORY')
    before = stamp(path.lstat())
    require(set(os.listdir(path)) == FILES, 'PACKAGE_CHECK_DIRECTORY_MEMBERS')
    files, total = {}, 0
    for name in sorted(FILES):
        budget()
        target = path / name
        original = target.lstat()
        require(ordinary(original) and stat.S_ISREG(original.st_mode) and original.st_nlink == 1 and
                0 < original.st_size <= limit(name), 'PACKAGE_CHECK_FILE')
        fd = os.open(target, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_NONBLOCK', 0))
        try:
            opened = stamp(os.fstat(fd))
            # Windows path/fd stat may expose different ctime semantics. Compare
            # identity/mtime across APIs, and each complete stamp within its API.
            require(opened[:-1] == stamp(original)[:-1], 'PACKAGE_CHECK_FILE_CHANGED')
            chunks, size = [], 0
            while True:
                budget()
                chunk = os.read(fd, min(65536, limit(name) + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                require(size <= limit(name), 'PACKAGE_CHECK_FILE_SIZE')
            require(stamp(os.fstat(fd)) == opened and stamp(target.lstat()) == stamp(original),
                    'PACKAGE_CHECK_FILE_CHANGED')
            files[name] = b''.join(chunks)
            total += size
            require(total <= MAX_TOTAL, 'PACKAGE_CHECK_TOTAL_SIZE')
        finally:
            os.close(fd)
    budget()
    require(stamp(path.lstat()) == before and set(os.listdir(path)) == FILES,
            'PACKAGE_CHECK_DIRECTORY_CHANGED')
    return files


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('--package', required=True)
    p.add_argument('--plan-sha256', required=True)
    p.add_argument('--timeout', required=True, type=float)
    args = p.parse_args(argv)
    try:
        require(digest(args.plan_sha256), 'PACKAGE_CHECK_EXTERNAL_HASH')
        require(math.isfinite(args.timeout) and 0 < args.timeout <= 600, 'PACKAGE_CHECK_TIMEOUT')
        deadline = time.monotonic() + args.timeout
        files = read_package(args.package, deadline)
        result = verify_bytes(files, args.plan_sha256)
        require(time.monotonic() < deadline, 'PACKAGE_CHECK_DEADLINE')
        print(json.dumps(result, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print('{"status":"STOP","reason":"INTERRUPTED","input_preserved":true,"installation":"NOT_RUN","runtime":"NOT_RUN"}')
        return 130
    except Exception:
        # No raw plan/source/paths, exception text, command output or credentials.
        print('{"status":"STOP","input_preserved":true,"installation":"NOT_RUN","runtime":"NOT_RUN"}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
