#!/usr/bin/env python3
"""Explicit file-only installation from a trusted, separately reviewed checkout.

The installer and validator dependencies must be authenticated BEFORE invocation.
Candidate package code is never imported. No mkdir, relabel, service operation,
Docker write, policy transition, Store initialization, automatic undo or resume.
"""
import sys

if __name__ == '__main__':
    if not (sys.platform == 'linux' and sys.version_info >= (3, 10) and
            sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and
            not sys.flags.optimize):
        print('{"status":"STOP","reason":"INSTALL_INTERPRETER"}')
        raise SystemExit(2)

import os

if __name__ == '__main__' and (os.geteuid() != 0 or os.getegid() != 0):
    print('{"status":"STOP","reason":"INSTALL_ROOT"}')
    raise SystemExit(2)

import argparse
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import importlib.util
import json
import math
from pathlib import Path, PurePosixPath
import re
import stat
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'scripts/recovery'))
from harbor_recovery_docker import UnixEngine, parse_json, remaining, require
from harbor_recovery_host import (HostProvider, host_provider, LinuxReadOnly, absolute,
                                  metadata_spec, engine_profile)
from harbor_recovery_policy_backend import MANAGER, MANAGER_PROPERTIES
from harbor_recovery_protected_store import label

# Trusted validator implementation, never an implementation from the package.
_loader = importlib.util.spec_from_file_location(
    'trusted_package_receipt', ROOT / 'scripts/preparation/harbor_review_package_check.py')
receipt = importlib.util.module_from_spec(_loader)
_loader.loader.exec_module(receipt)

REQUEST_FIELDS = {'schema', 'operation', 'plan_sha256', 'hostname', 'product_uuid',
                  'boot_id', 'not_before_epoch', 'expires_epoch', 'directories',
                  'receipt_path', 'receipt_context'}


def encode(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('utf-8')


def request_bytes(raw, expected_sha256, plan, bundle, *, wall=time.time):
    require(receipt.digest(expected_sha256) and isinstance(raw, bytes) and
            0 < len(raw) <= 1024 * 1024 and receipt.sha(raw) == expected_sha256,
            'INSTALL_REQUEST_HASH')
    obj = parse_json(raw)
    require(isinstance(obj, dict) and set(obj) == REQUEST_FIELDS and
            obj['schema'] == 'fds.harbor.file-install-request.v1' and
            obj['operation'] == 'NEW_FILES_ONLY' and
            receipt.digest(obj['plan_sha256']), 'INSTALL_REQUEST_SCHEMA')
    require(obj['hostname'] == bundle['host_policy']['hostname'] and
            obj['product_uuid'] == bundle['host_policy']['product_uuid'] and
            isinstance(obj['boot_id'], str) and str(uuid.UUID(obj['boot_id'])) == obj['boot_id'],
            'INSTALL_REQUEST_IDENTITY')
    require(all(type(obj[k]) in (int, float) and math.isfinite(obj[k])
                for k in ('not_before_epoch', 'expires_epoch')) and
            obj['not_before_epoch'] <= wall() < obj['expires_epoch'], 'INSTALL_REQUEST_WINDOW')
    target = obj['receipt_path']
    require(isinstance(target, str) and re.fullmatch(
        r'/var/lib/fds-harbor-recovery/install-receipts/[0-9a-f]{32}\.jsonl', target),
        'INSTALL_RECEIPT_PATH')
    label(obj['receipt_context'])
    parents = {str(PurePosixPath(e['target']).parent) for e in plan['files']}
    parents.add(str(PurePosixPath(target).parent))
    require(isinstance(obj['directories'], dict) and set(obj['directories']) == parents,
            'INSTALL_DIRECTORY_SET')
    for path, spec in obj['directories'].items():
        require(absolute(path), 'INSTALL_DIRECTORY_PATH')
        metadata_spec(spec)
        require(spec['gid'] == 0, 'INSTALL_DIRECTORY_GID')
    require(obj['directories'][str(PurePosixPath(target).parent)]['mode'] == 0o700,
            'INSTALL_RECEIPT_DIRECTORY_MODE')
    require(target not in {e['target'] for e in plan['files']}, 'INSTALL_RECEIPT_COLLISION')
    return deepcopy(obj)


class NewFiles:
    """Descriptor-relative Linux writes in already prepared, reviewed directories.

    No ownership/label repair. Tests override uid/gid and xattr checks only.
    Production fixes root ownership and exact inherited SELinux file labels.
    Other root writers must be excluded for the entire operation.
    """
    def __init__(self, *, clock=time.monotonic, uid=0, gid=0):
        require(sys.platform == 'linux', 'INSTALL_LINUX')
        self.clock, self.uid, self.gid = clock, uid, gid

    def attrs(self, fd, expected=None):
        names = set(os.listxattr(fd))
        require(not names & {'system.posix_acl_access', 'system.posix_acl_default', 'system.nfs4_acl'},
                'INSTALL_ACL')
        if expected is not None:
            require(names == {'security.selinux'} and
                    os.getxattr(fd, 'security.selinux').rstrip(b'\0').decode('ascii') == label(expected),
                    'INSTALL_CONTEXT')

    @contextmanager
    def directory(self, path, spec, deadline):
        require(absolute(path), 'INSTALL_DIRECTORY_PATH')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        try:
            for part in (None, *PurePosixPath(path).parts[1:]):
                remaining(deadline, self.clock)
                if part is not None:
                    child = os.open(part, flags, dir_fd=fd)
                    os.close(fd)
                    fd = child
                row = os.fstat(fd)
                require(stat.S_ISDIR(row.st_mode) and row.st_uid in (0, self.uid) and
                        not row.st_mode & 0o022, 'INSTALL_UNTRUSTED_PARENT')
                self.attrs(fd)
            row = os.fstat(fd)
            require(row.st_uid == self.uid and row.st_gid == self.gid and
                    stat.S_IMODE(row.st_mode) == spec['mode'], 'INSTALL_DIRECTORY_METADATA')
            self.attrs(fd, spec['selinux'])
            yield fd
        finally:
            os.close(fd)

    def absent(self, fd, name):
        require(PurePosixPath(name).name == name and name not in ('.', '..'), 'INSTALL_FILE_NAME')
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError('INSTALL_EXISTING_TARGET')

    def metadata(self, fd, mode, context):
        row = os.fstat(fd)
        require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and
                row.st_uid == self.uid and row.st_gid == self.gid and
                stat.S_IMODE(row.st_mode) == mode, 'INSTALL_NEW_FILE_METADATA')
        self.attrs(fd, context)

    def write_all(self, fd, raw, deadline):
        view = memoryview(raw)
        while view:
            remaining(deadline, self.clock)
            count = os.write(fd, view)
            require(count > 0, 'INSTALL_SHORT_WRITE')
            view = view[count:]

    @contextmanager
    def create(self, parent, name, context):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            # Restrictive umask or unexpected label stops BEFORE payload write.
            self.metadata(fd, 0o600, context)
            os.fsync(parent)
            yield fd
        finally:
            os.close(fd)

    def payload(self, parent, entry, raw, deadline):
        name = PurePosixPath(entry['target']).name
        with self.create(parent, name, entry['selinux']) as fd:
            self.write_all(fd, raw, deadline)
            os.fsync(fd)
            os.fchmod(fd, entry['mode'])  # Only this newly created descriptor.
            os.fsync(fd)
            self.metadata(fd, entry['mode'], entry['selinux'])
            os.lseek(fd, 0, os.SEEK_SET)
            blocks = []
            while True:
                remaining(deadline, self.clock)
                block = os.read(fd, 65536)
                if not block:
                    break
                blocks.append(block)
            require(b''.join(blocks) == raw, 'INSTALL_READBACK')
            row = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(receipt.stamp(row) == receipt.stamp(os.fstat(fd)), 'INSTALL_REPLACED_TARGET')
            os.fsync(parent)

    def verify(self, parent, entry, raw, deadline):
        name = PurePosixPath(entry['target']).name
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            self.metadata(fd, entry['mode'], entry['selinux'])
            before = receipt.stamp(os.fstat(fd))
            require(os.fstat(fd).st_size == len(raw), 'INSTALL_FINAL_SIZE')
            hashed = hashlib.sha256()
            while True:
                remaining(deadline, self.clock)
                block = os.read(fd, 65536)
                if not block:
                    break
                hashed.update(block)
            require(before == receipt.stamp(os.fstat(fd)) == receipt.stamp(
                    os.stat(name, dir_fd=parent, follow_symlinks=False)) and
                    hashed.hexdigest() == entry['sha256'], 'INSTALL_FINAL_READBACK')
        finally:
            os.close(fd)


class Preflight:
    """Read-only target checks. No process/service/Engine mutation."""
    def __init__(self, bundle, plan, *, clock=time.monotonic, io=None):
        self.bundle, self.plan = deepcopy(bundle), deepcopy(plan)
        self.clock = clock
        self.io = LinuxReadOnly(clock=clock) if io is None else io
        p = self.bundle['host_policy']
        self.host = host_provider(p, UnixEngine(p['api_version'], socket_path=p['socket']),
                                 clock=clock, io=self.io)

    def __call__(self, request, deadline, *, after=False):
        remaining(deadline, self.clock)
        p = self.bundle['host_policy']
        require(self.host._identity() == request['boot_id'], 'INSTALL_BOOT_CHANGED')
        self.io.pinned(p['directory'], p['directory_spec'], 'directory', deadline)
        for path, spec in self.plan['external_existing_inputs'].items():
            self.io.pinned(path, spec, 'file', deadline)
        self.io.pinned(p['socket'], p['socket_spec'], 'socket', deadline)
        self.host._guards(deadline)
        first = {n: self.host._unit(n, deadline) for n in p['units']}
        require(engine_profile(self.host.engine.profile(deadline)) == p['engine_profile'],
                'INSTALL_ENGINE_PROFILE')
        raw = self.io.run([p['tools']['systemctl'], 'show', MANAGER, '--no-pager',
                          '--property=' + MANAGER_PROPERTIES], p['directory'], deadline)
        row = {}
        for line in raw.decode('utf-8').splitlines():
            require('=' in line, 'INSTALL_MANAGER_FORMAT')
            key, value = line.split('=', 1)
            require(key not in row, 'INSTALL_MANAGER_DUPLICATE')
            row[key] = value
        require(set(row) == set(MANAGER_PROPERTIES.split(',')), 'INSTALL_MANAGER_FIELDS')
        require(row['ActiveState'] == 'inactive' and row['SubState'] == 'dead' and
                row['MainPID'] == row['ControlPID'] == '0' and row['Job'] == row['TriggeredBy'] == '' and
                row['Transient'] == 'no' and row['DropInPaths'] == '', 'INSTALL_MANAGER_ACTIVE')
        require((row['LoadState'] == 'not-found' and row['FragmentPath'] == '' and
                 row['UnitFileState'] == '') or
                (after and row['LoadState'] == 'loaded' and row['UnitFileState'] == 'disabled' and
                 row['FragmentPath'] == self.bundle['manager']['fragment']),
                'INSTALL_MANAGER_EXISTING')
        require(first == {n: self.host._unit(n, deadline) for n in first} and
                self.host._identity() == request['boot_id'], 'INSTALL_HOST_CHANGED')
        remaining(deadline, self.clock)


def install(files, expected_plan_sha256, request_raw, expected_request_sha256, deadline,
            *, execute=False, fs=None, preflight=None, clock=time.monotonic, wall=time.time):
    require(execute is True, 'INSTALL_EXPLICIT_REQUIRED')
    receipt.verify_bytes(files, expected_plan_sha256)
    plan = parse_json(files['INSTALL_PLAN.json'])
    bundle = parse_json(files['bundle.json'])
    request = request_bytes(request_raw, expected_request_sha256, plan, bundle, wall=wall)
    require(request['plan_sha256'] == expected_plan_sha256, 'INSTALL_REQUEST_PLAN_BINDING')
    fs = NewFiles(clock=clock) if fs is None else fs
    preflight = Preflight(bundle, plan, clock=clock) if preflight is None else preflight
    def window():
        remaining(deadline, clock)
        require(request['not_before_epoch'] <= wall() < request['expires_epoch'], 'INSTALL_REQUEST_WINDOW')
    window()
    preflight(request, deadline)
    # launch trust anchor is committed last; no subsequent automatic lifecycle.
    entries = sorted(plan['files'], key=lambda e: (e['file'] == 'launch.json', e['file']))
    with ExitStack() as stack:
        parents = {p: stack.enter_context(fs.directory(p, s, deadline))
                   for p, s in sorted(request['directories'].items())}
        def parent(path):
            return parents[str(PurePosixPath(path).parent)]
        def directories():
            for path, spec in request['directories'].items():
                with fs.directory(path, spec, deadline) as fresh:
                    old = os.fstat(parents[path])
                    new = os.fstat(fresh)
                    require((old.st_dev, old.st_ino) == (new.st_dev, new.st_ino),
                            'INSTALL_DIRECTORY_REPLACED')
        for entry in entries:
            fs.absent(parent(entry['target']), PurePosixPath(entry['target']).name)
        journal = request['receipt_path']
        fs.absent(parent(journal), PurePosixPath(journal).name)
        context = request['receipt_context']
        window()
        with fs.create(parent(journal), PurePosixPath(journal).name, context) as fd:
            def record(value):
                fs.write_all(fd, encode(value), deadline)
                os.fsync(fd)
            record({'stage': 'BEGIN', 'plan_sha256': expected_plan_sha256,
                    'request_sha256': expected_request_sha256, 'source_revision': plan['source_revision'],
                    'boot_id': request['boot_id'], 'runtime': 'NOT_RUN'})
            completed = []
            try:
                for entry in entries:
                    window()
                    directories()
                    preflight(request, deadline, after=bool(completed))
                    fs.absent(parent(entry['target']), PurePosixPath(entry['target']).name)
                    record({'stage': 'CREATE_INTENT', 'file': entry['file'], 'target': entry['target'],
                            'sha256': entry['sha256']})
                    fs.payload(parent(entry['target']), entry, files[entry['file']], deadline)
                    completed.append(entry['file'])
                    record({'stage': 'FILE_VERIFIED', 'file': entry['file'], 'sha256': entry['sha256']})
                window()
                preflight(request, deadline, after=True)
                directories()
                for entry in entries:
                    fs.verify(parent(entry['target']), entry, files[entry['file']], deadline)
                record({'stage': 'FILES_INSTALLED_ONLY', 'files': completed, 'runtime': 'NOT_RUN',
                        'policy': 'NOT_CHANGED', 'service_lifecycle': 'NOT_RUN'})
            except BaseException:
                # Deadline/disk failure may prevent the STOP record itself. The
                # last durable CREATE_INTENT remains authoritative; never reset.
                try:
                    record({'stage': 'STOP_PRESERVE_PARTIAL', 'verified_files': completed,
                            'automatic_undo': 'NOT_RUN'})
                except BaseException:
                    pass
                raise
    return {'status': 'FILES_INSTALLED_ONLY', 'files': len(completed),
            'plan_sha256': expected_plan_sha256, 'request_sha256': expected_request_sha256,
            'runtime': 'NOT_RUN', 'service_lifecycle': 'NOT_RUN', 'policy': 'NOT_CHANGED',
            'store_initialization': 'NOT_RUN'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('--package', required=True)
    p.add_argument('--plan-sha256', required=True)
    p.add_argument('--request', required=True)
    p.add_argument('--request-sha256', required=True)
    p.add_argument('--timeout', required=True, type=float)
    p.add_argument('--execute', action='store_true')
    args = p.parse_args(argv)
    try:
        require(args.execute and math.isfinite(args.timeout) and 0 < args.timeout <= 600,
                'INSTALL_EXPLICIT_TIMEOUT')
        deadline = time.monotonic() + args.timeout
        files = receipt.read_package(args.package, deadline)
        # Reviewed request lives on the same trusted private input path. Bounded
        # read + external hash; package/request directory owners exclude writers.
        with Path(args.request).open('rb') as stream:
            request = stream.read(1024 * 1024 + 1)
        result = install(files, args.plan_sha256, request, args.request_sha256, deadline,
                         execute=args.execute)
        print(json.dumps(result, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print('{"status":"STOP","partial_files":"PRESERVE_IF_PRESENT","runtime":"NOT_RUN"}')
        return 130
    except Exception:
        # Do not print host input, private paths, command output or exception text.
        print('{"status":"STOP","partial_files":"PRESERVE_IF_PRESENT","runtime":"NOT_RUN"}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
