#!/usr/bin/env python3
"""Same-code v4 input transition from an authenticated, reviewed checkout.

Creates one bundle, preserves the old launch with RENAME_NOREPLACE, then creates
the new launch. Never applies nft or routes, changes policies/services or initializes Store.
Other root writers must be excluded. A partial operation is NOT resumable.

Operations:
  SAME_CODE_NFT_INPUT_ONLY   only host_policy.nft_sha256 (+ Store path/binding) differs.
  SAME_CODE_NFT_ROUTE_INPUT  additionally host_policy.network.routes_sha256 differs, for the
                             fixed P2 ROSA cold-pull return route only (infra-rosa#12 C3):
                             ADD = the live host has exactly that route, REMOVE = it has none.
"""
import sys

if __name__ == '__main__' and not (sys.platform == 'linux' and sys.version_info >= (3, 10)
        and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
        and not sys.flags.optimize):
    print('{"status":"STOP","reason":"INTERPRETER"}')
    raise SystemExit(2)

import os

if __name__ == '__main__' and (os.geteuid() != 0 or os.getegid() != 0):
    print('{"status":"STOP","reason":"ROOT"}')
    raise SystemExit(2)

import argparse
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import ctypes
import importlib.util
import json
import math
from pathlib import Path, PurePosixPath
import re
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
_loader = importlib.util.spec_from_file_location('trusted_input_install',
    ROOT / 'scripts/preparation/harbor_review_package_install.py')
base = importlib.util.module_from_spec(_loader)
_loader.loader.exec_module(base)
check = base.receipt
from harbor_recovery_bundle import BOOT_SCHEMA
from harbor_recovery_core import Controller, Plan
from harbor_recovery_docker import UnixEngine, parse_json, project, remaining, require, logger_tcp
from harbor_recovery_host import LinuxReadOnly, host_provider, metadata_spec
from harbor_recovery_policy_backend import StoppedManager
from harbor_recovery_protected_store import NAMES, label
from harbor_recovery_store import decode

FIELDS = {'schema', 'operation', 'old_plan_sha256', 'new_plan_sha256', 'hostname',
          'product_uuid', 'boot_id', 'daemon_invocation_id', 'not_before_epoch',
          'expires_epoch', 'directories', 'receipt_path', 'receipt_context',
          'preserved_launch_path', 'old_store_files', 'containers'}
LAUNCH = '/etc/fds-harbor-recovery/launch.json'
NFT_ONLY, NFT_ROUTE = 'SAME_CODE_NFT_INPUT_ONLY', 'SAME_CODE_NFT_ROUTE_INPUT'
# The only route this tool accepts as a changed input (fds-project-baseline#37 S1 item 3, infra-vpn NETWORK.md R7).
P2_RETURN_ROUTE = {'dst': '10.20.0.0/16', 'gateway': '10.1.93.51', 'dev': 'ens160'}
ROUTE_CHANGES = ('ADD_P2_RETURN', 'REMOVE_P2_RETURN')


def request_operation(raw, sha):
    """Hash-verified operation name, read before the package comparison it selects."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= 1024 * 1024 and
            check.digest(sha) and check.sha(raw) == sha, 'TRANSITION_REQUEST_HASH')
    r = parse_json(raw)
    require(isinstance(r, dict) and r.get('operation') in (NFT_ONLY, NFT_ROUTE), 'TRANSITION_REQUEST_SCOPE')
    return r['operation']


def p2_route_check(routes, change):
    """`ip -j -4 route show table all`: exactly the fixed P2 return route (ADD) or none (REMOVE)."""
    require(isinstance(routes, list) and all(isinstance(row, dict) for row in routes), 'TRANSITION_ROUTE_SCHEMA')
    rows = [row for row in routes if row.get('dst') == P2_RETURN_ROUTE['dst']]
    if change == 'REMOVE_P2_RETURN':
        require(rows == [], 'TRANSITION_P2_ROUTE_PRESENT')
        return
    require(change == 'ADD_P2_RETURN' and len(rows) == 1, 'TRANSITION_P2_ROUTE_SET')
    row = rows[0]
    require({k: row.get(k) for k in P2_RETURN_ROUTE} == P2_RETURN_ROUTE and
            row.get('table', 'main') == 'main' and row.get('type', 'unicast') == 'unicast' and
            'nexthops' not in row and 'encap' not in row, 'TRANSITION_P2_ROUTE_EXACT')


def packages(old, old_sha, new, new_sha, operation=NFT_ONLY):
    """Only nft digest (+ routes digest for NFT_ROUTE), Store path and derived bundle/launch may differ."""
    require(operation in (NFT_ONLY, NFT_ROUTE), 'TRANSITION_REQUEST_SCOPE')
    for files, sha in ((old, old_sha), (new, new_sha)):
        check.verify_bytes(files, sha)
    a, b = (parse_json(files['bundle.json']) for files in (old, new))
    pa, pb = (parse_json(files['INSTALL_PLAN.json']) for files in (old, new))
    ea, eb = ({e['file']: e for e in p['files']} for p in (pa, pb))
    require(a['schema'] == b['schema'] == BOOT_SCHEMA, 'TRANSITION_V4_REQUIRED')
    for name in check.PAYLOADS - {'bundle.json', 'launch.json'}:
        require(old[name] == new[name] and ea[name] == eb[name], 'TRANSITION_CODE_CHANGED')
    require(pa['external_existing_inputs'] == pb['external_existing_inputs'],
            'TRANSITION_EXTERNAL_INPUT_CHANGED')
    aa, bb = deepcopy(a), deepcopy(b)
    require(aa['host_policy']['nft_sha256'] != bb['host_policy']['nft_sha256'] and
            aa['store']['path'] != bb['store']['path'], 'TRANSITION_NEW_INPUT_REQUIRED')
    if operation == NFT_ROUTE:
        networks = [obj['host_policy'].get('network') for obj in (aa, bb)]
        require(all(isinstance(n, dict) and check.digest(n.get('routes_sha256')) for n in networks) and
                networks[0]['routes_sha256'] != networks[1]['routes_sha256'], 'TRANSITION_NEW_ROUTE_INPUT_REQUIRED')
    for obj in (aa, bb):
        obj['host_policy'].pop('nft_sha256')
        if operation == NFT_ROUTE:
            obj['host_policy']['network'].pop('routes_sha256')
        obj['store'].pop('path')
        obj['plan'].pop('execution_binding')
    require(aa == bb, 'TRANSITION_SCOPE_CHANGED')
    require(ea['bundle.json']['target'] != eb['bundle.json']['target'], 'TRANSITION_BUNDLE_REUSE')
    for name in ('bundle.json', 'launch.json'):
        aa, bb = deepcopy(ea[name]), deepcopy(eb[name])
        for field in ('sha256', 'bytes'):
            aa.pop(field); bb.pop(field)
        if name == 'bundle.json':
            aa.pop('target'); bb.pop('target')
        require(aa == bb, 'TRANSITION_INPUT_METADATA_CHANGED')
    return a, b, ea, eb


def request_bytes(raw, sha, old_sha, new_sha, a, b, ea, eb, wall):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 1024 * 1024 and
            check.digest(sha) and check.sha(raw) == sha, 'TRANSITION_REQUEST_HASH')
    r = parse_json(raw)
    operation = r.get('operation') if isinstance(r, dict) else None
    fields = FIELDS | ({'route_change'} if operation == NFT_ROUTE else set())
    require(isinstance(r, dict) and set(r) == fields and
            r['schema'] == 'fds.harbor.input-transition-request.v1' and
            operation in (NFT_ONLY, NFT_ROUTE) and
            r['old_plan_sha256'] == old_sha and r['new_plan_sha256'] == new_sha,
            'TRANSITION_REQUEST_SCOPE')
    require(operation == NFT_ONLY or r['route_change'] in ROUTE_CHANGES, 'TRANSITION_ROUTE_CHANGE')
    require(r['hostname'] == a['host_policy']['hostname'] and
            r['product_uuid'] == a['host_policy']['product_uuid'] and
            isinstance(r['boot_id'], str) and str(uuid.UUID(r['boot_id'])) == r['boot_id'] and
            isinstance(r['daemon_invocation_id'], str) and
            re.fullmatch('[0-9a-f]{32}', r['daemon_invocation_id']), 'TRANSITION_IDENTITY')
    require(all(type(r[k]) in (int, float) and math.isfinite(r[k])
                for k in ('not_before_epoch', 'expires_epoch')) and
            r['not_before_epoch'] <= wall() < r['expires_epoch'], 'TRANSITION_WINDOW')
    require(isinstance(r['receipt_path'], str) and re.fullmatch(
        r'/var/lib/fds-harbor-recovery/install-receipts/[0-9a-f]{32}\.jsonl', r['receipt_path']),
        'TRANSITION_RECEIPT_PATH')
    require(isinstance(r['preserved_launch_path'], str) and re.fullmatch(
        r'/etc/fds-harbor-recovery/launch\.[0-9a-f]{32}\.preserved\.json', r['preserved_launch_path']),
        'TRANSITION_PRESERVE_PATH')
    label(r['receipt_context'])
    targets = {e['target'] for e in (*ea.values(), *eb.values())}
    require(not targets & {r['receipt_path'], r['preserved_launch_path']}, 'TRANSITION_COLLISION')
    parents = {str(PurePosixPath(p).parent) for p in targets | {r['receipt_path'], r['preserved_launch_path']}}
    parents.update((a['store']['path'], b['store']['path']))
    require(isinstance(r['directories'], dict) and set(r['directories']) == parents,
            'TRANSITION_DIRECTORY_SET')
    for spec in r['directories'].values():
        metadata_spec(spec)
        require(spec['gid'] == 0, 'TRANSITION_DIRECTORY_GID')
    require(r['directories'][str(PurePosixPath(r['receipt_path']).parent)]['mode'] == 0o700,
            'TRANSITION_RECEIPT_MODE')
    for bundle in (a, b):
        require(r['directories'][bundle['store']['path']] == dict(mode=0o700, gid=0,
                selinux=bundle['store']['directory_context']), 'TRANSITION_STORE_METADATA')
    sealed = r['old_store_files']
    require(isinstance(sealed, dict) and {'state.json', 'controller.lock', 'manager.lock'} <= set(sealed)
            and len(sealed) <= 4096, 'TRANSITION_STORE_SEAL')
    for name, spec in sealed.items():
        require(isinstance(name, str) and NAMES.fullmatch(name) and not name.endswith('.pending')
                and isinstance(spec, dict)
                and set(spec) == {'sha256', 'bytes'} and check.digest(spec['sha256'])
                and type(spec['bytes']) is int and 0 <= spec['bytes'] <= 1024 * 1024,
                'TRANSITION_STORE_ENTRY')
    require(sum(v['bytes'] for v in sealed.values()) <= 32 * 1024 * 1024, 'TRANSITION_STORE_SIZE')
    require(isinstance(r['containers'], dict) and set(r['containers']) == set(a['plan']['ids']),
            'TRANSITION_CONTAINER_SET')
    for row in r['containers'].values():
        require(isinstance(row, dict) and set(row) == {'pid', 'started_at', 'restart_count'} and
                type(row['pid']) is int and row['pid'] > 0 and
                type(row['restart_count']) is int and row['restart_count'] >= 0 and
                isinstance(row['started_at'], str) and 0 < len(row['started_at']) <= 64,
                'TRANSITION_CONTAINER_BINDING')
    return deepcopy(r)


class TransitionFiles(base.NewFiles):
    def read(self, parent, entry, deadline):
        name = PurePosixPath(entry['target']).name
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            self.metadata(fd, entry['mode'], entry['selinux'])
            before = check.stamp(os.fstat(fd))
            require(os.fstat(fd).st_size == entry['bytes'], 'TRANSITION_FILE_SIZE')
            parts, size = [], 0
            while True:
                remaining(deadline, self.clock)
                block = os.read(fd, min(65536, entry['bytes'] + 1 - size))
                if not block:
                    break
                parts.append(block); size += len(block)
                require(size <= entry['bytes'], 'TRANSITION_FILE_GROWTH')
            raw = b''.join(parts)
            require(len(raw) == entry['bytes'] and check.sha(raw) == entry['sha256'] and
                    before == check.stamp(os.fstat(fd)) == check.stamp(
                        os.stat(name, dir_fd=parent, follow_symlinks=False)), 'TRANSITION_FILE_CHANGED')
            return raw
        finally:
            os.close(fd)

    def names(self, parent):
        return set(os.listdir(parent))

    @contextmanager
    def locks(self, parent, context):
        import fcntl
        with ExitStack() as stack:
            held = {}
            # Same ordering as service -> controller. Never O_CREAT or write.
            for name in ('manager.lock', 'controller.lock'):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
                stack.callback(os.close, fd)
                self.metadata(fd, 0o600, context)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                require(check.stamp(os.fstat(fd)) == check.stamp(
                    os.stat(name, dir_fd=parent, follow_symlinks=False)), 'TRANSITION_LOCK_CHANGED')
                held[name] = fd
            def verify_locks():
                for name, fd in held.items():
                    self.metadata(fd, 0o600, context)
                    require(check.stamp(os.fstat(fd)) == check.stamp(
                        os.stat(name, dir_fd=parent, follow_symlinks=False)), 'TRANSITION_LOCK_CHANGED')
            yield verify_locks

    def preserve(self, parent, entry, destination, deadline):
        self.read(parent, entry, deadline)
        name = PurePosixPath(entry['target']).name
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self.absent(parent, destination)
        remaining(deadline, self.clock)
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2  # Missing syscall/symbol: fail closed, no fallback.
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(parent, os.fsencode(name), parent, os.fsencode(destination), 1) != 0:
            raise OSError(ctypes.get_errno(), 'TRANSITION_PRESERVE_FAILED')
        os.fsync(parent)
        preserved = dict(entry, target=str(PurePosixPath(entry['target']).parent / destination))
        self.read(parent, preserved, deadline)
        after = os.stat(destination, dir_fd=parent, follow_symlinks=False)
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), 'TRANSITION_PRESERVE_INODE')
        self.absent(parent, name)


class Preflight:
    def __init__(self, bundle, *, clock=time.monotonic, engine=None, host=None, stopped=None, probe=None,
                 routes=None):
        self.bundle, self.clock = deepcopy(bundle), clock
        p = bundle['host_policy']
        self.engine = engine if engine is not None else UnixEngine(p['api_version'], socket_path=p['socket'])
        self.host = host if host is not None else host_provider(p, self.engine, clock=clock)
        # Read-only `ip -j -4 route show table all` through the policy-pinned tool (NFT_ROUTE only).
        self.routes = routes if routes is not None else lambda deadline: self._ip_routes(p, deadline)
        m = bundle['manager']
        self.stopped = stopped if stopped is not None else StoppedManager(p, m['fragment'], m['dropins'], clock=clock)
        self.probe = probe if probe is not None else lambda deadline: logger_tcp(deadline, clock)

    def _ip_routes(self, policy, deadline):
        # Same bounded, environment-scrubbed runner as the host provider; rc != 0 is a STOP.
        raw = LinuxReadOnly(clock=self.clock).run(
            [policy['tools']['ip'], '-j', '-4', 'route', 'show', 'table', 'all'], policy['directory'], deadline)
        return parse_json(raw)

    def __call__(self, request, deadline):
        end = min(deadline, self.clock() + self.bundle['plan']['max_age_seconds'])
        first = self.host(end)
        if request.get('operation') == NFT_ROUTE:
            p2_route_check(self.routes(end), request['route_change'])
        self.stopped(end)
        def inventory():
            actual = {}
            for row in self.engine.inventory(end):
                labels = row.get('Labels')
                if isinstance(labels, dict) and labels.get('com.docker.compose.project') == 'harbor':
                    service = labels.get('com.docker.compose.service')
                    require(isinstance(service, str) and service not in actual, 'TRANSITION_INVENTORY_DUPLICATE')
                    actual[service] = row.get('Id')
            require(actual == self.bundle['plan']['ids'], 'TRANSITION_INVENTORY')
        def containers():
            for name, cid in self.bundle['plan']['ids'].items():
                raw = self.engine.inspect(cid, end)
                row = project(raw, name, cid, 'harbor', fingerprint_version=2)
                require(row.fingerprint == self.bundle['plan']['fingerprints'][name] and
                        row.status == 'running' and row.health == 'healthy', 'TRANSITION_APP_STATE')
                actual = dict(pid=raw['State'].get('Pid'), started_at=raw['State'].get('StartedAt'),
                              restart_count=raw.get('RestartCount'))
                require(actual == request['containers'][name], 'TRANSITION_APP_GENERATION')
        inventory(); containers()
        require(self.probe(end) is True, 'TRANSITION_LOGGER')
        inventory(); self.stopped(end)
        last = self.host(end)
        if request.get('operation') == NFT_ROUTE:
            p2_route_check(self.routes(end), request['route_change'])
        require((first.boot, first.daemon) == (last.boot, last.daemon) ==
                (request['boot_id'], request['daemon_invocation_id']), 'TRANSITION_HOST_GENERATION')
        containers()
        remaining(end, self.clock)


def transition(old, old_sha, new, new_sha, raw, request_sha, deadline, *, execute=False,
               fs=None, preflight=None, clock=time.monotonic, wall=time.time):
    require(execute is True, 'TRANSITION_EXPLICIT_REQUIRED')
    a, b, ea, eb = packages(old, old_sha, new, new_sha, request_operation(raw, request_sha))
    r = request_bytes(raw, request_sha, old_sha, new_sha, a, b, ea, eb, wall)
    fs = TransitionFiles(clock=clock) if fs is None else fs
    preflight = Preflight(b, clock=clock) if preflight is None else preflight
    def window():
        remaining(deadline, clock)
        require(r['not_before_epoch'] <= wall() < r['expires_epoch'], 'TRANSITION_WINDOW')
    with ExitStack() as stack:
        parents = {p: stack.enter_context(fs.directory(p, s, deadline)) for p, s in sorted(r['directories'].items())}
        def parent(path):
            return parents[str(PurePosixPath(path).parent)]
        old_store, new_store = parents[a['store']['path']], parents[b['store']['path']]
        verify_locks = stack.enter_context(fs.locks(old_store, a['store']['file_context']))
        preserved = dict(ea['launch.json'], target=r['preserved_launch_path'])
        journal = r['receipt_path']
        phase = 0
        def verify():
            window()
            verify_locks()
            for path, spec in r['directories'].items():
                with fs.directory(path, spec, deadline) as fresh:
                    x, y = os.fstat(parents[path]), os.fstat(fresh)
                    require((x.st_dev, x.st_ino) == (y.st_dev, y.st_ino), 'TRANSITION_DIRECTORY_REPLACED')
            preflight(r, deadline)
            for name in check.PAYLOADS - {'launch.json'}:
                fs.verify(parent(ea[name]['target']), ea[name], old[name], deadline)
            require(fs.names(old_store) == set(r['old_store_files']) and not fs.names(new_store),
                    'TRANSITION_STORE_CHANGED')
            state = None
            for name, spec in sorted(r['old_store_files'].items()):
                entry = dict(spec, target=a['store']['path'] + '/' + name, mode=0o600,
                             selinux=a['store']['file_context'])
                value = fs.read(old_store, entry, deadline)
                if name == 'state.json':
                    state = decode(value)
            require(state.desired == 'HOLD' and state.reason == 'OPERATOR_HOLD' and
                    state.pending is None and state.health_wait is None and
                    (state.boot, state.daemon) == (r['boot_id'], r['daemon_invocation_id']) and
                    state.plan_digest == Controller(Plan(**a['plan'])).plan_digest(), 'TRANSITION_STORE_NOT_HELD')
            if phase >= 1:
                fs.verify(parent(eb['bundle.json']['target']), eb['bundle.json'], new['bundle.json'], deadline)
            else:
                fs.absent(parent(eb['bundle.json']['target']), PurePosixPath(eb['bundle.json']['target']).name)
            if phase >= 2:
                fs.verify(parent(preserved['target']), preserved, old['launch.json'], deadline)
                if phase == 2:
                    fs.absent(parent(LAUNCH), 'launch.json')
                else:
                    fs.verify(parent(LAUNCH), eb['launch.json'], new['launch.json'], deadline)
            else:
                fs.verify(parent(LAUNCH), ea['launch.json'], old['launch.json'], deadline)
                fs.absent(parent(preserved['target']), PurePosixPath(preserved['target']).name)
            window()
        verify()
        fs.absent(parent(journal), PurePosixPath(journal).name)
        with fs.create(parent(journal), PurePosixPath(journal).name, r['receipt_context']) as fd:
            def record(stage):
                window()
                fs.metadata(fd, 0o600, r['receipt_context'])
                require(check.stamp(os.fstat(fd)) == check.stamp(os.stat(
                    PurePosixPath(journal).name, dir_fd=parent(journal), follow_symlinks=False)),
                    'TRANSITION_RECEIPT_REPLACED')
                fs.write_all(fd, base.encode(dict(stage=stage, phase=phase, request_sha256=request_sha,
                    old_plan_sha256=old_sha, new_plan_sha256=new_sha, runtime='NOT_RUN')), deadline)
                os.fsync(fd)
            try:
                record('BEGIN')
                for step in ('CREATE_BUNDLE', 'PRESERVE_LAUNCH', 'CREATE_LAUNCH'):
                    verify(); record(step + '_INTENT'); window()
                    if step == 'PRESERVE_LAUNCH':
                        fs.preserve(parent(LAUNCH), ea['launch.json'], PurePosixPath(preserved['target']).name, deadline)
                    else:
                        name = 'bundle.json' if phase == 0 else 'launch.json'
                        fs.payload(parent(eb[name]['target']), eb[name], new[name], deadline)
                    phase += 1
                    verify(); record(step + '_VERIFIED')
                record('INPUT_FILES_TRANSITIONED_ONLY')
            except BaseException:
                try:
                    record('STOP_PRESERVE_PARTIAL')
                except BaseException:
                    pass
                raise
    return dict(status='INPUT_FILES_TRANSITIONED_ONLY', created=2, preserved=1,
                service_lifecycle='NOT_RUN', policy='NOT_CHANGED', firewall='NOT_CHANGED',
                route='NOT_CHANGED', store_initialization='NOT_RUN', runtime='NOT_RUN',
                operation=r['operation'], request_sha256=request_sha)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('old-package', 'old-plan-sha256', 'package', 'plan-sha256', 'request', 'request-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--timeout', required=True, type=float)
    p.add_argument('--execute', action='store_true')
    args = p.parse_args(argv)
    try:
        require(args.execute and math.isfinite(args.timeout) and 0 < args.timeout <= 600, 'TRANSITION_TIMEOUT')
        end = time.monotonic() + args.timeout
        old, new = (check.read_package(path, end) for path in (args.old_package, args.package))
        with Path(args.request).open('rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
        print(json.dumps(transition(old, args.old_plan_sha256, new, args.plan_sha256, raw,
            args.request_sha256, end, execute=True), sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt):
        print('{"status":"STOP","partial_files":"PRESERVE_IF_PRESENT","runtime":"NOT_RUN"}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
