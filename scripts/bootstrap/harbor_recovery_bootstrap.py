#!/usr/bin/env python3
"""Trusted standalone entry point: verify all source bytes before importing.

This file, the interpreter and its standard library must be installed through
a trusted path first. A file cannot authenticate its own already-running code.
No installer or systemd enable/start here.
"""
import sys

# Check interpreter isolation before importing even argparse/json. Otherwise an
# unsafe invocation could execute a same-directory impostor before the guard.
if __name__ == '__main__':
    if not (sys.platform == 'linux' and sys.version_info >= (3, 10) and sys.flags.isolated and sys.flags.no_site and
            sys.dont_write_bytecode and not sys.flags.optimize):
        print('{"stage":"STOP","reason":"BOOTSTRAP_FLAGS_OR_PLATFORM"}')
        raise SystemExit(2)

import os

if __name__ == '__main__' and (os.geteuid() != 0 or os.getegid() != 0):
    print('{"stage":"STOP","reason":"BOOTSTRAP_ROOT_REQUIRED"}')
    raise SystemExit(2)

import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
import importlib.abc
import importlib.util
import json
import math
from pathlib import PurePosixPath
import re
import stat
import time

PREFIX = 'harbor_recovery_'
MODULES = frozenset(PREFIX + suffix for suffix in (
    'core', 'docker', 'executor', 'store', 'host', 'policy_backend',
    'transition', 'protected_store', 'bundle', 'service', 'control'))
OPERATIONS = ('verify', 'verify-writer', 'probe-create', 'probe-reopen', 'initialize', 'policy-install', 'arm', 'hold', 'policy-rollback', 'serve',
              'state', 'reconcile', 'graceful-stop', 'settle-stop-readback')
LAUNCH_PATH = '/etc/fds-harbor-recovery/launch.json'
MAX_JSON = 8 * 1024 * 1024
MAX_SOURCE = 1024 * 1024


class BootstrapError(ValueError):
    """Fixed local error codes only; other exception text never reaches output."""


def require(ok, code):
    if not ok: raise BootstrapError(code)


def absolute(path):
    return (isinstance(path, str) and re.fullmatch('/[A-Za-z0-9_./-]+', path) and
            path != '/' and str(PurePosixPath(path)) == path and '..' not in path.split('/'))


def context(value):
    require(isinstance(value, str) and re.fullmatch('[A-Za-z0-9_:.,-]+', value), 'BOOTSTRAP_CONTEXT')
    return value


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)


def remaining(deadline, clock):
    require(type(deadline) in (int, float) and math.isfinite(deadline) and
            deadline > clock(), 'BOOTSTRAP_DEADLINE')


def parse(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_JSON, 'BOOTSTRAP_JSON_SIZE')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'BOOTSTRAP_DUPLICATE_KEY')
            result[key] = value
        return result
    def invalid(_): raise BootstrapError('BOOTSTRAP_NONFINITE_JSON')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid)


def spec(value):
    require(isinstance(value, dict) and set(value) == {'sha256', 'mode', 'gid', 'selinux'} and
            sha(value['sha256']) and type(value['mode']) is int and 0 <= value['mode'] <= 0o777 and
            not value['mode'] & 0o022 and type(value['gid']) is int and value['gid'] == 0,
            'BOOTSTRAP_FILE_SPEC')
    context(value['selinux'])
    return deepcopy(value)


class SecureReader:
    """Root-owned local files, no symlink/ACL/unknown file xattr, no writes.

    uid/gid overrides are only for isolated unprivileged tests. CLI fixes both
    to zero. Interpreter and bootstrap provenance are outside this reader.
    """
    def __init__(self, *, clock=time.monotonic, uid=0, gid=0):
        self.clock, self.uid, self.gid = clock, uid, gid

    def _attrs(self, fd, label=None):
        attrs = set(os.listxattr(fd))
        require(not attrs & {'system.posix_acl_access', 'system.posix_acl_default', 'system.nfs4_acl'}, 'BOOTSTRAP_ACL')
        if label is not None:
            require(attrs == {'security.selinux'}, 'BOOTSTRAP_XATTR')
            require(os.getxattr(fd, 'security.selinux').rstrip(b'\0').decode('ascii') == label,
                    'BOOTSTRAP_LABEL')

    @contextmanager
    def _open(self, path):
        require(sys.platform == 'linux' and absolute(path), 'BOOTSTRAP_LINUX_PATH')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open('/', flags | os.O_DIRECTORY)
        file = None
        try:
            parts = PurePosixPath(path).parts[1:]
            for part in (None, *parts[:-1]):
                if part is not None:
                    child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
                    os.close(parent); parent = child
                row = os.fstat(parent)
                require(row.st_uid in (0, self.uid) and not row.st_mode & 0o022, 'BOOTSTRAP_PARENT')
                self._attrs(parent)
            file = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=parent)
            yield file
        finally:
            if file is not None: os.close(file)
            os.close(parent)

    def _metadata(self, fd, expected, limit):
        row = os.fstat(fd)
        require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_uid == self.uid and
                row.st_gid == self.gid and stat.S_IMODE(row.st_mode) == expected['mode'] and
                0 < row.st_size <= limit, 'BOOTSTRAP_FILE')
        self._attrs(fd, expected['selinux'])
        return (row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode, row.st_nlink,
                row.st_size, row.st_mtime_ns, row.st_ctime_ns)

    def _bytes(self, path, expected, deadline, limit):
        expected = spec(expected)
        remaining(deadline, self.clock)
        with self._open(path) as fd:
            before = self._metadata(fd, expected, limit)
            chunks, size = [], 0
            while True:
                remaining(deadline, self.clock)
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk: break
                chunks.append(chunk); size += len(chunk)
                require(size <= limit, 'BOOTSTRAP_FILE_SIZE')
            require(before == self._metadata(fd, expected, limit), 'BOOTSTRAP_FILE_CHANGED')
        raw = b''.join(chunks)
        remaining(deadline, self.clock)
        return raw

    def read(self, path, expected, deadline, limit):
        raw = self._bytes(path, expected, deadline, limit)
        require(hashlib.sha256(raw).hexdigest() == expected['sha256'], 'BOOTSTRAP_HASH')
        return raw

    def root_launch(self, expected_context, deadline):
        # This fixed root:root/0400 record is a trust anchor installed only after
        # external approval/hash verification. It does NOT authenticate itself.
        expected = {'mode': 0o400, 'gid': 0, 'selinux': context(expected_context), 'sha256': '0'*64}
        return self._bytes(LAUNCH_PATH, expected, deadline, 4096)


class Launch:
    def __init__(self, expected_context, deadline, *, reader=None, clock=time.monotonic):
        self.reader = reader if reader is not None else SecureReader(clock=clock)
        self.context, self.clock = context(expected_context), clock
        self.raw = self.reader.root_launch(self.context, deadline)
        obj = parse(self.raw)
        require(isinstance(obj, dict) and set(obj) == {'version', 'bundle', 'sha256', 'context'} and
                type(obj['version']) is int and obj['version'] == 1 and absolute(obj['bundle']) and
                obj['bundle'].endswith('.json') and obj['bundle'] != LAUNCH_PATH and sha(obj['sha256']),
                'BOOTSTRAP_LAUNCH_SCHEMA')
        context(obj['context'])
        self.data = obj

    def verify(self, deadline):
        require(self.reader.root_launch(self.context, deadline) == self.raw, 'BOOTSTRAP_LAUNCH_CHANGED')
        remaining(deadline, self.clock)


def collect(path, expected_sha256, expected_context, deadline, *, reader=None, clock=time.monotonic):
    """Minimal envelope validation before any project code runs.

    Full host/Plan/binding validation is deliberately performed only after all
    approved modules have passed metadata, byte hash and syntax checks.
    """
    require(absolute(path) and path.endswith('.json') and sha(expected_sha256), 'BOOTSTRAP_EXTERNAL_PIN')
    reader = reader if reader is not None else SecureReader(clock=clock)
    bundle_spec = {'sha256': expected_sha256, 'mode': 0o600, 'gid': 0, 'selinux': context(expected_context)}
    raw = reader.read(path, bundle_spec, deadline, MAX_JSON)
    obj = parse(raw)
    require(isinstance(obj, dict) and obj.get('schema') in
            ('fds.harbor.recovery.bundle.v2', 'fds.harbor.recovery.bundle.production.v2',
             'fds.harbor.recovery.bundle.production.v3', 'fds.harbor.recovery.bundle.production.v4'), 'BOOTSTRAP_SCHEMA')
    require(type(obj.get('host_policy')) is dict and obj['host_policy'].get('version') ==
            {'fds.harbor.recovery.bundle.v2': 1, 'fds.harbor.recovery.bundle.production.v2': 2,
             'fds.harbor.recovery.bundle.production.v3': 3,
             'fds.harbor.recovery.bundle.production.v4': 4}[obj['schema']], 'BOOTSTRAP_HOST_SCOPE')
    source = obj.get('source')
    require(isinstance(source, dict) and set(source) == {'revision', 'directory', 'files'} and
            isinstance(source['revision'], str) and re.fullmatch('[0-9a-f]{40}', source['revision']) and
            source['directory'] == '/opt/fds-harbor-recovery/versions/' + source['revision'] and
            isinstance(source['files'], dict) and set(source['files']) == {n+'.py' for n in MODULES},
            'BOOTSTRAP_SOURCE')
    pins = obj.get('host_policy', {}).get('files') if isinstance(obj.get('host_policy'), dict) else None
    require(isinstance(pins, dict) and path not in pins, 'BOOTSTRAP_PINS')
    code = {}
    for name in sorted(MODULES):
        file = source['directory'] + '/' + name + '.py'
        expected = spec(pins.get(file))
        require(source['files'][name+'.py'] == expected['sha256'], 'BOOTSTRAP_SOURCE_PIN')
        payload = reader.read(file, expected, deadline, MAX_SOURCE)
        # Compile verified bytes, never reopen an unverified pathname for import.
        code[name] = compile(payload.decode('utf-8'), file, 'exec', dont_inherit=True)
    require(reader.read(path, bundle_spec, deadline, MAX_JSON) == raw, 'BOOTSTRAP_BUNDLE_CHANGED')
    remaining(deadline, clock)
    return code, source['revision']


class VerifiedImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Fresh process only. Project imports cannot fall through to sys.path/pyc."""
    def __init__(self, code):
        require(isinstance(code, dict) and set(code) == MODULES, 'BOOTSTRAP_MODULE_SET')
        self.code = dict(code)

    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(PREFIX):
            require(fullname in self.code and path is None and target is None, 'BOOTSTRAP_IMPORT_NAME')
            return importlib.util.spec_from_loader(fullname, self, origin=self.code[fullname].co_filename)
        return None

    def create_module(self, spec): return None

    def exec_module(self, module):
        require(module.__name__ in self.code, 'BOOTSTRAP_IMPORT_NAME')
        module.__file__ = self.code[module.__name__].co_filename
        exec(self.code[module.__name__], module.__dict__)

    def __enter__(self):
        require(not any(n.startswith(PREFIX) for n in sys.modules), 'BOOTSTRAP_ALREADY_IMPORTED')
        require(not any(isinstance(f, VerifiedImporter) for f in sys.meta_path), 'BOOTSTRAP_NESTED')
        sys.meta_path.insert(0, self)
        return self

    def __exit__(self, kind, value, tb):
        sys.meta_path.remove(self)
        for name in tuple(sys.modules):
            if name.startswith(PREFIX): del sys.modules[name]


def runtime_guard():
    # Required even for verify; no unsafe fallback or environment re-exec.
    require(sys.platform == 'linux' and os.geteuid() == 0 and os.getegid() == 0, 'BOOTSTRAP_ROOT_LINUX')
    require(sys.version_info >= (3, 10), 'BOOTSTRAP_PYTHON_VERSION')
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'BOOTSTRAP_FLAGS_REQUIRED')
    require(not sys.flags.optimize, 'BOOTSTRAP_OPTIMIZE_FORBIDDEN')


def operate(module, bundle, operation, deadline, *, execute, state_pin=None, stop_seconds=None,
            claim_pin=None, ack_pin=None,
            clock=time.monotonic):
    require(operation in OPERATIONS, 'BOOTSTRAP_OPERATION')
    require(operation in ('verify','verify-writer','state') or execute is True, 'BOOTSTRAP_EXECUTE_REQUIRED')
    require(operation != 'serve', 'BOOTSTRAP_SERVE_NEEDS_OWNER')
    require((sha(state_pin) if operation in ('reconcile','graceful-stop','settle-stop-readback') else state_pin is None),
            'BOOTSTRAP_STATE_PIN_ARGUMENT')
    require((sha(claim_pin) and sha(ack_pin) if operation == 'settle-stop-readback' else
             claim_pin is None and ack_pin is None), 'BOOTSTRAP_STOP_RECORD_ARGUMENTS')
    require((type(stop_seconds) in (int,float) and math.isfinite(stop_seconds) and 0 < stop_seconds <= 600
             if operation == 'graceful-stop' else stop_seconds is None), 'BOOTSTRAP_STOP_BUDGET_ARGUMENT')
    remaining(deadline, clock)
    if operation == 'verify':
        bundle.verify(deadline)
        return 0, {'stage': 'INPUT_SOURCE_VERIFIED', 'runtime': 'NOT_RUN'}
    if operation == 'verify-writer':
        module.verify_store_writer(bundle, deadline, clock=clock)
        return 0, {'stage': 'STORE_WRITER_VERIFIED', 'store_io': 'NONE', 'creation_probe': 'STILL_REQUIRED'}
    if operation in ('probe-create', 'probe-reopen'):
        return 0, module.probe_store_writer(bundle, operation, deadline, clock=clock)
    components = module.build(bundle, deadline, clock=clock)
    if operation == 'state':
        return 0, dict(components['control'].inspect_state(),stage='STATE_READ')
    if operation == 'reconcile':
        state = components['control'].reconcile(state_pin,deadline,explicit=True)
        return 0, {'stage':state.reason,'desired':state.desired,'prior_ack':'NOT_INFERRED'}
    if operation == 'graceful-stop':
        state = components['control'].stop(state_pin,deadline,per_container_seconds=stop_seconds,explicit=True)
        return (0 if state.reason == 'APPS_STOPPED_LOGGER_PRESERVED' else 2), {'stage':state.reason,'desired':state.desired}
    if operation == 'settle-stop-readback':
        state = components['control'].settle_acknowledged_stop(state_pin,claim_pin,ack_pin,deadline,explicit=True)
        return 0, {'stage':state.reason,'desired':state.desired,'runtime':'READBACK_STATE_ONLY',
                   'engine_post':'NONE','prior_ack':'RECORDED_HTTP_204'}
    if operation == 'initialize':
        module.initialize_store(components, deadline, clock=clock)
        return 0, {'stage': 'INITIAL_HOLD_CREATED', 'runtime': 'STATE_ONLY'}
    if operation == 'policy-install':
        record = components['transition'].install(deadline, explicit=True)
        ok = record['phase'] == 'INSTALLED_HOLD'
        return (0 if ok else 2), {'stage': record['phase'], 'reason': record['reason'], 'runtime': 'POLICY_ONLY'}
    if operation == 'policy-rollback':
        record = components['transition'].rollback(deadline, explicit=True)
        ok = record['phase'] == 'ROLLED_BACK'
        return (0 if ok else 2), {'stage': record['phase'], 'reason': record['reason'], 'runtime': 'POLICY_ONLY'}
    if operation == 'arm':
        state = components['activation'].arm_initial(deadline, explicit=True)
        return 0, {'stage': 'INITIAL_ARMED', 'desired': state.desired, 'runtime': 'STATE_ONLY'}
    executor = components['executor']
    executor.open()
    state = executor.hold()
    return 0, {'stage': 'OPERATOR_HOLD', 'desired': state.desired, 'runtime': 'STATE_ONLY'}


def parser():
    value = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    value.add_argument('operation', choices=OPERATIONS)
    value.add_argument('--bundle')
    value.add_argument('--sha256')
    value.add_argument('--launch')
    value.add_argument('--state-sha256')
    value.add_argument('--claim-sha256')
    value.add_argument('--ack-sha256')
    value.add_argument('--stop-seconds',type=float)
    value.add_argument('--context', required=True)
    value.add_argument('--timeout', required=True, type=float)
    value.add_argument('--execute', action='store_true', help='Explicitly allow the named mutation only')
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        runtime_guard()
        require(math.isfinite(args.timeout) and 0 < args.timeout <= 600, 'BOOTSTRAP_TIMEOUT')
        require(args.operation in ('verify','verify-writer','state') or args.execute, 'BOOTSTRAP_EXECUTE_REQUIRED')
        require(args.operation in ('reconcile','graceful-stop','settle-stop-readback') or args.state_sha256 is None,
                'BOOTSTRAP_STATE_PIN_ARGUMENT')
        require((sha(args.claim_sha256) and sha(args.ack_sha256) if args.operation == 'settle-stop-readback' else
                 args.claim_sha256 is None and args.ack_sha256 is None), 'BOOTSTRAP_STOP_RECORD_ARGUMENTS')
        require(args.operation == 'graceful-stop' or args.stop_seconds is None,'BOOTSTRAP_STOP_BUDGET_ARGUMENT')
        deadline = time.monotonic() + args.timeout
        launch = None
        if args.operation == 'serve':
            require(args.launch == LAUNCH_PATH and args.bundle is None and args.sha256 is None,
                    'BOOTSTRAP_LAUNCH_ARGUMENTS')
            launch = Launch(args.context, deadline)
            path, pin, label = (launch.data[k] for k in ('bundle', 'sha256', 'context'))
        else:
            require(args.launch is None and args.bundle is not None and args.sha256 is not None,
                    'BOOTSTRAP_BUNDLE_ARGUMENTS')
            path, pin, label = args.bundle, args.sha256, args.context
        code, revision = collect(path, pin, label, deadline)
        with VerifiedImporter(code):
            module = importlib.import_module('harbor_recovery_bundle')
            require(module.MODULES == {n+'.py' for n in MODULES}, 'BOOTSTRAP_LIBRARY_SET')
            bundle = module.load_bundle(path, pin, label, deadline)
            if launch is None:
                rc, report = operate(module, bundle, args.operation, deadline, execute=args.execute,
                                     state_pin=args.state_sha256,stop_seconds=args.stop_seconds,
                                     claim_pin=args.claim_sha256,ack_pin=args.ack_sha256)
            else:
                service = importlib.import_module('harbor_recovery_service')
                parts = module.build(bundle, deadline)
                executor = parts['executor']
                obj = bundle.data
                owner = service.ActiveOwner(obj['host_policy'], obj['manager'])
                executor.backend.host_provider = service.RuntimeHost(executor.backend.host_provider,
                                                                      owner, launch.verify)
                # Validate target, source and actual own unit before lease/state writes.
                executor.backend.host_provider(deadline)
                def emit(row): print(json.dumps(row, sort_keys=True), flush=True)
                with service.shutdown_event() as event:
                    rc = service.run(executor, event, poll_seconds=1.0,
                                     verify_launch=lambda: launch.verify(time.monotonic()+5), report=emit)
                report = {'stage': 'MANAGER_RETURNED', 'exit_code': rc}
        print(json.dumps(dict(report, source_revision=revision, bundle_sha256=pin), sort_keys=True))
        return rc
    except KeyboardInterrupt:
        print('{"stage":"INTERRUPTED","records":"PRESERVED"}')
        return 130
    except Exception as error:
        # Paths, Docker responses, config and exception text may contain secrets.
        reason = error.args[0] if isinstance(error, BootstrapError) and error.args else None
        if not isinstance(reason, str) or not re.fullmatch('[A-Z][A-Z_]{1,63}', reason):
            reason = 'VERIFICATION_OR_OPERATION_FAILED'
        print(json.dumps({'stage': 'STOP', 'reason': reason, 'records': 'PRESERVED'}, sort_keys=True))
        return 2


if __name__ == '__main__': raise SystemExit(main())
