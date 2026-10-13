"""Pinned Linux Compose transport for one reviewed service at a time.

No CLI, defaults for real inputs, installer or host authorization. The caller
must hold the durable Sequence claim and supply the freshly verified generation,
complete preservation and protected-source guards. Outputs may contain secrets:
only bounded private bytes plus fixed, hashed diagnostics are retained here.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import threading
import time

from harbor_address_input import encode_stdin, expected_model, validate_rendered
from harbor_address_sequence import ORDER, SERVICES, NEW_ADDRESS, OLD_ADDRESS, fingerprint

MAX_OUTPUT = 8 * 1024 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def remaining(deadline, clock):
    now = clock()
    require(type(now) in (int, float) and type(deadline) in (int, float) and
            math.isfinite(now) and math.isfinite(deadline) and 0 <= now < deadline, 'COMPOSE_DEADLINE')
    return deadline - now


def parse(raw):
    require(type(raw) is bytes and len(raw) <= MAX_OUTPUT, 'COMPOSE_JSON_SIZE')
    def unique(items):
        value = {}
        for k, v in items:
            require(k not in value, 'COMPOSE_JSON_DUPLICATE')
            value[k] = v
        return value
    def invalid(_):
        raise ValueError('COMPOSE_JSON_INVALID')
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except Exception:
        raise ValueError('COMPOSE_JSON_INVALID') from None


def execution_model(base, candidate, *, resource_names, legacy_bindings=None, db_preserved=False):
    """Address-only comparison THEN explicit existing-resource translation.

    resource_names must be taken from separately verified current network and
    named-volume inventories. External references prevent Compose's create phase
    from reconciling/deleting these resources. This changes execution metadata,
    not the approved service definitions; it is not proof resources exist.
    """
    base = expected_model(base)
    candidate = expected_model(candidate)
    expected = deepcopy(base)
    require(type(db_preserved) is bool, 'ADDRESS_SCOPE')
    if db_preserved:
        db = expected['services']['postgresql']
        require(db.get('restart') == 'always' and db.get('logging', {}).get('driver') == 'syslog' and
                db['logging'].get('options', {}).get('syslog-address') == NEW_ADDRESS, 'BASE_PRESERVED_DB')
    for service in (ORDER[1:] if db_preserved else ORDER):
        row = expected['services'][service]
        require(row.get('restart') == 'always' and type(row.get('logging')) is dict and
                row['logging'].get('driver') == 'syslog' and
                row['logging'].get('options', {}).get('syslog-address') == OLD_ADDRESS, 'BASE_ADDRESS')
        row['logging']['options']['syslog-address'] = NEW_ADDRESS
    require(fingerprint(expected) == fingerprint(candidate), 'ADDRESS_SCOPE_CHANGED')
    require(candidate.get('name') == 'harbor', 'COMPOSE_PROJECT')
    require(set(candidate) <= {'name', 'services', 'networks', 'volumes'}, 'COMPOSE_TOP_LEVEL')
    require(type(resource_names) is dict and set(resource_names) == {'networks', 'volumes'}, 'RESOURCE_NAMES')
    for kind in ('networks', 'volumes'):
        declared = candidate.get(kind, {})
        names = resource_names[kind]
        require(type(declared) is dict and type(names) is dict and set(names) == set(declared), 'RESOURCE_SET')
        require(len(set(names.values())) == len(names), 'RESOURCE_DUPLICATE')
        for key, value in declared.items():
            name = names[key]
            require(type(value) is dict and type(name) is str and
                    re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', name) and
                    value.get('name') == name, 'RESOURCE_NAME')
        if kind in candidate:
            candidate[kind] = {key: {'name': names[key], 'external': True} for key in names}
            if kind == 'networks':
                # Compose 5.6.0 renders an empty IPAM object for external
                # networks. Make it explicit; never ignore populated IPAM.
                for value in candidate[kind].values():
                    value['ipam'] = {}
    validate_execution_model(candidate)
    if legacy_bindings is not None:
        candidate = legacy_bind_model(candidate, legacy_bindings)
    validate_execution_model(candidate, legacy_bindings=legacy_bindings)
    return candidate


def legacy_bind_model(model, bindings):
    """Retain only exact existing legacy Binds, including SELinux z/Z.

    Compose 5.6 uses the Mount API when create_host_path=false, which cannot
    carry SELinux options. This translation is explicit, never inferred from a
    successful render. The consumer must independently pin existing host paths.
    """
    require(type(bindings) is dict and set(bindings) == set(SERVICES), 'LEGACY_BIND_SERVICES')
    result = deepcopy(model)
    for service, row in result['services'].items():
        values = bindings[service]
        require(type(values) is list and all(type(v) is str for v in values), 'LEGACY_BIND_LIST')
        wanted = {}
        for v in values:
            parts = v.split(':')
            require(len(parts) == 3 and parts[0].startswith('/') and parts[1].startswith('/') and
                    parts[1] not in wanted and parts[2] in ('rw', 'ro', 'rw,z', 'ro,z', 'rw,Z', 'ro,Z'), 'LEGACY_BIND_FORMAT')
            wanted[parts[1]] = v
        actual = {}
        for m in row.get('volumes', []):
            if m['type'] != 'bind': continue
            options = m['bind']
            require(set(m) <= {'type','source','target','read_only','bind'} and
                    set(options) <= {'selinux','create_host_path'} and
                    type(m.get('read_only', False)) is bool and
                    options.get('selinux', '') in ('','z','Z'), 'LEGACY_BIND_OPTIONS')
            mode = 'ro' if m.get('read_only', False) else 'rw'
            if options.get('selinux'): mode += ',' + options['selinux']
            actual[m['target']] = m['source'] + ':' + m['target'] + ':' + mode
            options['create_host_path'] = True
        require(actual == wanted, 'LEGACY_BIND_SCOPE')
    return result


def validate_execution_model(candidate, *, legacy_bindings=None):
    """Recheck safety shape at consumption, even if builder was not called."""
    candidate = expected_model(candidate)
    if legacy_bindings is not None:
        require(candidate == legacy_bind_model(candidate, legacy_bindings), 'LEGACY_BIND_MODEL')
    require(type(candidate) is dict and candidate.get('name') == 'harbor' and
            set(candidate) <= {'name', 'services', 'networks', 'volumes'} and
            type(candidate.get('services')) is dict and set(candidate['services']) == set(SERVICES), 'COMPOSE_MODEL')
    for kind in ('networks', 'volumes'):
        keys = {'name', 'external', 'ipam'} if kind == 'networks' else {'name', 'external'}
        require(type(candidate.get(kind, {})) is dict and all(type(v) is dict and
                set(v) == keys and v.get('ipam', {}) == {} and v['external'] is True and type(v['name']) is str and
                re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', v['name'])
                for v in candidate.get(kind, {}).values()), 'COMPOSE_EXTERNAL_RESOURCES')
    forbidden = {'post_start', 'pre_stop', 'develop', 'provider', 'models', 'use_api_socket',
                 'build', 'env_file', 'extends', 'secrets', 'configs', 'volumes_from',
                 'links', 'external_links', 'profiles', 'scale', 'deploy'}
    for service, row in candidate['services'].items():
        require(not any(key in row for key in forbidden), 'COMPOSE_SIDE_EFFECT_FEATURE')
        require(not row.get('network_mode') and type(row.get('networks')) is dict and
                set(row['networks']) <= set(candidate.get('networks', {})) and row['networks'], 'COMPOSE_NETWORKS')
        require(type(row.get('container_name')) is str and row['container_name'], 'COMPOSE_CONTAINER_NAME')
        require(type(row.get('stop_signal', 'SIGTERM')) is str and
                row.get('stop_signal', 'SIGTERM').upper() not in ('SIGKILL', 'KILL', '9'), 'COMPOSE_FORCE_SIGNAL')
        for mount in row.get('volumes', []):
            if mount['type'] == 'bind':
                require(mount['bind']['create_host_path'] is (legacy_bindings is not None), 'BIND_CREATION_FORBIDDEN')
            else:
                require(mount.get('source') in candidate.get('volumes', {}), 'NAMED_VOLUME_REQUIRED')


def bind_source_paths(bindings):
    return {v.split(':')[0].rstrip('/') or '/' for values in bindings.values() for v in values}


def expected_process_render(model, *, legacy_bindings=None):
    expected = expected_model(model)
    if legacy_bindings is not None:
        validate_execution_model(model, legacy_bindings=legacy_bindings)
        # Verified Compose5.6.0 config serialization omits true; false remains
        # explicit. Do not read this omission back as a new execution input.
        for row in expected['services'].values():
            for m in row.get('volumes', []):
                if m['type'] == 'bind': del m['bind']['create_host_path']
    return expected


def validate_process_render(model, rendered, *, legacy_bindings=None):
    require(fingerprint(expected_process_render(model,legacy_bindings=legacy_bindings)) == fingerprint(rendered),
            'INPUT_ROUNDTRIP_CHANGED')
    return {'resolved_input_roundtrip':'MATCHED','runtime_apply':'NOT_PERFORMED'}


def bind_source_metadata(path, *, deadline, clock=time.monotonic):
    """Read each no-symlink component; never create, chmod or read file contents.

    Directory content/timestamps may change while an application runs; inode,
    type, owner, permission and security context stay pinned. This is a bounded
    drift check, NOT atomic exclusion of a concurrent privileged path change.
    """
    require(type(path) is str and path.startswith('/') and str(PurePosixPath(path)) == path and
            '..' not in PurePosixPath(path).parts and '\0' not in path and path != '/', 'BIND_SOURCE_PATH')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    chain, result = [], []
    try:
        fd = os.open('/', flags | os.O_DIRECTORY); chain.append((fd, None, '/'))
        parts = PurePosixPath(path).parts[1:]
        for index in range(len(parts)+1):
            remaining(deadline, clock)
            s = os.fstat(fd); attrs = sorted(os.listxattr(fd))
            directory = stat.S_ISDIR(s.st_mode)
            require((directory or stat.S_ISREG(s.st_mode)) and (directory or s.st_nlink == 1) and
                    not s.st_mode & 0o7022 and set(attrs) <= {'security.selinux'}, 'BIND_SOURCE_METADATA')
            require(index == len(parts) or directory, 'BIND_SOURCE_PARENT')
            label = os.getxattr(fd, 'security.selinux').rstrip(b'\0').decode('ascii') if attrs else None
            result.append(dict(device=s.st_dev,inode=s.st_ino,uid=s.st_uid,gid=s.st_gid,
                               mode=stat.S_IMODE(s.st_mode),directory=directory,selinux=label))
            if index < len(parts):
                child = os.open(parts[index], flags | (os.O_DIRECTORY if index < len(parts)-1 else 0), dir_fd=fd)
                chain.append((child, fd, parts[index])); fd = child
        for current, parent, name in chain[1:]:
            a, b = os.fstat(current), os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((a.st_dev,a.st_ino) == (b.st_dev,b.st_ino), 'BIND_SOURCE_PATH_CHANGED')
        remaining(deadline, clock)
        return result
    finally:
        for fd, _, _ in reversed(chain): os.close(fd)


def validate_bind_sources(bindings, specs):
    require(type(specs) is dict and set(specs) == bind_source_paths(bindings), 'BIND_SOURCE_SET')
    for path, chain in specs.items():
        require(type(chain) is list and len(chain) == len(PurePosixPath(path).parts), 'BIND_SOURCE_CHAIN')
        for index, row in enumerate(chain):
            require(type(row) is dict and set(row) == {'device','inode','uid','gid','mode','directory','selinux'} and
                    all(type(row[k]) is int and row[k] >= 0 for k in ('device','inode','uid','gid','mode')) and
                    row['mode'] <= 0o777 and not row['mode'] & 0o022 and type(row['directory']) is bool and
                    (index == len(chain)-1 or row['directory']) and
                    type(row['selinux']) is str and row['selinux'] and '\0' not in row['selinux'], 'BIND_SOURCE_PIN')


def check_bind_sources(specs, *, deadline, clock=time.monotonic):
    for path, expected in specs.items():
        require(bind_source_metadata(path, deadline=deadline, clock=clock) == expected, 'BIND_SOURCE_CHANGED')


def _signature(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _metadata(fd, *, directory, context=None, exact_mode=None):
    s = os.fstat(fd)
    require(s.st_uid == 0 and s.st_gid == 0 and not s.st_mode & 0o022 and
            (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)), 'PROTECTED_METADATA')
    require(not s.st_mode & 0o7000, 'PROTECTED_SPECIAL_MODE')
    if not directory:
        require(s.st_nlink == 1, 'PROTECTED_LINKS')
    if exact_mode is not None:
        require(stat.S_IMODE(s.st_mode) == exact_mode, 'PROTECTED_MODE')
    attrs = set(os.listxattr(fd))
    require(attrs <= {'security.selinux'}, 'PROTECTED_XATTR')
    if context is not None:
        require(type(context) is bytes and attrs == {'security.selinux'} and
                os.getxattr(fd, 'security.selinux').rstrip(b'\0') == context.rstrip(b'\0'), 'PROTECTED_CONTEXT')
    return s


@contextmanager
def protected_path(path, *, directory, context=None, exact_mode=None):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(type(path) is str and path.startswith('/') and str(PurePosixPath(path)) == path and
            '..' not in PurePosixPath(path).parts and '\0' not in path, 'PROTECTED_PATH')
    chain = []
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open('/', flags | os.O_DIRECTORY)
        chain.append((fd, None, '/'))
        parts = PurePosixPath(path).parts[1:]
        for i, part in enumerate(parts):
            _metadata(fd, directory=True)
            is_dir = i < len(parts)-1 or directory
            child = os.open(part, flags | (os.O_DIRECTORY if is_dir else 0), dir_fd=fd)
            chain.append((child, fd, part))
            fd = child
        _metadata(fd, directory=directory, context=context, exact_mode=exact_mode)
        yield fd
        for i, (opened, parent, name) in enumerate(chain):
            s = _metadata(opened, directory=(i < len(chain)-1 or directory),
                          context=context if i == len(chain)-1 else None,
                          exact_mode=exact_mode if i == len(chain)-1 else None)
            if parent is not None:
                p = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((s.st_dev, s.st_ino) == (p.st_dev, p.st_ino), 'PROTECTED_PATH_REPLACED')
    finally:
        for fd, _, _ in reversed(chain):
            os.close(fd)


@dataclass(repr=False)
class PrivateResult:
    rc: int | None
    reason: str
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    def diagnostic(self):
        return dict(rc=self.rc, reason=self.reason, stdout_size=len(self.stdout), stderr_size=len(self.stderr),
                    stdout_sha256=sha(self.stdout), stderr_sha256=sha(self.stderr))


def run_process(argv, payload, *, cwd, env, pass_fds, deadline, clock=time.monotonic):
    """Actual Linux pipes, bounded bytes and process group. No shell/retry.

    On deadline/output overflow only the CLI process group is killed. Docker may
    still complete an already accepted operation: never infer cancellation.
    """
    require(os.name == 'posix' and type(payload) is bytes and len(payload) <= MAX_OUTPUT, 'COMPOSE_PROCESS_INPUT')
    remaining(deadline, clock)
    out, err = bytearray(), bytearray()
    p = None
    reason = 'COMPOSE_PROCESS_FAILURE'
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=cwd, env=env, pass_fds=pass_fds, start_new_session=True, close_fds=True)
        with selectors.DefaultSelector() as sel:
            for stream, tag in ((p.stdout, 'out'), (p.stderr, 'err')):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, tag)
            if payload:
                os.set_blocking(p.stdin.fileno(), False)
                sel.register(p.stdin, selectors.EVENT_WRITE, 'in')
            else:
                p.stdin.close()
            sent = 0
            while sel.get_map():
                for key, _ in sel.select(min(0.1, remaining(deadline, clock))):
                    remaining(deadline, clock)
                    if key.data == 'in':
                        try:
                            sent += os.write(key.fd, payload[sent:sent+65536])
                        except BrokenPipeError:
                            raise ValueError('COMPOSE_STDIN_INCOMPLETE') from None
                        if sent == len(payload):
                            sel.unregister(key.fileobj); key.fileobj.close()
                    else:
                        data = os.read(key.fd, 65536)
                        if not data:
                            sel.unregister(key.fileobj); key.fileobj.close()
                            continue
                        target = out if key.data == 'out' else err
                        room = MAX_OUTPUT - len(target)
                        target.extend(data[:room])
                        require(len(data) <= room, 'COMPOSE_OUTPUT_LIMIT')
            rc = p.wait(timeout=remaining(deadline, clock))
            remaining(deadline, clock)
            return PrivateResult(rc, 'COMPLETED', bytes(out), bytes(err))
    except ValueError as exc:
        if str(exc) in {'COMPOSE_DEADLINE', 'COMPOSE_STDIN_INCOMPLETE', 'COMPOSE_OUTPUT_LIMIT'}:
            reason = str(exc)
    except subprocess.TimeoutExpired:
        reason = 'COMPOSE_DEADLINE'
    except Exception:
        pass
    finally:
        if p is not None:
            # Kill lingering group members as well as an alive group leader.
            # This is the client group; it does not signal Docker containers.
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
            for stream in (p.stdin, p.stdout, p.stderr):
                if not stream.closed:
                    stream.close()
    return PrivateResult(None, reason, bytes(out), bytes(err))


class PinnedCompose:
    """Standalone pinned Compose ELF, private empty config dir, exact stdin."""
    def __init__(self, *, binary, binary_sha256, binary_context, private_directory,
                 private_context, clock=time.monotonic, legacy_bindings=None, bind_sources=None):
        require(type(binary_sha256) is str and re.fullmatch('[0-9a-f]{64}', binary_sha256), 'COMPOSE_PIN')
        self.binary, self.binary_sha = binary, binary_sha256
        self.binary_context = binary_context
        self.directory, self.context, self.clock = private_directory, private_context, clock
        self.receipts = []
        self._private_results = []  # for an explicit protected evidence collector
        require((legacy_bindings is None) == (bind_sources is None), 'LEGACY_BIND_PINS_REQUIRED')
        if legacy_bindings is not None:
            validate_bind_sources(legacy_bindings, bind_sources)
        self.legacy_bindings, self.bind_sources = deepcopy(legacy_bindings), deepcopy(bind_sources)
        self.audit = None  # bound once by AuditedCompose before production use

    def call(self, operation, model, *, deadline, service=None):
        require(operation in ('render', 'recreate') and
                ((operation == 'render' and service is None) or (operation == 'recreate' and service in ORDER)), 'COMPOSE_OPERATION')
        validate_execution_model(model, legacy_bindings=self.legacy_bindings)
        payload = encode_stdin(model)
        result = None
        with protected_path(self.directory, directory=True, context=self.context, exact_mode=0o700) as work:
            require(os.listdir(work) == [], 'COMPOSE_PRIVATE_DIRECTORY_NOT_EMPTY')
            with protected_path(self.binary, directory=False, context=self.binary_context) as binary:
                before = os.fstat(binary)
                require(before.st_mode & 0o111 and before.st_size <= 256*1024*1024, 'COMPOSE_EXECUTABLE')
                hasher, prefix = hashlib.sha256(), b''
                while True:
                    remaining(deadline, self.clock)
                    chunk = os.read(binary, 65536)
                    if not chunk:
                        break
                    if not prefix:
                        prefix = chunk[:4]
                    hasher.update(chunk)
                require(prefix == b'\x7fELF' and hasher.hexdigest() == self.binary_sha and
                        _signature(before) == _signature(os.fstat(binary)), 'COMPOSE_EXECUTABLE_CHANGED')
                os.lseek(binary, 0, os.SEEK_SET)
                args = [f'/proc/self/fd/{binary}', '--host', 'unix:///run/docker.sock',
                        '--project-name', 'harbor', '--project-directory', '/', '--env-file', '/dev/null',
                        '--parallel', '1', '--ansi', 'never', '-f', '-']
                args += (['config', '--format', 'json'] if operation == 'render' else
                         ['up', '-d', '--no-deps', '--force-recreate', '--pull', 'never', '--no-build', '--timeout', '-1', service])
                env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                       'HOME': self.directory, 'DOCKER_CONFIG': self.directory,
                       'DOCKER_HOST': 'unix:///run/docker.sock', 'DOCKER_API_VERSION': '1.56',
                       'COMPOSE_DISABLE_ENV_FILE': 'true', 'COMPOSE_MENU': 'false'}
                if self.audit is not None:
                    self.audit('PROCESS_INTENT', operation, service,
                               {'stdin_sha256': sha(payload), 'binary_sha256': self.binary_sha}, {}, deadline)
                remaining(deadline, self.clock)  # durable intent may exhaust the call budget
                try:
                    if self.bind_sources is not None:
                        check_bind_sources(self.bind_sources, deadline=deadline, clock=self.clock)
                    result = run_process(args, payload, cwd=f'/proc/self/fd/{work}', env=env,
                                         pass_fds=(binary, work), deadline=deadline, clock=self.clock)
                finally:
                    if result is not None:
                        self._private_results.append(result)
                    self.receipts.append(dict(operation=operation, service=service,
                        stdin_sha256=sha(payload), binary_sha256=self.binary_sha,
                        **(result.diagnostic() if result is not None else {'reason': 'COMPOSE_PROCESS_INTERRUPTED'})))
                    if self.audit is not None:
                        self.audit('PROCESS_RESULT', operation, service,
                                   {'rc': result.rc, 'reason': result.reason} if result is not None else
                                   {'rc': None, 'reason': 'COMPOSE_PROCESS_INTERRUPTED'},
                                   {'stdout': result.stdout, 'stderr': result.stderr} if result is not None else {}, deadline)
                require(_signature(before) == _signature(os.fstat(binary)), 'COMPOSE_EXECUTABLE_CHANGED')
                if self.bind_sources is not None:
                    check_bind_sources(self.bind_sources, deadline=deadline, clock=self.clock)
            require(os.listdir(work) == [], 'COMPOSE_PRIVATE_DIRECTORY_CHANGED')
        require(result.reason == 'COMPLETED', 'COMPOSE_COMMAND_UNKNOWN')
        if operation == 'render':
            require(result.rc == 0, 'COMPOSE_RENDER_FAILED')
            validate_process_render(model, parse(result.stdout), legacy_bindings=self.legacy_bindings)
        return result.rc


class ComposeTransport:
    """Sequence backend.recreate transport with pre-write exact-state guards.

    verify(deadline) MUST independently validate current generation/protection,
    source/input bytes, full ten-row state, pinned images, external resources,
    mount profile and logger, and return exact service IDs. It is called after
    rendering, immediately before mutation. This does not make TOCTOU atomic.
    """
    def __init__(self, model, *, model_sha256, plan_sha256, ids, process, verify,
                 clock=time.monotonic, legacy_bindings=None, preflight_seconds=None, recreate_seconds=None, order=ORDER):
        require(fingerprint(model) == model_sha256 and re.fullmatch('[0-9a-f]{64}', plan_sha256), 'TRANSPORT_BINDING')
        require(set(ids) == set(SERVICES) and all(re.fullmatch('[0-9a-f]{64}', v) for v in ids.values()) and
                len(set(ids.values())) == 10, 'TRANSPORT_IDS')
        require(callable(verify), 'TRANSPORT_GUARD')
        require(preflight_seconds is None or (type(preflight_seconds) in (int,float) and
                math.isfinite(preflight_seconds) and preflight_seconds>0), 'TRANSPORT_READ_BUDGET')
        require(type(order) is tuple and order in (ORDER, ORDER[1:]), 'TRANSPORT_ORDER')
        self.order=order
        self.preflight_seconds=preflight_seconds
        require(recreate_seconds is None or (preflight_seconds is not None and
                type(recreate_seconds) is dict and set(recreate_seconds)==set(self.order) and
                all(type(v) in (int,float) and math.isfinite(v) and v>0 for v in recreate_seconds.values())),
                'TRANSPORT_RECREATE_BUDGET')
        self.recreate_seconds=deepcopy(recreate_seconds)
        validate_execution_model(model, legacy_bindings=legacy_bindings)
        self.model, self.ids = deepcopy(model), deepcopy(ids)
        self.plan_sha, self.model_sha = plan_sha256, model_sha256
        self.process, self.verify, self.clock = process, verify, clock
        self.claimed = []
        self.failed = False
        self.pid = os.getpid()
        self._lock = threading.Lock()

    def recreate(self, *, service, expected_id, plan_sha256, deadline_mono, on_dispatch=None):
        require(self._lock.acquire(blocking=False), 'TRANSPORT_BUSY')
        try:
            require(not self.failed and os.getpid() == self.pid and
                    len(self.claimed) < len(self.order) and service == self.order[len(self.claimed)] and
                    expected_id == self.ids[service] and plan_sha256 == self.plan_sha and
                    fingerprint(self.model) == self.model_sha, 'TRANSPORT_SEQUENCE')
            self.claimed.append(service)  # spent even if render/guard fails
            require(self.recreate_seconds is None or callable(on_dispatch),'TRANSPORT_DISPATCH_CALLBACK')
            remaining(deadline_mono, self.clock)
            read_deadline=(min(deadline_mono,self.clock()+self.preflight_seconds)
                           if self.preflight_seconds is not None else deadline_mono)
            require(self.process.call('render', self.model, deadline=read_deadline) == 0, 'TRANSPORT_RENDER_FAILED')
            remaining(read_deadline,self.clock)
            # The full observation has its own I/O cap; render cannot consume it.
            read_deadline=(min(deadline_mono,self.clock()+self.preflight_seconds)
                           if self.preflight_seconds is not None else deadline_mono)
            actual = self.verify(read_deadline)
            remaining(read_deadline,self.clock)
            require(type(actual) is dict and set(actual) == set(SERVICES) and
                    actual[service] == expected_id and actual['log'] == self.ids['log'], 'TRANSPORT_TARGET_CHANGED')
            remaining(deadline_mono, self.clock)
            if self.recreate_seconds is not None:
                deadline_mono=min(deadline_mono,self.clock()+self.recreate_seconds[service])
                on_dispatch(deadline_mono)
                remaining(deadline_mono,self.clock)
            rc = self.process.call('recreate', self.model, deadline=deadline_mono, service=service)
            remaining(deadline_mono, self.clock)
            require(type(rc) is int and rc == 0, 'TRANSPORT_COMMAND_FAILED')
            return rc
        except BaseException:
            self.failed = True
            raise
        finally:
            self._lock.release()
