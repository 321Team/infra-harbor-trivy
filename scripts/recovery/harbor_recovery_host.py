"""Read-only Linux guards for the disconnected Phase 1 clone.

No default policy, enrollment, CLI, installation, repair, or baseline learning.
The installer must supply a reviewed policy and canonical self-contained JSON
Compose inputs, rooted in a protected directory. Never point this at the old
user-owned source tree and relax permissions to make a check pass.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

from harbor_recovery_core import ENDPOINT, ORDER
from harbor_recovery_docker import HostSnapshot, digest, parse_json, remaining, require

GUARD = 'fds-harbor-ac04-guard.service'
TABLE = 'p1_hbr_ac04'
MAX_OUTPUT = 8 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
TOOLS = {'systemctl', 'nft', 'getenforce', 'ip', 'compose'}
PROPERTIES = ('LoadState,ActiveState,SubState,InvocationID,Requires,After,'
              'FragmentPath,DropInPaths,NeedDaemonReload')
PROFILE_VERSION = ('Version', 'ApiVersion', 'MinAPIVersion', 'GitCommit', 'Os', 'Arch')
PROFILE_INFO = ('ID', 'DockerRootDir', 'Driver', 'DriverStatus', 'SecurityOptions',
                'CgroupDriver', 'CgroupVersion', 'OSType', 'Architecture')


def absolute(path):
    # No escaping/quoting ambiguity in systemd's space-separated path fields.
    return (isinstance(path, str) and path.startswith('/') and path != '/' and
            re.fullmatch(r'/[A-Za-z0-9_./-]+', path) is not None and
            str(PurePosixPath(path)) == path and '..' not in path.split('/'))


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def metadata_spec(value, *, file=False, socket=False):
    keys = {'mode', 'gid', 'selinux'} | ({'sha256'} if file else set())
    require(isinstance(value, dict) and set(value) == keys, 'HOST_PATH_SPEC')
    require(type(value['mode']) is int and 0 <= value['mode'] <= 0o777 and
            not value['mode'] & (0o007 if socket else 0o022) and
            type(value['gid']) is int and value['gid'] >= 0 and
            isinstance(value['selinux'], str) and
            re.fullmatch('[A-Za-z0-9_:.,-]+', value['selinux']), 'HOST_PATH_SPEC')
    require(not file or sha(value['sha256']), 'HOST_PATH_HASH')


def validate_policy(p):
    keys = {'version', 'hostname', 'product_uuid', 'project', 'tools', 'files',
            'directory', 'directory_spec', 'compose_files', 'env_file',
            'compose_sha256', 'compose_version', 'socket', 'socket_spec',
            'api_version', 'engine_profile', 'nft_sha256', 'units'}
    require(isinstance(p, dict) and set(p) == keys and type(p['version']) is int and
            p['version'] == 1, 'HOST_POLICY_SCHEMA')
    require(p['hostname'] == 'harbor01' and p['project'] == 'harbor', 'HOST_POLICY_SCOPE')
    require(isinstance(p['product_uuid'], str) and
            str(uuid.UUID(p['product_uuid'])) == p['product_uuid'], 'HOST_POLICY_UUID')
    require(isinstance(p['tools'], dict) and set(p['tools']) == TOOLS and
            all(absolute(v) for v in p['tools'].values()), 'HOST_POLICY_TOOLS')
    require(isinstance(p['files'], dict) and 1 <= len(p['files']) <= 128 and
            all(absolute(v) for v in p['files']), 'HOST_POLICY_FILES')
    for spec in p['files'].values():
        metadata_spec(spec, file=True)
    require(absolute(p['directory']) and absolute(p['socket']) and
            absolute(p['env_file']), 'HOST_POLICY_PATH')
    metadata_spec(p['directory_spec'])
    require(p['directory_spec']['mode'] == 0o700, 'HOST_PRIVATE_DIRECTORY')
    metadata_spec(p['socket_spec'], socket=True)
    require(isinstance(p['compose_files'], list) and 1 <= len(p['compose_files']) <= 8 and
            len(set(p['compose_files'])) == len(p['compose_files']) and
            all(absolute(v) and v.endswith('.json') and
                str(PurePosixPath(v).parent) == p['directory'] for v in p['compose_files']),
            'HOST_COMPOSE_INPUTS')
    require(str(PurePosixPath(p['env_file']).parent) == p['directory'], 'HOST_ENV_PATH')
    require(isinstance(p['units'], dict) and set(p['units']) == {'docker.service', GUARD},
            'HOST_UNIT_SET')
    required = set(p['tools'].values()) | set(p['compose_files']) | {p['env_file']}
    for spec in p['units'].values():
        require(isinstance(spec, dict) and set(spec) == {'fragment', 'dropins'} and
                absolute(spec['fragment']) and isinstance(spec['dropins'], list) and
                all(absolute(v) for v in spec['dropins']) and
                len(set(spec['dropins'])) == len(spec['dropins']), 'HOST_UNIT_INPUTS')
        required.update([spec['fragment'], *spec['dropins']])
    require(required <= set(p['files']), 'HOST_UNPINNED_INPUT')
    require(all(p['files'][v]['mode'] & 0o100 for v in p['tools'].values()), 'HOST_TOOL_MODE')
    require(sha(p['compose_sha256']) and sha(p['nft_sha256']), 'HOST_POLICY_DIGEST')
    require(isinstance(p['compose_version'], str) and
            re.fullmatch(r'\d+\.\d+\.\d+', p['compose_version']) and
            isinstance(p['api_version'], str) and re.fullmatch(r'1\.\d{2}', p['api_version']),
            'HOST_POLICY_VERSION')
    profile = p['engine_profile']
    require(isinstance(profile, dict) and set(profile) == {'version', 'info'} and
            isinstance(profile['version'], dict) and set(profile['version']) == set(PROFILE_VERSION) and
            isinstance(profile['info'], dict) and set(profile['info']) == set(PROFILE_INFO),
            'HOST_ENGINE_PROFILE')
    require(profile['version']['Os'] == 'linux' and profile['info']['OSType'] == 'linux' and
            absolute(profile['info']['DockerRootDir']) and
            isinstance(profile['info']['SecurityOptions'], list) and
            isinstance(profile['info']['DriverStatus'], list), 'HOST_ENGINE_PROFILE')
    def api(value):
        require(isinstance(value, str) and re.fullmatch(r'1\.\d{2}', value), 'HOST_ENGINE_API')
        return int(value.split('.')[1])
    require(api(profile['version']['MinAPIVersion']) <= api(p['api_version']) <=
            api(profile['version']['ApiVersion']), 'HOST_ENGINE_API')


def properties(raw):
    result = {}
    for line in raw.decode('utf-8', errors='strict').splitlines():
        require('=' in line, 'HOST_UNIT_FORMAT')
        key, value = line.split('=', 1)
        require(key not in result, 'HOST_UNIT_DUPLICATE')
        result[key] = value
    require(set(result) == set(PROPERTIES.split(',')), 'HOST_UNIT_FIELDS')
    return result


def unit_check(row, expected, *, docker):
    require(row['LoadState'] == 'loaded' and row['ActiveState'] == 'active' and
            row['SubState'] == ('running' if docker else 'exited') and
            row['NeedDaemonReload'] == 'no', 'HOST_UNIT_NOT_READY')
    require(row['FragmentPath'] == expected['fragment'] and
            row['DropInPaths'].split() == expected['dropins'], 'HOST_UNIT_SOURCE_DRIFT')
    require(re.fullmatch('[0-9a-f]{32}', row['InvocationID']) and
            row['InvocationID'] != '0' * 32, 'HOST_UNIT_GENERATION')
    if docker:
        require(all(GUARD in row[k].split() for k in ('Requires', 'After')), 'HOST_AC04_DEPENDENCY')


def nft_fingerprint(raw):
    obj = parse_json(raw)
    require(isinstance(obj, dict) and set(obj) == {'nftables'} and
            isinstance(obj['nftables'], list), 'HOST_NFT_SCHEMA')
    rows = obj['nftables']
    require(any(isinstance(row, dict) and row.get('table', {}).get('family') == 'inet' and
                row.get('table', {}).get('name') == TABLE for row in rows), 'HOST_AC04_TABLE')
    def clean(value):
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            return {k: clean({a: b for a, b in v.items() if a not in ('packets', 'bytes')}
                             if k == 'counter' and isinstance(v, dict) else v)
                    for k, v in value.items() if k != 'handle'}
        return value
    return digest(clean([v for v in rows if 'metainfo' not in v]))


def standalone_compose(raw):
    """Only reviewed self-contained JSON; no includes, remote or env-file reads."""
    obj = parse_json(raw)
    require(isinstance(obj, dict), 'HOST_COMPOSE_SCHEMA')
    require(not {'configs', 'secrets'} & set(obj), 'HOST_COMPOSE_EXTERNAL_INPUT')
    def walk(value):
        if isinstance(value, dict):
            require(not {'include', 'extends', 'env_file', 'build'} & set(value),
                    'HOST_COMPOSE_EXTERNAL_INPUT')
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(obj)
    return obj


def compose_check(raw, expected):
    obj = standalone_compose(raw)
    require(digest(obj) == expected, 'HOST_EFFECTIVE_COMPOSE_DRIFT')
    services = obj.get('services')
    require(isinstance(services, dict) and set(services) == set(ORDER) | {'log'},
            'HOST_COMPOSE_SERVICES')
    for name, row in services.items():
        require(isinstance(row, dict) and row.get('restart') == ('always' if name == 'log' else 'no'),
                'HOST_COMPOSE_POLICY')
        if name != 'log':
            log = row.get('logging', {})
            require(log.get('driver') == 'syslog' and
                    log.get('options', {}).get('syslog-address') == ENDPOINT, 'HOST_COMPOSE_LOGGING')


def engine_profile(raw):
    require(isinstance(raw, dict) and set(raw) == {'version', 'info'}, 'HOST_ENGINE_SCHEMA')
    result = {}
    for name, keys in (('version', PROFILE_VERSION), ('info', PROFILE_INFO)):
        require(isinstance(raw[name], dict) and all(k in raw[name] for k in keys), 'HOST_ENGINE_FIELD')
        result[name] = {k: raw[name][k] for k in keys}
    return result


def network_check(raw):
    rows = parse_json(raw)
    require(isinstance(rows, list) and rows, 'HOST_LINKS')
    names = []
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get('ifname'), str), 'HOST_LINK_SCHEMA')
        names.append(row['ifname'])
        if row['ifname'] == 'lo':
            require(row.get('link_type') == 'loopback', 'HOST_LOOPBACK')
        else:
            require(row.get('linkinfo', {}).get('info_kind') in ('bridge', 'veth'),
                    'HOST_EXTERNAL_LINK')
    require('lo' in names and len(set(names)) == len(names), 'HOST_LINK_SET')


class LinuxReadOnly:
    """Small local I/O implementation. Commands are selected by HostProvider.

    File checks reject symlinks in every component, writable/non-root parents,
    POSIX access/default ACLs, changed content/labels, hardlinks and special
    files. Reads do not claim to exclude an independent root writer.
    """
    def __init__(self, *, clock=time.monotonic):
        self.clock = clock

    def identity(self):
        require(sys.platform == 'linux' and os.geteuid() == 0, 'HOST_LINUX_ROOT_REQUIRED')
        def read(path):
            with open(path, 'rb') as stream:
                raw = stream.read(MAX_OUTPUT + 1)
            require(len(raw) <= MAX_OUTPUT, 'HOST_KERNEL_READ_LIMIT')
            return raw.decode('utf-8', errors='strict')
        return {'hostname': socket.gethostname(),
                'product_uuid': read('/sys/class/dmi/id/product_uuid').strip().lower(),
                'boot': read('/proc/sys/kernel/random/boot_id').strip(),
                'mountinfo': read('/proc/self/mountinfo'),
                'physical_nics': any(os.path.exists('/sys/class/net/' + n + '/device')
                                     for n in os.listdir('/sys/class/net'))}

    def _security(self, fd, *, spec=None, socket_path=None):
        # For sockets O_PATH fds cannot getxattr; use a pinned procfd parent
        # path then compare the final inode again before accepting it.
        target = fd if socket_path is None else socket_path
        st = os.fstat(fd) if socket_path is None else os.stat(target, follow_symlinks=False)
        require(st.st_uid == 0, 'HOST_PATH_OWNER')
        kwargs = {} if socket_path is None else {'follow_symlinks':False}
        attrs = os.listxattr(target, **kwargs)
        require(not {'system.posix_acl_access', 'system.posix_acl_default', 'system.nfs4_acl'} & set(attrs),
                'HOST_PATH_ACL')
        if spec is None:
            require(stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022, 'HOST_PATH_PARENT')
        else:
            require(set(attrs) <= {'security.selinux'}, 'HOST_PATH_XATTR')
            require(stat.S_IMODE(st.st_mode) == spec['mode'] and st.st_gid == spec['gid'], 'HOST_PATH_MODE')
            label = os.getxattr(target, 'security.selinux', **kwargs).rstrip(b'\0').decode('ascii')
            require(label == spec['selinux'], 'HOST_PATH_LABEL')
        return st

    def pinned(self, path, spec, kind, deadline):
        require(absolute(path) and kind in ('file', 'directory', 'socket'), 'HOST_PIN_PATH')
        remaining(deadline, self.clock)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        try:
            self._security(fd)
            parts = PurePosixPath(path).parts[1:]
            for part in parts[:-1]:
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd); fd = child
                self._security(fd)
            if kind == 'socket':
                node = '/proc/self/fd/' + str(fd) + '/' + parts[-1]
                before = self._security(fd, spec=spec, socket_path=node)
                require(stat.S_ISSOCK(before.st_mode) and before.st_nlink == 1, 'HOST_SOCKET_TYPE')
                after = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
                require(before == after, 'HOST_SOCKET_RACE')
                return (before.st_dev, before.st_ino, before.st_ctime_ns)
            child = os.open(parts[-1], flags if kind == 'directory' else
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            try:
                before = self._security(child, spec=spec)
                if kind == 'directory':
                    require(stat.S_ISDIR(before.st_mode), 'HOST_DIRECTORY_TYPE')
                    return (before.st_dev, before.st_ino)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                        before.st_size <= MAX_FILE, 'HOST_FILE_TYPE_SIZE')
                hashed, chunks, total = hashlib.sha256(), [], 0
                keep = path.endswith('.json')
                while True:
                    remaining(deadline, self.clock)
                    block = os.read(child, 65536)
                    if not block:
                        break
                    total += len(block)
                    require(total <= (MAX_OUTPUT if keep else MAX_FILE), 'HOST_FILE_LIMIT')
                    hashed.update(block)
                    if keep:
                        chunks.append(block)
                after = os.fstat(child)
                stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                          'st_size', 'st_mtime_ns', 'st_ctime_ns')
                require(all(getattr(before, k) == getattr(after, k) for k in stable) and
                        total == before.st_size, 'HOST_FILE_RACE')
                require(hashed.hexdigest() == spec['sha256'], 'HOST_FILE_HASH')
                return b''.join(chunks) if keep else None
            finally:
                os.close(child)
        finally:
            os.close(fd)
            remaining(deadline, self.clock)

    def run(self, argv, cwd, deadline):
        require(sys.platform == 'linux' and absolute(argv[0]), 'HOST_COMMAND_PLATFORM')
        remaining(deadline, self.clock)
        # No inherited DOCKER_*, COMPOSE_*, HOME, proxy, plugin or shell values.
        env = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C', 'HOME': cwd,
               'DOCKER_CONFIG': cwd, 'COMPOSE_DISABLE_ENV_FILE': '1'}
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=cwd, env=env, start_new_session=True)
        outputs = {proc.stdout: bytearray(), proc.stderr: bytearray()}
        completed = False
        try:
            with selectors.DefaultSelector() as selected:
                for stream in outputs:
                    os.set_blocking(stream.fileno(), False)
                    selected.register(stream, selectors.EVENT_READ)
                while selected.get_map():
                    events = selected.select(remaining(deadline, self.clock))
                    require(events, 'HOST_COMMAND_DEADLINE')
                    for key, _ in events:
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selected.unregister(key.fileobj)
                        else:
                            outputs[key.fileobj].extend(block)
                            require(sum(map(len, outputs.values())) <= MAX_OUTPUT, 'HOST_COMMAND_LIMIT')
            rc = proc.wait(timeout=remaining(deadline, self.clock))
            require(rc == 0, 'HOST_COMMAND_FAILED')
            completed = True
            return bytes(outputs[proc.stdout])
        finally:
            if not completed:
                # A parent may exit while a descendant still owns a pipe.
                # On failure terminate the entire read-only helper group.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait(timeout=1)
            for stream in outputs:
                stream.close()


class HostProvider:
    """Callable adapter provider. Policy is reviewed input, never observed defaults.

    An I/O override is only for local synthetic tests. A deployment builder must
    use LinuxReadOnly and verified policy loading; this module has no CLI.
    """
    def __init__(self, policy, engine, *, io=None, clock=time.monotonic):
        self._policy = deepcopy(policy)
        validate_policy(self._policy)
        self._binding = digest({'host_provider_version': 1, 'policy': self._policy})
        self.engine, self.clock = engine, clock
        self.io = LinuxReadOnly(clock=clock) if io is None else io
        require(engine.path == policy['socket'] and engine.peer_uid == 0 and
                engine.prefix == '/v' + policy['api_version'], 'HOST_ENGINE_BINDING')

    @property
    def binding(self):
        return self._binding

    def _identity(self):
        identity = self.io.identity()
        p = self._policy
        require(identity['hostname'] == p['hostname'] and identity['product_uuid'] == p['product_uuid'],
                'HOST_IDENTITY')
        require(str(uuid.UUID(identity['boot'])) == identity['boot'], 'HOST_BOOT')
        require(identity['physical_nics'] is False and 'hgfs' not in identity['mountinfo'].lower(),
                'HOST_ISOLATION')
        return identity['boot']

    def _pins(self, deadline):
        p = self._policy
        directory = self.io.pinned(p['directory'], p['directory_spec'], 'directory', deadline)
        for path, spec in p['files'].items():
            raw = self.io.pinned(path, spec, 'file', deadline)
            if path in p['compose_files']:
                standalone_compose(raw)
        sock = self.io.pinned(p['socket'], p['socket_spec'], 'socket', deadline)
        return directory, sock

    def _run(self, name, args, deadline):
        p = self._policy
        return self.io.run([p['tools'][name], *args], p['directory'], deadline)

    def _unit(self, name, deadline):
        row = properties(self._run('systemctl', ['show', name, '--no-pager',
                         '--property=' + PROPERTIES], deadline))
        unit_check(row, self._policy['units'][name], docker=name == 'docker.service')
        return row

    def _guards(self, deadline):
        require(self._run('getenforce', [], deadline).strip() == b'Enforcing', 'HOST_SELINUX')
        network_check(self._run('ip', ['-j', '-d', 'link', 'show'], deadline))
        for family in ('-4', '-6'):
            routes = parse_json(self._run('ip', ['-j', family, 'route', 'show', 'table', 'all'], deadline))
            require(isinstance(routes, list) and all(isinstance(r, dict) and
                    r.get('dst') not in (None, 'default', '0.0.0.0/0', '::/0') for r in routes),
                    'HOST_EXTERNAL_ROUTE')
        require(nft_fingerprint(self._run('nft', ['-j', 'list', 'table', 'inet', TABLE], deadline)) ==
                self._policy['nft_sha256'], 'HOST_AC04_DRIFT')

    def __call__(self, deadline):
        # A fixed error code only: subprocess output can contain secrets.
        try:
            p = self._policy
            require(digest({'host_provider_version': 1, 'policy': p}) == self.binding, 'HOST_POLICY_MUTATED')
            require(self.engine.path == p['socket'] and self.engine.peer_uid == 0 and
                    self.engine.prefix == '/v' + p['api_version'], 'HOST_ENGINE_BINDING')
            started = self.clock()
            remaining(deadline, self.clock)
            boot = self._identity()
            pins = self._pins(deadline)
            first = {name: self._unit(name, deadline) for name in ('docker.service', GUARD)}
            self._guards(deadline)
            require(engine_profile(self.engine.profile(deadline)) == p['engine_profile'], 'HOST_ENGINE_DRIFT')
            require(self._run('compose', ['version', '--short'], deadline).strip().decode('ascii') ==
                    p['compose_version'], 'HOST_COMPOSE_VERSION')
            args = ['--project-directory', p['directory'], '--project-name', p['project'],
                    '--env-file', p['env_file']]
            for path in p['compose_files']:
                args.extend(['-f', path])
            args.extend(['config', '--format', 'json', '--no-interpolate', '--no-env-resolution'])
            compose_check(self._run('compose', args, deadline), p['compose_sha256'])
            # Recheck boundary conditions; do not refresh the start timestamp.
            self._guards(deadline)
            last = {name: self._unit(name, deadline) for name in first}
            require(first == last and boot == self._identity() and pins == self._pins(deadline),
                    'HOST_COLLECTION_CHANGED')
            remaining(deadline, self.clock)
            return HostSnapshot(boot, first['docker.service']['InvocationID'], self.binding, started)
        except Exception:
            raise ValueError('HOST_VERIFICATION_FAILED') from None
