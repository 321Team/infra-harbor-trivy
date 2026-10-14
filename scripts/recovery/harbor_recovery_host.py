"""Read-only Linux guards with separate clone and production contracts.

No default policy, enrollment, CLI, installation, repair, or baseline learning.
The installer must supply a reviewed policy and canonical self-contained JSON
Compose inputs, rooted in a protected directory. Never point this at the old
user-owned source tree and relax permissions to make a check pass.
"""
from copy import deepcopy
import hashlib
import ipaddress
import json
import math
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
    production = isinstance(p, dict) and p.get('version') in (2, 3)
    require(isinstance(p, dict) and set(p) == keys | ({'network'} if production else set()) and
            type(p['version']) is int and p['version'] in (1, 2, 3), 'HOST_POLICY_SCHEMA')
    require(p['hostname'] == 'harbor01' and p['project'] == 'harbor', 'HOST_POLICY_SCOPE')
    require(isinstance(p['product_uuid'], str) and
            str(uuid.UUID(p['product_uuid'])) == p['product_uuid'], 'HOST_POLICY_UUID')
    require(isinstance(p['tools'], dict) and set(p['tools']) == TOOLS | ({'nsenter'} if production else set()) and
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
    if production:
        validate_production_network(p['network'], version=p['version'])


def host_binding(policy):
    # Version 1 retains the exact historic digest. Version 2 cannot reuse it.
    return digest({'host_provider_version': policy['version'], 'policy': policy})


def host_provider(policy, engine, **kwargs):
    validate_policy(policy)
    cls = ProductionHostProvider if policy['version'] in (2, 3) else HostProvider
    return cls(policy, engine, **kwargs)


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
        def read(path, limit=MAX_OUTPUT):
            with open(path, 'rb') as stream:
                raw = stream.read(limit + 1)
            require(len(raw) <= limit, 'HOST_KERNEL_READ_LIMIT')
            return raw.decode('utf-8', errors='strict')
        return {'hostname': socket.gethostname(),
                'product_uuid': read('/sys/class/dmi/id/product_uuid', 128).strip().lower(),
                'boot': read('/proc/sys/kernel/random/boot_id', 128).strip(),
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

    def run(self, argv, cwd, deadline, *, pass_fds=()):
        require(sys.platform == 'linux' and absolute(argv[0]), 'HOST_COMMAND_PLATFORM')
        remaining(deadline, self.clock)
        # No inherited DOCKER_*, COMPOSE_*, HOME, proxy, plugin or shell values.
        env = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C', 'HOME': cwd,
               'DOCKER_CONFIG': cwd, 'COMPOSE_DISABLE_ENV_FILE': '1'}
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=cwd, env=env, start_new_session=True,
                                pass_fds=pass_fds)
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

    def physical_interfaces(self):
        return sorted(n for n in os.listdir('/sys/class/net') if os.path.exists('/sys/class/net/'+n+'/device'))

    def peer_links(self, pid, policy, deadline):
        require(type(pid) is int and pid > 1, 'PRODUCTION_CONTAINER_PID')
        # Hold the namespace fd so PID reuse cannot silently retarget nsenter.
        fd = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        try:
            before, own = os.fstat(fd), os.stat('/proc/self/ns/net')
            require((before.st_dev,before.st_ino) != (own.st_dev,own.st_ino), 'PRODUCTION_HOST_NETNS')
            for name in ('ip','nsenter'):
                path = policy['tools'][name]
                self.pinned(path, policy['files'][path], 'file', deadline)
            raw = self.run([policy['tools']['nsenter'], f'--net=/proc/self/fd/{fd}', '--',
                            policy['tools']['ip'], '-j','-d','link','show'],
                           policy['directory'], deadline, pass_fds=(fd,))
            after = os.stat(f'/proc/{pid}/ns/net')
            require((before.st_dev,before.st_ino) == (after.st_dev,after.st_ino), 'PRODUCTION_NETNS_CHANGED')
            remaining(deadline,self.clock)
            return parse_json(raw)
        finally:
            os.close(fd)


class HostProvider:
    """Callable adapter provider. Policy is reviewed input, never observed defaults.

    An I/O override is only for local synthetic tests. A deployment builder must
    use LinuxReadOnly and verified policy loading; this module has no CLI.
    """
    def __init__(self, policy, engine, *, io=None, clock=time.monotonic):
        self._policy = deepcopy(policy)
        validate_policy(self._policy)
        require(policy['version'] in ((2, 3) if isinstance(self, ProductionHostProvider) else (1,)), 'HOST_PROVIDER_SCOPE')
        self._binding = host_binding(self._policy)
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
            require(host_binding(p) == self.binding, 'HOST_POLICY_MUTATED')
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


# Network proof algorithms copied from PR55 2886789; dependencies renamed.
# Legacy eleven-module source catalogs remain supported.
_network_digest = digest

def _net_network_projection(row):
    require(type(row) is dict, 'NETWORK_SCHEMA')
    result=deepcopy(row)
    for key in ('Containers','Peers'):
        result.pop(key,None)
    status=result.get('Status')
    require(type(status) is dict and type(status.get('IPAM')) is dict and
            type(status['IPAM'].get('Subnets')) is dict, 'NETWORK_STATUS_SCHEMA')
    for subnet,values in status['IPAM']['Subnets'].items():
        require(type(subnet) is str and str(ipaddress.ip_network(subnet))==subnet and
                type(values) is dict, 'NETWORK_SUBNET_SCHEMA')
        # Preserve the existence of each counter, subnet, and every unknown key.
        for key in ('IPsInUse','DynamicIPsAvailable'):
            require(type(values.get(key)) is int and values[key]>=0, 'NETWORK_COUNTER_SCHEMA')
            values[key]=0
    return result

def _net_link_map(rows):
    require(type(rows) is list and all(type(r) is dict for r in rows), 'NETWORK_LINK_SCHEMA')
    result={}
    names=set()
    for row in rows:
        require(type(row.get('ifindex')) is int and row['ifindex']>0 and
                type(row.get('ifname')) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',row['ifname']) and
                row['ifindex'] not in result and row['ifname'] not in names, 'NETWORK_LINK_ID')
        result[row['ifindex']]=row
        names.add(row['ifname'])
    return result

def _net_link_projection(rows):
    """Normalize documented runtime timers, retain configuration and unknowns.

    The input rows are not mutated; this function does not persist raw evidence.
    Presence and types are preserved. No wildcard timer/key removal.
    """
    links=deepcopy(_net_link_map(rows))
    def normalize(data, timers, counters=()):
        require(type(data) is dict, 'NETWORK_LINK_DETAILS')
        for key in timers:
            if key in data:
                value=data[key]
                require(type(value) in (int,float) and math.isfinite(value) and
                        value>=0, 'NETWORK_LINK_TIMER')
                data[key]=0
        for key in counters:
            if key in data:
                require(type(data[key]) is int and data[key]>=0, 'NETWORK_LINK_COUNTER')
                data[key]=0
    for row in links.values():
        info=row.get('linkinfo',{})
        require(type(info) is dict, 'NETWORK_LINK_DETAILS')
        if info.get('info_kind')=='bridge' and 'info_data' in info:
            normalize(info['info_data'],
                      ('hello_timer','tcn_timer','topology_change_timer','gc_timer'),
                      ('fdb_n_learned',))
        if info.get('info_slave_kind')=='bridge' and 'info_slave_data' in info:
            normalize(info['info_slave_data'],
                      ('hold_timer','message_age_timer','forward_delay_timer'))
    return [links[index] for index in sorted(links)]

def _net_owned_links(host_links, endpoints, peers, *, bridge):
    """endpoints: exact Docker ID -> MAC. peers: independently read netns links.

    Both ends' kernel ifindex/link_index and endpoint MAC must agree. A bridge
    member count or a name starting with veth is not ownership proof.
    """
    links=_net_link_map(host_links)
    bridges=[r for r in links.values() if r['ifname']==bridge]
    require(len(bridges)==1 and bridges[0].get('linkinfo',{}).get('info_kind')=='bridge', 'NETWORK_BRIDGE')
    require(type(endpoints) is dict and endpoints and set(endpoints)==set(peers), 'NETWORK_PEER_SET')
    owned={}
    for cid,mac in endpoints.items():
        require(re.fullmatch('[0-9a-f]{64}',cid) and type(mac) is str and
                re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac), 'NETWORK_ENDPOINT')
        matches=[r for r in _net_link_map(peers[cid]).values()
                 if r.get('address')==mac and r.get('linkinfo',{}).get('info_kind')=='veth']
        require(len(matches)==1, 'NETWORK_PEER_MAC')
        peer=matches[0]
        host=links.get(peer.get('link_index'),{})
        require(host.get('linkinfo',{}).get('info_kind')=='veth' and
                host.get('master')==bridge and host.get('link_index')==peer['ifindex'] and
                host['ifname'] not in owned, 'NETWORK_PEER_PAIR')
        owned[host['ifname']]=host
    members={r['ifname'] for r in links.values() if r.get('master')==bridge}
    require(members==set(owned),'NETWORK_UNOWNED_BRIDGE_MEMBER')
    return owned

def _net_address_readiness(rows, owned):
    """Read-only proof of DAD, not permission to ignore an absent address.

    Supported contract: one EUI-64 link-local /64 per owned host veth.
    Disabled IPv6, other generation modes and DAD failures fail closed.
    """
    indexed=_net_link_map(rows)
    pending=set()
    for name,link in owned.items():
        row=indexed.get(link['ifindex'],{})
        require(row.get('ifname')==name and type(row.get('addr_info')) is list and
                len(row['addr_info'])==1, 'NETWORK_ADDRESS_SET')
        address=row['addr_info'][0]
        require(type(address) is dict and address.get('family')=='inet6' and
                address.get('scope')=='link' and address.get('prefixlen')==64 and
                address.get('local')==_net_link_local(link), 'NETWORK_ADDRESS_IDENTITY')
        for flag in ('tentative','dadfailed','optimistic'):
            require(type(address.get(flag,False)) is bool, 'NETWORK_ADDRESS_FLAGS')
        require(not address.get('dadfailed',False) and not address.get('optimistic',False),
                'NETWORK_ADDRESS_DAD_FAILED')
        if address.get('tentative',False):pending.add(name)
    return pending

def _net_link_local(link):
    mac=link.get('address','')
    require(type(mac) is str and re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac),'NETWORK_HOST_MAC')
    octets=bytearray.fromhex(mac.replace(':',''));octets[0]^=2
    eui=octets[:3]+b'\xff\xfe'+octets[3:]
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('fe80::'))|int.from_bytes(eui,'big')))

def _net_route_projection(routes, owned, *, pending=frozenset()):
    """Canonical stable routes. Refuse unexpected routes even on a proven veth."""
    require(type(routes) is list and all(type(r) is dict for r in routes), 'NETWORK_ROUTES_SCHEMA')
    require(type(pending) in (set,frozenset) and pending<=set(owned), 'NETWORK_PENDING_SET')
    stable=[];seen=set();counts={name:set() for name in owned}
    for row in routes:
        digest=_network_digest(row)
        require(digest not in seen,'NETWORK_DUPLICATE_ROUTE');seen.add(digest)
        name=row.get('dev')
        if name not in owned:
            stable.append(deepcopy(row))
            continue
        local=_net_link_local(owned[name])
        common=dict(dev=name,protocol='kernel',flags=[],pref='medium')
        allowed={
            'prefix':dict(common,dst='fe80::/64',metric=256),
            'local':dict(common,type='local',dst=local,table='local',metric=0),
            'multicast':dict(common,type='multicast',dst='ff00::/8',table='local',metric=256)}
        matches=[kind for kind,wanted in allowed.items() if row==wanted]
        require(len(matches)==1 and matches[0] not in counts[name],'NETWORK_DYNAMIC_ROUTE')
        counts[name].add(matches[0])
    require(all(kinds=={'prefix','local','multicast'} or
                (name in pending and kinds=={'prefix','multicast'})
                for name,kinds in counts.items()),'NETWORK_DYNAMIC_ROUTE_SET')
    return sorted(stable,key=_network_digest)


def default_bridge_projection(row):
    """Version 3 only: exact default configuration, excluding daemon identity.

    The built-in empty bridge is re-created by Docker at daemon startup. This
    exception never applies to a custom network or an attached container.
    """
    require(type(row) is dict and sha(row.get('Id')) and type(row.get('Created')) is str and
            bool(row['Created']) and row.get('Name') == 'bridge' and row.get('Driver') == 'bridge' and
            type(row.get('Options')) is dict and
            row['Options'].get('com.docker.network.bridge.default_bridge') == 'true' and
            row['Options'].get('com.docker.network.bridge.name') == 'docker0' and
            row.get('Containers') == {}, 'PRODUCTION_DEFAULT_BRIDGE')
    result = _net_network_projection(row)
    del result['Id'], result['Created']
    return result


def validate_production_network(network, *, version=2):
    require(type(version) is int and version in (2, 3), 'PRODUCTION_NETWORK_VERSION')
    keys = {'physical_interfaces', 'interfaces', 'bridges', 'routes_sha256', 'ids'}
    require(type(network) is dict and set(network) ==
            keys | ({'default_bridge'} if version == 3 else set()), 'PRODUCTION_NETWORK_SCHEMA')
    physical, interfaces, bridges = (network[k] for k in ('physical_interfaces', 'interfaces', 'bridges'))
    name_ok = lambda n: type(n) is str and re.fullmatch('[A-Za-z0-9_.-]{1,15}', n)
    require(type(physical) is list and 1 <= len(physical) <= 16 and physical == sorted(set(physical)) and
            all(name_ok(n) and n != 'lo' for n in physical), 'PRODUCTION_PHYSICAL_SET')
    require(type(bridges) is dict and 1 <= len(bridges) <= 16, 'PRODUCTION_BRIDGES')
    names, bridge_names = set(), set()
    for nid, row in bridges.items():
        require(sha(nid) and type(row) is dict and set(row) == {'name', 'bridge', 'sha256'} and
                type(row['name']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',row['name']) and
                name_ok(row['bridge']) and sha(row['sha256']) and row['name'] not in names and
                row['bridge'] not in bridge_names and row['bridge'] not in {'lo', *physical}, 'PRODUCTION_BRIDGE')
        names.add(row['name']); bridge_names.add(row['bridge'])
    if version == 3:
        default = network['default_bridge']
        require(type(default) is dict and set(default) == {'name', 'bridge', 'sha256'} and
                default['name'] == 'bridge' and default['bridge'] == 'docker0' and sha(default['sha256']) and
                'bridge' not in names and 'docker0' not in bridge_names and 'docker0' not in physical,
                'PRODUCTION_DEFAULT_BRIDGE_SPEC')
        bridge_names.add('docker0')
    require(type(interfaces) is dict and set(interfaces) == {'lo', *physical, *bridge_names} and
            all(sha(v) for v in interfaces.values()) and sha(network['routes_sha256']), 'PRODUCTION_NETWORK_DIGEST')
    ids = network['ids']
    require(type(ids) is dict and set(ids) == {'log', *ORDER} and all(sha(v) for v in ids.values()) and
            len(set(ids.values())) == 10, 'PRODUCTION_CONTAINER_IDS')


def production_link_projection(row, *, bridge):
    """Only index and proven bridge carrier/runtime counters vary across boots."""
    row = deepcopy(row)
    if bridge:
        row = _net_link_projection([row])[0]
        require(row.get('linkinfo', {}).get('info_kind') == 'bridge', 'PRODUCTION_BRIDGE_LINK')
        require(type(row.get('flags')) is list and all(type(v) is str for v in row['flags']) and
                row.get('operstate') in ('UP', 'DOWN', 'UNKNOWN'), 'PRODUCTION_BRIDGE_STATE')
        row['flags'] = [f for f in row['flags'] if f not in ('LOWER_UP', 'NO-CARRIER', 'RUNNING')]
        row['operstate'] = 'CARRIER_RUNTIME'
        # Kernel-derived TSO frame capability changes when veth ports join or
        # leave (CI: 65536 -> 524280). Keep its presence, reject malformed data;
        # retain configurable GSO/MTU and all other attributes verbatim.
        if 'tso_max_size' in row:
            require(type(row['tso_max_size']) is int and 0 < row['tso_max_size'] <= 0xffffffff,
                    'PRODUCTION_BRIDGE_TSO')
            row['tso_max_size'] = 'PORT_CAPABILITY_RUNTIME'
    require(type(row.get('ifindex')) is int and row['ifindex'] > 0, 'PRODUCTION_LINK_INDEX')
    del row['ifindex']
    return row


class ProductionNetworkReader:
    """Root-peer GET only. This adapter cannot start/stop or alter a network."""
    def __init__(self, policy, *, clock=time.monotonic):
        from harbor_recovery_docker import UnixEngine
        allowed = frozenset(policy['network']['bridges']) | ({'bridge'} if policy['version'] == 3 else set())
        class Reader(UnixEngine):
            def _validate_request(self, method, path, body):
                require(method == 'GET' and body == b'' and path.startswith('/networks/') and
                        path.removeprefix('/networks/') in allowed, 'PRODUCTION_NETWORK_GET_ONLY')
        self.engine = Reader(policy['api_version'], socket_path=policy['socket'], clock=clock)
    def read(self, nid, deadline):
        return self.engine._json('/networks/' + nid, deadline)


class ProductionHostProvider(HostProvider):
    """Existing IDs may be stopped; no fixed boot or manager-absence shortcut.

    Staged-manager and resident-owner gates remain in their existing callers.
    No policy enrollment, routes learning, container creation, or retries.
    """
    def __init__(self, policy, engine, *, io=None, clock=time.monotonic, network_reader=None):
        super().__init__(policy, engine, io=io, clock=clock)
        self.network_reader = network_reader or ProductionNetworkReader(self._policy, clock=clock)

    def _identity(self):
        identity = self.io.identity()
        p = self._policy
        require(identity['hostname'] == p['hostname'] and identity['product_uuid'] == p['product_uuid'], 'HOST_IDENTITY')
        require(str(uuid.UUID(identity['boot'])) == identity['boot'], 'HOST_BOOT')
        require('hgfs' not in identity['mountinfo'].lower(), 'HOST_ISOLATION')
        require(self.io.physical_interfaces() == p['network']['physical_interfaces'], 'PRODUCTION_PHYSICAL_DRIFT')
        return identity['boot']

    def _network(self, deadline):
        p, spec = self._policy, self._policy['network']
        links = _net_link_projection(parse_json(self._run('ip', ['-j', '-d', 'link', 'show'], deadline)))
        by_name = {row['ifname']: row for row in links}
        bridge_names = {row['bridge'] for row in spec['bridges'].values()}
        if p['version'] == 3:
            bridge_names.add('docker0')
        for name, expected in spec['interfaces'].items():
            require(name in by_name and digest(production_link_projection(by_name[name], bridge=name in bridge_names)) == expected,
                    'PRODUCTION_INTERFACE_DRIFT')
        inventory = self.engine.inventory(deadline)
        require(type(inventory) is list, 'PRODUCTION_INVENTORY')
        selected = {}
        for row in inventory:
            require(type(row) is dict and (row.get('Labels') is None or type(row.get('Labels')) is dict), 'PRODUCTION_INVENTORY')
            labels = row.get('Labels') or {}
            if labels.get('com.docker.compose.project') == p['project']:
                name = labels.get('com.docker.compose.service')
                require(type(name) is str and name in spec['ids'] and name not in selected, 'PRODUCTION_SERVICE_SET')
                selected[name] = row.get('Id')
        require(selected == spec['ids'], 'PRODUCTION_CONTAINER_IDS_CHANGED')
        containers = {cid:self.engine.inspect(cid, deadline) for cid in spec['ids'].values()}
        networks, owned, members = {}, {}, set()
        if p['version'] == 3:
            # Only this exact name lookup may vary its ID. Pin its full stable
            # configuration and refuse endpoints, bridge ports or ID aliasing.
            default = self.network_reader.read('bridge', deadline)
            require(digest(default_bridge_projection(default)) == spec['default_bridge']['sha256'] and
                    default['Id'] not in spec['bridges'] and
                    not any(r.get('master') == 'docker0' for r in links), 'PRODUCTION_DEFAULT_BRIDGE_DRIFT')
            networks['bridge'] = default
        for nid, network_spec in spec['bridges'].items():
            row = self.network_reader.read(nid, deadline); networks[nid] = row
            require(type(row) is dict and row.get('Id') == nid and row.get('Name') == network_spec['name'] and
                    row.get('Driver') == 'bridge' and type(row.get('Options')) is dict and
                    row['Options'].get('com.docker.network.bridge.name', 'br-'+nid[:12]) == network_spec['bridge'] and
                    digest(_net_network_projection(row)) == network_spec['sha256'], 'PRODUCTION_NETWORK_DRIFT')
            endpoints = row.get('Containers')
            require(type(endpoints) is dict and set(endpoints) <= set(containers), 'PRODUCTION_FOREIGN_ENDPOINT')
            endpoint_macs, peers = {}, {}
            for cid, endpoint in endpoints.items():
                require(cid not in members and type(endpoint) is dict, 'PRODUCTION_ENDPOINT_DUPLICATE')
                item = containers[cid]; state = item.get('State', {})
                attached = item.get('NetworkSettings', {}).get('Networks', {})
                require(item.get('Id') == cid and state.get('Running') is True and state.get('Paused') is False and
                        state.get('Restarting') is False and type(state.get('Pid')) is int and state['Pid'] > 1 and
                        type(attached) is dict and set(attached) == {row['Name']}, 'PRODUCTION_ENDPOINT_STATE')
                config = attached[row['Name']]
                require(type(config) is dict and sha(config.get('EndpointID')) and
                        config.get('NetworkID') == nid and config.get('EndpointID') == endpoint.get('EndpointID') and
                        config.get('MacAddress') == endpoint.get('MacAddress'), 'PRODUCTION_ENDPOINT_BINDING')
                endpoint_macs[cid] = config['MacAddress']
                peers[cid] = self.io.peer_links(state['Pid'], p, deadline)
                members.add(cid)
            if endpoint_macs:
                proof = _net_owned_links(links, endpoint_macs, peers, bridge=network_spec['bridge'])
                require(not set(proof) & set(owned), 'PRODUCTION_ENDPOINT_DUPLICATE')
                owned.update(proof)
            else:
                require(not any(r.get('master') == network_spec['bridge'] for r in links), 'PRODUCTION_UNOWNED_MEMBER')
        for cid, item in containers.items():
            require(type(item) is dict and item.get('Id') == cid and type(item.get('State')) is dict, 'PRODUCTION_CONTAINER_SCHEMA')
            state = item['State']
            if cid not in members:
                require(state.get('Running') is False and state.get('Status') in ('exited','created') and
                        state.get('Pid') == 0 and state.get('Paused') is False and state.get('Restarting') is False,
                        'PRODUCTION_MISSING_ENDPOINT')
                attached = item.get('NetworkSettings', {}).get('Networks')
                allowed = {v['name']: nid for nid,v in spec['bridges'].items()}
                require(type(attached) is dict and len(attached) == 1 and set(attached) <= set(allowed),
                        'PRODUCTION_STOPPED_ATTACHMENTS')
                for name, config in attached.items():
                    require(type(config) is dict and config.get('NetworkID') == allowed[name] and
                            config.get('EndpointID') in ('', None), 'PRODUCTION_STOPPED_ATTACHMENTS')
        require(set(by_name) == set(spec['interfaces']) | set(owned), 'PRODUCTION_UNOWNED_LINK')
        pending = _net_address_readiness(parse_json(self._run('ip', ['-j','-6','address','show'], deadline)), owned)
        routes = parse_json(self._run('ip', ['-j','route','show','table','all'], deadline))
        stable = _net_route_projection(routes, owned, pending=pending)
        for row in stable:
            if row.get('dev') in bridge_names and 'flags' in row:
                require(type(row['flags']) is list, 'PRODUCTION_ROUTE_FLAGS')
                row['flags'] = [v for v in row['flags'] if v != 'linkdown']
        require(digest(sorted(stable,key=digest)) == spec['routes_sha256'], 'PRODUCTION_ROUTE_DRIFT')
        for cid, item in containers.items():
            later = self.engine.inspect(cid, deadline)
            signature = lambda r: [r.get('Id'), r.get('State',{}).get('Pid'), r.get('State',{}).get('Running'), r.get('NetworkSettings')]
            require(signature(later) == signature(item), 'PRODUCTION_ENDPOINT_CHANGED')
        require(all(self.network_reader.read(nid,deadline) == row for nid,row in networks.items()) and
                _net_link_projection(parse_json(self._run('ip',['-j','-d','link','show'],deadline))) == links,
                'PRODUCTION_TOPOLOGY_CHANGED')

    def _guards(self, deadline):
        require(self._run('getenforce', [], deadline).strip() == b'Enforcing', 'HOST_SELINUX')
        self._network(deadline)
        require(nft_fingerprint(self._run('nft', ['-j','list','table','inet',TABLE], deadline)) ==
                self._policy['nft_sha256'], 'HOST_AC04_DRIFT')
