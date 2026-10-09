"""Synthetic host gates plus Linux temporary-file/process I/O. No Docker/VM."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/recovery'))
import harbor_recovery_host as h
import harbor_recovery_docker as d
import harbor_recovery_core as c
from test_docker_adapter import FakeEngine

BOOT = '12345678-1234-1234-1234-123456789abc'
DAEMON = 'a' * 32
LABEL = 'system_u:object_r:admin_home_t:s0'


def raw(obj):
    return json.dumps(obj).encode()


def compose():
    return {'name': 'harbor', 'services': {name: {
        'image': 'example/' + name, 'restart': 'always' if name == 'log' else 'no',
        'environment': {'SYNTHETIC_SECRET': 'do-not-print'},
        'logging': {'driver': 'json-file'} if name == 'log' else {
            'driver': 'syslog', 'options': {'syslog-address': c.ENDPOINT, 'tag': name}}}
        for name in (*c.ORDER, 'log')}}


NFT = {'nftables': [{'metainfo': {'version': 'test'}},
                   {'table': {'family': 'inet', 'name': h.TABLE, 'handle': 1}},
                   {'rule': {'family': 'inet', 'table': h.TABLE, 'chain': 'input', 'handle': 3,
                             'expr': [{'counter': {'packets': 1, 'bytes': 2}}, {'drop': None}]}}]}


def policy():
    paths = ['/root/hbr-input/compose.json', '/root/hbr-input/empty.env',
             '/usr/lib/systemd/system/docker.service', '/etc/systemd/system/guard.service']
    tools = {name: '/usr/bin/' + name for name in h.TOOLS}
    files = {path: {'mode': 0o600, 'gid': 0, 'selinux': LABEL, 'sha256': 'b' * 64} for path in paths}
    files.update({path: {'mode': 0o755, 'gid': 0, 'selinux': LABEL, 'sha256': 'b' * 64}
                  for path in tools.values()})
    return {'version': 1, 'hostname': 'harbor01', 'product_uuid': BOOT, 'project': 'harbor',
            'tools': tools, 'files': files, 'directory': '/root/hbr-input',
            'directory_spec': {'mode': 0o700, 'gid': 0, 'selinux': LABEL},
            'compose_files': [paths[0]], 'env_file': paths[1],
            'compose_sha256': h.digest(compose()), 'compose_version': '5.5.1',
            'socket': '/run/docker.sock', 'socket_spec': {'mode': 0o660, 'gid': 0, 'selinux': LABEL},
            'api_version': '1.53', 'engine_profile': {
                'version': dict(zip(h.PROFILE_VERSION, ['29.8.0', '1.53', '1.44', '3ce5872', 'linux', 'amd64'])),
                'info': dict(zip(h.PROFILE_INFO, ['engine-test', '/var/lib/docker', 'overlayfs', [],
                                  ['name=seccomp,profile=builtin', 'name=cgroupns'], 'systemd', '2', 'linux', 'x86_64']))},
            'nft_sha256': h.nft_fingerprint(raw(NFT)), 'units': {
                'docker.service': {'fragment': paths[2], 'dropins': []},
                h.GUARD: {'fragment': paths[3], 'dropins': []}}}


class FakeIO:
    def __init__(self, p):
        self.p, self.calls, self.pin_calls = deepcopy(p), [], []
        self.stamp = {'hostname': 'harbor01', 'product_uuid': BOOT, 'boot': BOOT,
                      'mountinfo': 'root / xfs', 'physical_nics': False}
        self.on_run = lambda argv: None
        self.on_pin = lambda path: None
        self.outputs = {}
        self.socket_stamp = (1, 2, 3)

    def identity(self):
        return deepcopy(self.stamp)

    def pinned(self, path, spec, kind, deadline):
        self.pin_calls.append((path, kind)); self.on_pin(path)
        if kind == 'socket':
            return self.socket_stamp
        if kind == 'directory':
            return (1, 3)
        if path in self.p['compose_files']:
            return raw(compose())

    def run(self, argv, cwd, deadline):
        self.calls.append(argv); self.on_run(argv)
        tool = Path(argv[0]).name
        if tool in self.outputs:
            return self.outputs[tool]
        if tool == 'systemctl':
            name = argv[2]
            row = dict(LoadState='loaded', ActiveState='active',
                       SubState='running' if name == 'docker.service' else 'exited',
                       InvocationID=DAEMON, Requires=h.GUARD, After=h.GUARD,
                       FragmentPath=self.p['units'][name]['fragment'], DropInPaths='', NeedDaemonReload='no')
            return '\n'.join(k + '=' + v for k, v in row.items()).encode()
        if tool == 'getenforce': return b'Enforcing\n'
        if tool == 'ip':
            return raw([{'ifname': 'lo', 'link_type': 'loopback'},
                        {'ifname': 'docker0', 'linkinfo': {'info_kind': 'bridge'}}]) if 'link' in argv else b'[]'
        if tool == 'nft': return raw(NFT)
        if tool == 'compose': return b'5.5.1\n' if 'version' in argv else raw(compose())
        raise AssertionError('unexpected command')


class HostTests(unittest.TestCase):
    def setUp(self):
        self.p = policy()
        self.io = FakeIO(self.p)
        self.now = 10
        self.engine = FakeEngine()
        self.engine.path, self.engine.peer_uid, self.engine.prefix = '/run/docker.sock', 0, '/v1.53'
        self.engine.profile = lambda deadline: deepcopy(self.p['engine_profile'])
        self.provider = h.HostProvider(self.p, self.engine, io=self.io, clock=lambda: self.now)

    def reject(self):
        with self.assertRaisesRegex(ValueError, '^HOST_VERIFICATION_FAILED$'):
            self.provider(20)
        self.assertEqual(self.engine.posts, [])

    def test_fresh_snapshot_binding_and_private_outputs(self):
        stamp = self.provider(20)
        self.assertEqual(stamp, d.HostSnapshot(BOOT, DAEMON, self.provider.binding, 10))
        self.assertNotIn('do-not-print', repr(stamp))
        self.assertEqual(self.engine.posts, [])
        self.assertEqual(sum('config' in a for a in self.io.calls), 1)
        self.assertTrue(all(not {'up', 'start', 'restart', 'update', 'stop', 'pull', 'down'} & set(a)
                            for a in self.io.calls))

    def test_real_provider_contract_connects_to_docker_backend(self):
        plan = c.Plan(self.engine.ids, {s: d.project(r, s, r['Id'], 'harbor').fingerprint
                     for s, r in self.engine.rows.items()}, {s: 60 for s in c.ORDER},
                     execution_binding=d.execution_binding(self.provider.binding, 'harbor', self.engine.binding))
        backend = d.DockerBackend(plan, self.engine, self.provider, self.provider.binding, 'harbor',
                                  clock=lambda: self.now, probe=lambda _: True)
        self.assertTrue(backend.observe().guards_ok)
        self.io.outputs['getenforce'] = b'Permissive'
        action = c.Action(1, 'postgresql', plan.ids['postgresql'], BOOT, DAEMON, 20)
        self.assertEqual(backend.start(action, 5), 'failed')
        self.assertEqual(self.engine.posts, [])

    def test_copy_policy_and_reject_internal_policy_drift(self):
        self.p['hostname'] = 'changed'
        self.assertEqual(self.provider(20).binding, self.provider.binding)
        self.provider._policy['hostname'] = 'changed'
        self.reject()

    def test_all_policy_values_bound(self):
        before = self.provider.binding
        changed = policy(); changed['compose_sha256'] = 'f' * 64
        self.assertNotEqual(before, h.HostProvider(changed, self.engine, io=self.io).binding)

    def test_identity_and_isolation_fail_closed(self):
        for key, value in [('hostname', 'production'), ('product_uuid', 'f' * 36),
                           ('boot', 'invalid'), ('physical_nics', True),
                           ('mountinfo', 'fuse.vmhgfs-fuse .host:/shared')]:
            with self.subTest(key=key):
                old = self.io.stamp[key]; self.io.stamp[key] = value
                self.reject(); self.io.stamp[key] = old

    def test_selinux_rejected_before_compose(self):
        self.io.outputs['getenforce'] = b'Permissive'
        self.reject()
        self.assertFalse(any('config' in a for a in self.io.calls))

    def test_guard_change_during_collection(self):
        def change(argv):
            if 'config' in argv: self.io.outputs['getenforce'] = b'Disabled'
        self.io.on_run = change
        self.reject()

    def test_default_route_blocks_even_with_only_virtual_interfaces(self):
        normal = self.io.run
        def run(argv, cwd, deadline):
            if 'route' in argv: return raw([{'dst': 'default', 'gateway': '192.0.2.1'}])
            return normal(argv, cwd, deadline)
        self.io.run = run
        self.reject()

    def test_boot_or_socket_replacement_during_collection(self):
        for change in (lambda: self.io.stamp.update(boot='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
                       lambda: setattr(self.io, 'socket_stamp', (9, 9, 9))):
            self.setUp()
            self.io.on_run = lambda argv: change() if 'config' in argv else None
            self.reject()

    def test_deadline_is_not_refreshed(self):
        self.io.on_run = lambda _: setattr(self, 'now', 21)
        self.reject()

    def test_engine_profile_mismatch_and_missing_field(self):
        self.p['engine_profile']['info']['Driver'] = 'other'
        self.reject()
        del self.p['engine_profile']['info']['Driver']
        self.reject()

    def test_transport_mutation_rejected(self):
        self.engine.peer_uid = 1000
        self.reject()
        self.assertEqual(self.io.calls, [])

    def test_ac04_rule_drift_rejected(self):
        changed = deepcopy(NFT); changed['nftables'][2]['rule']['expr'][-1] = {'accept': None}
        self.io.outputs['nft'] = raw(changed)
        self.reject()

    def test_counter_handle_changes_are_not_policy_drift(self):
        changed = deepcopy(NFT)
        changed['nftables'][1]['table']['handle'] = 999
        changed['nftables'][2]['rule']['expr'][0]['counter']['packets'] = 999
        self.assertEqual(h.nft_fingerprint(raw(changed)), self.p['nft_sha256'])

    def test_compose_drift_and_source_external_input(self):
        changed = compose(); changed['services']['core']['environment']['SYNTHETIC_SECRET'] = 'changed'
        self.io.outputs['compose'] = raw(changed)
        self.reject()
        for obj in ({'include': ['https://invalid.example']}, {'services': {'x': {'env_file': '/private'}}},
                    {'services': {'x': {'extends': 'remote'}}}, {'secrets': {}}):
            with self.assertRaisesRegex(ValueError, 'EXTERNAL_INPUT'):
                h.standalone_compose(raw(obj))

    def test_rendered_policy_and_logging_checks_even_if_pinned(self):
        for update in (lambda obj: obj['services']['core'].update(restart='always'),
                       lambda obj: obj['services']['core']['logging']['options'].update(
                           **{'syslog-address': 'tcp://localhost:1514'})):
            obj = compose(); update(obj)
            with self.assertRaises(ValueError): h.compose_check(raw(obj), h.digest(obj))

    def test_secret_in_command_error_does_not_escape(self):
        self.io.on_run = lambda _: (_ for _ in ()).throw(RuntimeError('PRIVATE_ENV_VALUE'))
        self.reject()

    def test_command_exact_compose_paths_and_no_environment_render(self):
        self.provider(20)
        argv = next(a for a in self.io.calls if 'config' in a)
        self.assertEqual(argv, ['/usr/bin/compose', '--project-directory', '/root/hbr-input',
                        '--project-name', 'harbor', '--env-file', '/root/hbr-input/empty.env',
                        '-f', '/root/hbr-input/compose.json', 'config', '--format', 'json',
                        '--no-interpolate', '--no-env-resolution'])

    def test_no_arbitrary_tool_or_unpinned_path_policy(self):
        changes = [lambda p: p['tools'].update(extra='/usr/bin/anything'),
                   lambda p: p['files'].pop('/usr/bin/nft'),
                   lambda p: p.update(directory='/root/../etc'),
                   lambda p: p.update(compose_files=['/home/server08/compose.yaml']),
                   lambda p: p.update(api_version='1.99'),
                   lambda p: p['directory_spec'].update(mode=0o755),
                   lambda p: p['socket_spec'].update(mode=0o666),
                   lambda p: p['files']['/usr/bin/nft'].update(mode=0o777)]
        for change in changes:
            p = policy(); change(p)
            with self.subTest(change=change), self.assertRaises(ValueError):
                h.HostProvider(p, self.engine, io=self.io)


class ParsingTests(unittest.TestCase):
    def test_unit_expected_sources_and_dependency(self):
        p = policy(); io = FakeIO(p)
        row = h.properties(io.run(['/usr/bin/systemctl', 'show', 'docker.service'], '/', 20))
        h.unit_check(row, p['units']['docker.service'], docker=True)
        for key, value in [('LoadState', 'not-found'), ('ActiveState', 'inactive'),
                           ('SubState', 'dead'), ('Requires', ''), ('After', ''),
                           ('NeedDaemonReload', 'yes'), ('InvocationID', '0' * 32),
                           ('FragmentPath', '/other'), ('DropInPaths', '/etc/injected')]:
            changed = dict(row, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                h.unit_check(changed, p['units']['docker.service'], docker=True)

    def test_duplicate_unit_and_json_keys_rejected(self):
        with self.assertRaises(ValueError): h.properties(b'LoadState=loaded\nLoadState=other')
        with self.assertRaises(ValueError): h.standalone_compose(b'{"services":{},"services":{}}')

    def test_unexpected_network_link_rejected(self):
        for link in ({'ifname': 'eth0', 'link_type': 'ether'},
                     {'ifname': 'tun0', 'linkinfo': {'info_kind': 'tun'}},
                     {'ifname': 'lo', 'link_type': 'ether'}):
            with self.assertRaises(ValueError): h.network_check(raw([link]))

    def test_profile_excludes_unstable_counters_but_keeps_security(self):
        profile = policy()['engine_profile']; changed = deepcopy(profile)
        changed['info']['ContainersRunning'] = 10
        self.assertEqual(h.engine_profile(changed), profile)

    def test_engine_profile_get_allowlist(self):
        engine = d.UnixEngine('1.53')
        calls = []
        with patch.object(engine, '_request', side_effect=lambda m, p, t: (calls.append((m, p)) or (200, b'{}'))):
            self.assertEqual(engine.profile(20), {'version': {}, 'info': {}})
        self.assertEqual(calls, [('GET', '/version'), ('GET', '/info')])


@unittest.skipUnless(sys.platform == 'linux', 'Linux file/xattr/process test')
class LinuxIOTests(unittest.TestCase):
    def setUp(self):
        self.io = h.LinuxReadOnly()
        self.temp = tempfile.TemporaryDirectory(prefix='host-guard-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / 'input.json'
        self.file.write_bytes(b'{"test":true}')
        self.file.chmod(0o600)
        self.spec = {'mode': 0o600, 'gid': os.getgid(), 'selinux': LABEL,
                     'sha256': hashlib.sha256(self.file.read_bytes()).hexdigest()}
        # CI is unprivileged/non-SELinux. Keep real nofollow/type/content checks;
        # mock only expected root ownership and SELinux xattrs for local files.
        self.original_security = self.io._security
        def security(fd, *, spec=None, socket_path=None):
            target = fd if socket_path is None else socket_path
            st = os.fstat(fd) if socket_path is None else os.stat(target, follow_symlinks=False)
            self.assertIn(st.st_uid, (0, os.getuid()))
            if spec is None:
                self.assertFalse(st.st_mode & 0o022)
            else:
                self.assertEqual(st.st_mode & 0o777, spec['mode'])
            return st
        self.io._security = security

    def pin(self, path=None):
        return self.io.pinned(str(path or self.file), self.spec, 'file', time.monotonic() + 5)

    def test_actual_read_hash_and_reject_content_change(self):
        self.assertEqual(self.pin(), b'{"test":true}')
        self.file.write_bytes(b'{"test":false}')
        with self.assertRaisesRegex(ValueError, 'HASH'): self.pin()

    def test_reject_symlink_parent_and_final_hardlink_fifo(self):
        link = self.root / 'link.json'; link.symlink_to(self.file)
        with self.assertRaises(OSError): self.pin(link)
        parent = self.root / 'parent'; parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): self.pin(parent / 'input.json')
        link.unlink(); os.link(self.file, link)
        with self.assertRaisesRegex(ValueError, 'TYPE_SIZE'): self.pin()
        fifo = self.root / 'fifo.json'; os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(ValueError, 'TYPE_SIZE'): self.pin(fifo)

    def test_security_acl_label_and_owner_checks(self):
        with self.file.open('rb') as stream:
            st = os.fstat(stream.fileno())
            with patch.object(h.os, 'fstat', return_value=type('Stat', (), {
                    'st_uid': 0, 'st_mode': st.st_mode, 'st_gid': st.st_gid})()), \
                    patch.object(h.os, 'listxattr', return_value=['system.posix_acl_default']):
                with self.assertRaisesRegex(ValueError, 'ACL'): self.original_security(stream.fileno(), spec=self.spec)
            with patch.object(h.os, 'fstat', return_value=type('Stat', (), {
                    'st_uid': 0, 'st_mode': st.st_mode, 'st_gid': st.st_gid})()), \
                    patch.object(h.os, 'listxattr', return_value=[]), \
                    patch.object(h.os, 'getxattr', return_value=b'wrong_label'):
                with self.assertRaisesRegex(ValueError, 'LABEL'): self.original_security(stream.fileno(), spec=self.spec)

    def test_command_reads_only_output_and_cleans_environment(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://bad', 'COMPOSE_FILE': '/bad', 'PRIVATE': 'secret'}):
            out = self.io.run([sys.executable, '-c',
                              'import os,json;print(json.dumps(dict(os.environ)))'], str(self.root), time.monotonic() + 5)
        env = json.loads(out)
        self.assertNotIn('DOCKER_HOST', env); self.assertNotIn('COMPOSE_FILE', env)
        self.assertNotIn('PRIVATE', env)

    def test_nfs_acl_capability_and_socket_symlink_xattr_rejected(self):
        fake=type('Stat',(),{'st_uid':0,'st_gid':0,'st_mode':0o140600})()
        spec={'mode':0o600,'gid':0,'selinux':LABEL}
        for attr,code in [('system.nfs4_acl','ACL'),('security.capability','XATTR')]:
            with patch.object(h.os,'stat',return_value=fake),patch.object(h.os,'listxattr',return_value=[attr]):
                with self.assertRaisesRegex(ValueError,code):self.original_security(0,spec=spec,socket_path='/test/socket')
        with patch.object(h.os,'stat',return_value=fake), \
             patch.object(h.os,'listxattr',return_value=['security.selinux']) as listing, \
             patch.object(h.os,'getxattr',return_value=LABEL.encode()) as get:
            self.original_security(0,spec=spec,socket_path='/test/socket')
            listing.assert_called_once_with('/test/socket',follow_symlinks=False)
            get.assert_called_once_with('/test/socket','security.selinux',follow_symlinks=False)

    def test_command_timeout_output_limit_nonzero(self):
        for code, budget in [('import time;time.sleep(2)', .05),
                             ('import sys;sys.stdout.write("x"*2000)', 2),
                             ('import sys;sys.stderr.write("secret");sys.exit(4)', 2)]:
            with self.subTest(code=code), patch.object(h, 'MAX_OUTPUT', 1000):
                with self.assertRaises((ValueError, TimeoutError)) as caught:
                    self.io.run([sys.executable, '-c', code], str(self.root), time.monotonic() + budget)
                self.assertNotIn('secret', str(caught.exception))

    def test_helper_parent_exit_with_pipe_owner_is_bounded(self):
        code = ('import os,time; child=os.fork(); '
                'time.sleep(3) if child==0 else os._exit(0)')
        started = time.monotonic()
        with self.assertRaises(ValueError):
            self.io.run([sys.executable, '-c', code], str(self.root), started + .2)
        self.assertLess(time.monotonic() - started, 2)


if __name__ == '__main__':
    unittest.main()
