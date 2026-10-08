import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


renderer = load('renderer', 'scripts/verify/render-clone-ssh-plan.py')
if sys.platform == 'win32':
    # Only POSIX identity lookup is stubbed; no actual Windows authentication test.
    with patch.dict(sys.modules, {'pwd': types.ModuleType('pwd')}):
        endpoint = load('endpoint', 'scripts/verify/hbr-ssh-readonly.py')
else:
    endpoint = load('endpoint', 'scripts/verify/hbr-ssh-readonly.py')

# Synthetic wire-format test material. Never an authorized key or runtime receipt.
KEY = 'ssh-ed25519 ' + base64.b64encode(
    struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))
).decode('ascii')


class RenderTests(unittest.TestCase):
    def render(self, **overrides):
        args = dict(interface='ens192', mac='00:50:56:30:00:02', key=KEY,
                    expires=2000, now=1000)
        args.update(overrides)
        return renderer.render(**args)

    def test_injection_and_bridge_interfaces_rejected(self):
        for value in ['lo', 'docker0', 'br1234', 'veth1', 'ens192"; flush ruleset',
                      '../etc', 'ens192\n', '', 'x' * 16]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.render(interface=value)

    def test_mac_not_arbitrary_vmware_address(self):
        for mac in ['ff:ff:ff:ff:ff:ff', '00:50:56:80:00:02', '00:0c:29:00:00:01',
                    '00:50:56:30:00:02\n', 'invalid']:
            with self.subTest(mac=mac), self.assertRaises(ValueError):
                self.render(mac=mac)

    def test_no_private_key_options_or_invalid_wire_format(self):
        for key in ['-----BEGIN OPENSSH PRIVATE KEY-----', 'command="sh" ' + KEY,
                    'ssh-ed25519 AAAA', KEY + '\n' + KEY, KEY + ' bad\"comment']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.render(key=key)

    def test_expired_or_long_lived_policy_rejected(self):
        for expires in [999, 1000, 15401, 2000.0, True]:
            with self.subTest(expires=expires), self.assertRaises(ValueError):
                self.render(expires=expires)

    def test_candidate_has_no_ready_claim_or_default_route(self):
        files = self.render()
        plan = json.loads(files['plan.json'])
        self.assertEqual(plan['runtime'], 'NOT_RUN')
        self.assertEqual(plan['status'], 'REVIEW_CANDIDATE_NOT_DEPLOYABLE')
        self.assertEqual(len(plan['old_profiles_disable_autoconnect']), 2)
        profile = files['hbr-mgmt.nmconnection.candidate']
        self.assertIn('autoconnect=false', profile)
        self.assertNotIn('gateway=', profile)
        self.assertIn('method=disabled', profile)
        nft = files['hbr-mgmt.nft.candidate']
        self.assertIn('iifname "ens192" counter drop', nft)
        self.assertIn('oifname "ens192" counter drop', nft)
        self.assertNotIn('flush ruleset\n', nft)
        self.assertNotIn('sudo', files['00-hbr-mgmt-sshd.conf.candidate'])

    def test_existing_output_not_overwritten_and_hashes_bind_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'candidate'
            renderer.write_candidates(output, self.render())
            manifest = (output / 'SHA256SUMS').read_bytes()
            for line in manifest.decode('ascii').splitlines():
                sha, name = line.split('  ', 1)
                self.assertEqual(sha, hashlib.sha256((output / name).read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                renderer.write_candidates(output, self.render())
            self.assertEqual(manifest, (output / 'SHA256SUMS').read_bytes())


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(renderer.render('ens192', '00:50:56:30:00:02', KEY,
                                                2000, now=1000)['hbr-ssh-policy.json.candidate'])
        self.env = {'SSH_CONNECTION': '192.168.253.1 54321 192.168.253.2 22',
                    'SSH_ORIGINAL_COMMAND': 'identity'}

    def call(self, **overrides):
        args = dict(policy=self.policy, environ=self.env, username='hbrctl', uid=1002, now=1000)
        args.update(overrides)
        return endpoint.authorize(**args)

    def test_exact_allowlist_only(self):
        for command in ['identity', 'network', 'services']:
            self.env['SSH_ORIGINAL_COMMAND'] = command
            _, argv = self.call()
            self.assertEqual(argv, endpoint.COMMANDS[command])
        for command in ['', 'sh', 'sudo docker ps', 'services; reboot', ' network',
                        'network\n', 'scp -t /tmp/file', 'internal-sftp', 'identity --help']:
            self.env['SSH_ORIGINAL_COMMAND'] = command
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.call()

    def test_wrong_peer_local_address_or_port_denied(self):
        for connection in ['', '192.168.253.3 42 192.168.253.2 22',
                           '192.168.253.1 42 10.1.93.54 22',
                           '192.168.253.1 42 192.168.253.2 2222',
                           '192.168.253.1 0 192.168.253.2 22']:
            self.env['SSH_CONNECTION'] = connection
            with self.subTest(connection=connection), self.assertRaises(ValueError):
                self.call()

    def test_expiry_and_root_or_wrong_user_denied(self):
        for overrides in [dict(now=2000), dict(now=2001), dict(uid=0), dict(username='server08')]:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.call(**overrides)

    def test_policy_cannot_expand_scope(self):
        for key, value in [('allowed', ['identity', 'shell']), ('guest', '10.1.93.54'),
                           ('host', '0.0.0.0'), ('user', 'root'), ('expires_epoch', '2000')]:
            policy = dict(self.policy, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.call(policy=policy)

    def test_denial_never_starts_process(self):
        with patch.object(endpoint, 'load_policy', return_value=self.policy), \
             patch.object(endpoint.os, 'getuid', return_value=1002, create=True), \
             patch.object(endpoint.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_name='hbrctl'), create=True), \
             patch.dict(endpoint.os.environ, dict(self.env, SSH_ORIGINAL_COMMAND='sh'), clear=True), \
             patch.object(endpoint.subprocess, 'run') as run:
            self.assertEqual(endpoint.main(), 2)
            run.assert_not_called()

    def test_fixed_environment_and_timeout_failure(self):
        with patch.object(endpoint, 'load_policy', return_value=self.policy), \
             patch.object(endpoint.os, 'getuid', return_value=1002, create=True), \
             patch.object(endpoint.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_name='hbrctl'), create=True), \
             patch.dict(endpoint.os.environ, dict(self.env, PATH='/evil', PYTHONPATH='/evil'), clear=True), \
             patch.object(endpoint.time, 'time', return_value=1995), \
             patch.object(endpoint.subprocess, 'run', side_effect=endpoint.subprocess.TimeoutExpired(['id'], 5)) as run:
            self.assertEqual(endpoint.main(), 2)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/id'])
            self.assertEqual(run.call_args.kwargs['env'], endpoint.ENV)
            self.assertEqual(run.call_args.kwargs['timeout'], 5)
            self.assertNotIn('shell', run.call_args.kwargs)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX file ownership and O_NOFOLLOW')
    def test_root_owned_mode_check_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy'
            path.write_text(json.dumps(self.policy))
            for mode, uid, denied in [(0o644, 0, False), (0o666, 0, True),
                                      (0o664, 0, True), (0o644, 1000, True)]:
                metadata = types.SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid,
                                                 st_size=path.stat().st_size)
                with self.subTest(mode=mode, uid=uid), patch.object(endpoint.os, 'fstat', return_value=metadata):
                    if denied:
                        with self.assertRaises(ValueError):
                            endpoint.load_policy(path)
                    else:
                        self.assertEqual(endpoint.load_policy(path), self.policy)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX file ownership and O_NOFOLLOW')
    def test_policy_symlink_and_world_writable_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy'
            path.write_text(json.dumps(self.policy))
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                endpoint.load_policy(link)
            path.chmod(0o666)
            with self.assertRaises(ValueError):
                endpoint.load_policy(path)


if __name__ == '__main__':
    unittest.main()
