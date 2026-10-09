import contextlib
import json
import subprocess
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import patch

from test_ssh_plan import KEY, ROOT, load, renderer
import sys

if sys.platform == 'win32':
    with patch.dict(sys.modules, {'pwd': types.ModuleType('pwd'), 'grp': types.ModuleType('grp')}):
        lifecycle = load('lifecycle', 'scripts/verify/hbr-ssh-lifecycle.py')
else:
    lifecycle = load('lifecycle', 'scripts/verify/hbr-ssh-lifecycle.py')


class GuardTests(unittest.TestCase):
    def test_naming_precheck_rejects_collision_missing_tool_and_dropin(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tool = base / 'udevadm'
            roots = [base / 'network']
            with self.assertRaisesRegex(ValueError, 'UDEVADM_MISSING'):
                lifecycle.naming_precheck('hbrmgmt0', base, tool, roots)
            tool.touch()
            lifecycle.naming_precheck('hbrmgmt0', base, tool, roots)
            (base / 'hbrmgmt0').mkdir()
            with self.assertRaisesRegex(ValueError, 'INTERFACE_NAME_IN_USE'):
                lifecycle.naming_precheck('hbrmgmt0', base, tool, roots)
            (base / 'hbrmgmt0').rmdir()
            roots[0].mkdir()
            (roots[0] / '10-hbr-mgmt.link.d').mkdir()
            with self.assertRaisesRegex(ValueError, 'LINK_DROPIN_EXISTS'):
                lifecycle.naming_precheck('hbrmgmt0', base, tool, roots)
            (roots[0] / '10-hbr-mgmt.link.d').rmdir()
            (roots[0] / '10-hbr-mgmt.link').touch()
            with self.assertRaisesRegex(ValueError, 'LINK_CONFIG_EXISTS'):
                lifecycle.naming_precheck('hbrmgmt0', base, tool, roots)

    def test_management_only_addresses(self):
        row = {'ifname': 'ens192', 'flags': ['UP'], 'addr_info':
               [{'family': 'inet', 'local': '192.168.253.2', 'prefixlen': 24}]}
        lifecycle.validate_addresses([row], 'ens192', True)
        for address in ['10.1.93.54', '192.168.253.3', 'fe80::1']:
            changed = dict(row, addr_info=[{'family': 'inet', 'local': address, 'prefixlen': 24}])
            with self.subTest(address=address), self.assertRaises(ValueError):
                lifecycle.validate_addresses([changed], 'ens192', True)
        with self.assertRaises(ValueError):
            lifecycle.validate_addresses([row], 'ens192', False)

    def test_even_secondary_production_ip_is_rejected(self):
        management = {'ifname': 'ens192', 'flags': [], 'addr_info': []}
        other = {'ifname': 'dummy0', 'addr_info': [{'local': '10.1.93.54'}]}
        with self.assertRaises(ValueError):
            lifecycle.validate_addresses([management, other], 'ens192', False)

    def test_host_gate_expiry_identity_and_types(self):
        plan = {'mac': '00:50:56:30:00:02', 'interface': 'ens192'}
        gate = dict(plan, vmnet='VMnet2', host_only=True, dhcp=False, nat=False,
                    bridge=False, other_guests=False, host_forwarding=False,
                    host='192.168.253.1', guest='192.168.253.2', checked_epoch=1000)
        lifecycle.gate_valid(gate, plan, 1500)
        for changes in [dict(nat=True), dict(host_only=1), dict(checked_epoch=0),
                        dict(checked_epoch=1501), dict(mac='00:50:56:30:00:03'), dict(extra=True)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                lifecycle.gate_valid(dict(gate, **changes), plan, 1500)

    def test_nft_ignores_only_counters_and_handles(self):
        before = {'nftables': [{'rule': {'handle': 1, 'expr': [{'counter': {'packets': 0}}, {'drop': None}]}}]}
        after = {'nftables': [{'rule': {'handle': 99, 'expr': [{'counter': {'packets': 42}}, {'drop': None}]}}]}
        self.assertEqual(lifecycle.nft_shape(json.dumps(before)), lifecycle.nft_shape(json.dumps(after)))
        after['nftables'][0]['rule']['expr'][1] = {'accept': None}
        self.assertNotEqual(lifecycle.nft_shape(json.dumps(before)), lifecycle.nft_shape(json.dumps(after)))

    def test_no_nic_does_not_mean_guest_ready(self):
        with patch.object(lifecycle, 'physical', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'NIC_SET'):
                lifecycle.network_guard({'plan': {'interface': 'ens192'}})

    def test_disconnect_does_not_require_selinux_or_hgfs_clean(self):
        state = {'plan': {'interface': 'ens192'}, 'commands': []}
        with patch.object(lifecycle, 'identity_guard'), \
             patch.object(lifecycle, 'host_guard', side_effect=AssertionError('must not block teardown')), \
             patch.object(lifecycle, 'physical', return_value=[]), \
             patch.object(lifecycle, 'save'):
            lifecycle.disconnect(state)
        self.assertEqual(state['status'], 'SESSION_STOPPED')


class InstallTests(unittest.TestCase):
    """MOCK command adapter; real temporary file writes, no host configuration changes."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.calls = []
        self.account = False
        self.group = False
        self.fail_command = None
        self.disabled = set()
        self.bundle = base / 'bundle'
        renderer.write_candidates(self.bundle, renderer.render('ens192', '00:50:56:30:00:02', KEY,
                                                               int(time.time()) + 3600))
        state_root = base / 'private'
        self.stack.enter_context(patch.object(lifecycle, 'ROOT', state_root))
        self.stack.enter_context(patch.object(lifecycle, 'STATE', state_root / 'state.json'))
        mapping = {}
        for name, old in lifecycle.FILES.items():
            target = state_root / 'hbr-mgmt.nft' if name == 'hbr-mgmt.nft.candidate' else base / old.name
            mapping[name] = target
        for key in ['SELF', 'ENDPOINT', 'UNIT', 'EXPIRE', 'TIMER', 'NMCONF', 'LINK', 'ZONE', 'SSHD', 'KEY', 'POLICY']:
            self.stack.enter_context(patch.object(lifecycle, key, base / getattr(lifecycle, key).name))
        self.stack.enter_context(patch.object(lifecycle, 'NFT', state_root / 'hbr-mgmt.nft'))
        self.stack.enter_context(patch.object(lifecycle, 'FILES', mapping))
        self.host = self.stack.enter_context(patch.object(lifecycle, 'host_guard'))
        self.stack.enter_context(patch.object(lifecycle, 'read_safe', side_effect=lambda p: Path(p).read_bytes()))
        self.stack.enter_context(patch.object(lifecycle, 'trusted_parents'))
        self.stack.enter_context(patch.object(lifecycle, 'naming_precheck'))
        self.stack.enter_context(patch.object(lifecycle, 'run', side_effect=self.fake_run))
        self.stack.enter_context(patch.object(lifecycle, 'ssh_guard'))
        self.stack.enter_context(patch.object(lifecycle, 'current_nft', return_value={'mock': True}))
        self.stack.enter_context(patch.object(lifecycle.pwd, 'getpwnam', side_effect=self.lookup, create=True))
        self.stack.enter_context(patch.object(lifecycle.grp, 'getgrnam', side_effect=self.lookup_group, create=True))

    def lookup(self, _):
        if not self.account:
            raise KeyError('no account')
        return types.SimpleNamespace(pw_uid=1234, pw_gid=1234)

    def lookup_group(self, _):
        if not self.group:
            raise KeyError('no group')
        return types.SimpleNamespace(gr_gid=1234, gr_mem=[])

    def fake_run(self, argv, state=None, check=True):
        self.calls.append(argv)
        if self.fail_command and self.fail_command(argv):
            raise ValueError('injected command failure')
        if argv[0].endswith('/ip') and '-j' in argv:
            return 0, '[]'
        if argv[0].endswith('useradd'):
            self.account = self.group = True
        if argv[0].endswith('userdel'):
            self.account = False
        if argv[0].endswith('groupdel'):
            self.group = False
        if argv[1:3] == ['connection', 'modify']:
            if argv[-1] == 'no':
                self.disabled.add(argv[3])
            else:
                self.disabled.discard(argv[3])
        if argv[1:3] == ['-g', 'connection.autoconnect']:
            return 0, 'no' if argv[-1] in self.disabled else 'yes'
        if argv[1:3] == ['-g', 'UUID']:
            return 0, '\n'.join(lifecycle.OLD)
        if argv[1:3] == ['-g', 'connection.type']:
            return 0, '802-3-ethernet'
        if argv[1:] == ['is-active', 'hbr-ssh-expire.timer']:
            return 0, 'active'
        if argv[1:] == ['--get-zone-of-interface=ens192']:
            return 0, 'hbr-mgmt'
        return 0, ''

    def install(self):
        lifecycle.install(self.bundle, ROOT / 'scripts/verify')

    def test_install_does_not_raise_link_or_enable_boot_service(self):
        self.install()
        state = json.loads(lifecycle.STATE.read_text())
        self.assertEqual(state['status'], 'INSTALLED_LINK_DISABLED')
        self.assertEqual(self.disabled, set(lifecycle.OLD))
        self.assertFalse(any('docker' in ' '.join(c) for c in self.calls))
        self.assertFalse(any(c[0].endswith('/ip') and '-j' not in c for c in self.calls))
        self.assertFalse(any('enable' in c for c in self.calls))
        self.assertFalse(any('trigger' in c for c in self.calls))
        self.assertIn(['/usr/bin/udevadm', 'control', '--reload'], self.calls)
        self.assertIn('OnCalendar=', lifecycle.TIMER.read_text())
        self.host.assert_called_with(disconnected=True)

    def test_install_failure_retains_receipt_and_explicit_rollback(self):
        self.fail_command = lambda c: c[0].endswith('/nft') and '-f' in c
        with self.assertRaises(ValueError):
            self.install()
        state = json.loads(lifecycle.STATE.read_text())
        self.assertEqual(state['status'], 'INSTALL_FAILED_CONSOLE_ROLLBACK_REQUIRED')
        self.assertEqual(self.disabled, set(lifecycle.OLD))
        self.fail_command = None
        lifecycle.rollback()
        self.assertEqual(json.loads(lifecycle.STATE.read_text())['status'], 'ROLLED_BACK')
        self.assertFalse(self.account)
        self.assertFalse(self.group)
        self.assertEqual(self.disabled, set())

    def test_udev_reload_failure_preserves_naming_file_until_rollback(self):
        self.fail_command = lambda c: c[0].endswith('/udevadm')
        with self.assertRaises(ValueError):
            self.install()
        self.assertTrue(lifecycle.LINK.exists())
        self.assertEqual(json.loads(lifecycle.STATE.read_text())['status'],
                         'INSTALL_FAILED_CONSOLE_ROLLBACK_REQUIRED')
        self.assertFalse(any('up' in c or 'trigger' in c for c in self.calls))
        self.fail_command = None
        lifecycle.rollback()
        self.assertFalse(lifecycle.LINK.exists())
        self.assertEqual(self.disabled, set())

    def test_rollback_refuses_changed_naming_file(self):
        self.install()
        lifecycle.LINK.write_text('[Match]\nOriginalName=*\n')
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'ROLLBACK_FILE_DRIFT'):
            lifecycle.rollback()
        self.assertEqual(self.calls, [])

    def check_rollback_udev_failure(self, timeout=False):
        self.install()
        claim = lifecycle.ROOT / 'session.claim'
        claim.write_text('preserve one-use claim')
        fail_udev, nft_exists = True, True

        def run(argv, state=None, check=True):
            nonlocal nft_exists
            result = self.fake_run(argv, state, check)
            if argv == ['/usr/sbin/nft', 'list', 'tables']:
                return 0, 'table inet hbr_ssh_guard' if nft_exists else ''
            if argv == ['/usr/sbin/nft', 'delete', 'table', 'inet', 'hbr_ssh_guard']:
                nft_exists = False
            if argv[0] == '/usr/bin/udevadm' and fail_udev:
                if timeout:
                    raise subprocess.TimeoutExpired(argv, 20)
                raise ValueError('COMMAND_FAILED: /usr/bin/udevadm')
            return result

        with patch.object(lifecycle, 'run', side_effect=run):
            for attempt in range(2):
                self.calls.clear()
                error = subprocess.TimeoutExpired if timeout else ValueError
                with self.assertRaises(error):
                    lifecycle.rollback()
                state = json.loads(lifecycle.STATE.read_text())
                self.assertEqual(state['status'], 'ROLLBACK_UDEV_RELOAD_FAILED')
                self.assertEqual(len(state['rollback_udev_failures']), attempt + 1)
                self.assertEqual(state['rollback_udev_failures'][-1]['error_type'], error.__name__)
                self.assertIn(['/usr/sbin/sshd', '-t'], self.calls)
                self.assertIn(['/usr/bin/systemctl', 'reload', 'sshd.service'], self.calls)
                self.assertIn(['/usr/bin/firewall-cmd', '--reload'], self.calls)
                self.assertIn(['/usr/bin/nmcli', 'general', 'reload', 'conf'], self.calls)
                self.assertIn(['/usr/bin/systemctl', 'daemon-reload'], self.calls)
                if attempt == 0:
                    self.assertIn(['/usr/sbin/nft', 'delete', 'table', 'inet', 'hbr_ssh_guard'], self.calls)
                self.assertFalse(nft_exists)
                self.assertEqual(self.disabled, set())
                self.assertFalse(self.account or self.group or lifecycle.LINK.exists())
                self.assertEqual(self.calls[-1], ['/usr/bin/udevadm', 'control', '--reload'])
                self.assertEqual(claim.read_text(), 'preserve one-use claim')
            fail_udev = False
            lifecycle.rollback()
        state = json.loads(lifecycle.STATE.read_text())
        self.assertEqual(state['status'], 'ROLLED_BACK')
        self.assertEqual(len(state['rollback_udev_failures']), 2)
        self.assertEqual(claim.read_text(), 'preserve one-use claim')

    def test_rollback_udev_failure_does_not_block_other_cleanup_or_explicit_retry(self):
        self.check_rollback_udev_failure()

    def test_rollback_udev_timeout_does_not_block_other_cleanup_or_explicit_retry(self):
        self.check_rollback_udev_failure(timeout=True)

    def test_wrong_hotplug_name_never_claims_or_activates_session(self):
        self.prepare_session()
        with patch.object(lifecycle, 'physical', return_value=['ens224']):
            with self.assertRaisesRegex(ValueError, 'NIC_SET'):
                lifecycle.session()
        self.assertFalse(any('up' in c for c in self.calls))
        self.assertFalse((lifecycle.ROOT / 'session.claim').exists())

    def test_rollback_refuses_connected_clone_before_commands(self):
        self.install()
        self.calls.clear()
        self.host.side_effect = ValueError('PHYSICAL_NIC_PRESENT')
        with self.assertRaises(ValueError):
            lifecycle.rollback()
        self.assertEqual(self.calls, [])

    def test_rollback_refuses_changed_installed_file(self):
        self.install()
        lifecycle.ENDPOINT.write_text('unexpected local edit')
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'ROLLBACK_FILE_DRIFT'):
            lifecycle.rollback()
        self.assertEqual(self.calls, [])

    def test_bundle_edit_rejected_before_modifications(self):
        with (self.bundle / 'hbr-mgmt.nft.candidate').open('a') as stream:
            stream.write('\nflush ruleset\n')
        with self.assertRaisesRegex(ValueError, 'BUNDLE_CONTENT'):
            self.install()
        self.assertFalse(lifecycle.ROOT.exists())
        self.assertEqual(self.calls, [])

    def test_naming_precheck_failure_precedes_installation(self):
        lifecycle.naming_precheck.side_effect = ValueError('INTERFACE_NAME_IN_USE')
        with self.assertRaisesRegex(ValueError, 'INTERFACE_NAME_IN_USE'):
            self.install()
        self.assertFalse(lifecycle.ROOT.exists())
        self.assertEqual(self.calls, [])

    def test_install_refuses_overwrite(self):
        lifecycle.KEY.write_text('preexisting')
        with self.assertRaisesRegex(ValueError, 'INSTALL_PATH_EXISTS'):
            self.install()
        self.assertEqual(lifecycle.KEY.read_text(), 'preexisting')

    def prepare_session(self):
        self.install()
        gate = {'vmnet': 'VMnet2', 'host_only': True, 'dhcp': False, 'nat': False,
                'bridge': False, 'other_guests': False, 'host_forwarding': False,
                'host': '192.168.253.1', 'guest': '192.168.253.2',
                'mac': '00:50:56:30:00:02', 'interface': 'ens192', 'checked_epoch': time.time()}
        (lifecycle.ROOT / 'host-gate.json').write_text(json.dumps(gate))
        self.stack.enter_context(patch.object(lifecycle, 'verify_account'))
        self.stack.enter_context(patch.object(lifecycle.signal, 'signal'))
        self.calls.clear()

    def test_invalid_host_gate_never_raises_link(self):
        self.prepare_session()
        (lifecycle.ROOT / 'host-gate.json').write_text('{}')
        with self.assertRaises(ValueError):
            lifecycle.session()
        self.assertFalse(any('up' in c for c in self.calls))
        self.assertFalse((lifecycle.ROOT / 'session.claim').exists())

    def test_watch_failure_tears_down_and_preserves_reason_and_claim(self):
        self.prepare_session()
        def network(_state, active=False):
            if active:
                raise ValueError('injected route drift')
        with patch.object(lifecycle, 'network_guard', side_effect=network), \
             patch.object(lifecycle, 'disconnect') as disconnect:
            with self.assertRaisesRegex(ValueError, 'route drift'):
                lifecycle.session()
        disconnect.assert_called_once()
        state = json.loads(lifecycle.STATE.read_text())
        self.assertIn('route drift', state['end_reason'])
        self.assertTrue((lifecycle.ROOT / 'session.claim').exists())

    def test_link_activation_failure_still_calls_disconnect(self):
        self.prepare_session()
        self.fail_command = lambda c: c[0].endswith('/ip') and 'up' in c
        with patch.object(lifecycle, 'network_guard'), patch.object(lifecycle, 'disconnect') as disconnect:
            with self.assertRaises(ValueError):
                lifecycle.session()
        disconnect.assert_called_once()
        self.assertTrue((lifecycle.ROOT / 'session.claim').exists())


if __name__ == '__main__':
    unittest.main()
