"""MOCK only: no system command, NIC, timer, firewall or Docker mutation."""
import copy
import json
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

from test_ssh_plan import load
import test_lifecycle

cold = load('coldboot', 'scripts/verify/hbr-ssh-coldboot.py')
base = test_lifecycle.lifecycle


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.old = {'lo': [['inet', '127.0.0.1', 8]],
                    'docker0': [['inet', '172.17.0.1', 16]],
                    'veth111': [['inet6', 'fe80::1', 64]]}
        self.rows = [dict(ifindex=1, ifname='lo', addr_info=[dict(family='inet', local='127.0.0.1', prefixlen=8)]),
            dict(ifindex=2, ifname='docker0', addr_info=[dict(family='inet', local='172.17.0.1', prefixlen=16)]),
            dict(ifindex=8, ifname='veth222', master='docker0', addr_info=[dict(family='inet6', local='fe80::2', prefixlen=64)]),
            dict(ifindex=9, ifname='hbrmgmt0', flags=[], addr_info=[])]
        self.routes = {'-4': [dict(dst='172.17.0.0/16', dev='docker0')],
                        '-6': [dict(dst='fe80::/64', dev='veth222')]}
        self.state = dict(plan={'interface': 'hbrmgmt0'}, baseline_addresses=self.old,
                          baseline_routes={'-4': copy.deepcopy(self.routes['-4']), '-6': []})

    def test_bounded_veth_churn_is_capturable_not_silent_acceptance(self):
        cold.check_network(base, self.state, self.rows, self.routes)
        self.assertEqual(self.state['baseline_addresses'], self.old)

    def test_new_bridge_ip_master_link_or_gateway_rejected(self):
        changes = ('new_bridge', 'global_ip', 'master', 'link', 'gateway', 'ipv4_route', 'ipv6_route')
        for change in changes:
            rows, routes = copy.deepcopy(self.rows), copy.deepcopy(self.routes)
            if change == 'new_bridge':
                rows.append(dict(ifindex=10, ifname='br-123456789012', addr_info=[]))
            elif change == 'global_ip':
                rows[2]['addr_info'] = [dict(family='inet', local='172.17.0.44', prefixlen=16)]
            elif change == 'master':
                rows[2]['master'] = 'hbrmgmt0'
            elif change == 'link':
                rows[3]['flags'] = ['UP']
            elif change == 'gateway':
                routes['-4'].append(dict(dst='default', dev='docker0', gateway='172.17.0.2'))
            elif change == 'ipv4_route':
                routes['-4'] = []
            else:
                routes['-6'].append(dict(dst='2001:db8::/64', dev='veth222'))
            with self.subTest(change=change), self.assertRaises(ValueError):
                cold.check_network(base, self.state, rows, routes)

    def test_carrier_or_any_management_address_rejected(self):
        for flags, addresses in [(['LOWER_UP'], []), ([], [dict(family='inet6', local='fe80::2', prefixlen=64)])]:
            rows = copy.deepcopy(self.rows)
            rows[-1].update(flags=flags, addr_info=addresses)
            with self.assertRaises(ValueError):
                cold.check_network(base, self.state, rows, self.routes)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state = {'status': 'INSTALLED_LINK_DISABLED', 'plan': {
            'interface': 'hbrmgmt0', 'mac': '00:50:56:35:78:e4', 'expires_epoch': time.time()+1000},
            'nft_shape': {'expected': True}, 'baseline_addresses': {'old': []},
            'baseline_routes': {'-4': [], '-6': []}, 'commands': []}
        self.original = cold.encoded(self.state)
        self.report = {'boot': 'new-boot', 'baseline_addresses': {'new': []},
                       'baseline_routes': {'-4': [], '-6': []}, 'plan': self.state['plan']}
        self.sha = cold.digest(cold.encoded(self.report))
        self.life = types.SimpleNamespace(ROOT=root, STATE=root/'state.json', NFT=root/'rules.nft',
            read_safe=lambda p: Path(p).read_bytes(), gate_valid=base.gate_valid,
            save=lambda value: (root/'state.json').write_bytes(cold.encoded(value)),
            run=Mock(return_value=(0, 'active')), current_nft=Mock(return_value={'expected': True}),
            host_guard=Mock(), verify_files=Mock(), verify_account=Mock(), ssh_guard=Mock(), network_guard=Mock())
        self.life.STATE.write_bytes(self.original)
        (root/('coldboot-review-'+self.sha+'.json')).write_bytes(cold.encoded(self.report))
        self.gate = dict(vmnet='VMnet2', host_only=True, dhcp=False, nat=False, bridge=False,
            other_guests=False, host_forwarding=False, host='192.168.253.1', guest='192.168.253.2',
            mac='00:50:56:35:78:e4', interface='hbrmgmt0', checked_epoch=time.time(),
            cable_disconnected=True, boot='new-boot', review_sha256=self.sha)
        self.write_gate()
        boot = root/'boot'
        boot.write_text('new-boot')
        patches = [patch.object(cold, 'STATE_SHA', cold.digest(self.original)),
                   patch.object(cold, 'BOOT_FILE', boot),
                   patch.object(cold, 'snapshot', side_effect=lambda _: (copy.deepcopy(self.report), copy.deepcopy(self.state)))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def write_gate(self):
        (self.life.ROOT/'coldboot-host-gate.json').write_bytes(cold.encoded(self.gate))

    def test_success_retains_original_and_claim_only_applies_nft_and_timer(self):
        cold.apply(self.life, self.sha)
        final = json.loads(self.life.STATE.read_bytes())
        self.assertEqual(final['status'], 'INSTALLED_LINK_DISABLED')
        self.assertEqual(final['baseline_addresses'], self.report['baseline_addresses'])
        self.assertEqual(final['plan'], self.state['plan'])
        self.assertEqual((self.life.ROOT/'before-coldboot-state.json').read_bytes(), self.original)
        self.assertTrue((self.life.ROOT/'coldboot.claim').exists())
        commands = [c.args[0] for c in self.life.run.call_args_list]
        self.assertEqual(commands, [['/usr/sbin/nft', '-c', '-f', str(self.life.NFT)],
            ['/usr/sbin/nft', '-f', str(self.life.NFT)],
            ['/usr/bin/systemctl', 'start', 'hbr-ssh-expire.timer'],
            ['/usr/bin/systemctl', 'is-active', 'hbr-ssh-expire.timer']])

    def test_gate_false_integer_stale_wrong_boot_or_review_cannot_mutate(self):
        for change in [dict(cable_disconnected=False), dict(nat=0), dict(host_only=1),
                       dict(checked_epoch=0), dict(boot='old'), dict(review_sha256='0'*64), dict(other_guests=True)]:
            gate = dict(self.gate, **change)
            (self.life.ROOT/'coldboot-host-gate.json').write_bytes(cold.encoded(gate))
            with self.subTest(change=change), self.assertRaises(ValueError):
                cold.apply(self.life, self.sha)
            self.life.run.assert_not_called()
            self.assertFalse((self.life.ROOT/'coldboot.claim').exists())

    def test_report_drift_rejected_without_changing_state(self):
        self.report['baseline_addresses'] = {'drift': []}
        with self.assertRaisesRegex(ValueError, 'POST_REVIEW_DRIFT'):
            cold.apply(self.life, self.sha)
        self.assertEqual(self.life.STATE.read_bytes(), self.original)
        self.life.run.assert_not_called()

    def test_timer_failure_keeps_old_baseline_and_failure_receipt(self):
        def run(argv, state=None):
            if 'start' in argv:
                raise TimeoutError('timer timeout')
            return 0, ''
        self.life.run.side_effect = run
        with self.assertRaises(TimeoutError):
            cold.apply(self.life, self.sha)
        state = json.loads(self.life.STATE.read_bytes())
        self.assertEqual(state['status'], 'COLDBOOT_REARM_FAILED_CONSOLE_REVIEW_REQUIRED')
        self.assertEqual(state['baseline_addresses'], self.state['baseline_addresses'])
        self.assertTrue((self.life.ROOT/'coldboot.claim').exists())
        self.life.network_guard.assert_not_called()

    def test_nft_mismatch_never_starts_timer(self):
        self.life.current_nft.return_value = {'changed': True}
        with self.assertRaisesRegex(ValueError, 'NFT_SHAPE_MISMATCH'):
            cold.apply(self.life, self.sha)
        self.assertFalse(any('start' in c.args[0] for c in self.life.run.call_args_list))

    def test_final_network_drift_is_failure_not_rebaseline(self):
        self.life.network_guard.side_effect = ValueError('OTHER_ROUTE_DRIFT')
        with self.assertRaises(ValueError):
            cold.apply(self.life, self.sha)
        final = json.loads(self.life.STATE.read_bytes())
        self.assertEqual(final['baseline_addresses'], self.state['baseline_addresses'])
        self.assertEqual(final['status'], 'COLDBOOT_REARM_FAILED_CONSOLE_REVIEW_REQUIRED')

    def test_existing_claim_is_never_removed_or_reused(self):
        (self.life.ROOT/'coldboot.claim').write_text('prior attempt')
        with self.assertRaises(FileExistsError):
            cold.apply(self.life, self.sha)
        self.assertEqual((self.life.ROOT/'coldboot.claim').read_text(), 'prior attempt')
        self.life.run.assert_not_called()


class SealedGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.boot = self.root/'boot'
        self.boot.write_text('11111111-2222-3333-4444-555555555555')
        self.nic = self.root/'hbrmgmt0'
        self.nic.mkdir()
        (self.nic/'address').write_text('00:50:56:35:78:e4')
        self.a3 = self.root/'a3'
        self.a3.write_bytes(b'original A3')
        self.state = dict(status='INSTALLED_LINK_DISABLED',
                          plan=dict(interface='hbrmgmt0', mac='00:50:56:35:78:e4', expires_epoch=time.time()+1000))
        self.life = types.SimpleNamespace(ROOT=self.root, STATE=self.root/'state.json',
            host_guard=Mock(), read_safe=lambda p: p.read_bytes(), verify_files=Mock(),
            verify_account=Mock(), old_profiles_off=Mock(), ssh_guard=Mock(),
            physical=Mock(return_value=['hbrmgmt0']), run=Mock(return_value=(0,'10 (unmanaged)')))
        self.life.STATE.write_bytes(cold.encoded(self.state))
        self.pin = patch.object(cold, 'STATE_SHA', cold.digest(self.life.STATE.read_bytes()))
        for p in [self.pin, patch.object(cold, 'NET', self.root), patch.object(cold, 'BOOT_FILE', self.boot),
                  patch.object(cold, 'A3_FILES', {str(self.a3): cold.digest(self.a3.read_bytes())})]:
            p.start()
            self.addCleanup(p.stop)

    def test_new_boot_with_sealed_files_and_exact_nic_passes(self):
        raw, state, boot = cold.guard(self.life)
        self.assertEqual(cold.digest(raw), cold.STATE_SHA)
        self.assertNotEqual(boot, cold.PREVIOUS_BOOT)
        self.life.verify_files.assert_called_once()
        self.life.verify_account.assert_called_once()

    def test_wrong_mac_or_extra_nic_refused(self):
        (self.nic/'address').write_text('00:50:56:35:78:e5')
        with self.assertRaisesRegex(ValueError, 'NIC_MAC'):
            cold.guard(self.life)
        self.life.physical.return_value = ['hbrmgmt0','ens160']
        with self.assertRaisesRegex(ValueError, 'NIC_SET'):
            cold.guard(self.life)

    def test_same_boot_or_original_drift_refused(self):
        self.boot.write_text(cold.PREVIOUS_BOOT)
        with self.assertRaisesRegex(ValueError, 'NEW_BOOT_REQUIRED'):
            cold.guard(self.life)
        self.a3.write_bytes(b'changed original')
        with self.assertRaisesRegex(ValueError, 'A3_PRESERVATION_DRIFT'):
            cold.guard(self.life)

    def test_expiry_state_drift_and_claim_are_fail_closed(self):
        with patch.object(cold.time, 'time', return_value=self.state['plan']['expires_epoch']+1):
            with self.assertRaisesRegex(ValueError, 'EXPIRED'):
                cold.guard(self.life)
        (self.root/'session.claim').write_text('previous attempt')
        with self.assertRaisesRegex(ValueError, 'SESSION_ALREADY_ATTEMPTED'):
            cold.guard(self.life)
        self.life.STATE.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'SEALED_STATE_CHANGED'):
            cold.guard(self.life)


if __name__ == '__main__':
    unittest.main()
