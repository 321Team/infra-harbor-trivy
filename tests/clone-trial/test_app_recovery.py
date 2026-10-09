"""Recovery orchestration tests. No Docker or guest commands are executed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name == 'nt':
    sys.modules.setdefault('fcntl', types.SimpleNamespace())
SOURCE = Path(__file__).resolve().parents[2] / 'scripts/verify/clone-app-recovery.py'
spec = importlib.util.spec_from_file_location('app_recovery', SOURCE)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def rows():
    return {name: {'id': f'{i:064x}', 'name': '/' + name, 'service': name, 'project': 'harbor',
                   'image': 'sha256:' + 'b' * 64, 'mounts': [], 'ports': {},
                   'restart': {'Name': 'always'}, 'logging': {'Type': 'syslog'},
                   'status': 'running' if name == 'log' else 'exited',
                   'health': 'healthy' if name == 'log' else 'unhealthy'}
            for i, name in enumerate((*recovery.ORDER, 'log'), 1)}


class Harness(recovery.Recovery):
    def __init__(self, work):
        self.current = rows()
        super().__init__(work, types.SimpleNamespace(DOCKER=['docker']),
                         {'after': copy.deepcopy(self.current)}, {})
        self.starts = []
        self.failure = None

    def ready(self):
        return copy.deepcopy(self.current)

    def state(self):
        return copy.deepcopy(self.current)

    def preflight(self):
        self.result['before'] = copy.deepcopy(self.current)

    def claim(self):
        recovery.CLAIM.write_text('claimed')

    def read(self, name, argv, timeout=20):
        if 'start' in argv:
            cid = argv[-1]
            service = next(k for k, r in self.current.items() if r['id'] == cid)
            self.starts.append((service, tuple(argv)))
            if self.failure == service:
                raise ValueError('START_FAILED')
            self.current[service].update(status='running', health='healthy')
        return '{}'

    def finish(self):
        self.result['status'] = 'MANUAL_RECOVERY_HEALTHY_REVIEW_REQUIRED'


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.work = Path(self.directory.name)
        self.claim_patch = patch.object(recovery, 'CLAIM', self.work / 'claim')
        self.claim_patch.start()
        self.addCleanup(self.claim_patch.stop)
        self.addCleanup(self.directory.cleanup)
        self.session = Harness(self.work)

    def test_nine_exact_ids_once_and_no_autostart_claim(self):
        self.assertEqual(self.session.execute(), 0)
        self.assertEqual([s for s, _ in self.session.starts], list(recovery.ORDER))
        self.assertTrue(all(argv == ('docker', 'start', self.session.current[s]['id'])
                            for s, argv in self.session.starts))
        self.assertEqual(self.session.result['AUTOSTART'], 'NOT_TESTED')
        self.assertEqual(self.session.result['SYSLOG_INGESTION'], 'NOT_TESTED')
        self.assertEqual(self.session.result['AC_CLOSE'], 'NOT_EVALUATED')
        self.assertTrue(recovery.CLAIM.exists())

    def test_start_failure_stops_later_apps_and_keeps_claim(self):
        self.session.failure = 'registry'
        self.assertEqual(self.session.execute(), 2)
        self.assertEqual([s for s, _ in self.session.starts], list(recovery.ORDER[:3]))
        self.assertEqual(self.session.result['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertTrue(recovery.CLAIM.exists())
        self.assertEqual(set(self.session.result['failure_capture']), {'state', 'unit', 'ac04'})

    def test_preflight_failure_never_claims_or_starts(self):
        with patch.object(self.session, 'preflight', side_effect=ValueError('SSH_NOT_ROLLED_BACK')):
            self.assertEqual(self.session.execute(), 2)
        self.assertFalse(recovery.CLAIM.exists())
        self.assertFalse(self.session.starts)
        self.assertEqual(self.session.result['status'], 'STOP_BEFORE_CHANGE')

    def test_unplanned_running_app_stops_before_start(self):
        self.session.current['redis'].update(status='running', health='healthy')
        self.assertEqual(self.session.execute(), 2)
        self.assertFalse(self.session.starts)

    def test_completed_app_losing_health_stops_next_start(self):
        original = self.session.ready
        def ready():
            if self.session.done:
                self.session.current['postgresql']['health'] = 'unhealthy'
            return original()
        with patch.object(self.session, 'ready', side_effect=ready):
            self.assertEqual(self.session.execute(), 2)
        self.assertEqual(len(self.session.starts), 1)

    def test_poll_metadata_drift_stops(self):
        original = self.session.state
        def drift():
            value = original()
            value['redis']['image'] = 'different'
            return value
        with patch.object(self.session, 'state', side_effect=drift):
            self.assertEqual(self.session.execute(), 2)
        self.assertEqual(len(self.session.starts), 1)

    def test_logger_loss_stops(self):
        original = self.session.state
        def lost():
            value = original(); value['log']['health'] = 'unhealthy'; return value
        with patch.object(self.session, 'state', side_effect=lost):
            self.assertEqual(self.session.execute(), 2)
        self.assertEqual(len(self.session.starts), 1)

    def test_health_timeout_does_not_retry_start(self):
        original = self.session.state
        def waiting():
            value = original()
            value['postgresql']['health'] = 'starting'
            return value
        self.session.deadline = -1
        with patch.object(self.session, 'state', side_effect=waiting):
            self.assertEqual(self.session.execute(), 2)
        self.assertEqual(len(self.session.starts), 1)

    def test_capture_failure_keeps_other_captures(self):
        self.session.failure = 'postgresql'
        with patch.object(self.session, 'state', side_effect=ValueError('QUERY_FAILED')):
            self.assertEqual(self.session.execute(), 2)
        self.assertIn('error', self.session.result['failure_capture']['state'])
        self.assertIn('value', self.session.result['failure_capture']['unit'])
        self.assertIn('value', self.session.result['failure_capture']['ac04'])

    def test_real_command_timeout_records_and_rejects_without_retry(self):
        with patch.object(recovery.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['docker'], 60)) as proc:
            with self.assertRaisesRegex(ValueError, 'COMMAND_FAILED_START'):
                recovery.Recovery.read(self.session, 'start', ['docker', 'start', 'fixed-id'], timeout=60)
        self.assertEqual(proc.call_count, 1)
        self.assertEqual(self.session.result['commands'][0]['rc'], 124)
        self.assertEqual(json.loads((self.work / 'result.json').read_text())['commands'][0]['rc'], 124)

    def test_claim_is_exclusive_in_real_method(self):
        self.session.result['before'] = self.session.state()
        recovery.Recovery.claim(self.session)
        with self.assertRaises(FileExistsError):
            recovery.Recovery.claim(self.session)

    def test_claim_rejects_fresh_state_drift(self):
        self.session.result['before'] = self.session.state()
        self.session.current['redis']['status'] = 'running'
        with self.assertRaisesRegex(ValueError, 'STATE_CHANGED'):
            recovery.Recovery.claim(self.session)
        self.assertFalse(recovery.CLAIM.exists())

    def test_unit_requires_both_dependency_and_order(self):
        text = 'ActiveState=active\nSubState=running\nInvocationID=abc\nRequires=fds-harbor-ac04-guard.service\nAfter=fds-harbor-ac04-guard.service\n'
        self.assertEqual(recovery.unit(text, 'abc')['InvocationID'], 'abc')
        for changed in (text.replace('After=fds-harbor-ac04-guard.service', 'After=basic.target'),
                        text.replace('Requires=fds-harbor-ac04-guard.service', 'Requires=docker.socket')):
            with self.assertRaisesRegex(ValueError, 'GUARD_DEPENDENCY'):
                recovery.unit(changed, 'abc')
        with self.assertRaisesRegex(ValueError, 'DOCKER_UNIT_CHANGED'):
            recovery.unit(text, 'new-invocation')

    def test_nft_ignores_only_volatile_counters_and_handles(self):
        original = {'nftables': [{'table': {'family': 'inet', 'name': 'p1_hbr_ac04', 'handle': 1}},
                    {'rule': {'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}}]}
        changed = copy.deepcopy(original)
        changed['nftables'][0]['table']['handle'] = 7
        changed['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 10
        self.assertEqual(recovery.nft_shape(json.dumps(original)), recovery.nft_shape(json.dumps(changed)))
        changed['nftables'][1]['rule']['expr'][-1] = {'accept': None}
        self.assertNotEqual(recovery.nft_shape(json.dumps(original)), recovery.nft_shape(json.dumps(changed)))
        with self.assertRaisesRegex(ValueError, 'AC04_TABLE_MISSING'):
            recovery.nft_shape('{"nftables":[]}')

    def test_metadata_tolerates_health_but_not_config_changes(self):
        original = rows(); changed = copy.deepcopy(original)
        changed['redis'].update(status='running', health='healthy')
        self.assertEqual(recovery.metadata(original), recovery.metadata(changed))
        for key in ('id', 'image', 'restart', 'logging', 'ports', 'mounts'):
            changed = copy.deepcopy(original)
            changed['redis'][key] = [] if key == 'mounts' else 'different'
            if key == 'mounts':
                changed['redis'][key] = [{'Destination': '/data', 'Source': '/different'}]
            self.assertNotEqual(recovery.metadata(original), recovery.metadata(changed))

    def test_guard_checks_boot_mount_identity_and_pins(self):
        self.session.history['boot_after'] = 'original-boot'
        self.session.trial.clone_guard = lambda: None
        def read_path(path, *args, **kwargs):
            return 'original-boot' if str(path).endswith('boot_id') else 'ordinary mount'
        with patch.object(Path, 'read_text', autospec=True, side_effect=read_path), \
                patch.object(recovery, 'pinned') as pin, \
                patch.object(self.session, 'read', return_value='Enforcing'):
            recovery.Recovery.guard(self.session)
            self.assertEqual(pin.call_count, 2)
        for invalid, code in [('fuse.vmhgfs-fuse', 'HGFS_MOUNT'), ('new-boot', 'BOOT_CHANGED')]:
            def changed(path, *args, **kwargs):
                if str(path).endswith('boot_id'):
                    return invalid if invalid == 'new-boot' else 'original-boot'
                return invalid if 'hgfs' in invalid else 'ordinary mount'
            with patch.object(Path, 'read_text', autospec=True, side_effect=changed), \
                    patch.object(recovery, 'pinned'), patch.object(self.session, 'read', return_value='Enforcing'):
                with self.assertRaisesRegex(ValueError, code):
                    recovery.Recovery.guard(self.session)

    def test_ready_requires_logger_before_tcp_and_stops_nft_drift(self):
        self.session.history['unit_after'] = {'InvocationID': 'abc'}
        table = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': 'p1_hbr_ac04'}}]})
        def read(name, *args, **kwargs):
            return 'active' if name == 'guard-active' else table
        with patch.object(self.session, 'guard'), patch.object(recovery, 'unit'), \
                patch.object(self.session, 'read', side_effect=read), \
                patch.object(recovery.socket, 'create_connection') as tcp:
            recovery.Recovery.ready(self.session)
            tcp.assert_called_once_with(('127.0.0.1', 1514), timeout=3)
            tcp.reset_mock()
            self.session.current['log']['health'] = 'unhealthy'
            with self.assertRaisesRegex(ValueError, 'LOGGER_NOT_READY'):
                recovery.Recovery.ready(self.session)
            tcp.assert_not_called()
            self.session.current['log']['health'] = 'healthy'
            self.session.firewall = []
            with self.assertRaisesRegex(ValueError, 'AC04_DRIFT'):
                recovery.Recovery.ready(self.session)

    def test_finish_rejects_profile_drift_and_preserves_status(self):
        for row in self.session.current.values():
            row.update(status='running', health='healthy')
        self.session.result['profile_before'] = {'version': 'expected'}
        with patch.object(self.session, 'profile', return_value={'version': 'different'}):
            with self.assertRaisesRegex(ValueError, 'PROFILE_DRIFT'):
                recovery.Recovery.finish(self.session)
        self.assertNotEqual(self.session.result['status'], 'MANUAL_RECOVERY_HEALTHY_REVIEW_REQUIRED')

    def test_preflight_rejects_ssh_state_or_changed_failure(self):
        with patch.object(recovery, 'trusted', return_value=b'{"status":"INSTALLED_LINK_DISABLED"}'):
            with self.assertRaisesRegex(ValueError, 'SSH_NOT_ROLLED_BACK'):
                recovery.Recovery.preflight(self.session)
        with patch.object(recovery, 'trusted', return_value=b'{"status":"ROLLED_BACK"}'), \
                patch.object(self.session, 'read', return_value='{"id":"wrong","error":"","exit":0}'):
            with self.assertRaisesRegex(ValueError, 'APP_FAILURE_CHANGED'):
                recovery.Recovery.preflight(self.session)

    def test_identity_failure_and_error_pin_stop_guard(self):
        self.session.trial.clone_guard = lambda: (_ for _ in ()).throw(ValueError('PHYSICAL_NIC_PRESENT'))
        with self.assertRaisesRegex(ValueError, 'PHYSICAL_NIC_PRESENT'):
            recovery.Recovery.guard(self.session)
        with patch.object(recovery, 'trusted', return_value=b'drift'):
            with self.assertRaisesRegex(ValueError, 'PIN_MISMATCH'):
                recovery.pinned(Path('/root/test'), '0' * 64)


if __name__ == '__main__':
    unittest.main()
