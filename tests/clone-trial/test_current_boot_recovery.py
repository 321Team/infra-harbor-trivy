"""Current-boot recovery boundaries. MOCK only; no guest/Docker execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name == 'nt':
    sys.modules.setdefault('fcntl', types.SimpleNamespace())
ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


boot = module('current_boot_recovery', 'scripts/verify/clone-current-boot-recovery.py')
parent = module('prior_app_recovery', 'scripts/verify/clone-app-recovery.py')
Base = boot.recovery_class(parent)
ERROR = 'failed to create task for container: failed to initialize logging driver: dial tcp 127.0.0.1:1514: connect: connection refused'


def rows(healthy=False):
    return {s: {'id': f'{i:064x}', 'name': '/' + s, 'service': s, 'project': 'harbor',
                'image': 'sha256:' + 'b' * 64, 'mounts': [], 'ports': {},
                'restart': {'Name': 'always'}, 'logging': {'Type': 'syslog'},
                'status': 'running' if healthy or s == 'log' else 'exited',
                'health': 'healthy' if healthy or s == 'log' else 'unhealthy'}
            for i, s in enumerate((*parent.ORDER, 'log'), 1)}


def prior():
    return {'status': 'MANUAL_RECOVERY_HEALTHY_REVIEW_REQUIRED',
            'started_services': list(parent.ORDER), 'source_sha256': boot.PARENT_SHA,
            'trial_sha256': boot.TRIAL_SHA, 'after': rows(True),
            'commands': [{'rc': 0}], 'finished_epoch': boot.CUTOFF - 86400,
            'profile_after': {'profile': 'preserved'}, 'firewall_before': []}


def prior_claim():
    return {'work': str(boot.PRIOR_WORK), 'source_sha256': boot.PARENT_SHA}


class Harness(Base):
    def __init__(self, work):
        self.current = rows()
        with patch.object(boot, 'trusted', return_value=b'new-source'):
            super().__init__(work, types.SimpleNamespace(DOCKER=['docker'], clone_guard=lambda: None),
                             prior(), {'before': rows()}, Path('/root/mock-bundle'))
        self.starts = []
        self.fail_start = None
        self.manager_text = 'LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\n'
        self.firewall = []

    def ready(self):
        return copy.deepcopy(self.current)

    def state(self):
        return copy.deepcopy(self.current)

    def profile(self, rows):
        return {'profile': 'preserved'}

    def claim(self):
        if os.name == 'nt':
            # Windows cannot fsync a directory; that real claim path runs in Linux CI.
            boot.CLAIM.write_text('MOCK_CLAIM')
        else:
            super().claim()

    def read(self, name, argv, timeout=20):
        if name == 'manager':
            return self.manager_text
        if name == 'selinux':
            return 'Enforcing'
        if name == 'app-errors':
            return '\n'.join(json.dumps({'id': self.current[s]['id'], 'exit': 128, 'error': ERROR})
                             for s in parent.ORDER)
        if 'start' in argv:
            cid = argv[-1]
            service = next(s for s,r in self.current.items() if r['id'] == cid)
            self.starts.append((service, tuple(argv)))
            if service == self.fail_start:
                raise ValueError('START_FAILED')
            self.current[service].update(status='running', health='healthy')
        return '{}'


class CurrentBootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.clock_patch = patch.object(boot.time, 'time', return_value=boot.CUTOFF-3600)
        self.clock_patch.start(); self.addCleanup(self.clock_patch.stop)
        self.claim_patch = patch.object(boot, 'CLAIM', self.work/'current-claim')
        self.claim_patch.start(); self.addCleanup(self.claim_patch.stop)
        self.trust_patch = patch.object(parent, 'trusted', return_value=b'{"status":"ROLLED_BACK"}')
        self.trust_patch.start(); self.addCleanup(self.trust_patch.stop)
        self.session = Harness(self.work)

    def test_prior_success_is_required_not_just_a_new_filename(self):
        value = prior(); value['status'] = 'STOP_RECOVERY_REQUIRED'
        with self.assertRaisesRegex(ValueError, 'PRIOR_NOT_COMPLETED'):
            boot.completed_prior(value, prior_claim(), parent.ORDER)

    def test_prior_partial_start_and_missing_health_are_rejected(self):
        for field in ('started_services', 'after'):
            value = prior()
            if field == 'started_services': value[field].pop()
            else: value[field]['redis']['health'] = 'unhealthy'
            with self.subTest(field=field), self.assertRaises(ValueError):
                boot.completed_prior(value, prior_claim(), parent.ORDER)

    def test_ambiguous_prior_command_is_rejected(self):
        value = prior(); value['commands'][0]['rc'] = None
        with self.assertRaisesRegex(ValueError, 'PRIOR_INCOMPLETE_COMMANDS'):
            boot.completed_prior(value, prior_claim(), parent.ORDER)

    def test_prior_claim_must_link_the_exact_completed_work_and_source(self):
        for field in ('work','source_sha256'):
            value = prior_claim(); value[field] = 'different'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'PRIOR_CLAIM_NOT_LINKED'):
                boot.completed_prior(prior(), value, parent.ORDER)

    def test_completed_prior_is_accepted_without_deleting_old_claim(self):
        old = self.work/'old-used-claim'; old.write_bytes(b'preserved')
        boot.completed_prior(prior(), prior_claim(), parent.ORDER)
        self.assertEqual(self.session.execute(), 0)
        self.assertEqual(old.read_bytes(), b'preserved')
        self.assertEqual([s for s,_ in self.session.starts], list(parent.ORDER))
        self.assertTrue(all(a == ('docker','start',self.session.current[s]['id']) for s,a in self.session.starts))
        self.assertEqual(self.session.result['status'], 'MANUAL_BOOT_RECOVERY_HEALTHY_REVIEW_REQUIRED')
        self.assertEqual(self.session.result['AUTOSTART'], 'NOT_TESTED')
        self.assertEqual(self.session.result['AC_CLOSE'], 'NOT_EVALUATED')

    def test_used_current_claim_prevents_all_new_starts(self):
        boot.CLAIM.write_bytes(b'used-current')
        self.assertEqual(self.session.execute(), 2)
        self.assertFalse(self.session.starts)
        self.assertEqual(boot.CLAIM.read_bytes(), b'used-current')

    def test_preflight_failure_is_not_misclassified_by_old_claim(self):
        self.work.joinpath('old-used-claim').write_bytes(b'old')
        with patch.object(self.session, 'profile', side_effect=ValueError('PROFILE_CHANGED')):
            self.assertEqual(self.session.execute(), 2)
        self.assertEqual(self.session.result['status'], 'STOP_BEFORE_CHANGE')
        self.assertFalse(boot.CLAIM.exists())
        self.assertFalse(self.session.starts)

    def test_wrong_profile_and_wrong_error_never_claim(self):
        for kind in ('profile','error'):
            with self.subTest(kind=kind):
                session = Harness(self.work)
                if kind == 'profile':
                    target = patch.object(session, 'profile', return_value={'changed':True})
                else:
                    target = patch.object(session, 'read', return_value=json.dumps({'id':'wrong','exit':128,'error':ERROR}))
                with target:
                    self.assertEqual(session.execute(), 2)
                self.assertFalse(boot.CLAIM.exists())
                self.assertFalse(session.starts)

    def test_start_failure_stops_later_apps_preserves_claim_and_captures_independently(self):
        self.session.fail_start = 'registry'
        with patch.object(self.session, 'state', side_effect=ValueError('QUERY_FAILED')):
            self.assertEqual(self.session.execute(), 2)
        # Failure happens on the first poll in this variant, so no later start.
        self.assertEqual(len(self.session.starts), 1)
        self.assertTrue(boot.CLAIM.exists())
        self.assertIn('error', self.session.result['failure_capture']['state'])
        self.assertIn('value', self.session.result['failure_capture']['unit'])
        self.assertIn('value', self.session.result['failure_capture']['ac04'])

    def test_actual_partial_start_failure_never_retries(self):
        self.session.fail_start = 'registry'
        self.assertEqual(self.session.execute(), 2)
        self.assertEqual([s for s,_ in self.session.starts], list(parent.ORDER[:3]))
        self.assertTrue(boot.CLAIM.exists())
        self.assertEqual(self.session.result['status'], 'STOP_RECOVERY_REQUIRED')

    @unittest.skipIf(os.name == 'nt', 'Real O_DIRECTORY/fsync requires Linux')
    def test_real_exclusive_claim_is_private_and_links_history_and_boot(self):
        self.session.result['before'] = self.session.ready()
        Base.claim(self.session)
        data = json.loads(boot.CLAIM.read_text())
        self.assertEqual(data['boot'], boot.BOOT)
        self.assertEqual(data['prior_claim_sha256'], boot.PRIOR_CLAIM_SHA)
        self.assertEqual(boot.CLAIM.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): Base.claim(self.session)

    def test_manager_ownership_and_firewall_drift_block_readiness(self):
        for kind in ('manager','firewall'):
            self.session.manager_text = 'LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=7\n' if kind=='manager' else 'LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\n'
            self.session.firewall = ['changed'] if kind=='firewall' else []
            with self.subTest(kind=kind), patch.object(parent.Recovery,'ready',return_value=rows()), self.assertRaises(ValueError):
                Base.ready(self.session)

    def guard_pinned(self, path, digest):
        if path == boot.PRIOR_WORK/'result.json': return json.dumps(prior()).encode()
        if path == boot.PRIOR_CLAIM: return json.dumps(prior_claim()).encode()
        return b'dependency'

    def test_boot_drift_and_cutoff_stop_before_any_start(self):
        def read_text(path, *args, **kwargs):
            return 'different-boot' if path.name == 'boot_id' else ''
        with patch.object(boot.time,'time',return_value=boot.CUTOFF-1000), patch.object(boot.Path,'read_text',read_text), self.assertRaisesRegex(ValueError,'BOOT_CHANGED'):
            Base.guard(self.session)
        with patch.object(boot.time,'time',return_value=boot.CUTOFF), self.assertRaisesRegex(ValueError,'FIELD_WINDOW_ENDED'):
            Base.guard(self.session)
        self.assertFalse(self.session.starts)

    def test_prior_pin_failure_in_guard_blocks_change(self):
        def read_text(path, *args, **kwargs): return boot.BOOT if path.name == 'boot_id' else ''
        def pinned(path,digest):
            if path == boot.PRIOR_CLAIM: raise ValueError('PIN_MISMATCH')
            return self.guard_pinned(path,digest)
        with patch.object(boot.time,'time',return_value=boot.CUTOFF-1000), patch.object(boot.Path,'read_text',read_text), patch.object(boot,'pinned',side_effect=pinned), self.assertRaisesRegex(ValueError,'PIN_MISMATCH'):
            Base.guard(self.session)

    def test_generation_drift_blocks_inherited_readiness_before_start(self):
        original = self.session.read
        def read(name,argv,timeout=20):
            if name=='docker-unit':
                return 'ActiveState=active\nSubState=running\nInvocationID=changed\nRequires=fds-harbor-ac04-guard.service\nAfter=fds-harbor-ac04-guard.service\n'
            return original(name,argv,timeout)
        with patch.object(self.session,'guard'), patch.object(self.session,'read',side_effect=read), self.assertRaisesRegex(ValueError,'DOCKER_UNIT_CHANGED'):
            Base.ready(self.session)
        self.assertFalse(self.session.starts)

    def test_start_submission_checks_cutoff_again_after_readiness(self):
        with patch.object(boot.time,'time',return_value=boot.CUTOFF), patch.object(parent.Recovery,'read') as read, self.assertRaisesRegex(ValueError,'FIELD_WINDOW_ENDED'):
            Base.read(self.session,'start-postgresql',['docker','start',self.session.current['postgresql']['id']],60)
        read.assert_not_called()

    def test_expired_change_deadline_never_submits_start(self):
        self.session.deadline=-1
        with patch.object(boot.time,'time',return_value=boot.CUTOFF-1000), patch.object(parent.Recovery,'read') as read, self.assertRaisesRegex(ValueError,'RECOVERY_DEADLINE'):
            Base.read(self.session,'start-postgresql',['docker','start',self.session.current['postgresql']['id']],60)
        read.assert_not_called()

    @unittest.skipIf(os.name == 'nt', 'Real O_DIRECTORY/fsync requires Linux')
    def test_directory_fsync_failure_preserves_claim_and_blocks_future_start(self):
        self.session.result['before'] = self.session.ready()
        with patch.object(boot.os,'fsync',side_effect=[None,OSError('dir-fsync-failed')]), self.assertRaises(OSError):
            Base.claim(self.session)
        self.assertTrue(boot.CLAIM.exists())
        self.assertEqual(self.session.execute(),2)
        self.assertFalse(self.session.starts)

    def test_loader_executes_verified_bytes_and_pin_failure_never_executes(self):
        p=self.work/'dependency.py'; p.write_text('answer = 7\n')
        with patch.object(boot,'trusted',return_value=p.read_bytes()):
            m=boot.load_module(p,boot.sha(p.read_bytes()),'test_dependency')
            self.assertEqual(m.answer,7)
            with self.assertRaisesRegex(ValueError,'PIN_MISMATCH'):
                boot.load_module(p,'0'*64,'bad_dependency')

    def test_cli_requires_root_and_remaining_window_before_loading_dependencies(self):
        argv=['recovery','--bundle','/root/mock','--confirm-host-gate','a3-evidence-preserved-no-nic-no-hgfs']
        with patch.object(sys,'argv',argv), patch.object(boot.os,'geteuid',return_value=1,create=True), patch.object(boot,'load_module') as loader, self.assertRaisesRegex(ValueError,'ROOT_REQUIRED'):
            boot.main()
        loader.assert_not_called()
        with patch.object(sys,'argv',argv), patch.object(boot.os,'geteuid',return_value=0,create=True), patch.object(boot.time,'time',return_value=boot.LATEST_START), patch.object(boot,'load_module') as loader, self.assertRaisesRegex(ValueError,'INSUFFICIENT_FIELD_WINDOW'):
            boot.main()
        loader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
