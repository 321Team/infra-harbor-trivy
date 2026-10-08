import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('trial', Path(__file__).resolve().parents[2] / 'scripts/verify/clone-address-trial.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

def rows():
    return {s: {'id': s + '-old', 'name': '/' + n, 'service': s, 'project': 'harbor',
                'image': 'sha256:' + s, 'status': 'running', 'health': 'healthy',
                'restart': {'Name': 'always', 'MaximumRetryCount': 0},
                'mounts': [{'Type': 'bind', 'Source': '/data/' + s, 'Destination': '/data', 'RW': True}],
                'ports': {}, 'logging': {'Type': 'syslog', 'Config': {'syslog-address': 'tcp://localhost:1514', 'tag': s}}}
            for s, n in zip((*t.SERVICES, 'log'), t.NAMES)}

def add_observed_volumes(state):
    # Real mount metadata from the sealed pre-change STOP; no volume contents.
    fixture = json.loads((Path(__file__).parent / 'observed-volume-mounts.json').read_text())
    for service, mounts in fixture.items():
        state[service]['mounts'].extend(copy.deepcopy(mounts))
    return state

class Guards(unittest.TestCase):
    def test_healthy_baseline(self):
        r = rows(); t.validate_before(r, {s: v['image'] for s, v in r.items()}, 'tcp://localhost:1514')
    def test_local_tag_drift(self):
        r = rows(); images = {s: v['image'] for s, v in r.items()}; images['core'] = 'other'
        with self.assertRaisesRegex(ValueError, 'LOCAL_IMAGE_DRIFT'):
            t.validate_before(r, images, 'tcp://localhost:1514')
    def test_not_healthy(self):
        r = rows(); r['core']['health'] = 'unhealthy'
        with self.assertRaisesRegex(ValueError, 'NOT_ALL_HEALTHY'):
            t.validate_before(r, {s: v['image'] for s, v in r.items()}, 'tcp://localhost:1514')
    def candidate(self):
        before = rows(); after = copy.deepcopy(before)
        for s in t.SERVICES:
            after[s]['id'] += '-new'; after[s]['logging']['Config']['syslog-address'] = 'tcp://127.0.0.1:1514'
        return before, after
    def test_exact_change(self):
        b, a = self.candidate(); t.validate_after(b, a, 'tcp://127.0.0.1:1514')
    def test_preservation_failures(self):
        changes = [('image', 'different'), ('ports', {'80': 'bad'}), ('restart', {'Name': 'no'}),
                   ('mounts', [{'Type': 'bind', 'Source': '/lost-data', 'Destination': '/data'}]),
                   ('logging', {'Type': 'json-file'})]
        for key, value in changes:
            with self.subTest(key=key):
                b, a = self.candidate(); a['core'][key] = value
                with self.assertRaises(ValueError): t.validate_after(b, a, 'tcp://127.0.0.1:1514')
    def test_logger_not_recreated(self):
        b, a = self.candidate(); a['log']['id'] = 'new-logger'
        with self.assertRaisesRegex(ValueError, 'LOGGER_RECREATED'): t.validate_after(b, a, 'tcp://127.0.0.1:1514')
    def test_app_must_recreate(self):
        b, a = self.candidate(); a['core']['id'] = b['core']['id']
        with self.assertRaisesRegex(ValueError, 'APP_NOT_RECREATED'): t.validate_after(b, a, 'tcp://127.0.0.1:1514')
    def test_host_guard_rejects_before_subprocess(self):
        with patch.object(t.os, 'geteuid', return_value=0, create=True), patch.object(t.socket, 'gethostname', return_value='production'), patch.object(t.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'HOST_MISMATCH'): t.main(['apply', '--bundle', '/tmp/test', '--work', '/root/hbr-address-trial-test'])
            run.assert_not_called()
    def test_unknown_uuid_rejected(self):
        with patch.object(t.os, 'geteuid', return_value=0, create=True), patch.object(t.socket, 'gethostname', return_value='harbor01'), patch.object(t.Path, 'read_text', return_value='11111111-1111-1111-1111-111111111111'):
            with self.assertRaisesRegex(ValueError, 'CLONE_UUID_MISMATCH'): t.clone_guard()

    def exercise(self, mutation_rc=0, mode='apply', volumes=False, missing_current=False,
                 missing_volume=False, mutation_timeout=False, prior_status='STOP_RECOVERY_REQUIRED'):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); bundle = root / 'bundle'; bundle.mkdir(); work = root / 'hbr-address-trial-test'
            for n in ('checker.py', 'override.json'): (bundle / n).write_text('{}')
            before, after = self.candidate()
            if volumes:
                add_observed_volumes(before); add_observed_volumes(after)
            if mode == 'restore':
                work.mkdir(); (work / 'apply.claim').write_text('prior')
                (work / 'apply-result.json').write_text(json.dumps({'before': before, 'status': prior_status}))
                for n in ('checker.py', 'override.json'): (work / n).write_text('{}')
                for s in t.SERVICES: after[s]['logging']['Config']['syslog-address'] = 'tcp://localhost:1514'
            calls = []; mutated = False
            def fake_run(cmd, **kw):
                nonlocal mutated
                calls.append(cmd)
                if 'up' in cmd:
                    mutated = True
                    if mutation_timeout: raise subprocess.TimeoutExpired(cmd, 120)
                    return SimpleNamespace(returncode=mutation_rc)
                if 'config' in cmd: out = json.dumps({'services': {s: {'image': s} for s in before}})
                elif 'image' in cmd: out = 'sha256:' + cmd[-1]
                elif 'volume' in cmd:
                    if missing_volume: return SimpleNamespace(returncode=1)
                    mount = t.volume_mounts(before)[cmd[-1]]
                    out = json.dumps({'name': mount['Name'], 'driver': 'local', 'mountpoint': mount['Source'], 'scope': 'local', 'has_options': False})
                elif 'inspect' in cmd:
                    if missing_current and not mutated: return SimpleNamespace(returncode=1)
                    if cmd[-1] == 'harbor-log' and cmd.count('harbor-log') == 1 and len(cmd) < 10:
                        out = json.dumps(before['log'])
                    else: out = '\n'.join(json.dumps(r) for r in (after if mutated else before).values())
                else: out = 'LISTEN 0 4096 127.0.0.1:1514 0.0.0.0:*'
                kw['stdout'].write(out.encode()); return SimpleNamespace(returncode=0)
            def paths(p): return root if str(p) == '/root' else Path(p)
            def hashes(p):
                return {'checker.py': t.CHECKER_SHA, 'override.json': t.OVERRIDE_SHA,
                        'docker-compose.yml': t.BASE_SHA}.get(p.name, 'source-sha')
            module = SimpleNamespace(check=lambda a, b: (0, {'CONFIG_DELTA': 'PASS'}))
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m: None))
            with patch.object(t, 'Path', side_effect=paths), patch.object(t, 'clone_guard'), patch.object(t, 'digest', side_effect=hashes), patch.object(t.subprocess, 'run', side_effect=fake_run), patch.object(t.importlib.util, 'spec_from_file_location', return_value=spec), patch.object(t.importlib.util, 'module_from_spec', return_value=module):
                rc = t.main([mode, '--bundle', str(bundle), '--work', str(work)])
            result = json.loads((work / (mode + '-result.json')).read_text())
            changes = [c for c in calls if 'up' in c]
            self.assertEqual(len(changes), 0 if missing_current or missing_volume else 1)
            if changes:
                self.assertEqual(changes[0][-9:], list(t.SERVICES))
                self.assertIn('--no-deps', changes[0]); self.assertIn('never', changes[0])
                self.assertNotIn('--renew-anon-volumes', changes[0]); self.assertNotIn('-V', changes[0])
            self.assertFalse(any('restart' in c or 'down' in c for c in calls))
            return rc, result

    def test_apply_execution_one_change(self):
        rc, result = self.exercise(); self.assertEqual(rc, 0)
        self.assertEqual(result['status'], 'ADDRESS_APPLIED_HEALTHY')

    def test_apply_failure_does_not_retry(self):
        rc, result = self.exercise(mutation_rc=1); self.assertEqual(rc, 2)
        self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')

    def test_restore_checks_current_inventory(self):
        rc, result = self.exercise(mode='restore'); self.assertEqual(rc, 0)
        self.assertEqual(result['status'], 'ORIGINAL_ADDRESS_RESTORED_HEALTHY')

    def test_real_volume_layout_precheck(self):
        r = add_observed_volumes(rows())
        self.assertEqual(len(t.volume_mounts(r)), 9)
        t.validate_before(r, {s: v['image'] for s, v in r.items()}, 'tcp://localhost:1514')

    def test_unknown_non_bind_target_still_rejected(self):
        r = add_observed_volumes(rows())
        r['postgresql']['mounts'].append(copy.deepcopy(r['portal']['mounts'][1]))
        with self.assertRaisesRegex(ValueError, 'UNEXPECTED_NON_BIND_DATA'): t.volume_mounts(r)

    def test_volume_mount_metadata_drift_rejected(self):
        for field, value in [('Type', 'tmpfs'), ('Name', 'named-volume'), ('Driver', 'nfs'),
                             ('Source', '/other/data'), ('RW', False), ('Mode', 'ro')]:
            with self.subTest(field=field):
                r = add_observed_volumes(rows()); r['portal']['mounts'][1][field] = value
                with self.assertRaises(ValueError): t.volume_mounts(r)

    def test_volume_inventory_options_and_path_rejected(self):
        mount = next(iter(t.volume_mounts(add_observed_volumes(rows())).values()))
        actual = {'name': mount['Name'], 'driver': 'local', 'mountpoint': mount['Source'], 'scope': 'local', 'has_options': False}
        t.validate_volume_inventory(mount, actual)
        for field, value in [('mountpoint', '/other'), ('driver', 'nfs'), ('has_options', True)]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'VOLUME_INVENTORY_CHANGED'):
                t.validate_volume_inventory(mount, dict(actual, **{field: value}))

    def test_new_volume_identity_after_change_rejected(self):
        b, a = self.candidate(); add_observed_volumes(b); add_observed_volumes(a)
        a['portal']['mounts'][1]['Name'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'PRESERVATION_MOUNTS'): t.validate_after(b, a, 'tcp://127.0.0.1:1514')

    def test_restore_rejects_mount_drift_before_mutation(self):
        b = add_observed_volumes(rows()); a = copy.deepcopy(b)
        a['portal']['mounts'][1]['Source'] = '/lost-data'
        with self.assertRaisesRegex(ValueError, 'RESTORE_MOUNTS_CHANGED'): t.validate_restore_current(b, a)

    def test_real_volume_apply_flow(self):
        rc, result = self.exercise(volumes=True)
        self.assertEqual(rc, 0)
        self.assertEqual(sum(c['name'].startswith('volume-') for c in result['commands']), 9)

    def test_real_volume_restore_flow(self):
        rc, result = self.exercise(mode='restore', volumes=True)
        self.assertEqual(rc, 0)

    def test_missing_volume_stops_before_change(self):
        rc, result = self.exercise(volumes=True, missing_volume=True)
        self.assertEqual(rc, 2); self.assertEqual(result['status'], 'STOP_BEFORE_CHANGE')

    def test_missing_container_restore_stops_before_change(self):
        rc, result = self.exercise(mode='restore', volumes=True, missing_current=True)
        self.assertEqual(rc, 2); self.assertEqual(result['status'], 'STOP_BEFORE_CHANGE')

    def test_prechange_stop_cannot_restore(self):
        with self.assertRaisesRegex(ValueError, 'NO_CHANGE_TO_RESTORE'):
            self.exercise(mode='restore', prior_status='STOP_BEFORE_CHANGE')

    def test_mutation_timeout_not_retried(self):
        rc, result = self.exercise(volumes=True, mutation_timeout=True)
        self.assertEqual(rc, 2); self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertEqual(result['commands'][-1]['rc'], 124)

if __name__ == '__main__': unittest.main()
