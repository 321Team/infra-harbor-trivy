import copy
import importlib.util
import json
from pathlib import Path
import tempfile
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

    def exercise(self, mutation_rc=0, mode='apply'):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); bundle = root / 'bundle'; bundle.mkdir(); work = root / 'hbr-address-trial-test'
            for n in ('checker.py', 'override.json'): (bundle / n).write_text('{}')
            before, after = self.candidate()
            if mode == 'restore':
                work.mkdir(); (work / 'apply.claim').write_text('prior')
                (work / 'apply-result.json').write_text(json.dumps({'before': before}))
                for n in ('checker.py', 'override.json'): (work / n).write_text('{}')
                for s in t.SERVICES: after[s]['logging']['Config']['syslog-address'] = 'tcp://localhost:1514'
            calls = []; mutated = False
            def fake_run(cmd, **kw):
                nonlocal mutated
                calls.append(cmd)
                if 'up' in cmd:
                    mutated = True
                    return SimpleNamespace(returncode=mutation_rc)
                if 'config' in cmd: out = json.dumps({'services': {s: {'image': s} for s in before}})
                elif 'image' in cmd: out = 'sha256:' + cmd[-1]
                elif 'inspect' in cmd:
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
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0][-9:], list(t.SERVICES))
            self.assertIn('--no-deps', changes[0]); self.assertIn('never', changes[0])
            self.assertFalse(any('restart' in c or 'down' in c for c in calls))
            return rc, result

    def test_apply_execution_one_change(self):
        rc, result = self.exercise(); self.assertEqual(rc, 0)
        self.assertEqual(result['status'], 'ADDRESS_APPLIED_HEALTHY')

    def test_apply_failure_does_not_retry(self):
        rc, result = self.exercise(mutation_rc=1); self.assertEqual(rc, 2)
        self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')

    def test_restore_uses_before_snapshot_without_full_current_inventory(self):
        rc, result = self.exercise(mode='restore'); self.assertEqual(rc, 0)
        self.assertEqual(result['status'], 'ORIGINAL_ADDRESS_RESTORED_HEALTHY')

if __name__ == '__main__': unittest.main()
