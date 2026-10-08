"""Real sealed metadata, fake process execution. Never access a Docker daemon."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_clone_trial import t

FIXTURE = Path(__file__).parent / 'observed-a2r1-result.json'


class A2R1(unittest.TestCase):
    def setUp(self):
        self.prior = json.loads(FIXTURE.read_text())
        self.before = self.prior['before']
        self.current = self.prior['after']

    def test_fixture_matches_pinned_original_stop(self):
        self.assertEqual(t.digest(FIXTURE), t.A2R1_RESULT_SHA)
        self.assertEqual(self.prior['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertEqual(self.prior['error_code'], 'PRESERVATION_MOUNTS')

    def test_original_strict_path_still_rejects(self):
        with self.assertRaisesRegex(ValueError, 'RESTORE_MOUNTS_CHANGED'):
            t.validate_restore_current(self.before, self.current)

    def test_only_recorded_seven_modes_are_accepted(self):
        t.validate_restore_current(self.before, self.current, True)
        t.validate_after(self.before, self.current, 'tcp://127.0.0.1:1514', True)

    def test_profile_cannot_hide_other_mount_drift(self):
        mutations = [('Name', '0'*64), ('Source', '/wrong'), ('Driver', 'nfs'),
                     ('RW', False), ('Propagation', 'rshared'), ('Mode', 'Z'),
                     ('Mode', ''), ('Type', 'bind'), ('Destination', '/other')]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                a = copy.deepcopy(self.current)
                mount = next(m for m in a['portal']['mounts'] if m['Type'] == 'volume')
                mount[key] = value
                with self.assertRaisesRegex(ValueError, 'RESTORE_MOUNTS_CHANGED'):
                    t.validate_restore_current(self.before, a, True)

    def test_logger_and_bind_modes_remain_exact(self):
        for service, mount_type in [('log', 'volume'), ('proxy', 'bind')]:
            a = copy.deepcopy(self.current)
            next(m for m in a[service]['mounts'] if m['Type'] == mount_type)['Mode'] = 'changed'
            with self.assertRaisesRegex(ValueError, 'RESTORE_MOUNTS_CHANGED'):
                t.validate_restore_current(self.before, a, True)

    def test_restore_must_replace_current_app_not_historical_id(self):
        after = copy.deepcopy(self.current)
        for s in t.SERVICES:
            after[s]['logging']['Config']['syslog-address'] = 'tcp://localhost:1514'
        with self.assertRaisesRegex(ValueError, 'APP_NOT_RECREATED'):
            t.validate_after(self.before, after, 'tcp://localhost:1514', True, self.current)

    def test_apply_cannot_use_exception(self):
        with patch.object(t, 'clone_guard') as guard, self.assertRaisesRegex(ValueError, 'PROFILE_APPLY_FORBIDDEN'):
            t.main(['apply', '--bundle', 'unused', '--work', 'unused', '--a2r1-mode-profile'])
        guard.assert_not_called()

    def exercise(self, mode='check-current', drift=None, mutation_error=None, bad_hash=False):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / 'hbr-address-trial-test'; work.mkdir()
            capture = root / 'capture'; capture.mkdir()
            (work / 'apply-result.json').write_bytes(FIXTURE.read_bytes())
            (work / 'apply.claim').write_text('historical claim')
            for name in ('checker.py', 'override.json'): (work / name).write_text('{}')
            calls = []; mutated = False
            def run(cmd, **kw):
                nonlocal mutated
                calls.append(cmd)
                if 'up' in cmd:
                    mutated = True
                    if mutation_error: raise mutation_error
                    return SimpleNamespace(returncode=0)
                if 'config' in cmd:
                    out = json.dumps({'services': {s: {'image': s} for s in self.before}})
                elif 'image' in cmd: out = self.before[cmd[-1]]['image']
                elif 'volume' in cmd:
                    m = t.volume_mounts(self.before)[cmd[-1]]
                    out = json.dumps({'name': m['Name'], 'driver': 'local', 'mountpoint': m['Source'], 'scope': 'local', 'has_options': False})
                elif 'version' in cmd:
                    out = '5.5.1' if 'compose' in cmd else json.dumps({'Version': '29.8.0', 'GitCommit': '3ce5872'})
                    if drift == 'version': out = out.replace('29.8.0', '29.9.0')
                elif 'info' in cmd:
                    opts = ['name=seccomp,profile=builtin', 'name=cgroupns']
                    if drift == 'security': opts.append('name=selinux')
                    out = json.dumps({'security_options': opts, 'root': '/var/lib/docker', 'driver': 'overlayfs'})
                elif cmd[0] == 'getenforce': out = 'Enforcing'
                elif t.SECURITY_FORMAT in cmd:
                    out = '\n'.join(json.dumps({'id': cid, 'mount_label': 'changed' if drift == 'label' else '',
                        'process_label': '', 'security_opt': None, 'privileged': False}) for cid in cmd[-3:])
                elif 'inspect' in cmd:
                    a = copy.deepcopy(self.current)
                    if drift == 'candidate': a['core']['id'] = 'other'
                    if mutated:
                        for s in t.SERVICES:
                            a[s]['id'] += '-restored'
                            a[s]['logging']['Config']['syslog-address'] = 'tcp://localhost:1514'
                    out = '\n'.join(json.dumps(r) for r in a.values())
                else: out = 'LISTEN 0 4096 127.0.0.1:1514 0.0.0.0:*'
                kw['stdout'].write(out.encode()); return SimpleNamespace(returncode=0)
            original_digest = t.digest
            def hashes(p):
                return {'checker.py': t.CHECKER_SHA, 'override.json': t.OVERRIDE_SHA,
                        'docker-compose.yml': t.BASE_SHA}.get(p.name) or original_digest(p)
            def paths(p): return root if str(p) == '/root' else Path(p)
            module = SimpleNamespace(check=lambda a,b: (0, {'CONFIG_DELTA': 'PASS'}))
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m: None))
            with patch.object(t, 'clone_guard'), patch.object(t, 'Path', side_effect=paths), \
                 patch.object(t, 'A2R1_WORK', str(work)), patch.object(t, 'digest', side_effect=hashes), \
                 patch.object(t, 'A2R1_RESULT_SHA', 'wrong' if bad_hash else t.A2R1_RESULT_SHA), \
                 patch.object(t.tempfile, 'mkdtemp', return_value=str(capture)), \
                 patch.object(t.subprocess, 'run', side_effect=run), \
                 patch.object(t.os, 'getxattr', return_value=b'wrong' if drift == 'xattr' else b'system_u:object_r:container_file_t:s0\0', create=True), \
                 patch.object(t.importlib.util, 'spec_from_file_location', return_value=spec), \
                 patch.object(t.importlib.util, 'module_from_spec', return_value=module):
                args = [mode, '--bundle', str(work), '--work', str(work), '--a2r1-mode-profile']
                if bad_hash:
                    with self.assertRaisesRegex(ValueError, 'PROFILE_RESULT_CHANGED'): t.main(args)
                    self.assertEqual(calls, [])
                    return
                rc = t.main(args)
            output = capture if mode == 'check-current' else work
            result = json.loads((output / (mode + '-result.json')).read_text())
            self.assertEqual((work / 'apply-result.json').read_bytes(), FIXTURE.read_bytes())
            self.assertFalse(any('restart' in c or 'down' in c for c in calls))
            changes = [c for c in calls if 'up' in c]
            self.assertEqual(len(changes), 1 if mode == 'restore' and not drift else 0)
            return rc, result

    def test_check_current_never_mutates(self):
        rc, result = self.exercise()
        self.assertEqual((rc, result['status']), (0, 'CANDIDATE_METADATA_VERIFIED'))
        self.assertEqual(result['AUTOSTART'], 'NOT_TESTED')

    def test_profile_restore_execution(self):
        rc, result = self.exercise('restore')
        self.assertEqual((rc, result['status']), (0, 'ORIGINAL_ADDRESS_RESTORED_HEALTHY'))
        self.assertEqual(result['profile_before']['volume_xattrs'], result['profile_after']['volume_xattrs'])

    def test_runtime_drift_stops_before_restore(self):
        for drift in ('version', 'security', 'label', 'candidate', 'xattr'):
            with self.subTest(drift=drift):
                rc, result = self.exercise('restore', drift=drift)
                self.assertEqual((rc, result['status']), (2, 'STOP_BEFORE_CHANGE'))

    def test_modified_prior_result_rejected_without_queries(self):
        self.exercise(bad_hash=True)

    def test_profile_restore_timeout_or_interrupt_does_not_retry(self):
        for exc in (subprocess.TimeoutExpired(['mock'],120), KeyboardInterrupt()):
            with self.subTest(exc=type(exc).__name__):
                rc, result = self.exercise('restore', mutation_error=exc)
                self.assertEqual((rc, result['status']), (2, 'STOP_RECOVERY_REQUIRED'))


if __name__ == '__main__': unittest.main()
