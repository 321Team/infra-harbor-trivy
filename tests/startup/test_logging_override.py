"""Synthetic normalized configs; no Docker, credentials or service use."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/verify/validate-logging-override.py'
SPEC = importlib.util.spec_from_file_location('logging_override', SCRIPT)
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


def raw(obj):
    return json.dumps(obj).encode()


def fixtures():
    services = {name: {'image': 'SYNTHETIC:' + name, 'restart': 'always',
                       'logging': {'driver': 'syslog', 'options': {'tag': name, 'syslog-address': v.OLD}},
                       'environment': {'PRIVATE': 'SYNTHETIC_SECRET_CANARY'},
                       'volumes': [{'type': 'bind', 'source': '/synthetic/data', 'target': '/data'}]}
                for name in v.SERVICES}
    services['log'] = {'restart': 'always', 'ports': [{'host_ip': '127.0.0.1', 'target': 10514,
                                                     'published': '1514', 'protocol': 'tcp', 'mode': 'ingress'}]}
    base = {'name': 'harbor', 'services': services, 'networks': {'harbor': {'external': False}}}
    effective = copy.deepcopy(base)
    override = json.loads((ROOT / 'config/harbor/compose.logging-loopback.override.json').read_bytes())
    for name, value in override['services'].items():
        effective['services'][name]['logging']['options'].update(value['logging']['options'])
    return base, effective, override


class OverrideTests(unittest.TestCase):
    def setUp(self):
        self.base, self.effective, self.override = fixtures()

    def check(self):
        rc, result = v.check(raw(self.base), raw(self.effective))
        self.assertNotIn('SYNTHETIC_SECRET_CANARY', str(result))
        self.assertEqual(result['AUTOSTART'], 'NOT_TESTED')
        self.assertEqual(result['RUNTIME_APPLY'], 'NOT_PERFORMED')
        return rc, result

    def test_committed_override_exactly_contains_nine_addresses(self):
        self.assertEqual(self.override, {'services': {
            name: {'logging': {'options': {'syslog-address': v.NEW}}} for name in v.SERVICES}})

    def test_exact_delta_preserves_input_and_never_upgrades_autostart(self):
        before = copy.deepcopy(self.base)
        rc, result = self.check()
        self.assertEqual(rc, 0)
        self.assertEqual(result['address_change_count'], 9)
        self.assertEqual(self.base, before)

    def test_effective_unrelated_changes_all_fail(self):
        changes = {'image': 'different', 'restart': 'no', 'volumes': [],
                   'ports': [443], 'environment': {}, 'privileged': True,
                   'security_opt': ['label=disable'], 'depends_on': {}, 'healthcheck': {'disable': True}}
        original = copy.deepcopy(self.effective)
        for field, value in changes.items():
            self.effective = copy.deepcopy(original)
            self.effective['services']['core'][field] = value
            with self.subTest(field=field):
                self.assertEqual(self.check()[0], 2)

    def test_missing_or_extra_service_fails(self):
        for selected in ('base', 'effective'):
            for operation in ('missing', 'extra'):
                self.base, self.effective, _ = fixtures()
                target = getattr(self, selected)['services']
                target.pop('redis') if operation == 'missing' else target.update(extra={})
                with self.subTest(selected=selected, operation=operation):
                    self.assertEqual(self.check()[0], 2)

    def test_partial_or_already_changed_baseline_fails(self):
        for selected, value in [('base', v.NEW), ('effective', v.OLD)]:
            self.base, self.effective, _ = fixtures()
            getattr(self, selected)['services']['core']['logging']['options']['syslog-address'] = value
            self.assertEqual(self.check()[0], 2)

    def test_wrong_logger_binding_or_protocol_fails_even_if_both_match(self):
        for key, value in [('host_ip', '0.0.0.0'), ('protocol', 'udp'), ('target', True), ('published', '2514')]:
            self.base, self.effective, _ = fixtures()
            for obj in (self.base, self.effective):
                obj['services']['log']['ports'][0][key] = value
            with self.subTest(key=key):
                self.assertEqual(self.check()[0], 2)

    def test_type_only_change_is_not_hidden_by_python_equality(self):
        self.base['extension'] = 1
        self.effective['extension'] = True
        self.assertEqual(self.check()[0], 2)

    def test_changed_global_network_is_rejected(self):
        self.effective['networks']['harbor']['external'] = True
        self.assertEqual(self.check()[0], 2)

    def test_duplicate_nonfinite_and_malformed_json_are_sanitized(self):
        for invalid in [b'{"services":{},"services":{}}', b'{"secret":NaN}',
                        b'SYNTHETIC_SECRET_CANARY', b'[]', b'{}', b'\xff', b'x' * (v.MAX_BYTES + 1)]:
            with self.subTest(size=len(invalid)):
                rc, result = v.check(invalid, raw(self.effective))
                self.assertEqual(rc, 2)
                self.assertNotIn('SYNTHETIC_SECRET_CANARY', str(result))

    def test_cli_failure_never_prints_input_values_or_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'base.json').write_bytes(raw(self.base))
            self.effective['services']['core']['image'] = 'SYNTHETIC_SECRET_CANARY'
            (path / 'effective.json').write_bytes(raw(self.effective))
            result = subprocess.run([sys.executable, str(SCRIPT), '--base-json', str(path / 'base.json'),
                                     '--effective-json', str(path / 'effective.json')], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'SYNTHETIC_SECRET_CANARY', result.stdout + result.stderr)
            self.assertNotIn(b'Traceback', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
