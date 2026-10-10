"""Synthetic offline receipt checks; no host enrollment, installer or Docker."""
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_review_package as package_fixture

package = package_fixture.x

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location(
    'package_check_subject', ROOT / 'scripts/preparation/harbor_review_package_check.py')
x = importlib.util.module_from_spec(loader)
loader.loader.exec_module(x)


class ReceiptFixture:
    def setUp(self):
        builder = package_fixture.PackageTests()
        builder.setUp()
        self.files, self.plan = builder.prepare()
        self.expected = x.sha(self.files['INSTALL_PLAN.json'])

    def change_plan(self, mutate):
        obj = deepcopy(self.plan)
        mutate(obj)
        self.files['INSTALL_PLAN.json'] = package.encoded(obj)
        self.expected = x.sha(self.files['INSTALL_PLAN.json'])

    def verify(self):
        return x.verify_bytes(self.files, self.expected)


class ReceiptTests(ReceiptFixture, unittest.TestCase):
    def test_generated_package_pass_is_only_integrity_with_no_candidate_execution(self):
        # Compiling the source is allowed; loading it would violate receipt-only scope.
        with patch.object(x.UnixEngine, '_request', side_effect=AssertionError('Docker request')), \
             patch.object(x, 'UnixEngine', wraps=x.UnixEngine) as engine, \
             patch('builtins.exec', side_effect=AssertionError('candidate execution')):
            result = self.verify()
        self.assertEqual(result['status'], 'PACKAGE_BYTES_VERIFIED')
        self.assertEqual(result['files'], 16)
        for field in ('approval', 'target_metadata', 'external_existing_inputs'):
            self.assertEqual(result[field], 'NOT_VERIFIED')
        self.assertEqual(result['original_input_bytes'], 'NOT_INCLUDED_NOT_VERIFIED')
        self.assertEqual(result['installation'], 'NOT_RUN')
        self.assertEqual(result['runtime'], 'NOT_RUN')
        engine.assert_called_once()
        self.assertNotIn('host_policy', json.dumps(result))

    def test_hash_must_arrive_externally_and_not_be_derived_as_new_baseline(self):
        for expected in (None, '', '0' * 64, self.expected.upper()):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                x.verify_bytes(self.files, expected)
        self.files['INSTALL_PLAN.json'] += b' '
        with self.assertRaisesRegex(ValueError, 'PLAN_HASH'):
            self.verify()

    def test_missing_extra_empty_and_oversized_member_block(self):
        original = deepcopy(self.files)
        cases = (lambda f: f.pop('launch.json'), lambda f: f.update(extra=b'private'),
                 lambda f: f.update({'manager.service': b''}),
                 lambda f: f.update({'manager.service': b'x' * (x.limit('manager.service') + 1)}))
        for mutate in cases:
            self.files = deepcopy(original)
            mutate(self.files)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, 'FILE_SET_OR_SIZE'):
                self.verify()

    def test_payload_tamper_is_not_hidden_by_successful_plan_hash(self):
        for name in sorted(x.PAYLOADS):
            original = self.files[name]
            self.files[name] += b' '
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'CHECK_BYTES'):
                self.verify()
            self.files[name] = original

    def test_duplicate_entries_unknown_fields_and_boolean_metadata_rejected(self):
        cases = (
            lambda p: p['files'].__setitem__(0, deepcopy(p['files'][1])),
            lambda p: p['files'][0].update(extra='private'),
            lambda p: p['files'][0].update(uid=False),
            lambda p: p['files'][0].update(gid=False),
            lambda p: p['files'][0].update(mode=True),
            lambda p: p['files'][0].update(bytes=True),
            lambda p: p['files'][0].update(existing_target='OVERWRITE'),
            lambda p: p.update(runtime_go=True),
            lambda p: p.update(automatic_deletion=True),
            lambda p: p.update(status='INSTALLED'),
        )
        for mutate in cases:
            self.change_plan(mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.verify()

    def test_plan_scope_store_and_external_input_omission_rejected(self):
        for mutate in (lambda p: p.update(source_revision='b' * 40),
                       lambda p: p['store'].update(path='/var/lib/other'),
                       lambda p: p.update(external_existing_inputs={})):
            self.change_plan(mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.verify()

    def test_destination_drift_and_traversal_do_not_become_installation_plan(self):
        names = ('harbor_recovery_core.py', 'harbor_recovery_bootstrap.py', 'manager.service',
                 'bundle.json', 'launch.json')
        for name in names:
            for target in ('/root/unrelated', '/etc/fds-harbor-recovery/bundles/../escape.json'):
                self.change_plan(lambda p: next(e for e in p['files'] if e['file'] == name).update(target=target))
                with self.subTest(name=name, target=target), self.assertRaises(ValueError):
                    self.verify()

    def test_rehashed_outer_manifest_does_not_repin_candidate_source(self):
        name = 'harbor_recovery_core.py'
        self.files[name] = b'raise PRIVATE_SYNTAX(\n'
        self.change_plan(lambda p: next(e for e in p['files'] if e['file'] == name).update(
            sha256=x.sha(self.files[name]), bytes=len(self.files[name])))
        # The source must also match the original bundle pin before compilation.
        with self.assertRaisesRegex(ValueError, 'SOURCE_PIN'):
            self.verify()

    def test_launch_hash_binding_survives_rehashed_outer_manifest(self):
        launch = json.loads(self.files['launch.json'])
        launch['sha256'] = 'f' * 64
        self.files['launch.json'] = package.encoded(launch)
        self.change_plan(lambda p: next(e for e in p['files'] if e['file'] == 'launch.json').update(
            sha256=x.sha(self.files['launch.json']), bytes=len(self.files['launch.json'])))
        with self.assertRaisesRegex(ValueError, 'LAUNCH_BINDING'):
            self.verify()

    def test_bootstrap_payload_correction_requires_unit_connection_not_only_outer_hash(self):
        name = 'harbor_recovery_bootstrap.py'
        self.files[name] += b'\n'
        self.change_plan(lambda p: next(e for e in p['files'] if e['file'] == name).update(
            sha256=x.sha(self.files[name]), bytes=len(self.files[name]),
            target='/opt/fds-harbor-recovery/bootstrap/' + x.sha(self.files[name]) + '/' + name))
        with self.assertRaisesRegex(ValueError, 'UNIT_LAUNCH_BINDING'):
            self.verify()

    def test_anchor_context_correction_requires_unit_connection(self):
        self.change_plan(lambda p: next(e for e in p['files'] if e['file'] == 'launch.json').update(
            selinux='system_u:object_r:other_t:s0'))
        with self.assertRaisesRegex(ValueError, 'UNIT_LAUNCH_BINDING'):
            self.verify()

    def repin_unit_fixture(self):
        # Synthetic fixture only; not a production baseline/approval updater.
        bundle = json.loads(self.files['bundle.json'])
        p = bundle['host_policy']
        p['files'][bundle['manager']['fragment']]['sha256'] = x.sha(self.files['manager.service'])
        bundle['plan']['execution_binding'] = x.execution_binding(
            x.bound_host_digest(bundle), p['project'], x.UnixEngine(p['api_version'], socket_path=p['socket']).binding)
        self.files['bundle.json'] = package.encoded(bundle)
        launch = json.loads(self.files['launch.json'])
        launch['sha256'] = x.sha(self.files['bundle.json'])
        self.files['launch.json'] = package.encoded(launch)
        def repin(plan):
            for name in ('manager.service', 'bundle.json', 'launch.json'):
                entry = next(e for e in plan['files'] if e['file'] == name)
                entry.update(sha256=x.sha(self.files[name]), bytes=len(self.files[name]))
        self.change_plan(repin)

    def test_rehashed_noncanonical_unit_or_short_shutdown_is_rejected(self):
        original = deepcopy(self.files)
        for mutate, reason in (
                (lambda raw: raw + b'ExecStartPost=/bin/false\n', 'UNIT_BYTES'),
                (lambda raw: raw.replace(b'TimeoutStopSec=90', b'TimeoutStopSec=30'), 'SHUTDOWN_BUDGET')):
            self.files = deepcopy(original)
            self.files['manager.service'] = mutate(self.files['manager.service'])
            self.repin_unit_fixture()
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                self.verify()


class FileReceiptTests(ReceiptFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'package'
        package.write_package(self.directory, self.files)

    def read(self, **kwargs):
        return x.read_package(self.directory, 100, clock=kwargs.pop('clock', lambda: 0), **kwargs)

    def test_receipt_reads_original_bytes_without_any_writes(self):
        before = {name: (p.read_bytes(), x.stamp(p.lstat()))
                  for name in x.FILES for p in [self.directory / name]}
        with patch.object(os, 'write', side_effect=AssertionError('receipt attempted write')):
            self.assertEqual(self.read(), self.files)
        after = {name: (p.read_bytes(), x.stamp(p.lstat()))
                 for name in x.FILES for p in [self.directory / name]}
        self.assertEqual(before, after)

    def test_extra_member_and_empty_file_stop_before_verification(self):
        (self.directory / 'extra').write_bytes(b'KEEP_ME')
        with self.assertRaisesRegex(ValueError, 'DIRECTORY_MEMBERS'):
            self.read()
        self.assertEqual((self.directory / 'extra').read_bytes(), b'KEEP_ME')
        (self.directory / 'extra').unlink()  # Synthetic test fixture only.
        (self.directory / 'launch.json').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'CHECK_FILE'):
            self.read()

    def test_hardlinked_file_is_refused(self):
        target = self.directory / 'launch.json'
        os.link(target, Path(self.tmp.name) / 'alias')
        with self.assertRaisesRegex(ValueError, 'CHECK_FILE'):
            self.read()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux symlink/FIFO semantics')
    def test_symlink_parent_member_and_fifo_are_refused_without_opening(self):
        alias = Path(self.tmp.name) / 'alias'
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'DIRECTORY'):
            x.read_package(alias, 100, clock=lambda: 0)
        target = self.directory / 'launch.json'
        target.unlink()
        target.symlink_to(self.directory / 'bundle.json')
        with self.assertRaisesRegex(ValueError, 'CHECK_FILE'):
            self.read()
        target.unlink()
        os.mkfifo(target)
        with self.assertRaisesRegex(ValueError, 'CHECK_FILE'):
            self.read()

    def test_deadline_and_nonfinite_timeout_fail_with_no_input_changes(self):
        for value in (100, float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'DEADLINE'):
                x.read_package(self.directory, value, clock=lambda: 100)
        for timeout in ('0', '-1', 'nan', 'inf', '601'):
            with patch('builtins.print') as output:
                self.assertEqual(x.main(['--package', str(self.directory), '--plan-sha256', self.expected,
                                         '--timeout', timeout]), 2)
            self.assertNotIn(str(self.directory), str(output.call_args))

    def test_member_change_during_read_is_rejected_and_preserved(self):
        real_read = os.read
        changed = False
        def change(fd, size):
            nonlocal changed
            raw = real_read(fd, size)
            if not changed:
                changed = True
                with (self.directory / 'INSTALL_PLAN.json').open('ab') as stream:
                    stream.write(b' ')
            return raw
        with patch.object(os, 'read', side_effect=change):
            with self.assertRaisesRegex(ValueError, 'FILE_CHANGED'):
                self.read()
        self.assertTrue((self.directory / 'INSTALL_PLAN.json').read_bytes().endswith(b' '))

    def test_cli_success_and_failure_never_claim_approval_or_leak_private_text(self):
        arguments = ['--package', str(self.directory), '--plan-sha256', self.expected, '--timeout', '10']
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(x.main(arguments), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'PACKAGE_BYTES_VERIFIED')
        self.assertEqual(result['approval'], 'NOT_VERIFIED')
        with patch.object(x, 'read_package', side_effect=ValueError('PRIVATE_PLAN_TOKEN')), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(x.main(arguments), 2)
        self.assertNotIn('PRIVATE', output.getvalue())
        self.assertNotIn(str(self.directory), output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['runtime'], 'NOT_RUN')
        with patch.object(x, 'read_package', side_effect=KeyboardInterrupt), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(x.main(arguments), 130)
        self.assertEqual(json.loads(output.getvalue())['reason'], 'INTERRUPTED')


if __name__ == '__main__':
    unittest.main()
