"""Actual verified importer with synthetic catalog/helper and pinned byte reader."""
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'scripts/preparation'))
import harbor_stopped_recovery_entry as entry
import test_verified_bootstrap as v


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.reader = v.Reader()
        self.helper = '/opt/fds-harbor-recovery/manual/helper.py'
        self.raw = b'''import harbor_recovery_bundle as b
class StoppedRecovery:
    def __init__(self, control, **kw): b.CALLS.append('construct-helper')
    def inspect(self, pin, deadline): return ('inspect', pin, b.CALLS)
    def run(self, pin, stop, deadline, explicit=False): return ('recover', pin, stop, explicit, b.CALLS)
'''
        self.reader.data[self.helper] = self.raw
        self.spec = {'sha256': hashlib.sha256(self.raw).hexdigest(), 'mode':0o444, 'gid':0, 'selinux':v.LABEL}
        source = b'''CALLS = []
def load_bundle(*a, **kw): CALLS.append('load-bundle'); return object()
def verify_store_writer(*a, **kw): CALLS.append('writer')
def build(*a, **kw): CALLS.append('build'); return {'control': object()}
'''
        self.change_source('harbor_recovery_bundle', source)
        self.kw = dict(helper_path=self.helper, helper_spec=self.spec, bundle_path=v.BUNDLE,
                       bundle_sha256=self.reader.sha, bundle_context=v.LABEL, state_pin='a'*64,
                       operation='inspect', deadline=20, reader=self.reader, clock=lambda:10)

    def change_source(self, name, raw):
        path = self.reader.obj['source']['directory']+'/'+name+'.py'
        self.reader.data[path] = raw
        pin = hashlib.sha256(raw).hexdigest()
        self.reader.obj['source']['files'][name+'.py'] = pin
        self.reader.obj['host_policy']['files'][path]['sha256'] = pin
        self.reader.refresh()

    def call(self, **kw):
        with v.clean_project_imports(), patch.object(v.x, 'runtime_guard'):
            return entry.operate(v.x, **(self.kw | kw))

    def test_verified_byte_import_and_writer_precede_helper_operation(self):
        result = self.call()
        self.assertEqual(result, ('inspect', 'a'*64, ['load-bundle','writer','build','construct-helper']))
        self.assertEqual(self.reader.calls[0], self.helper)
        self.assertEqual(self.reader.calls[-1], self.helper)
        self.assertEqual(len(self.reader.calls), len(v.x.MODULES)+4)

    def test_only_explicit_recovery_routes_to_run(self):
        result = self.call(operation='recover', stop_pin='b'*64, execute=True)
        self.assertEqual(result[:4], ('recover','a'*64,'b'*64,True))
        for kw in ({'operation':'recover'}, {'execute':True}, {'stop_pin':'b'*64}, {'operation':'serve'}):
            with self.subTest(kw=kw), self.assertRaises(ValueError): self.call(**kw)

    def test_unisolated_or_nonroot_entry_refused(self):
        with self.assertRaises(ValueError): entry.operate(v.x, **self.kw)
        self.assertEqual(self.reader.calls, [])

    def test_bad_helper_hash_never_imports_catalog(self):
        self.reader.data[self.helper] += b'raise AssertionError("never imported")\n'
        with self.assertRaisesRegex(ValueError, 'HASH'): self.call()
        self.assertEqual(self.reader.calls, [self.helper])

    def test_last_catalog_file_hash_error_never_executes_helper(self):
        last = self.reader.obj['source']['directory']+'/'+sorted(v.x.MODULES)[-1]+'.py'
        self.reader.data[last] += b'raise AssertionError("never imported")\n'
        with self.assertRaisesRegex(ValueError, 'HASH'): self.call()

    def test_writer_failure_precedes_helper_and_runtime_build(self):
        source = b'''def load_bundle(*a, **kw): return object()
def verify_store_writer(*a, **kw): raise ValueError('writer mismatch')
def build(*a, **kw): raise AssertionError('must not build')
'''
        self.change_source('harbor_recovery_bundle', source)
        with self.assertRaisesRegex(ValueError, 'writer mismatch'):
            self.call(bundle_sha256=self.reader.sha)

    def test_no_preimported_project_module_or_path_fallback(self):
        with patch.object(v.x, 'runtime_guard'), self.assertRaisesRegex(ValueError, 'ALREADY_IMPORTED'):
            entry.operate(v.x, **self.kw)

    def test_expired_input_refused_before_any_file_read(self):
        with self.assertRaisesRegex(ValueError, 'DEADLINE'): self.call(deadline=10)
        self.assertEqual(self.reader.calls, [])
