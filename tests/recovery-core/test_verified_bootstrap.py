"""Pre-import trust boundary and explicit command routing; no guest access."""
from contextlib import contextmanager, redirect_stdout, nullcontext
from copy import deepcopy
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_approved_bundle import candidate, b as model_bundle
from test_host_provider import LABEL
from test_policy_transition import fixture

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/bootstrap/harbor_recovery_bootstrap.py'
loader = importlib.util.spec_from_file_location('verified_bootstrap_test_subject', SCRIPT)
x = importlib.util.module_from_spec(loader)
loader.loader.exec_module(x)
BUNDLE = '/etc/fds-harbor-recovery/input.json'


class Reader:
    def __init__(self, obj=None, actual=False):
        self.obj = obj if obj is not None else candidate()
        self.data, self.calls = {}, []
        for name in x.MODULES:
            raw = ((ROOT/'scripts/recovery'/f'{name}.py').read_bytes() if actual else
                   f'MARKER = {name!r}\n'.encode())
            path = self.obj['source']['directory'] + '/' + name + '.py'
            sha = hashlib.sha256(raw).hexdigest()
            self.obj['source']['files'][name+'.py'] = sha
            self.obj['host_policy']['files'][path]['sha256'] = sha
            self.data[path] = raw
        self.refresh()

    def refresh(self):
        self.data[BUNDLE] = json.dumps(self.obj).encode()
        self.sha = hashlib.sha256(self.data[BUNDLE]).hexdigest()

    def read(self, path, expected, deadline, limit):
        self.calls.append(path)
        raw = self.data[path]
        if hashlib.sha256(raw).hexdigest() != expected['sha256']: raise ValueError('BOOTSTRAP_HASH')
        return raw


@contextmanager
def clean_project_imports():
    # Test process already imported project modules. Production has no such reset.
    old = {n: v for n, v in sys.modules.items() if n.startswith(x.PREFIX)}
    try:
        for name in old: del sys.modules[name]
        yield
    finally:
        for name in tuple(sys.modules):
            if name.startswith(x.PREFIX): del sys.modules[name]
        sys.modules.update(old)


class SourceTests(unittest.TestCase):
    def setUp(self): self.reader = Reader()

    def collect(self):
        return x.collect(BUNDLE, self.reader.sha, LABEL, 20, reader=self.reader, clock=lambda: 10)

    def test_collect_reads_all_sources_and_rechecks_bundle_without_import(self):
        before = {n for n in sys.modules if n.startswith(x.PREFIX)}
        code, revision = self.collect()
        self.assertEqual(set(code), x.MODULES)
        self.assertEqual(revision, 'a'*40)
        self.assertEqual(self.reader.calls[0], BUNDLE)
        self.assertEqual(self.reader.calls[-1], BUNDLE)
        self.assertEqual(len(self.reader.calls), len(x.MODULES)+2)
        self.assertEqual(before, {n for n in sys.modules if n.startswith(x.PREFIX)})

    def test_last_source_hash_error_does_not_import_any_candidate(self):
        last = self.reader.obj['source']['directory'] + '/' + sorted(x.MODULES)[-1] + '.py'
        self.reader.data[last] += b'raise Exception("must never execute")\n'
        with clean_project_imports():
            with self.assertRaisesRegex(ValueError, 'HASH'): self.collect()
            self.assertFalse(any(n.startswith(x.PREFIX) for n in sys.modules))

    def test_schema_paths_module_sets_and_metadata_pin_rejected(self):
        changes = (lambda o: o.update(schema='unknown'),
                   lambda o: o['source'].update(directory='/tmp/code'),
                   lambda o: o['source']['files'].pop('harbor_recovery_core.py'),
                   lambda o: o['source']['files'].update(injected='a'*64),
                   lambda o: o['host_policy']['files'].pop(o['source']['directory']+'/harbor_recovery_core.py'),
                   lambda o: o['host_policy']['files'][o['source']['directory']+'/harbor_recovery_core.py'].update(mode=0o666),
                   lambda o: o['host_policy']['files'][o['source']['directory']+'/harbor_recovery_core.py'].update(gid=1000))
        for change in changes:
            self.reader = Reader(); change(self.reader.obj); self.reader.refresh()
            with self.assertRaises(ValueError): self.collect()

    def test_syntax_error_occurs_before_import(self):
        path = self.reader.obj['source']['directory']+'/harbor_recovery_core.py'
        raw = b'def invalid(\n'
        self.reader.data[path] = raw
        pin = hashlib.sha256(raw).hexdigest()
        self.reader.obj['source']['files']['harbor_recovery_core.py'] = pin
        self.reader.obj['host_policy']['files'][path]['sha256'] = pin
        self.reader.refresh()
        with clean_project_imports():
            with self.assertRaises(SyntaxError): self.collect()
            self.assertFalse(any(n.startswith(x.PREFIX) for n in sys.modules))

    def test_bundle_changed_during_collection_rejected(self):
        read = self.reader.read
        def changed(path, *args):
            if path == BUNDLE and self.reader.calls:
                self.reader.data[BUNDLE] += b' '
            return read(path, *args)
        self.reader.read = changed
        with self.assertRaisesRegex(ValueError, 'HASH'): self.collect()

    def test_duplicate_json_nonfinite_and_expired_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError): x.parse(raw)
        with self.assertRaisesRegex(ValueError, 'DEADLINE'):
            x.collect(BUNDLE, self.reader.sha, LABEL, 9, reader=self.reader, clock=lambda: 10)

    def test_import_exact_verified_bytes_ignores_later_path_contents(self):
        code, _ = self.collect()
        self.reader.data.clear()
        with clean_project_imports(), x.VerifiedImporter(code):
            module = importlib.import_module('harbor_recovery_core')
            self.assertEqual(module.MARKER, 'harbor_recovery_core')
            self.assertEqual(module.__file__, self.reader.obj['source']['directory']+'/harbor_recovery_core.py')
        self.assertFalse(any(isinstance(f, x.VerifiedImporter) for f in sys.meta_path))

    def test_preimported_module_unknown_import_and_reload_rejected(self):
        code, _ = self.collect()
        with self.assertRaisesRegex(ValueError, 'ALREADY_IMPORTED'):
            with x.VerifiedImporter(code): pass
        with clean_project_imports(), x.VerifiedImporter(code):
            with self.assertRaisesRegex(ValueError, 'IMPORT_NAME'):
                importlib.import_module('harbor_recovery_unapproved')
            module = importlib.import_module('harbor_recovery_core')
            with self.assertRaisesRegex(ValueError, 'IMPORT_NAME'): importlib.reload(module)

    def test_import_real_nine_modules_and_reject_untrusted_full_bundle(self):
        self.reader = Reader(actual=True)
        code, _ = self.collect()
        with clean_project_imports(), x.VerifiedImporter(code):
            module = importlib.import_module('harbor_recovery_bundle')
            self.assertEqual(module.MODULES, {n+'.py' for n in x.MODULES})
            # Fixture's old binding must not survive the actual source hashes.
            class Pins:
                def pinned(inner, *args): return self.reader.data[BUNDLE]
            with self.assertRaisesRegex(ValueError, 'EXECUTION_BINDING'):
                module.load_bundle(BUNDLE, self.reader.sha, LABEL, 20, io=Pins(), clock=lambda: 10)

    def test_actual_source_valid_bundle_verify_without_constructing_runtime(self):
        self.reader = Reader(actual=True)
        obj = self.reader.obj
        engine = model_bundle.UnixEngine(obj['host_policy']['api_version'],
                                         socket_path=obj['host_policy']['socket'])
        obj['plan']['execution_binding'] = model_bundle.execution_binding(
            model_bundle.bound_host_digest(obj), 'harbor', engine.binding)
        self.reader.refresh()
        code, _ = self.collect()
        with clean_project_imports(), x.VerifiedImporter(code):
            module = importlib.import_module('harbor_recovery_bundle')
            class Pins:
                def pinned(inner, *args): return self.reader.data[BUNDLE]
            bundle = module.load_bundle(BUNDLE, self.reader.sha, LABEL, 20, io=Pins(), clock=lambda: 10)
            with patch.object(module, 'build', side_effect=AssertionError('No runtime construction')):
                self.assertEqual(x.operate(module, bundle, 'verify', 20, execute=False,
                                           clock=lambda: 10)[1]['runtime'], 'NOT_RUN')

    def test_failed_import_cleans_only_candidate_namespace(self):
        code, _ = self.collect()
        code['harbor_recovery_core'] = compile('raise ValueError("synthetic")', '<synthetic>', 'exec')
        with clean_project_imports():
            with self.assertRaises(ValueError), x.VerifiedImporter(code):
                importlib.import_module('harbor_recovery_core')
            self.assertFalse(any(n.startswith(x.PREFIX) for n in sys.modules))
            self.assertIs(sys.modules['json'], json)


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.bundle = SimpleNamespace(verify=lambda end: self.calls.append(('verify', end)))
        class Store:
            @contextmanager
            def locked(inner):
                self.calls.append('lock'); yield
            def initialize(inner): self.calls.append('initialize')
        def record(name, phase):
            def op(end, *, explicit):
                self.calls.append((name, end, explicit))
                return {'phase': phase, 'reason': 'TEST_RESULT'}
            return op
        def arm(end, *, explicit):
            self.calls.append(('arm', end, explicit))
            return SimpleNamespace(desired='RUN')
        def hold():
            self.calls.append('hold')
            return SimpleNamespace(desired='HOLD')
        self.parts = dict(store=Store(),
            transition=SimpleNamespace(install=record('install', 'INSTALLED_HOLD'),
                                       rollback=record('rollback', 'ROLLED_BACK')),
            activation=SimpleNamespace(arm_initial=arm),
            executor=SimpleNamespace(open=lambda: self.calls.append('open'), hold=hold))
        def build(bundle, end, **kwargs):
            self.calls.append('build'); return self.parts
        def initialize(parts, end, **kwargs):
            self.calls.append(('initialize-preflight', end))
            with parts['store'].locked(): parts['store'].initialize()
        self.module = SimpleNamespace(build=build, initialize_store=initialize)

    def run_op(self, operation, execute=True):
        return x.operate(self.module, self.bundle, operation, 20, execute=execute, clock=lambda: 10)

    def test_verify_never_builds_or_mutates(self):
        self.assertEqual(self.run_op('verify', False), (0, {'stage': 'INPUT_SOURCE_VERIFIED', 'runtime': 'NOT_RUN'}))
        self.assertEqual(self.calls, [('verify', 20)])

    def test_every_mutation_requires_execute_before_build(self):
        for name in set(x.OPERATIONS)-{'verify','state'}:
            with self.assertRaisesRegex(ValueError, 'EXECUTE'): self.run_op(name, False)
        self.assertEqual(self.calls, [])

    def test_named_operations_only_no_combined_install_arm_start(self):
        expected = {'initialize': ['build', ('initialize-preflight', 20), 'lock', 'initialize'],
                    'policy-install': ['build', ('install', 20, True)],
                    'policy-rollback': ['build', ('rollback', 20, True)],
                    'arm': ['build', ('arm', 20, True)], 'hold': ['build', 'open', 'hold']}
        for name, calls in expected.items():
            self.calls.clear()
            self.assertEqual(self.run_op(name)[0], 0)
            self.assertEqual(self.calls, calls)

    def test_incomplete_install_is_error_without_auto_rollback(self):
        self.parts['transition'].install = lambda *a, **k: {'phase': 'HOLD', 'reason': 'UPDATE_UNCERTAIN'}
        self.assertEqual(self.run_op('policy-install')[0], 2)
        self.assertEqual(self.calls, ['build'])

    def test_expired_or_unknown_operation_never_builds(self):
        with self.assertRaises(ValueError): self.run_op('start')
        with self.assertRaises(ValueError):
            x.operate(self.module, self.bundle, 'initialize', 9, execute=True, clock=lambda: 10)
        self.assertEqual(self.calls, [])

    def test_serve_cannot_fall_through_to_operator_hold(self):
        with self.assertRaisesRegex(ValueError, 'SERVE_NEEDS_OWNER'): self.run_op('serve')
        self.assertEqual(self.calls, [])

    def test_serve_requires_fixed_launch_and_no_direct_bundle(self):
        common = ['serve', '--context', LABEL, '--timeout', '10', '--execute']
        with patch.object(x, 'runtime_guard'), patch.object(x, 'Launch') as launch:
            for extra in ([], ['--launch','/tmp/launch.json'],
                          ['--launch',x.LAUNCH_PATH,'--bundle',BUNDLE,'--sha256','a'*64]):
                with redirect_stdout(io.StringIO()): self.assertEqual(x.main(common+extra), 2)
            launch.assert_not_called()

    def test_control_commands_require_state_pin_and_only_stop_accepts_budget(self):
        for name, pin, seconds in [('reconcile',None,None),('graceful-stop','a'*64,None),
                                   ('hold','a'*64,None),('reconcile','a'*64,5)]:
            with self.assertRaises(ValueError):
                x.operate(self.module,self.bundle,name,20,execute=True,state_pin=pin,stop_seconds=seconds,
                          clock=lambda:10)
        self.assertEqual(self.calls,[])

    def test_read_state_and_reconcile_stop_routing(self):
        control=SimpleNamespace(inspect_state=lambda:{'state_sha256':'a'*64},
            reconcile=lambda *a,**kw: SimpleNamespace(desired='RUN',reason='EXPLICIT_HEALTHY_RECONCILIATION'),
            stop=lambda *a,**kw: SimpleNamespace(desired='HOLD',reason='STOP_INTERRUPTED_OR_UNKNOWN'))
        self.parts['control']=control
        self.assertEqual(self.run_op('state',False)[1]['stage'],'STATE_READ')
        result=x.operate(self.module,self.bundle,'reconcile',20,execute=True,state_pin='a'*64,clock=lambda:10)
        self.assertEqual(result[1]['prior_ack'],'NOT_INFERRED')
        result=x.operate(self.module,self.bundle,'graceful-stop',20,execute=True,state_pin='a'*64,
                         stop_seconds=10,clock=lambda:10)
        self.assertEqual(result[0],2)

    def test_cli_errors_do_not_print_sensitive_exception_or_attempt_repair(self):
        args = ['verify', '--bundle', BUNDLE, '--sha256', 'a'*64, '--context', LABEL, '--timeout', '10']
        output = io.StringIO()
        with patch.object(x, 'runtime_guard'), patch.object(x, 'collect', side_effect=ValueError('secret=password')):
            with redirect_stdout(output): rc = x.main(args)
        self.assertEqual(rc, 2)
        self.assertNotIn('password', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['records'], 'PRESERVED')

    def test_cli_timeout_execute_and_fixed_error_codes(self):
        args = ['initialize', '--bundle', BUNDLE, '--sha256', 'a'*64, '--context', LABEL, '--timeout', '10']
        with patch.object(x, 'runtime_guard'), patch.object(x, 'collect') as collect:
            output = io.StringIO()
            with redirect_stdout(output): self.assertEqual(x.main(args), 2)
            self.assertEqual(json.loads(output.getvalue())['reason'], 'BOOTSTRAP_EXECUTE_REQUIRED')
            collect.assert_not_called()
            args[0] = 'verify'; args[-1] = 'nan'
            with redirect_stdout(io.StringIO()): self.assertEqual(x.main(args), 2)
            collect.assert_not_called()

    def test_unsafe_process_stops_before_same_directory_stdlib_impostor(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'bootstrap.py'; path.write_bytes(SCRIPT.read_bytes())
            marker = Path(folder)/'executed'
            (Path(folder)/'argparse.py').write_text(f'open({str(marker)!r}, "w").write("bad")\n')
            result = subprocess.run([sys.executable, '-B', str(path), '--help'], cwd=folder,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'BOOTSTRAP_FLAGS_OR_PLATFORM', result.stdout)
            self.assertFalse(marker.exists())

    def test_initialize_verifies_original_target_before_any_state_file(self):
        plan, item = fixture()
        store = self.parts['store']
        def observe(end):
            self.calls.append('observe'); return item
        parts = dict(store=store, transition=SimpleNamespace(store=store, plan=plan,
                     backend=SimpleNamespace(observe=observe)))
        model_bundle.initialize_store(parts, 20, clock=lambda: 10)
        self.assertEqual(self.calls, ['observe', 'lock', 'initialize'])
        item.policies['core'] = {'Name': 'no', 'MaximumRetryCount': 0}
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'GUARD'):
            model_bundle.initialize_store(parts, 20, clock=lambda: 10)
        self.assertEqual(self.calls, ['observe'])


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.obj = dict(version=1, bundle=BUNDLE, sha256='a'*64, context=LABEL)
        self.raw = json.dumps(self.obj).encode()
        self.reader = SimpleNamespace(root_launch=lambda label, end: self.raw)

    def load(self): return x.Launch(LABEL, 20, reader=self.reader, clock=lambda: 10)

    def test_exact_protected_anchor_and_changed_bytes_rejected(self):
        launch = self.load(); launch.verify(20)
        self.assertEqual(launch.data, self.obj)
        self.raw += b'\n'
        with self.assertRaisesRegex(ValueError, 'CHANGED'): launch.verify(20)

    def test_invalid_schema_duplicate_and_self_reference(self):
        for key, value in [('version',True), ('bundle',x.LAUNCH_PATH), ('bundle','/tmp/../a.json'),
                           ('sha256','bad'), ('context','bad context'), ('extra',1)]:
            obj = dict(self.obj); obj[key] = value; self.raw = json.dumps(obj).encode()
            with self.assertRaises(ValueError): self.load()
        self.raw = b'{"version":1,"version":1}'
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'): self.load()

    def test_anchor_uses_fixed_root_mode_label_limit_without_self_hash(self):
        reader = x.SecureReader(clock=lambda: 10)
        with patch.object(reader, '_bytes', return_value=self.raw) as read:
            self.assertEqual(reader.root_launch(LABEL,20), self.raw)
            args = read.call_args.args
            self.assertEqual(args[0], x.LAUNCH_PATH)
            self.assertEqual((args[1]['mode'],args[1]['gid'],args[1]['selinux'],args[3]),
                             (0o400,0,LABEL,4096))

    def test_main_serve_validates_owner_before_loop_and_uses_anchor_pin(self):
        calls = []
        executor = SimpleNamespace(backend=SimpleNamespace(host_provider='base'))
        bundle = SimpleNamespace(data={'host_policy':'policy','manager':'manager'})
        module = SimpleNamespace(MODULES={n+'.py' for n in x.MODULES},
            load_bundle=lambda *args: bundle, build=lambda *args: {'executor':executor})
        service = SimpleNamespace(
            ActiveOwner=lambda *args: 'owner',
            RuntimeHost=lambda base,owner,verify: lambda end: calls.append('owner-verified'),
            shutdown_event=lambda: nullcontext('event'),
            run=lambda *args, **kw: calls.append('loop') or 0)
        launch = SimpleNamespace(data=self.obj, verify=lambda end: None)
        args = ['serve','--launch',x.LAUNCH_PATH,'--context',LABEL,'--timeout','10','--execute']
        with patch.object(x,'runtime_guard'), patch.object(x,'Launch',return_value=launch), \
             patch.object(x,'collect',return_value=({},'a'*40)) as collect, \
             patch.object(x,'VerifiedImporter',return_value=nullcontext()), \
             patch.object(x.importlib,'import_module',side_effect=[module,service]), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(x.main(args),0)
        self.assertEqual(calls,['owner-verified','loop'])
        self.assertEqual(collect.call_args.args[:3],(BUNDLE,'a'*64,LABEL))



@unittest.skipUnless(sys.platform == 'linux', 'Linux secure file descriptors and metadata')
class SecureReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home()); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'source.py'; self.raw = b'MARKER = 1\n'
        self.path.write_bytes(self.raw); self.path.chmod(0o600)
        self.expected = {'mode': 0o600, 'gid': 0, 'selinux': LABEL,
                         'sha256': hashlib.sha256(self.raw).hexdigest()}
        self.reader = x.SecureReader(clock=lambda: 10, uid=os.getuid(), gid=os.getgid())
        attrs = patch.object(x.os, 'listxattr', return_value=['security.selinux'])
        labels = patch.object(x.os, 'getxattr', return_value=LABEL.encode()+b'\0')
        attrs.start(); labels.start(); self.addCleanup(attrs.stop); self.addCleanup(labels.stop)

    def read(self): return self.reader.read(str(self.path), self.expected, 20, 1024)

    def test_exact_file_bytes_and_no_writes(self):
        before = self.path.stat()
        self.assertEqual(self.read(), self.raw)
        after = self.path.stat()
        self.assertEqual((before.st_size, before.st_mtime_ns, before.st_mode),
                         (after.st_size, after.st_mtime_ns, after.st_mode))

    def test_wrong_hash_mode_hardlink_symlink_and_fifo(self):
        self.expected['sha256'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'HASH'): self.read()
        self.expected['sha256'] = hashlib.sha256(self.raw).hexdigest()
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'FILE'): self.read()
        self.path.chmod(0o600)
        link = self.path.with_name('link'); link.hardlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'FILE'): self.read()
        link.unlink(); self.path.rename(link); self.path.symlink_to(link)
        with self.assertRaises(OSError): self.read()
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaisesRegex(ValueError, 'FILE'): self.read()

    def test_parent_acl_label_unknown_xattr_and_size_reject(self):
        with patch.object(x.os, 'listxattr', return_value=['system.posix_acl_access']):
            with self.assertRaisesRegex(ValueError, 'ACL'): self.read()
        with patch.object(x.os, 'listxattr', return_value=['security.selinux', 'user.extra']):
            with self.assertRaisesRegex(ValueError, 'XATTR'): self.read()
        with patch.object(x.os, 'getxattr', return_value=b'wrong'):
            with self.assertRaisesRegex(ValueError, 'LABEL'): self.read()
        with self.assertRaisesRegex(ValueError, 'FILE'):
            self.reader.read(str(self.path), self.expected, 20, 1)

    def test_mid_read_metadata_change_is_rejected(self):
        read = os.read
        def mutate(fd, count):
            block = read(fd, count)
            if block: os.utime(self.path, ns=(1, 1))
            return block
        with patch.object(x.os, 'read', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'FILE_CHANGED'): self.read()

    def test_root_guard_has_no_nonroot_or_unsafe_flags_fallback(self):
        with patch.object(x.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(ValueError, 'ROOT'): x.runtime_guard()
        with patch.object(x.os, 'geteuid', return_value=0), patch.object(x.os, 'getegid', return_value=0):
            # Test runner is not started with -I -S; it must not become an operator.
            with self.assertRaisesRegex(ValueError, 'FLAGS'): x.runtime_guard()


if __name__ == '__main__': unittest.main()
