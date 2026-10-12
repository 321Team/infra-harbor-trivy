"""Synthetic launch/host; Linux real fd paths and isolated Python, no systemd/Docker writes."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/production'),str(ROOT/'scripts/recovery')]
import harbor_address_launch as launch
import test_protected_runtime as runtime
BOOT=ROOT/'scripts/bootstrap/harbor_address_bootstrap.py'
module_spec=importlib.util.spec_from_file_location('address_bootstrap_test',BOOT)
boot=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(boot)

def fixture():
    pin=dict(sha256='a'*64,mode=0o600,gid=0,selinux='synthetic_t')
    return dict(schema='fds.harbor.address-launch.v1',source=dict(directory='/root/synthetic/source',revision='b'*40,
        files={n:dict(pin) for n in boot.MODULES}),interpreter=dict(path='/usr/bin/python3.12',spec=dict(pin,mode=0o755)),
        bootstrap=dict(path='/root/synthetic/bootstrap.py',spec=dict(pin)),
        session=dict(package_path='/root/synthetic/package',package_sha256='a'*64,package_context='synthetic_t',
            journal_path='/root/synthetic/journal',journal_context='synthetic_t',evidence_path='/root/synthetic/evidence',
            evidence_context='synthetic_t',private_path='/root/synthetic/private',private_context='synthetic_t'),
        budgets=dict(prepare_seconds=5,mutation_seconds=60,collection_seconds=10,termination_seconds=3),
        supervisor=dict(unit='fds-harbor-address-synthetic.service',context='synthetic_t'))

def arguments():
    return dict(launch_path='/root/synthetic/launch.json',launch_sha256='a'*64,launch_context='synthetic_t',
        deadline=36,bootstrap_path='/root/synthetic/bootstrap.py',interpreter_path='/usr/bin/python3.12',clock=lambda:32.)

class FakeReader:
    def __init__(self,value):
        self.value=value;self.calls=[];self.changed=False
        self.code={n:('VALUE='+repr(n)).encode() for n in boot.MODULES}
    def read(self,path,spec,deadline,limit):
        self.calls.append(path)
        if path.endswith('/launch.json'):return json.dumps(self.value if not self.changed else {}).encode()
        return self.code[Path(path).stem]

@contextmanager
def clean_imports():
    old={k:v for k,v in sys.modules.items() if k.startswith(boot.PREFIXES)}
    for k in old:del sys.modules[k]
    try:yield
    finally:
        for k in tuple(sys.modules):
            if k.startswith(boot.PREFIXES):del sys.modules[k]
        sys.modules.update(old)

class BootstrapTests(unittest.TestCase):
    def test_real_approved_module_set_imports_without_project_sys_path(self):
        code={}
        for name in boot.MODULES:
            source=ROOT/'scripts'/('recovery' if name.startswith('harbor_recovery_') else 'production')/(name+'.py')
            code[name]=compile(source.read_text(encoding='utf-8'),'/synthetic/verified/'+name+'.py','exec',dont_inherit=True)
        with clean_imports(),boot.VerifiedImporter(code):
            module=importlib.import_module('harbor_address_launch')
            self.assertEqual(module.validate(fixture())['schema'],'fds.harbor.address-launch.v1')
            self.assertTrue(all(sys.modules[n].__file__.startswith('/synthetic/verified/') for n in boot.MODULES))
    def test_collect_compiles_every_source_before_project_import(self):
        reader=FakeReader(fixture())
        values,code=boot.collect('/root/synthetic/launch.json','a'*64,'synthetic_t',100,reader=reader,clock=lambda:10)
        self.assertEqual(set(code),boot.MODULES);self.assertEqual(len(reader.calls),17)
        with clean_imports(),boot.VerifiedImporter(code):
            module=importlib.import_module('harbor_address_launch')
            self.assertEqual(module.VALUE,'harbor_address_launch')
            with self.assertRaises(boot.Stop):importlib.import_module('harbor_address_unlisted')
            with self.assertRaises(boot.Stop):importlib.reload(module)
    def test_last_source_syntax_failure_or_launch_drift_never_imports(self):
        reader=FakeReader(fixture());reader.code[sorted(boot.MODULES)[-1]]=b'BAD SYNTAX !'
        with self.assertRaises(SyntaxError):boot.collect('/root/synthetic/launch.json','a'*64,'synthetic_t',100,reader=reader,clock=lambda:10)
        reader=FakeReader(fixture());original=reader.read
        def changed(*args):
            if len(reader.calls)==16:reader.changed=True
            return original(*args)
        reader.read=changed
        with self.assertRaises(boot.Stop):boot.collect('/root/synthetic/launch.json','a'*64,'synthetic_t',100,reader=reader,clock=lambda:10)
    def test_preimported_namespace_cannot_be_reused(self):
        reader=FakeReader(fixture());_,code=boot.collect('/root/synthetic/launch.json','a'*64,'synthetic_t',100,reader=reader,clock=lambda:10)
        with self.assertRaises(boot.Stop):
            with boot.VerifiedImporter(code):pass
    def test_duplicate_nonfinite_and_unsafe_paths_rejected(self):
        for data in (b'{"k":1,"k":2}',b'{"x":NaN}',b'{"x":Infinity}'):
            with self.assertRaises(ValueError):boot.parse(data)
        for path in ('relative','/root/../etc/file','/root/a%X','/root/a$X','/root//file'):
            self.assertFalse(boot.absolute(path))

class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.value=fixture();self.args=arguments()
    def test_unit_is_bounded_no_restart_no_install_and_literal_pins(self):
        text=launch.unit_text(self.value,**{k:self.args[k] for k in ('launch_path','launch_sha256','launch_context')})
        for line in ('Type=exec','KillMode=control-group','RuntimeMaxSec=75','TimeoutStopSec=3','Restart=no',
                     'StandardInput=null','--timeout 5 --execute',' -I -S -B '):self.assertIn(line,text)
        for text_absent in ('[Install]','ExecStartPre','ExecStopPost','EnvironmentFile','Restart=always'):self.assertNotIn(text_absent,text)
    def test_no_defaults_or_escape_in_unit_and_launch(self):
        changes=[lambda v:v['budgets'].update(prepare_seconds=True),lambda v:v['budgets'].update(mutation_seconds=0),
            lambda v:v['session'].update(private_context=None),lambda v:v['session'].update(journal_path=v['session']['package_path']),
            lambda v:v['supervisor'].update(unit='fds-harbor-address-X%Y.service'),
            lambda v:v['bootstrap'].update(path='/root/evil\nExecStart=/bin/true'),
            lambda v:v['source']['files'].pop('harbor_address_launch')]
        for change in changes:
            value=deepcopy(self.value);change(value)
            with self.assertRaises((ValueError,TypeError)):launch.validate(value)
    def test_duration_parser_checks_numeric_runtime_not_human_format(self):
        self.assertEqual(launch.microseconds('1min 15s'),75000000)
        self.assertEqual(launch.microseconds('0'),0)
        self.assertEqual(launch.microseconds('100ms 1us'),100001)
        for value in ('infinity','nan','1.0000001s','1s1s','-1s','0.1us'):
            with self.assertRaises(ValueError):launch.microseconds(value)
    def test_verify_and_unit_never_construct_runtime(self):
        for operation in ('verify','unit'):
            with patch.object(launch,'ProtectedSession') as ctor,patch.object(launch,'ProductionReadOnly') as io:
                rc,result=launch.operate(self.value,operation=operation,execute=False,**self.args)
            self.assertEqual(rc,0);ctor.assert_not_called();io.assert_not_called()
    def test_runtime_input_sources_cannot_differ_from_package_pins(self):
        values=runtime.host_fixture()['package'];pins=values['host-policy.json']['pinned_files']
        for k in ('bootstrap','interpreter'):pins[self.value[k]['path']]=self.value[k]['spec']
        pins.update({self.value['source']['directory']+'/'+n+'.py':v for n,v in self.value['source']['files'].items()})
        args=dict(deadline=100,bootstrap_path=self.args['bootstrap_path'],interpreter_path=self.args['interpreter_path'],io=Mock())
        with patch.object(launch,'load_package',return_value=values):
            launch.runtime_inputs(self.value,**args)
            pins[self.value['source']['directory']+'/harbor_address_launch.py']=dict(pins[self.value['source']['directory']+'/harbor_address_launch.py'],sha256='f'*64)
            with self.assertRaisesRegex(ValueError,'PACKAGE_SOURCE'):launch.runtime_inputs(self.value,**args)

class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.value=fixture();self.args=arguments();outer=self
        unit=self.value['supervisor']['unit']
        self.row=dict(Id=unit,Type='exec',User='root',Group='root',ActiveState='active',SubState='running',
            MainPID=str(os.getpid()),InvocationID='c'*32,FragmentPath='/run/systemd/system/'+unit,DropInPaths='',
            NeedDaemonReload='no',ControlGroup='/system.slice/'+unit,Restart='no',KillMode='control-group',SendSIGKILL='yes',
            KillSignal='15',FinalKillSignal='9',RuntimeMaxUSec='1min 15s',RuntimeRandomizedExtraUSec='0',TimeoutStopUSec='3s',
            ExecMainStartTimestampMonotonic='30000000',WorkingDirectory='/',UMask='0077',EnvironmentFiles='')
        class IO:
            def pinned(self,*args):pass
            def command(self,*args):return 0,'\n'.join(k+'='+v for k,v in outer.row.items()).encode()
            def cgroup(self):return ['0::/system.slice/'+unit]
        self.io=IO()
        self.guard=launch.UnitGuard(self.value,**{k:self.args[k] for k in ('launch_path','launch_sha256','launch_context')},
            systemctl={},io=self.io,clock=lambda:32)
    def test_guard_deadlines_use_unit_start_not_restarted_python_clock(self):
        self.assertEqual(self.guard.verify(36),(35,95,105))
        self.row['InvocationID']='d'*32
        with self.assertRaisesRegex(ValueError,'GENERATION_CHANGED'):self.guard.verify(36)
    def test_mutation_rejected_for_unsupervised_wrong_budget_or_owner(self):
        for field,value in [('KillMode','process'),('Restart','always'),('MainPID','999999'),('RuntimeMaxUSec','infinity'),
            ('TimeoutStopUSec','5s'),('DropInPaths','/other'),('NeedDaemonReload','yes'),('Type','simple'),
            ('SendSIGKILL','no'),('ControlGroup','/user.slice'),('ExecMainStartTimestampMonotonic','99999999999')]:
            self.setUp();self.row[field]=value
            with self.assertRaises(ValueError):self.guard.verify(36)
        self.setUp();self.io.cgroup=lambda:['0::/other']
        with self.assertRaisesRegex(ValueError,'CGROUP'):self.guard.verify(36)
    def test_apply_gate_runs_before_session_and_uses_fixed_deadlines(self):
        values=runtime.host_fixture()['package']
        result=dict(sequence={'status':'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED'},collection={'complete':False},
                    evidence_sealed=True,reason='EVIDENCE_SEALED')
        obj=SimpleNamespace(sequence=SimpleNamespace(_backend=SimpleNamespace(host=lambda d:{})),run=Mock(return_value=result))
        with patch.object(launch,'runtime_inputs',return_value=values),patch.object(launch,'ProductionReadOnly',return_value=self.io),patch.object(launch,'ProtectedSession',return_value=obj) as ctor:
            rc,out=launch.operate(self.value,operation='apply',execute=True,**self.args)
            self.assertEqual(rc,0);self.assertFalse(out['runtime_acceptance'])
            self.assertEqual(ctor.call_args.kwargs['preparation_deadline'],35)
            obj.run.assert_called_once_with(mutation_deadline=95,collection_deadline=105)
        self.row['MainPID']='0'
        with patch.object(launch,'runtime_inputs',return_value=values),patch.object(launch,'ProductionReadOnly',return_value=self.io),patch.object(launch,'ProtectedSession') as ctor:
            with self.assertRaises(ValueError):launch.operate(self.value,operation='apply',execute=True,**self.args)
            ctor.assert_not_called()
    def test_preflight_only_renders_and_rechecks_without_claim_or_apply(self):
        values=runtime.host_fixture()['package']
        backend=SimpleNamespace(_prewrite=Mock())
        obj=SimpleNamespace(sequence=SimpleNamespace(_backend=backend),run=Mock())
        process=SimpleNamespace(call=Mock(return_value=0),receipts=[{'rc':0,'stdout_sha256':'a'*64}])
        with patch.object(launch,'runtime_inputs',return_value=values),patch.object(launch,'ProtectedSession',return_value=obj),patch.object(launch,'PinnedCompose',return_value=process),patch.object(launch,'UnitGuard') as guard:
            rc,out=launch.operate(self.value,operation='preflight',execute=False,**self.args)
        self.assertEqual(out['runtime'],'READ_ONLY');self.assertEqual(backend._prewrite.call_count,2)
        obj.run.assert_not_called();guard.assert_not_called();self.assertEqual(process.call.call_args.args[0],'render')

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Linux root fd/isolated Python only')
class LinuxBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='address-entry-test-',dir='/root'))
    def tearDown(self):
        assert self.base.parent==Path('/root') and self.base.name.startswith('address-entry-test-')
        shutil.rmtree(self.base)
    @contextmanager
    def synthetic_selinux(self):
        original=os.listxattr
        with patch.object(boot.os,'listxattr',side_effect=lambda fd:list(set(original(fd))|{'security.selinux'})),patch.object(boot.os,'getxattr',return_value=b'synthetic_t\0'):
            yield
    def test_real_fd_path_hash_mode_link_and_acl_checks(self):
        path=self.base/'source';path.write_bytes(b'APPROVED');path.chmod(0o600)
        pin=dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),mode=0o600,gid=0,selinux='synthetic_t')
        reader=boot.Reader()
        with self.synthetic_selinux():
            self.assertEqual(reader.read(str(path),pin,time.monotonic()+5,100),b'APPROVED')
            path.write_bytes(b'CHANGED')
            with self.assertRaises(boot.Stop):reader.read(str(path),pin,time.monotonic()+5,100)
            path.write_bytes(b'APPROVED');os.link(path,self.base/'hardlink')
            with self.assertRaises(boot.Stop):reader.read(str(path),pin,time.monotonic()+5,100)
            (self.base/'hardlink').unlink();path.chmod(0o644)
            with self.assertRaises(boot.Stop):reader.read(str(path),pin,time.monotonic()+5,100)
            path.chmod(0o600);os.setxattr(path,'user.synthetic',b'unknown')
            with self.assertRaises(boot.Stop):reader.read(str(path),pin,time.monotonic()+5,100)
    def test_symlink_or_parent_replacement_is_not_executed(self):
        real=self.base/'real';real.write_bytes(b'APPROVED');real.chmod(0o600)
        path=self.base/'link';path.symlink_to(real)
        pin=dict(sha256=hashlib.sha256(real.read_bytes()).hexdigest(),mode=0o600,gid=0,selinux='synthetic_t')
        with self.synthetic_selinux(),self.assertRaises(OSError):boot.Reader().read(str(path),pin,time.monotonic()+5,100)
    def test_isolation_gate_and_invalid_launch_have_fixed_output_no_traceback(self):
        unsafe=subprocess.run([sys.executable,str(BOOT),'verify'],capture_output=True,timeout=5)
        self.assertEqual(unsafe.returncode,2);self.assertIn(b'BOOTSTRAP_FLAGS_OR_PLATFORM',unsafe.stdout)
        safe=subprocess.run([sys.executable,'-I','-S','-B',str(BOOT),'verify','--launch','/missing',
            '--sha256','a'*64,'--context','synthetic_t','--timeout','1'],capture_output=True,timeout=5)
        self.assertEqual(safe.returncode,2);self.assertEqual(safe.stderr,b'')
        self.assertEqual(json.loads(safe.stdout)['reason'],'INPUT_OR_RUNTIME_FAILURE')
    def test_generated_unit_parses_with_systemd_without_install_or_start(self):
        executable=shutil.which('systemd-analyze')
        self.assertIsNotNone(executable,'Linux CI must include the unit parser')
        value=fixture();value['interpreter']['path']=str(Path(sys.executable).resolve())
        value['bootstrap']['path']=str(BOOT)
        path=self.base/value['supervisor']['unit']
        path.write_text(launch.unit_text(value,launch_path='/root/synthetic/launch.json',launch_sha256='a'*64,launch_context='synthetic_t'))
        result=subprocess.run([executable,'verify','--man=no',str(path)],capture_output=True,timeout=10,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','SYSTEMD_LOG_LEVEL':'err'})
        self.assertEqual(result.returncode,0,result.stderr.decode())

if __name__=='__main__':unittest.main()
