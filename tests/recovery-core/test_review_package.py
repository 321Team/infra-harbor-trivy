"""Offline synthetic inputs; produced files are not field evidence."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_approved_bundle import candidate
from test_host_provider import LABEL
from harbor_recovery_bundle import MODULES,bound_host_digest
from harbor_recovery_docker import UnixEngine,execution_binding
from harbor_recovery_service import unit_text

ROOT=Path(__file__).resolve().parents[2]
loader=importlib.util.spec_from_file_location('package_subject',ROOT/'scripts/preparation/harbor_review_package.py')
x=importlib.util.module_from_spec(loader); loader.loader.exec_module(x)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.obj=candidate()
        self.sources={name:(ROOT/'scripts/recovery'/name).read_bytes() for name in MODULES}
        self.boot=(ROOT/'scripts/bootstrap/harbor_recovery_bootstrap.py').read_bytes()
        self.runtime=dict(python='/usr/bin/python3',bootstrap_context=LABEL,bundle_context=LABEL,
            launch_context=LABEL,bundle_path='/etc/fds-harbor-recovery/bundles/candidate.json',
            startup_seconds=30,shutdown_seconds=90)
        for name,raw in self.sources.items():
            self.obj['source']['files'][name]=x.sha(raw)
            self.obj['host_policy']['files'][self.obj['source']['directory']+'/'+name]['sha256']=x.sha(raw)
        self.rebind()

    def rebind(self):
        unit=unit_text(self.runtime['python'],'/opt/fds-harbor-recovery/bootstrap/'+x.sha(self.boot)+
             '/harbor_recovery_bootstrap.py',LABEL,startup_seconds=self.runtime['startup_seconds'],
             shutdown_seconds=self.runtime['shutdown_seconds']).encode()
        p=self.obj['host_policy']; p['files'][self.obj['manager']['fragment']]['sha256']=x.sha(unit)
        self.obj['plan']['execution_binding']=execution_binding(bound_host_digest(self.obj),'harbor',
                                                               UnixEngine(p['api_version'],socket_path=p['socket']).binding)

    def prepare(self):
        raw=x.encoded(dict(version=1,bundle=self.obj,runtime=self.runtime))
        return x.prepare(raw,x.sha(raw),self.sources,self.boot,source_revision='a'*40)

    def test_complete_pack_is_integrity_only_and_not_installation(self):
        files,plan=self.prepare()
        self.assertEqual(len(files),len(MODULES)+5)
        self.assertFalse(plan['runtime_go']); self.assertFalse(plan['automatic_deletion'])
        for item in plan['files']: self.assertEqual(x.sha(files[item['file']]),item['sha256'])
        self.assertNotIn('--sha256',files['manager.service'].decode())
        self.assertTrue(plan['external_existing_inputs'])
        self.assertEqual(plan['store'], self.obj['store'])
        self.assertIn('writer_context', plan['store'])

    def test_input_source_unit_and_binding_changes_block_pack(self):
        raw=x.encoded(dict(version=1,bundle=self.obj,runtime=self.runtime))
        with self.assertRaises(ValueError):x.prepare(raw,'f'*64,self.sources,self.boot,source_revision='a'*40)
        with self.assertRaisesRegex(ValueError,'SOURCE_REVISION'):
            x.prepare(raw,x.sha(raw),self.sources,self.boot,source_revision='b'*40)
        name=next(iter(self.sources)); old=self.sources[name]; self.sources[name]+=b'\n'
        with self.assertRaisesRegex(ValueError,'SOURCE_HASH'):self.prepare()
        self.sources[name]=old; self.runtime['startup_seconds']=31
        with self.assertRaisesRegex(ValueError,'UNIT_HASH'):self.prepare()
        self.rebind(); self.obj['plan']['execution_binding']='f'*64
        with self.assertRaisesRegex(ValueError,'EXECUTION_BINDING'):self.prepare()

    def test_incomplete_input_or_short_shutdown_budget_rejected(self):
        old=self.runtime.pop('launch_context')
        with self.assertRaises(ValueError):self.prepare()
        self.runtime['launch_context']=old; self.runtime['shutdown_seconds']=10; self.rebind()
        with self.assertRaisesRegex(ValueError,'SHUTDOWN_BUDGET'):self.prepare()

    def test_new_output_only_and_existing_files_never_changed(self):
        files,_=self.prepare()
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'package'; x.write_package(target,files)
            with self.assertRaises(FileExistsError):x.write_package(target,files)
            self.assertEqual((target/'bundle.json').read_bytes(),files['bundle.json'])

    def test_scope_rejects_external_bundle_destination_and_manager_dropin(self):
        self.runtime['bundle_path']='/root/raw-evidence.json'
        with self.assertRaisesRegex(ValueError,'BUNDLE_PATH'):self.prepare()
        self.runtime['bundle_path']='/etc/fds-harbor-recovery/bundles/candidate.json'
        self.obj['manager']['fragment']='/usr/lib/systemd/system/fds-harbor-recovery.service'
        with self.assertRaises(ValueError):self.prepare()


    def test_source_provenance_reads_one_actual_local_git_commit(self):
        with patch.object(Path,'read_bytes',side_effect=AssertionError('working tree read')):
            revision,sources,bootstrap=x.committed_sources()
        self.assertRegex(revision,r'^[0-9a-f]{40}$')
        self.assertEqual(set(sources),MODULES)
        for name,raw in sources.items():compile(raw,name,'exec')
        compile(bootstrap,'bootstrap.py','exec')

    def test_validator_requires_same_revision_and_clean_checkout(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            def git(*args):
                return x.subprocess.run(['git','-C',folder,*args],check=True,capture_output=True).stdout
            git('init');(root/'validator.py').write_text('pass\n')
            git('add','validator.py')
            git('-c','user.name=Package Test','-c','user.email=test@example.invalid',
                'commit','-m','test fixture')
            revision=git('rev-parse','HEAD').decode().strip()
            with patch.object(x,'ROOT',root):
                x.verify_checkout(revision)
                with self.assertRaisesRegex(ValueError,'VALIDATOR_REVISION'):x.verify_checkout('0'*40)
                (root/'extra.py').write_text('pass\n')
                with self.assertRaisesRegex(ValueError,'VALIDATOR_DIRTY'):x.verify_checkout(revision)
                git('add','extra.py')
                with self.assertRaisesRegex(ValueError,'VALIDATOR_DIRTY'):x.verify_checkout(revision)

    def test_checkout_drift_after_validation_does_not_write_package(self):
        with patch.object(x,'committed_sources',return_value=('a'*40,{},b'')), \
             patch.object(x,'verify_checkout',side_effect=[None,ValueError('PACKAGE_VALIDATOR_DIRTY')]), \
             patch.object(Path,'read_bytes',return_value=b'{}'), \
             patch.object(x,'prepare',return_value=({},{})), \
             patch.object(x,'write_package') as write,patch('builtins.print'):
            self.assertEqual(x.main(['--input','input.json','--input-sha256','0'*64,'--output','out']),2)
            write.assert_not_called()


if __name__=='__main__':unittest.main()
