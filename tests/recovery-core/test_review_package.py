"""Offline synthetic inputs; produced files are not field evidence."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import tempfile
import unittest

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
        return x.prepare(raw,x.sha(raw),self.sources,self.boot)

    def test_complete_pack_is_integrity_only_and_not_installation(self):
        files,plan=self.prepare()
        self.assertEqual(len(files),len(MODULES)+5)
        self.assertFalse(plan['runtime_go']); self.assertFalse(plan['automatic_deletion'])
        for item in plan['files']: self.assertEqual(x.sha(files[item['file']]),item['sha256'])
        self.assertNotIn('--sha256',files['manager.service'].decode())
        self.assertTrue(plan['external_existing_inputs'])

    def test_input_source_unit_and_binding_changes_block_pack(self):
        raw=x.encoded(dict(version=1,bundle=self.obj,runtime=self.runtime))
        with self.assertRaises(ValueError):x.prepare(raw,'f'*64,self.sources,self.boot)
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


if __name__=='__main__':unittest.main()
