"""Synthetic Engine shapes; Linux fd tests use private temporary paths only."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path[:0]=[str(Path(__file__).resolve().parents[2]/'scripts/production'),
              str(Path(__file__).resolve().parents[2]/'scripts/recovery')]
import harbor_address_compose as c
import harbor_address_inspect as i
import harbor_address_session as session
import test_compose_backend as cb
import test_protected_runtime as rt


def binding_fixture():
    f=cb.fixture()
    bindings={s:['/synthetic/data:/data:rw,z'] for s in c.SERVICES}
    for version in ('base','candidate'):
        for row in f[version]['services'].values():
            row['volumes'][0]['bind']['selinux']='z'
    model=c.execution_model(f['base'],f['candidate'],resource_names=f['names'],legacy_bindings=bindings)
    return f,bindings,model


def fake_chain(path):
    return [dict(device=1,inode=n+1,uid=0,gid=0,mode=0o755,directory=True,selinux='synthetic_t')
            for n in range(len(Path(path).parts))]


class ModelContractTests(unittest.TestCase):
    def test_legacy_config_omits_true_only_and_false_or_changed_z_refused(self):
        _,b,model=binding_fixture()
        rendered=c.expected_process_render(model,legacy_bindings=b)
        self.assertNotIn('create_host_path',rendered['services']['core']['volumes'][0]['bind'])
        c.validate_process_render(model,rendered,legacy_bindings=b)
        for change in ({'create_host_path':False},{'selinux':'Z'},{'other':False}):
            wrong=deepcopy(rendered);wrong['services']['core']['volumes'][0]['bind'].update(change)
            with self.assertRaisesRegex(ValueError,'ROUNDTRIP_CHANGED'):c.validate_process_render(model,wrong,legacy_bindings=b)
    def test_legacy_keeps_z_source_destination_and_readwrite(self):
        f,b,model=binding_fixture()
        for row in model['services'].values():
            self.assertEqual(row['volumes'],[dict(type='bind',source='/synthetic/data',target='/data',
                                                 bind=dict(selinux='z',create_host_path=True))])
        self.assertFalse(f['candidate']['services']['core']['volumes'][0]['bind']['create_host_path'])
        c.validate_execution_model(model,legacy_bindings=b)
        with self.assertRaisesRegex(ValueError,'BIND_CREATION_FORBIDDEN'): c.validate_execution_model(model)
    def test_source_target_access_label_extra_option_changes_refused(self):
        for kind in ('source','target','mode','label','option','extra','duplicate'):
            f,b,model=binding_fixture()
            if kind=='source':b['core']=['/other:/data:rw,z']
            elif kind=='target':b['core']=['/synthetic/data:/other:rw,z']
            elif kind=='mode':b['core']=['/synthetic/data:/data:ro,z']
            elif kind=='label':b['core']=['/synthetic/data:/data:rw,Z']
            elif kind=='option':model['services']['core']['volumes'][0]['bind']['propagation']='rshared'
            elif kind=='extra':b['core'].append('/other:/other:rw')
            else:b['core']*=2
            with self.assertRaises(ValueError): c.validate_execution_model(model,legacy_bindings=b)
    def test_true_not_granted_in_base_candidate(self):
        f,b,_=binding_fixture()
        for version in ('base','candidate'):
            f[version]['services']['core']['volumes'][0]['bind']['create_host_path']=True
        with self.assertRaisesRegex(ValueError,'BIND_CREATION_FORBIDDEN'):
            c.execution_model(f['base'],f['candidate'],resource_names=f['names'],legacy_bindings=b)
    def test_missing_source_pin_and_bad_metadata_refused(self):
        _,b,_=binding_fixture();specs={'/synthetic/data':fake_chain('/synthetic/data')}
        c.validate_bind_sources(b,specs)
        for kind in ('empty','mode','label','chain','type'):
            changed=deepcopy(specs)
            if kind=='empty':changed={}
            elif kind=='mode':changed['/synthetic/data'][-1]['mode']=0o777
            elif kind=='label':changed['/synthetic/data'][-1]['selinux']=None
            elif kind=='chain':changed['/synthetic/data'].pop()
            else:changed['/synthetic/data'][-1]['inode']=True
            with self.assertRaises(ValueError):c.validate_bind_sources(b,changed)
    def test_unbound_old_session_stops_before_assemble(self):
        values={'host-policy.json':{'schema':'fds.harbor.production-address-host.v1'},
                'preservation.json':{'baseline':cb.fixture()['before']}}
        values['preservation.json']['baseline']['core']['HostConfig']['Binds']=['/old:/data:rw,z']
        with self.assertRaisesRegex(ValueError,'LEGACY_BIND_POLICY_REQUIRED'):session.legacy_bindings(values)
    def test_session_v2_binds_exact_existing_source_pins(self):
        f,b,_=binding_fixture()
        for s in c.SERVICES:f['before'][s]['HostConfig']['Binds']=b[s]
        values={'host-policy.json':{'schema':'fds.harbor.production-address-host.v2',
                 'bind_sources':{'/synthetic/data':fake_chain('/synthetic/data')}},'preservation.json':{'baseline':f['before']}}
        self.assertEqual(session.legacy_bindings(values),b)
        values['preservation.json']['baseline']['core']['HostConfig']['Mounts']=[{'Target':'/other'}]
        with self.assertRaisesRegex(ValueError,'LEGACY_HOST_MOUNTS'):session.legacy_bindings(values)
    def test_complete_v2_assemble_binds_model_policy_and_preservation(self):
        data=rt.host_fixture();values=data['package'];bindings={s:['/synthetic/data:/data:rw'] for s in c.SERVICES}
        for s, row in values['preservation.json']['baseline'].items():row['HostConfig']['Binds']=bindings[s]
        policy=values['host-policy.json'];policy.update(schema='fds.harbor.production-address-host.v2',
            bind_sources={'/synthetic/data':fake_chain('/synthetic/data')})
        values['model.json']=c.execution_model(values['base.json'],values['candidate.json'],resource_names=data['f']['names'],legacy_bindings=bindings)
        projection=values['preservation.json']
        full=i.FullPreservation(projection['baseline'],after_labels=projection['after_labels'],
            after_host_mounts=projection['after_host_mounts'],auto_hostnames=projection['auto_hostnames'],auto_addresses=projection['auto_addresses'])
        values['plan.json'].update(binding_sha256=c.fingerprint(policy),baseline={s:full.row(s,row,recreated=False,mounts_verified=row['Mounts']) for s,row in projection['baseline'].items()})
        values['profile.json']['host_binding_sha256']=c.fingerprint(policy)
        session.assemble(values)
        values['model.json']['services']['core']['volumes'][0]['bind']['create_host_path']=False
        with self.assertRaisesRegex(ValueError,'MODEL_BINDING'):session.assemble(values)


class InspectContractTests(unittest.TestCase):
    def test_engine_omitempty_false_is_explicit_expected_shape(self):
        f=cb.fixture();target=f['inherited']['portal']
        for row in target:del row['ReadOnly']
        full=i.FullPreservation(f['before'],after_labels=f['target_labels'],after_host_mounts=f['inherited'],
             auto_hostnames=list(c.ORDER),auto_addresses=list(c.ORDER))
        actual=cb.recreated(f,'portal');actual['HostConfig']['Mounts'].reverse()
        full.row('portal',actual,recreated=True,mounts_verified=f['ma']['after']['portal'])
        actual['HostConfig']['Mounts'][0]['ReadOnly']=True
        with self.assertRaisesRegex(ValueError,'PRESERVATION_CHANGED'):
            full.row('portal',actual,recreated=True,mounts_verified=f['ma']['after']['portal'])
    def test_readonly_omission_cannot_match_a_readonly_source(self):
        f=cb.fixture();mounts=f['before']['registryctl']['Mounts'];mounts[0]['RW']=False
        target=f['inherited']['registryctl'];del target[0]['ReadOnly']
        with self.assertRaisesRegex(ValueError,'INHERITED_IDENTITY'):i.validate_inherited([],target,mounts)
    def test_false_type_and_volume_unknown_options_never_ignored(self):
        for change in ({'ReadOnly':0},{'ReadOnly':None},{'VolumeOptions':{'NoCopy':0}},
                       {'VolumeOptions':{'NoCopy':True}},{'VolumeOptions':{'Labels':{}}},{'Unknown':False}):
            f=cb.fixture();target=f['inherited']['portal'];target[0].update(change)
            with self.assertRaisesRegex(ValueError,'INHERITED_OPTIONS'):
                i.validate_inherited([],target,f['before']['portal']['Mounts'])
    def test_order_only_does_not_change_existing_options_or_targets(self):
        f=cb.fixture();f['before']['portal']['HostConfig']['Binds']=['/one:/one:rw,z','/two:/two:ro']
        full=i.FullPreservation(f['before'],after_labels=f['target_labels'],after_host_mounts=f['inherited'],
             auto_hostnames=list(c.ORDER),auto_addresses=list(c.ORDER))
        actual=cb.recreated(f,'portal');actual['HostConfig']['Binds'].reverse();actual['HostConfig']['Mounts'].reverse()
        full.row('portal',actual,recreated=True,mounts_verified=f['ma']['after']['portal'])
        actual['HostConfig']['Binds'][0]='/two:/two:rw'
        with self.assertRaisesRegex(ValueError,'PRESERVATION_CHANGED'):
            full.row('portal',actual,recreated=True,mounts_verified=f['ma']['after']['portal'])
    def test_duplicate_mount_target_rejected_even_across_bind_and_mount(self):
        for value in ({'Binds':['/a:/a:rw','/b:/a:rw']},
                      {'Mounts':[{'Target':'/a'},{'Target':'/a'}]},
                      {'Binds':['/a:/a:rw'],'Mounts':[{'Target':'/a'}]}):
            with self.assertRaises(ValueError):i.host_config(value)
    def test_preexisting_host_mount_cannot_be_changed_or_dropped(self):
        f=cb.fixture();old=[dict(Type='bind',Source='/old',Target='/old',ReadOnly=True)]
        after=f['inherited']['portal']+deepcopy(old)
        i.validate_inherited(old,after,f['before']['portal']['Mounts'])
        after[-1]['Source']='/changed'
        with self.assertRaisesRegex(ValueError,'HOST_MOUNTS_CHANGED'):i.validate_inherited(old,after,f['before']['portal']['Mounts'])

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Linux root fd checks')
class BindSourceFdTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/root');self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'data';self.path.mkdir(mode=0o755)
        self.deadline=lambda:time.monotonic()+5
    def test_stable_then_missing_replaced_symlink_or_permission_change(self):
        expected=c.bind_source_metadata(str(self.path),deadline=self.deadline())
        c.check_bind_sources({str(self.path):expected},deadline=self.deadline())
        self.path.chmod(0o700)
        with self.assertRaisesRegex(ValueError,'BIND_SOURCE_CHANGED'):
            c.check_bind_sources({str(self.path):expected},deadline=self.deadline())
        self.path.rmdir()
        with self.assertRaises(OSError):c.check_bind_sources({str(self.path):expected},deadline=self.deadline())
        self.path.symlink_to('/root',target_is_directory=True)
        with self.assertRaises(OSError):c.check_bind_sources({str(self.path):expected},deadline=self.deadline())
    def test_regular_file_is_metadata_only_and_content_writes_not_claimed_as_integrity(self):
        file=self.path/'file';file.write_bytes(b'PRIVATE');file.chmod(0o640)
        before=c.bind_source_metadata(str(file),deadline=self.deadline())
        file.write_bytes(b'NORMAL_APP_WRITE')
        self.assertEqual(c.bind_source_metadata(str(file),deadline=self.deadline()),before)
        os.chown(file,10000,10000)
        with self.assertRaises(ValueError):c.check_bind_sources({str(file):before},deadline=self.deadline())
    def test_acl_hardlink_and_world_writable_parent_refused(self):
        file=self.path/'file';file.write_bytes(b'PRIVATE')
        os.link(file,self.path/'second')
        with self.assertRaisesRegex(ValueError,'SOURCE_METADATA'):c.bind_source_metadata(str(file),deadline=self.deadline())
        (self.path/'second').unlink();os.setxattr(file,'user.extra',b'no')
        with self.assertRaisesRegex(ValueError,'SOURCE_METADATA'):c.bind_source_metadata(str(file),deadline=self.deadline())
        os.removexattr(file,'user.extra');self.path.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'SOURCE_METADATA'):c.bind_source_metadata(str(file),deadline=self.deadline())

    def test_pinned_consumer_requires_paths_before_process_and_after_result(self):
        helper=rt.LinuxProtectedTests();helper.setUp();self.addCleanup(helper.tearDown)
        _,bindings,model=binding_fixture();process=helper.pinned()
        specs={'/synthetic/data':fake_chain('/synthetic/data')}
        process.legacy_bindings=deepcopy(bindings);process.bind_sources=deepcopy(specs)
        with patch.object(c,'check_bind_sources',side_effect=ValueError('BIND_SOURCE_CHANGED')) as guard,patch.object(c,'run_process') as run:
            with self.assertRaisesRegex(ValueError,'BIND_SOURCE_CHANGED'):
                process.call('recreate',model,service='postgresql',deadline=helper.deadline())
            run.assert_not_called();self.assertEqual(guard.call_count,1)
        with patch.object(c,'check_bind_sources',side_effect=[None,ValueError('BIND_SOURCE_CHANGED')]) as guard,\
             patch.object(c,'run_process',return_value=c.PrivateResult(0,'COMPLETED',b'',b'')) as run:
            with self.assertRaisesRegex(ValueError,'BIND_SOURCE_CHANGED'):
                process.call('recreate',model,service='postgresql',deadline=helper.deadline())
            self.assertEqual(run.call_count,1);self.assertEqual(guard.call_count,2)
            self.assertEqual(process._private_results[-1].rc,0)


if __name__=='__main__':unittest.main()
