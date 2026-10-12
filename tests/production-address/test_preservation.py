"""SYNTHETIC profile; no real authorization/request, contents or Docker I/O."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('preservation',Path(__file__).resolve().parents[2]/'scripts/production/harbor_address_preservation.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    profile=dict(schema='fds.harbor.production-volume-mode.v1',host_binding_sha256='a'*64,authorization_sha256='b'*64,
        engine=deepcopy(m.ENGINE),compose_version='5.6.0',security_options=list(m.SECURITY),baseline_mounts={},source_metadata={},volume_inventory={})
    n=0
    for service,targets in m.TARGETS.items():
        profile['baseline_mounts'][service]=[]
        for target in sorted(targets):
            n+=1;name=f'{n:064x}';path='/var/lib/docker/volumes/'+name+'/_data'
            mount=dict(Type='volume',Name=name,Source=path,Destination=target,Driver='local',Mode='',RW=True,Propagation='')
            profile['baseline_mounts'][service].append(mount)
            profile['source_metadata'][path]=dict(uid=0,gid=0,mode=0o755,directory=True,symlink=False,xattrs=['security.selinux'],selinux=m.CONTEXT)
            profile['volume_inventory'][name]=dict(name=name,driver='local',mountpoint=path,scope='local',has_options=False)
    names=['postgresql','redis','registry','registryctl','core','portal','jobservice','trivy-adapter','proxy','log']
    before={s:deepcopy(profile['baseline_mounts'].get(s,[])) for s in names}
    before['log']=[dict(Type='volume',Name='f'*64,Source='/synthetic/logger',Destination='/run',Driver='local',Mode='',RW=True,Propagation='')]
    after=deepcopy(before)
    for service in m.TARGETS:
        for mount in after[service]:mount['Mode']='z'
    return profile,dict(before=before,after=after,completed_services=list(m.TARGETS),current_metadata=deepcopy(profile['source_metadata']),
        host_binding_sha256='a'*64,authorization_sha256='b'*64,engine=deepcopy(m.ENGINE),compose_version='5.6.0',security_options=list(m.SECURITY),
        enforcing='Enforcing',labels={s:dict(MountLabel='',ProcessLabel='') for s in names},current_inventory=deepcopy(profile['volume_inventory']))


class PreservationTests(unittest.TestCase):
    def setUp(self):self.p,self.args=fixture();self.validator=m.MountPreservation(self.p)
    def check(self):return self.validator.check(**self.args)

    def test_only_exact_seven_mode_changes_match_not_content_or_acceptance(self):
        r=self.check();self.assertEqual(r['content_integrity'],'NOT_TESTED');self.assertFalse(r['runtime_acceptance'])

    def test_unperformed_services_remain_exact(self):
        self.args['completed_services']=['registryctl']
        self.args['after']['portal']=deepcopy(self.args['before']['portal'])
        self.args['after']['proxy']=deepcopy(self.args['before']['proxy'])
        self.check()
        self.args['after']['portal'][0]['Mode']='z'
        with self.assertRaisesRegex(ValueError,'OUTSIDE_PROFILE'):self.check()

    def test_no_implicit_blank_mode_or_capital_Z_acceptance(self):
        for mode in ['', 'Z','rw,z']:
            self.args['after']['registryctl'][0]['Mode']=mode
            with self.assertRaisesRegex(ValueError,'OUTSIDE_PROFILE'):self.check()

    def test_name_source_driver_rw_propagation_destination_extra_fields_refused(self):
        for field,value in [('Name','e'*64),('Source','/elsewhere'),('Driver','nfs'),('RW',False),('Propagation','rshared'),('Destination','/elsewhere'),('unknown','value')]:
            self.setUp();self.args['after']['portal'][0][field]=value
            with self.assertRaises(ValueError):self.check()

    def test_extra_or_duplicate_volume_refused(self):
        self.args['after']['portal'].append(deepcopy(self.args['after']['portal'][0]))
        with self.assertRaisesRegex(ValueError,'DUPLICATE'):self.check()

    def test_logger_never_in_profile_or_recreated_scope(self):
        self.args['after']['log'][0]['Mode']='z'
        with self.assertRaisesRegex(ValueError,'OUTSIDE_PROFILE'):self.check()
        self.setUp();self.args['completed_services'].append('log')
        with self.assertRaisesRegex(ValueError,'SCOPE'):self.check()

    def test_source_owner_permissions_context_acl_and_symlink_drift_refused(self):
        for key,value in [('uid',1),('gid',1),('mode',0o777),('selinux','wrong'),('xattrs',['system.posix_acl_access']),('symlink',True)]:
            self.setUp();next(iter(self.args['current_metadata'].values()))[key]=value
            with self.assertRaisesRegex(ValueError,'SOURCE_METADATA_CHANGED'):self.check()

    def test_volume_driver_options_change_refused(self):
        next(iter(self.args['current_inventory'].values()))['has_options']=True
        with self.assertRaisesRegex(ValueError,'INVENTORY_CHANGED'):self.check()

    def test_host_authorization_engine_compose_security_label_drift_refused(self):
        for key,value in [('host_binding_sha256','c'*64),('authorization_sha256','c'*64),('engine',{}),('compose_version','5.5.1'),('security_options',[]),('enforcing','Permissive')]:
            self.setUp();self.args[key]=value
            with self.assertRaises(ValueError):self.check()
        self.setUp();self.args['labels']['core']['ProcessLabel']='new'
        with self.assertRaisesRegex(ValueError,'LABEL_CHANGED'):self.check()

    def test_baseline_cannot_be_rewritten_to_bless_new_volume(self):
        self.args['before']['portal'][0]['Name']='e'*64
        with self.assertRaisesRegex(ValueError,'BASELINE_CHANGED'):self.check()

    def test_no_automatic_clone_profile_enrollment(self):
        for key,value in [('schema','clone-A2R1'),('authorization_sha256',''),('engine',{'Version':'29.8.0'}),('compose_version','5.5.1')]:
            p=deepcopy(self.p);p[key]=value
            with self.assertRaises(ValueError):m.MountPreservation(p)

    def test_profile_is_private_copy_and_exact_target_count(self):
        self.p['baseline_mounts'].clear();self.check()
        p,_=fixture();p['baseline_mounts']['registryctl'].clear()
        with self.assertRaises(ValueError):m.MountPreservation(p)


if __name__=='__main__':unittest.main()
