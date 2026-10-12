"""Synthetic host/Engine; Linux root temporary storage. No real Docker/guest."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/production'),str(ROOT/'scripts/recovery')]
import harbor_address_compose as c
import harbor_address_evidence as e
import harbor_address_package as p
import harbor_address_host as h
import harbor_address_sequence as seq
import harbor_address_session as session
import test_compose_backend as cb


def host_fixture():
    f=cb.fixture()
    tools={n:dict(path='/synthetic/bin/'+n,mode=0o755,selinux='synthetic_t',sha256='a'*64) for n in h.TOOLS}
    units={}
    for name in ('docker.service',h.GUARD):
        row=dict.fromkeys(h.PROPERTIES.split(','),'')
        row.update(LoadState='loaded',ActiveState='active',SubState='running' if name=='docker.service' else 'exited',
                   InvocationID='a'*32,Requires=h.GUARD if name=='docker.service' else '',
                   After=h.GUARD if name=='docker.service' else '',FragmentPath='/synthetic/'+name,
                   NeedDaemonReload='no')
        units[name]=row
    version={k:'synthetic' for k in h.engine_profile.__globals__['PROFILE_VERSION']}
    version.update(f['profile']['engine'])
    info={k:'synthetic' for k in h.engine_profile.__globals__['PROFILE_INFO']}
    info['SecurityOptions']=f['profile']['security_options']
    nft={'nftables':[{'table':{'family':'inet','name':'p1_hbr_ac04'}},
                    {'rule':{'expr':[{'counter':{'packets':1,'bytes':2}}]}}]}
    addresses={n:[{'ifname':n,'addr_info':[]}] for n in ('lo','ens160')}
    network={'Name':'harbor_default','Id':'c'*64,'Driver':'bridge','Containers':{}}
    volumes={}
    for name,row in f['profile']['volume_inventory'].items():
        volumes[name]=dict(Name=name,Driver=row['driver'],Mountpoint=row['mountpoint'],Scope='local',Options=None)
    policy=dict(schema='fds.harbor.production-address-host.v1',
        identity={'hostname':'harbor01','product_uuid':'11111111-1111-1111-1111-111111111111','boot':'22222222-2222-2222-2222-222222222222'},
        physical_interfaces=['ens160'],interfaces={k:seq.fingerprint(v) for k,v in addresses.items()},
        routes_sha256=seq.fingerprint([]),tools=tools,
        pinned_files={row['FragmentPath']:{'mode':0o644,'gid':0,'selinux':'synthetic_t','sha256':'a'*64} for row in units.values()},
        source_files={'/synthetic/user-parent/source':{'uid':0,'gid':0,'mode':0o640,'selinux':'synthetic_t','sha256':'a'*64}},
        socket_spec={'mode':0o660,'gid':1,'selinux':'synthetic_t'},engine_profile={'version':version,'info':info},units=units,
        manager={'LoadState':'not-found','ActiveState':'inactive','SubState':'dead','MainPID':'0','UnitFileState':''},
        nft_sha256=h.nft_fingerprint(json.dumps(nft).encode()),
        images={r['image']:f['before'][s]['Image'] for s,r in f['model']['services'].items()},
        resources={'networks':{'harbor_default':seq.fingerprint(h.resource_projection('networks',network))},
                   'volumes':{n:seq.fingerprint(v) for n,v in volumes.items()}},inputs_sha256='b'*64,compose_version='5.6.0')
    f['profile']['host_binding_sha256']=seq.fingerprint(policy)
    preservation=dict(baseline=f['before'],after_labels=f['target_labels'],after_host_mounts=f['inherited'],
                      auto_hostnames=list(seq.ORDER),auto_addresses=list(seq.ORDER))
    f['plan'].update(binding_sha256=seq.fingerprint(policy),inputs_sha256='b'*64)
    package={'host-policy.json':policy,'profile.json':f['profile'],'plan.json':f['plan'],
             'preservation.json':preservation,'model.json':f['model'],'base.json':f['base'],'candidate.json':f['candidate']}
    return dict(f=f,policy=policy,nft=nft,addresses=addresses,network=network,volumes=volumes,package=package)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.x=host_fixture();self.data=deepcopy(self.x)
        self.data['package']=deepcopy(self.x['package'])  # live drift must not edit the reviewed package
        self.t=10.;self.calls=[];outer=self
        class IO:
            def identity(self):return deepcopy(outer.data['policy']['identity'])
            def physical_interfaces(self):return outer.data['policy']['physical_interfaces']
            def pinned(self,*a):outer.calls.append(('pin',a[0]));return (1,2,3)
            def source(self,*a):outer.calls.append(('source',a[0]))
            def volume_metadata(self,path,deadline):return outer.data['f']['profile']['source_metadata'][path]
            def command(self,tool,args,deadline):
                name=tool['path'].split('/')[-1];outer.calls.append((name,args))
                if name=='getenforce':return 0,b'Enforcing'
                if name=='compose':return 0,b'5.6.0'
                if name=='nft':return 0,json.dumps(outer.data['nft']).encode()
                if name=='ip':return 0,json.dumps([] if 'route' in args else outer.data['addresses'][args[-1]]).encode()
                row=outer.data['policy']['manager'] if args[1]==h.MANAGER else outer.data['policy']['units'][args[1]]
                return 0,'\n'.join(k+'='+v for k,v in row.items()).encode()
        class Engine(cb.Engine):
            path='/run/docker.sock';prefix='/v1.56';peer_uid=0
            def profile(self,d):return outer.data['policy']['engine_profile']
            def image(self,ref,d):return {'Id':outer.data['policy']['images'][ref]}
            def resource(self,kind,name,d):return outer.data['network'] if kind=='networks' else outer.data['volumes'][name]
        self.io=IO();self.engine=Engine(self.x['f'])
        self.host=h.ProductionHost(self.x['policy'],profile=self.x['f']['profile'],
            package_path='/synthetic/package',package_sha256='a'*64,package_context=b'synthetic_t',
            model_sha256=seq.fingerprint(self.x['f']['model']),preservation_binding=seq.fingerprint(self.x['package']['preservation.json']),
            engine=self.engine,io=self.io,clock=lambda:self.t)
    def read(self):
        with patch.object(h,'load_package',side_effect=lambda *a,**kw:deepcopy(self.data['package'])),patch.object(h,'logger_tcp',return_value=True):
            return self.host(100)
    def test_complete_host_observation_uses_actual_collectors_and_binding(self):
        value=self.read();self.assertEqual(value['binding_sha256'],seq.fingerprint(self.x['policy']))
        self.assertTrue(value['logger_ipv4']);self.assertEqual(value['mount_inputs']['current_inventory'],self.x['f']['profile']['volume_inventory'])
        self.assertEqual(sum(n=='getenforce' for n,_ in self.calls),2)
        self.assertEqual(sum(n=='source' for n,_ in self.calls),2)
    def test_dependency_presentation_order_does_not_change_reviewed_policy(self):
        # Sanitized actual observation after unit reload: only set presentation changed.
        dependencies={
            'docker.service': {
                'Requires':'docker.socket sysinit.target fds-harbor-ac04-guard.service system.slice',
                'After':'sysinit.target fds-harbor-ac04-guard.service network-online.target systemd-journald.socket containerd.service basic.target system.slice time-set.target nss-lookup.target firewalld.service docker.socket'},
            h.GUARD: {'Requires':'sysinit.target system.slice',
                'After':'systemd-journald.socket firewalld.service sysinit.target system.slice basic.target'}}
        for name,fields in dependencies.items():
            self.host.policy['units'][name].update(fields)
            self.data['policy']['units'][name].update({k:' '.join(reversed(v.split())) for k,v in fields.items()})
        before=deepcopy(self.host.policy)
        self.host._guards(100)
        self.assertEqual(self.host.policy,before)  # no rebinding/learning from live observations
    def test_dependency_membership_and_duplicates_remain_blocking(self):
        for name in ('docker.service',h.GUARD):
            for key in ('Requires','After'):
                for kind in ('added','removed','duplicate','empty'):
                    with self.subTest(unit=name,property=key,change=kind):
                        self.setUp()
                        expected=h.GUARD+' system.slice'
                        self.host.policy['units'][name][key]=expected
                        live={'added':expected+' unexpected.service','removed':h.GUARD,
                            'duplicate':expected+' system.slice','empty':''}[kind]
                        self.data['policy']['units'][name][key]=live
                        with self.assertRaises(ValueError):self.host._guards(100)
    def test_dependency_projection_does_not_relax_other_unit_properties(self):
        for name in ('docker.service',h.GUARD):
            for key,value in dict(LoadState='not-found',ActiveState='inactive',SubState='dead',
                    InvocationID='b'*32,FragmentPath='/unexpected/unit',DropInPaths='/unexpected/dropin',
                    NeedDaemonReload='yes').items():
                with self.subTest(unit=name,property=key):
                    self.setUp();self.data['policy']['units'][name][key]=value
                    with self.assertRaises(ValueError):self.host._guards(100)
    def test_dependency_change_during_second_observation_is_refused(self):
        original=self.io.command;count=0
        def changed(tool,args,deadline):
            nonlocal count
            if tool['path'].endswith('/systemctl') and args[1]=='docker.service':
                count+=1
                if count==2:self.data['policy']['units']['docker.service']['After']+=' new.service'
            return original(tool,args,deadline)
        self.io.command=changed
        with self.assertRaisesRegex(ValueError,'HOST_UNIT_CHANGED'):self.read()
    def test_unit_projection_rejects_malformed_policy_and_preserves_dropin_order(self):
        row=deepcopy(self.x['policy']['units']['docker.service'])
        for key in ('Requires','After'):
            for bad in (None,[],1,row[key]+' '+row[key]):
                with self.subTest(property=key,value=bad):
                    with self.assertRaises(ValueError):h.unit_projection(dict(row,**{key:bad}))
        for bad in (None,dict(row,Unexpected='value'),{k:v for k,v in row.items() if k!='After'}):
            with self.assertRaises(ValueError):h.unit_projection(bad)
        self.assertNotEqual(h.unit_projection(dict(row,DropInPaths='/a /b')),
                            h.unit_projection(dict(row,DropInPaths='/b /a')))
    def test_changed_identity_nic_guard_route_image_and_volume_rejected(self):
        changes=[lambda d:d['policy']['identity'].update(boot='33333333-3333-3333-3333-333333333333'),
            lambda d:d['policy']['physical_interfaces'].append('ens999'),
            lambda d:d['policy']['units']['docker.service'].update(Requires=''),
            lambda d:d['addresses']['ens160'].append({'ifname':'other'}),
            lambda d:d['policy']['images'].update({next(iter(d['policy']['images'])):'sha256:'+'f'*64}),
            lambda d:d['network'].update(Driver='overlay'),
            lambda d:next(iter(d['f']['profile']['source_metadata'].values())).update(mode=0o777)]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.setUp();change(self.data)
                with self.assertRaises((ValueError,KeyError)):self.read()
    def test_selinux_compose_command_failure_or_manager_present_refused(self):
        for name,rc,raw in [('getenforce',0,b'Permissive'),('compose',0,b'5.7.0'),('ip',1,b'SECRET')]:
            self.setUp();original=self.io.command
            self.io.command=lambda tool,args,d: (rc,raw) if tool['path'].endswith('/'+name) else original(tool,args,d)
            with self.assertRaises(ValueError):self.read()
        self.setUp();self.data['policy']['manager'].update(LoadState='loaded')
        with self.assertRaises(ValueError):self.read()
    def test_dynamic_network_endpoints_and_nft_counters_are_not_config(self):
        self.data['network']['Containers']={'dynamic':{'Name':'new'}}
        self.data['nft']['nftables'][1]['rule']['expr'][0]['counter']['packets']=999
        self.read()
        self.data['nft']['nftables'][1]['rule']['expr'].append({'accept':None})
        with self.assertRaisesRegex(ValueError,'NFT_CHANGED'):self.read()
    def test_engine_profile_socket_source_failure_blocks(self):
        self.data['policy']['engine_profile']['version']['GitCommit']='changed'
        with self.assertRaisesRegex(ValueError,'ENGINE_CHANGED'):self.read()
        self.setUp();self.io.source=lambda *a:(_ for _ in ()).throw(ValueError('SOURCE_CHANGED'))
        with self.assertRaises(ValueError):self.read()
        self.setUp();self.io.pinned=lambda *a:(_ for _ in ()).throw(ValueError('SOCKET_CHANGED'))
        with self.assertRaises(ValueError):self.read()
    def test_package_or_preservation_rebinding_refused(self):
        self.data['package']['preservation.json']['baseline']['core']['Config']['Env'].append('NEW=secret')
        with self.assertRaisesRegex(ValueError,'PACKAGE_BINDING'):self.read()
    def test_logger_deadline_and_second_pass_drift_refused(self):
        with patch.object(h,'load_package',return_value=self.data['package']),patch.object(h,'logger_tcp',return_value=False):
            with self.assertRaises(ValueError):self.host(100)
        with self.assertRaises(ValueError):self.host(10)
        self.setUp();calls=0;original=self.io.identity
        def changed():
            nonlocal calls
            calls+=1
            return original() if calls==1 else dict(original(),boot='33333333-3333-3333-3333-333333333333')
        self.io.identity=changed
        with self.assertRaises(ValueError):self.read()
    def test_unit_files_must_be_pinned_and_socket_remote_override_refused(self):
        bad=deepcopy(self.x['policy']);bad['pinned_files']={}
        with self.assertRaises(ValueError):h.ProductionHost(bad,profile=self.x['f']['profile'],package_path='x',package_sha256='a'*64,
            package_context=None,model_sha256='a'*64,preservation_binding='a'*64,engine=self.engine,io=self.io)
    def test_read_only_engine_never_accepts_start_or_unrelated_endpoint(self):
        engine=h.ReadOnlyEngine('1.56')
        for method,path in [('POST','/containers/'+'a'*64+'/start'),('GET','/events'),('DELETE','/volumes/test')]:
            with self.assertRaises(ValueError):engine._validate_request(method,path,b'')
        with patch.object(engine,'_json',return_value={}) as read:
            engine.image('registry.test:5000/team/image:tag',100)
            self.assertEqual(read.call_args.args[0],'/images/registry.test%3A5000%2Fteam%2Fimage%3Atag/json')
        with self.assertRaises(ValueError):engine.image('name?escape',100)
    def test_full_package_linkage_and_address_only_consumption(self):
        session.assemble(self.x['package'])
        self.x['package']['candidate.json']['services']['core']['environment']['SECRET']='changed'
        with self.assertRaisesRegex(ValueError,'SCOPE'):session.assemble(self.x['package'])
    def test_wrong_baseline_image_profile_or_host_cannot_be_assembled(self):
        for kind in ('baseline','image','profile','host'):
            values=deepcopy(self.x['package'])
            if kind=='baseline':values['plan.json']['baseline']['core']['preservation_sha256']='e'*64
            elif kind=='image':values['preservation.json']['baseline']['core']['Image']='sha256:'+'f'*64
            elif kind=='profile':values['profile.json']['host_binding_sha256']='f'*64
            else:values['host-policy.json']['inputs_sha256']='c'*64
            with self.assertRaises(ValueError):session.assemble(values)
    def test_production_session_has_no_no_selinux_or_overlapping_path_escape(self):
        args=dict(package_path='/root/package',journal_path='/root/journal',evidence_path='/root/evidence',private_path='/root/private',
            package_sha256='a'*64,package_context=b'expected',journal_context=b'expected',evidence_context=b'expected',
            private_context=None,preparation_deadline=100)
        with self.assertRaisesRegex(ValueError,'SESSION_CONTEXT'):session.ProtectedSession(**args)
        args.update(private_context=b'expected',journal_path='/root/package/journal')
        with self.assertRaisesRegex(ValueError,'PATH_OVERLAP'):session.ProtectedSession(**args)
    def test_coordinator_refuses_reuse_fork_concurrency_and_bad_budget_before_io(self):
        for kind in ('used','fork','busy','budget'):
            obj=session.ProtectedSession.__new__(session.ProtectedSession)
            obj.clock=lambda:10.;obj.used=kind=='used';obj.pid=-1 if kind=='fork' else os.getpid()
            obj.mutex=threading.Lock()
            if kind=='busy':obj.mutex.acquire()
            with self.assertRaises(ValueError):obj.run(mutation_deadline=100,collection_deadline=99 if kind=='budget' else 200)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Linux root temporary storage only')
class LinuxProtectedTests(unittest.TestCase):
    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='address-runtime-test-',dir='/root'))
        self.context=os.getxattr(self.base,'security.selinux').rstrip(b'\0') if 'security.selinux' in os.listxattr(self.base) else None
    def tearDown(self):
        assert self.base.parent==Path('/root') and self.base.name.startswith('address-runtime-test-')
        shutil.rmtree(self.base)
    def deadline(self):return time.monotonic()+10
    def directory(self,name):
        path=self.base/name;path.mkdir(mode=0o700);return path
    def evidence(self,name='evidence'):
        return e.Evidence(str(self.directory(name)),context=self.context,plan_sha256='a'*64)
    def inspect(self,evidence):
        return e.inspect_evidence(evidence.path,context=self.context,plan_sha256='a'*64,deadline=self.deadline())
    def test_private_durable_payloads_chain_and_sealed_no_up(self):
        store=self.evidence()
        with store.locked(self.deadline()):
            store.save(kind='CALL_INTENT',operation='render',payloads={},diagnostic={},deadline=self.deadline())
            store.save(kind='CALL_END',operation='render',payloads={'stdout':b'PRIVATE_SECRET'},diagnostic={'rc':1},deadline=self.deadline())
        summary=self.inspect(store)
        self.assertTrue(summary['valid']);self.assertEqual(summary['this_client_up'],'NOT_INVOKED')
        self.assertNotIn('PRIVATE_SECRET',json.dumps(summary));self.assertFalse(summary['may_resume'])
        self.assertEqual((Path(store.path)/'000001.stdout.bin').read_bytes(),b'PRIVATE_SECRET')
        self.assertTrue(all((f.stat().st_mode&0o777)==0o600 for f in Path(store.path).iterdir()))
    def test_up_intent_is_may_have_run_not_success(self):
        store=self.evidence()
        with store.locked(self.deadline()):
            for kind in ('CALL_INTENT','PROCESS_INTENT','PROCESS_RESULT','CALL_END'):
                store.save(kind=kind,operation='recreate',service='postgresql',diagnostic={},payloads={},deadline=self.deadline())
        result=self.inspect(store);self.assertEqual(result['this_client_up'],'MAY_HAVE_RUN')
        self.assertEqual(result['runtime_outcome'],'NOT_INFERRED')
    def test_crash_missing_close_does_not_prove_no_up(self):
        store=self.evidence()
        with self.assertRaises(KeyboardInterrupt):
            with store.locked(self.deadline()):raise KeyboardInterrupt()
        self.assertEqual(self.inspect(store)['this_client_up'],'UNKNOWN')
        with self.assertRaises(ValueError):
            with e.Evidence(store.path,context=self.context,plan_sha256='a'*64).locked(self.deadline()):pass
    def test_sealed_open_call_is_invalid_even_without_process_intent(self):
        for stage in ('CALL_INTENT','PROCESS_INTENT','PROCESS_RESULT'):
            store=self.evidence(stage)
            with store.locked(self.deadline()):
                for kind in ('CALL_INTENT','PROCESS_INTENT','PROCESS_RESULT'):
                    store.save(kind=kind,operation='recreate',service='postgresql',diagnostic={},payloads={},deadline=self.deadline())
                    if kind==stage:break
            result=self.inspect(store)
            self.assertFalse(result['valid']);self.assertEqual(result['this_client_up'],'UNKNOWN')
    def test_truncated_payload_orphan_tampered_record_refused(self):
        for change in ('payload','orphan','chain'):
            store=self.evidence(change)
            with store.locked(self.deadline()):store.save(kind='INSPECT',payloads={'private':b'PRIVATE'},diagnostic={},deadline=self.deadline())
            path=Path(store.path)
            if change=='payload':(path/'000000.private.bin').write_bytes(b'changed')
            elif change=='orphan':(path/'000009.record.json').write_text('{}')
            else:
                record=json.loads((path/'000000.record.json').read_text());record['kind']='PROCESS_INTENT'
                (path/'000000.record.json').write_text(json.dumps(record))
            self.assertFalse(self.inspect(store)['valid'])
    def test_disk_failure_preserves_partial_and_poisoned_writer(self):
        store=self.evidence()
        with self.assertRaises(OSError):
            with store.locked(self.deadline()):
                with patch.object(e.os,'fsync',side_effect=OSError('synthetic fault')):
                    store.save(kind='INSPECT',payloads={'private':b'partial'},diagnostic={},deadline=self.deadline())
        self.assertTrue((Path(store.path)/'000000.private.bin').exists())
        self.assertFalse(self.inspect(store)['valid'])
        with self.assertRaises(ValueError):store.save(kind='INSPECT',payloads={},diagnostic={},deadline=self.deadline())
    def test_writable_directory_or_replaced_prior_file_stops_new_write(self):
        for kind in ('mode','replacement'):
            store=self.evidence(kind)
            with self.assertRaises(ValueError):
                with store.locked(self.deadline()):
                    if kind=='mode':os.chmod(store.path,0o777)
                    else:
                        old=Path(store.path)/'evidence.claim';old.rename(Path(store.path)/'previous');old.write_text('{}')
                    store.save(kind='INSPECT',payloads={},diagnostic={},deadline=self.deadline())
            self.assertFalse((Path(store.path)/'000000.record.json').exists())
    def pinned(self):
        exe=self.base/'elf';shutil.copyfile(Path(sys.executable).resolve(),exe);exe.chmod(0o700)
        config=self.directory('config')
        return c.PinnedCompose(binary=str(exe),binary_sha256=c.sha(exe.read_bytes()),binary_context=None,
            private_directory=str(config),private_context=None)
    def test_audit_render_failure_and_expired_up_have_durable_distinct_evidence(self):
        process=self.pinned();store=self.evidence();model=cb.fixture()['model']
        with store.locked(self.deadline()):
            audited=e.AuditedCompose(process,store)
            with patch.object(c,'run_process',return_value=c.PrivateResult(9,'COMPLETED',b'',b'PRIVATE')):
                with self.assertRaises(ValueError):audited.call('render',model,deadline=self.deadline())
        self.assertEqual(self.inspect(store)['this_client_up'],'NOT_INVOKED')
        self.assertTrue(any(f.read_bytes()==b'PRIVATE' for f in Path(store.path).glob('*.stderr.bin')))
    def test_late_result_uses_separate_evidence_budget(self):
        process=self.pinned();store=self.evidence();model=cb.fixture()['model']
        tick=[10.0];process.clock=store.clock=lambda:tick[0]
        def late(*args,**kwargs):
            tick[0]=12.0
            return c.PrivateResult(None,'COMPOSE_DEADLINE',b'partial',b'PRIVATE')
        with store.locked(100):
            audited=e.AuditedCompose(process,store,clock=lambda:tick[0])
            with patch.object(c,'run_process',side_effect=late):
                with self.assertRaises(ValueError):audited.call('recreate',model,service='postgresql',deadline=11)
        result=self.inspect(store);self.assertEqual(result['this_client_up'],'MAY_HAVE_RUN')
        self.assertTrue(any(f.read_bytes()==b'partial' for f in Path(store.path).glob('*.stdout.bin')))
    def test_intent_disk_failure_prevents_process_invocation(self):
        process=self.pinned();store=self.evidence();model=cb.fixture()['model']
        with self.assertRaises(OSError):
            with store.locked(self.deadline()):
                audited=e.AuditedCompose(process,store)
                with patch.object(store,'save',side_effect=OSError('disk')),patch.object(c,'run_process') as run:
                    try:audited.call('recreate',model,service='postgresql',deadline=self.deadline())
                    finally:run.assert_not_called()
    def test_partial_collection_keeps_old_missing_and_new_duplicate_ids(self):
        f=cb.fixture();engine=cb.Engine(f);old_id=f['before']['portal']['Id'];new=cb.recreated(f,'portal');engine.rows['portal']=new
        store=self.evidence();ids={s:r['Id'] for s,r in f['before'].items()}
        with store.locked(self.deadline()):result=e.collect_partial(engine,store,baseline_ids=ids,deadline=self.deadline())
        self.assertFalse(result['complete']);self.assertEqual(result['failures'],1)
        self.assertIn(new['Id'],result['inspected']);self.assertNotIn(old_id,result['inspected'])
        self.assertTrue(self.inspect(store)['valid'])
    def package(self,name='package'):
        path=self.directory(name);contents={n:json.dumps({'private':'SECRET','file':n}).encode() for n in p.FILES}
        hashes={n:hashlib.sha256(v).hexdigest() for n,v in contents.items()}
        result=p.seal_package(str(path),contents=contents,hashes=hashes,context=self.context,deadline=self.deadline())
        return path,contents,hashes,result
    def test_package_exact_roundtrip_and_duplicate_supply_refused(self):
        path,contents,hashes,result=self.package()
        loaded=p.load_package(str(path),manifest_sha256=result['manifest_sha256'],context=self.context,deadline=self.deadline())
        self.assertEqual(loaded,{n:json.loads(v) for n,v in contents.items()});self.assertNotIn('SECRET',json.dumps(result))
        with self.assertRaises(ValueError):p.seal_package(str(path),contents=contents,hashes=hashes,context=self.context,deadline=self.deadline())
    def test_package_corruption_acl_links_extra_and_wrong_hash_refused(self):
        for kind in ('hash','bytes','extra','symlink','hardlink','xattr'):
            path,contents,hashes,result=self.package(kind);first=path/'model.json'
            if kind=='bytes':first.write_bytes(b'{}')
            elif kind=='extra':(path/'unexpected').write_bytes(b'')
            elif kind=='symlink':first.rename(path/'original');first.symlink_to(path/'original')
            elif kind=='hardlink':os.link(first,path/'link')
            elif kind=='xattr':os.setxattr(first,'user.synthetic',b'blocked')
            else:result['manifest_sha256']='0'*64
            with self.assertRaises((ValueError,OSError)):p.load_package(str(path),manifest_sha256=result['manifest_sha256'],context=self.context,deadline=self.deadline())
    def test_partial_package_is_not_loadable_or_resumable(self):
        path=self.directory('partial');contents={n:b'{}' for n in p.FILES};hashes={n:c.sha(v) for n,v in contents.items()}
        with patch.object(p,'write_all',side_effect=OSError('disk')):
            with self.assertRaises(OSError):p.seal_package(str(path),contents=contents,hashes=hashes,context=self.context,deadline=self.deadline())
        self.assertTrue((path/'supply.claim').exists());self.assertFalse((path/'manifest.json').exists())
        with self.assertRaises(ValueError):p.seal_package(str(path),contents=contents,hashes=hashes,context=self.context,deadline=self.deadline())
    def test_wrong_context_or_private_mode_blocks_supply(self):
        path=self.directory('bad');contents={n:b'{}' for n in p.FILES};hashes={n:c.sha(v) for n,v in contents.items()}
        with self.assertRaises(ValueError):p.seal_package(str(path),contents=contents,hashes=hashes,context=b'wrong',deadline=self.deadline())
        self.assertEqual(list(path.iterdir()),[])
        path.chmod(0o755)
        with self.assertRaises(ValueError):p.seal_package(str(path),contents=contents,hashes=hashes,context=self.context,deadline=self.deadline())
    def test_source_hash_read_accepts_user_parent_but_never_symlink_or_drift(self):
        directory=self.directory('user');os.chown(directory,12345,12345)
        source=directory/'source';source.write_bytes(b'PRIVATE');source.chmod(0o640)
        io=h.ProductionReadOnly();spec={'uid':0,'gid':0,'mode':0o640,'selinux':'ci-synthetic','sha256':c.sha(b'PRIVATE')}
        # CI lacks SELinux; this test exercises fd/hash/path controls only.
        with patch.object(h,'context_check'):
            io.source(str(source),spec,self.deadline())
            source.write_bytes(b'CHANGED')
            with self.assertRaises(ValueError):io.source(str(source),spec,self.deadline())
            source.unlink();source.symlink_to('/dev/null')
            with self.assertRaises(OSError):io.source(str(source),spec,self.deadline())
    def connected_session(self):
        # Real Sequence/Journal/Evidence/PinnedCompose fd checks; synthetic
        # Engine, host, process result only. Production constructor is NOT run.
        fixture=cb.ConnectedTests();fixture.setUp()
        obj=session.ProtectedSession.__new__(session.ProtectedSession)
        obj.clock=lambda:fixture.clock;obj.used=False;obj.pid=os.getpid();obj.mutex=threading.Lock()
        obj.evidence=e.Evidence(str(self.directory('connected-evidence')),context=self.context,
                               plan_sha256=seq.fingerprint(fixture.f['plan']),clock=obj.clock)
        process=self.pinned();process.clock=obj.clock
        fixture.backend.transport.process=e.AuditedCompose(process,obj.evidence,clock=obj.clock)
        obj.sequence=seq.Sequence(fixture.f['plan'],fixture.backend,
            cb.journal.Journal(str(self.directory('journal')),expected_selinux=self.context),clock=obj.clock)
        obj.engine=fixture.engine;obj.ids={s:r['Id'] for s,r in fixture.f['before'].items()}
        return obj,fixture
    def test_all_nine_audited_calls_and_private_handoff_are_sealed(self):
        obj,fixture=self.connected_session();writes=[]
        def process(args,*a,**kw):
            if 'up' in args:
                service=args[-1];writes.append(service);fixture.engine.rows[service]=cb.recreated(fixture.f,service)
                return c.PrivateResult(0,'COMPLETED',b'',b'')
            return c.PrivateResult(0,'COMPLETED',e.encode(fixture.f['model']),b'')
        with patch.object(c,'run_process',side_effect=process):result=obj.run(mutation_deadline=100,collection_deadline=200)
        self.assertEqual(writes,list(seq.ORDER));self.assertTrue(result['evidence_sealed'])
        self.assertEqual(result['sequence']['status'],'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        self.assertFalse(result['daemon_effects_may_continue'])
        # Removed OLD IDs cannot be read; this is not a new application failure.
        self.assertEqual(result['collection']['failures'],9);self.assertFalse(result['runtime_acceptance'])
        summary=e.inspect_evidence(obj.evidence.path,context=self.context,plan_sha256=seq.fingerprint(fixture.f['plan']),deadline=self.deadline())
        self.assertTrue(summary['valid']);self.assertEqual(summary['up_process_intents'],list(seq.ORDER))
        with self.assertRaisesRegex(ValueError,'SPENT'):obj.run(mutation_deadline=100,collection_deadline=200)
    def test_late_first_write_stops_next_and_collects_without_extending_mutation(self):
        obj,fixture=self.connected_session();writes=[]
        def process(args,*a,**kw):
            if 'up' in args:
                writes.append(args[-1]);fixture.engine.rows[args[-1]]=cb.recreated(fixture.f,args[-1]);fixture.clock=110.
                return c.PrivateResult(None,'COMPOSE_DEADLINE',b'partial',b'PRIVATE')
            return c.PrivateResult(0,'COMPLETED',e.encode(fixture.f['model']),b'')
        with patch.object(c,'run_process',side_effect=process):result=obj.run(mutation_deadline=100,collection_deadline=200)
        self.assertEqual(writes,['postgresql']);self.assertTrue(result['evidence_sealed'])
        self.assertEqual(result['sequence']['status'],'STOP_RECOVERY_REQUIRED')
        self.assertTrue(result['daemon_effects_may_continue'])
        self.assertEqual(result['collection']['failures'],1)
        self.assertTrue(any(f.read_bytes()==b'PRIVATE' for f in Path(obj.evidence.path).glob('*.stderr.bin')))
    def test_collection_disk_failure_retains_sequence_and_no_retry(self):
        obj,fixture=self.connected_session();fixture.host_drift=True
        with patch.object(session,'collect_partial',side_effect=OSError('PRIVATE')) as collector:
            result=obj.run(mutation_deadline=100,collection_deadline=200)
        self.assertEqual(result['sequence']['status'],'STOP_BEFORE_CHANGE');self.assertFalse(result['evidence_sealed'])
        self.assertEqual(collector.call_count,1);self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertTrue((Path(obj.evidence.path)/'000000.private.bin').exists())


if __name__=='__main__':unittest.main()
