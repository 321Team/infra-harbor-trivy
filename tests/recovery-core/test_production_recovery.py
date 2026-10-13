"""Production lifecycle/network contract using synthetic I/O; no guest/Engine writes."""
from copy import deepcopy
from contextlib import nullcontext
from dataclasses import asdict
import importlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from test_host_provider import policy, FakeIO, BOOT, LABEL, raw
from test_docker_adapter import FakeEngine
import harbor_recovery_host as h
import harbor_recovery_docker as d
import harbor_recovery_core as c
import harbor_recovery_bundle as b

NID='d'*64
BRIDGE='br-harbor'


class NetworkFixture:
    def __init__(self, running=('log',)):
        self.policy=policy(); self.engine=FakeEngine()
        for name in ('proxy', 'portal'):
            self.engine.rows[name]['Config']['StopSignal']='SIGQUIT'
        self.engine.path,self.engine.peer_uid,self.engine.prefix='/run/docker.sock',0,'/v1.53'
        self.engine.profile=lambda deadline:deepcopy(self.policy['engine_profile'])
        self.links=[{'ifindex':1,'ifname':'lo','link_type':'loopback','address':'00:00:00:00:00:00'},
                    {'ifindex':2,'ifname':'ens33','link_type':'ether','address':'02:00:00:00:00:02','mtu':1500},
                    {'ifindex':3,'ifname':BRIDGE,'address':'02:00:00:00:00:03','flags':['BROADCAST','UP'],
                     'operstate':'DOWN','linkinfo':{'info_kind':'bridge','info_data':{'hello_timer':0,'fdb_n_learned':0}}}]
        self.stable=[{'dst':'default','gateway':'192.0.2.1','dev':'ens33','flags':[]},
                     {'dst':'172.18.0.0/16','dev':BRIDGE,'flags':[]}]
        self.network={'Id':NID,'Name':'harbor_harbor','Driver':'bridge','Options':{'com.docker.network.bridge.name':BRIDGE},
                      'Containers':{},'Status':{'IPAM':{'Subnets':{'172.18.0.0/16':{'IPsInUse':0,'DynamicIPsAvailable':65000}}}}}
        self.policy['version']=2
        self.policy['tools']['nsenter']='/usr/bin/nsenter'
        self.policy['files']['/usr/bin/nsenter']={'mode':0o755,'gid':0,'selinux':LABEL,'sha256':'b'*64}
        self.policy['network']={'physical_interfaces':['ens33'],
            'interfaces':{r['ifname']:d.digest(h.production_link_projection(r,bridge=r['ifname']==BRIDGE)) for r in self.links},
            'bridges':{NID:{'name':'harbor_harbor','bridge':BRIDGE,'sha256':d.digest(h._net_network_projection(self.network))}},
            'routes_sha256':d.digest(sorted(self.stable,key=d.digest)),'ids':deepcopy(self.engine.ids)}
        self.physical=['ens33'];self.pending=set();self.peers={};self.addresses=[];self.routes=[]
        self.io=FakeIO(self.policy);self.io.stamp['physical_nics']=True
        self.io.physical_interfaces=lambda:deepcopy(self.physical)
        self.io.peer_links=lambda pid,p,deadline:deepcopy(self.peers[pid])
        normal=self.io.run
        def run(argv,cwd,deadline):
            if Path(argv[0]).name=='ip':
                if 'address' in argv:return raw(self.addresses)
                if 'route' in argv:return raw(self.routes)
                return raw(self.links)
            return normal(argv,cwd,deadline)
        self.io.run=run
        self.reader=type('NetworkReader',(),{'read':lambda _,nid,deadline:deepcopy(self.network)})()
        self.running(running)
        self.host=h.host_provider(self.policy,self.engine,io=self.io,clock=lambda:10,network_reader=self.reader)

    def running(self, services):
        self.links=self.links[:3];self.peers={};self.addresses=[];self.routes=deepcopy(self.stable)
        self.network['Containers']={}
        for index,(service,item) in enumerate(self.engine.rows.items()):
            is_running=service in services;pid=1000+index if is_running else 0
            item['State'].update(Running=is_running,Status='running' if is_running else 'exited',Pid=pid,
                                 Health={'Status':'healthy' if is_running else 'unhealthy'})
            mac=f'02:00:00:01:00:{index+1:02x}';eid=f'{index+20:064x}' if is_running else ''
            item['NetworkSettings']={'Networks':{'harbor_harbor':{'NetworkID':NID,'EndpointID':eid,'MacAddress':mac if is_running else ''}}}
            if not is_running:continue
            cid=item['Id'];self.network['Containers'][cid]={'EndpointID':eid,'MacAddress':mac}
            link={'ifindex':10+index,'ifname':'veth'+str(index),'link_index':2,'master':BRIDGE,
                  'address':f'02:00:00:02:00:{index+1:02x}','linkinfo':{'info_kind':'veth'}}
            self.links.append(link)
            self.peers[pid]=[{'ifindex':2,'ifname':'eth0','link_index':link['ifindex'],'address':mac,'linkinfo':{'info_kind':'veth'}}]
            address={'family':'inet6','scope':'link','prefixlen':64,'local':h._net_link_local(link)}
            if service in self.pending:address['tentative']=True
            self.addresses.append({'ifindex':link['ifindex'],'ifname':link['ifname'],'addr_info':[address]})
            common={'dev':link['ifname'],'protocol':'kernel','flags':[],'pref':'medium'}
            self.routes.extend([dict(common,dst='fe80::/64',metric=256),dict(common,type='multicast',dst='ff00::/8',table='local',metric=256)])
            if service not in self.pending:self.routes.append(dict(common,type='local',dst=address['local'],table='local',metric=0))

    def read(self):return self.host(30)
    def plan(self):
        return c.Plan(self.engine.ids,{s:d.project(r,s,r['Id'],'harbor').fingerprint for s,r in self.engine.rows.items()},
            {s:60 for s in c.ORDER},execution_binding=d.execution_binding(self.host.binding,'harbor',self.engine.binding))


class ProductionHostTests(unittest.TestCase):
    def reject(self,f):
        with self.assertRaisesRegex(ValueError,'^HOST_VERIFICATION_FAILED$'):f.read()
        self.assertEqual(f.engine.posts,[])

    def test_running_stopped_and_mixed_states_use_same_reviewed_binding(self):
        f=NetworkFixture();binding=f.read().binding
        for services in ([],['log'],list(f.engine.ids),['log','postgresql']):
            f.running(services);self.assertEqual(f.read().binding,binding)
        self.assertEqual(f.engine.posts,[])

    def test_new_boot_and_daemon_are_fresh_facts_not_enrollment_changes(self):
        f=NetworkFixture();first=f.read()
        f.io.stamp['boot']='23456789-1234-1234-1234-123456789abc'
        second=f.read();self.assertNotEqual(first.boot,second.boot);self.assertEqual(first.binding,second.binding)
        normal=f.io.run
        f.io.run=lambda argv,cwd,deadline:normal(argv,cwd,deadline).replace(('InvocationID='+'a'*32).encode(),('InvocationID='+'c'*32).encode()) if 'systemctl' in argv[0] else normal(argv,cwd,deadline)
        self.assertNotEqual(f.read().daemon,second.daemon)
        f.io.stamp['product_uuid']=f.io.stamp['boot'];self.reject(f)

    def test_production_policy_never_weakens_clone_provider(self):
        f=NetworkFixture()
        with self.assertRaisesRegex(ValueError,'PROVIDER_SCOPE'):h.HostProvider(f.policy,f.engine,io=f.io)
        old=policy();oldio=FakeIO(old);oldio.stamp['physical_nics']=True
        with self.assertRaisesRegex(ValueError,'HOST_ISOLATION'):h.HostProvider(old,f.engine,io=oldio)._identity()

    def test_physical_route_security_and_link_drift_rejected(self):
        changes=[lambda f:f.physical.append('ens34'),lambda f:f.routes[0].update(gateway='192.0.2.254'),
                 lambda f:f.links[1].update(mtu=9000),lambda f:f.links.append({'ifindex':80,'ifname':'rogue','linkinfo':{'info_kind':'veth'}}),
                 lambda f:f.io.outputs.update(getenforce=b'Permissive'),lambda f:f.io.stamp.update(mountinfo='vmhgfs'),
                 lambda f:f.host._policy['network'].update(routes_sha256='a'*64)]
        for change in changes:
            f=NetworkFixture();change(f);self.reject(f)

    def test_bridge_carrier_and_timers_vary_configuration_does_not(self):
        f=NetworkFixture();f.links[2]['operstate']='UP';f.links[2]['flags'].append('LOWER_UP')
        f.links[2]['linkinfo']['info_data'].update(hello_timer=8,fdb_n_learned=10)
        f.routes[1]['flags']=['linkdown'];f.read()
        f.links[2]['linkinfo']['info_data']['stp_state']=1;self.reject(f)

    def test_ifindex_changes_across_boot_do_not_change_static_policy(self):
        f=NetworkFixture();f.links[0]['ifindex']=90;f.links[1]['ifindex']=91;f.links[2]['ifindex']=92;f.read()

    def test_only_bridge_tso_capability_can_vary_not_gso_or_physical_configuration(self):
        f=NetworkFixture();row=deepcopy(f.links[2]);row['tso_max_size']=65536
        before=h.production_link_projection(row,bridge=True)
        row['tso_max_size']=524280;self.assertEqual(before,h.production_link_projection(row,bridge=True))
        for bad in (0,-1,True,'524280',2**32):
            row['tso_max_size']=bad
            with self.assertRaisesRegex(ValueError,'BRIDGE_TSO'):h.production_link_projection(row,bridge=True)
        row['tso_max_size']=524280;row['gso_max_size']=524280
        self.assertNotEqual(before,h.production_link_projection(row,bridge=True))
        nic=deepcopy(f.links[1]);nic['tso_max_size']=65536;before=h.production_link_projection(nic,bridge=False)
        nic['tso_max_size']=524280;self.assertNotEqual(before,h.production_link_projection(nic,bridge=False))

    def test_missing_or_foreign_or_rewired_endpoint_rejected(self):
        changes=[lambda f:f.network['Containers'].update({'f'*64:{}}),lambda f:f.network['Containers'].clear(),
                 lambda f:f.peers[next(iter(f.peers))][0].update(link_index=999),
                 lambda f:f.links[-1].update(master='other'),lambda f:f.engine.listed.pop(),
                 lambda f:f.network['Options'].update({'com.docker.network.bridge.name':'other'})]
        for change in changes:
            f=NetworkFixture();change(f);self.reject(f)

    def test_stopped_container_cannot_hide_foreign_attachment(self):
        f=NetworkFixture();f.engine.rows['postgresql']['NetworkSettings']['Networks']={'foreign':{'NetworkID':'f'*64}}
        self.reject(f)

    def test_proven_tentative_to_ready_is_safe_but_dad_failure_is_not(self):
        f=NetworkFixture();f.pending={'log'};f.running(['log']);f.read()
        f.pending=set();f.running(['log']);f.read()
        f.addresses[0]['addr_info'][0]['dadfailed']=True;self.reject(f)

    def test_extra_veth_route_or_unknown_field_not_discarded(self):
        f=NetworkFixture();f.routes[-1]['gateway']='192.0.2.4';self.reject(f)
        f=NetworkFixture();f.routes[0]['new_config']=True;self.reject(f)

    def test_racing_namespace_or_inspect_rejected_without_writes(self):
        f=NetworkFixture();normal=f.engine.inspect;counts={}
        def inspect(cid,deadline):
            counts[cid]=counts.get(cid,0)+1
            row=normal(cid,deadline)
            if counts[cid]>1:row['State']['Pid']+=1
            return row
        f.engine.inspect=inspect;self.reject(f)

    def test_read_only_network_transport_has_exact_get_allowlist(self):
        f=NetworkFixture();reader=h.ProductionNetworkReader(f.policy)
        reader.engine._validate_request('GET','/networks/'+NID,b'')
        for method,path,body in [('POST','/networks/'+NID,b''),('GET','/networks/'+'e'*64,b''),
                                  ('GET','/networks/'+NID,b'{}'),('POST','/containers/'+'1'*64+'/start',b'')]:
            with self.assertRaisesRegex(ValueError,'GET_ONLY'):reader.engine._validate_request(method,path,body)

    def test_real_backend_accepts_stopped_apps_and_refuses_start_on_guard_drift(self):
        f=NetworkFixture();plan=f.plan()
        backend=d.DockerBackend(plan,f.engine,f.host,f.host.binding,'harbor',clock=lambda:10,probe=lambda _:True)
        self.assertTrue(backend.observe().guards_ok)
        f.physical.append('ens34')
        action=c.Action(1,'postgresql',plan.ids['postgresql'],BOOT,'a'*32,30)
        self.assertEqual(backend.start(action,5),'failed');self.assertEqual(f.engine.posts,[])

    def test_kernel_uuid_read_request_is_bounded(self):
        calls=[]
        class Stream(io.BytesIO):
            def read(self,n=-1):calls.append(n);return super().read(n)
        def opened(path,mode):return Stream(b'root / xfs' if path.endswith('mountinfo') else (BOOT+'\n').encode())
        with patch.object(h.sys,'platform','linux'),patch.object(h.os,'geteuid',return_value=0,create=True),\
             patch.object(h.socket,'gethostname',return_value='harbor01'),patch('builtins.open',side_effect=opened),\
             patch.object(h.os,'listdir',return_value=[]):
            h.LinuxReadOnly().identity()
        self.assertEqual(calls[:2],[129,129])


class ProductionPackageTests(unittest.TestCase):
    def candidate(self):
        from test_approved_bundle import candidate
        obj=candidate();f=NetworkFixture();obj['schema']=b.PRODUCTION_SCHEMA
        obj['host_policy']['version']=2;obj['host_policy']['network']=deepcopy(f.policy['network'])
        obj['host_policy']['network']['ids']=deepcopy(obj['plan']['ids'])
        obj['host_policy']['tools']['nsenter']='/usr/bin/nsenter'
        obj['host_policy']['files']['/usr/bin/nsenter']=deepcopy(f.policy['files']['/usr/bin/nsenter'])
        p=obj['host_policy'];obj['plan']['execution_binding']=d.execution_binding(b.bound_host_digest(obj),'harbor',d.UnixEngine(p['api_version'],socket_path=p['socket']).binding)
        return obj

    def test_bundle_scope_ids_and_legacy_bindings_are_separate(self):
        obj=self.candidate();self.assertEqual(b.parse_bundle(raw(obj)),obj)
        old=deepcopy(obj);old['schema']=b.SCHEMA
        with self.assertRaisesRegex(ValueError,'HOST_SCOPE'):b.parse_bundle(raw(old))
        obj['host_policy']['network']['ids']['log']='f'*64
        with self.assertRaisesRegex(ValueError,'NETWORK_IDS'):b.parse_bundle(raw(obj))

    def test_prepare_receipt_and_bootstrap_all_use_production_envelope(self):
        from test_review_package import PackageTests, x, ROOT
        from test_review_package_check import x as checker
        from test_verified_bootstrap import Reader, x as boot, BUNDLE, clean_project_imports
        fixture=PackageTests();fixture.setUp();obj=self.candidate()
        fixture.obj['schema']=b.PRODUCTION_SCHEMA
        fixture.obj['host_policy']['version']=2
        fixture.obj['host_policy']['network']=obj['host_policy']['network']
        fixture.obj['host_policy']['tools']['nsenter']='/usr/bin/nsenter'
        fixture.obj['host_policy']['files']['/usr/bin/nsenter']=obj['host_policy']['files']['/usr/bin/nsenter']
        from harbor_recovery_service import unit_text
        unit=unit_text(fixture.runtime['python'],'/opt/fds-harbor-recovery/bootstrap/'+x.sha(fixture.boot)+'/harbor_recovery_bootstrap.py',
                       LABEL,startup_seconds=30,shutdown_seconds=90,production=True)
        fixture.obj['host_policy']['files'][fixture.obj['manager']['fragment']]['sha256']=x.sha(unit.encode())
        p=fixture.obj['host_policy'];fixture.obj['plan']['execution_binding']=d.execution_binding(b.bound_host_digest(fixture.obj),'harbor',d.UnixEngine(p['api_version'],socket_path=p['socket']).binding)
        files,plan=fixture.prepare();receipt=checker.verify_bytes(files,x.sha(files['INSTALL_PLAN.json']))
        self.assertEqual(receipt['status'],'PACKAGE_BYTES_VERIFIED')
        self.assertIn('network-online.target',files['manager.service'].decode())
        self.assertTrue(any('production identity' in text for text in plan['prerequisites']))
        reader=Reader(fixture.obj,actual=True)
        code,revision=boot.collect(BUNDLE,reader.sha,LABEL,30,reader=reader,clock=lambda:10)
        with clean_project_imports(),boot.VerifiedImporter(code):
            module=importlib.import_module('harbor_recovery_bundle')
            self.assertEqual(module.parse_bundle(raw(reader.obj))['schema'],b.PRODUCTION_SCHEMA)

    def test_installer_and_runtime_select_same_production_provider(self):
        from test_file_install import x
        obj=self.candidate()
        before=x.Preflight(obj,{'external_existing_inputs':{}},io=FakeIO(obj['host_policy']),clock=lambda:10)
        self.assertIsInstance(before.host,h.ProductionHostProvider)
        from test_approved_bundle import Pins
        pins=Pins(obj);loaded=b.load_bundle('/etc/bundle.json',pins.sha,LABEL,30,io=pins,clock=lambda:10)
        from test_state_executor import MemoryStore
        with patch.object(b,'host_provider',wraps=h.host_provider) as factory,patch.object(b,'ProtectedStore',return_value=MemoryStore()):
            components=b.build(loaded,30,clock=lambda:10)
        self.assertEqual(factory.call_count,1)
        self.assertIsInstance(components['executor'].backend.host_provider.base,h.ProductionHostProvider)


class ProductionLifecycleTests(unittest.TestCase):
    def setup_components(self):
        from test_state_executor import MemoryStore
        from harbor_recovery_executor import Executor
        f=NetworkFixture(running=(*c.ORDER,'log'));plan=f.plan();core=c.Controller(plan)
        store=MemoryStore()
        backend=d.DockerBackend(plan,f.engine,f.host,f.host.binding,'harbor',clock=lambda:10,probe=lambda _:True)
        store.state=core.arm(c.State(),backend.observe(),10).state
        executor=Executor(core,store,backend,clock=lambda:10,gate=lambda:None)
        return f,core,store,executor

    def test_new_boot_restarts_existing_ids_in_order_without_reenrolling(self):
        f,core,store,executor=self.setup_components()
        f.io.stamp['boot']='23456789-1234-1234-1234-123456789abc';running=['log'];f.running(running)
        calls=[]
        def start(cid,deadline):
            calls.append(cid);name=next(s for s,i in f.engine.ids.items() if i==cid)
            running.append(name);f.running(running);return 'ok'
        f.engine.start=start;executor.open()
        for _ in range(22):executor.tick()
        self.assertEqual(calls,[f.engine.ids[s] for s in c.ORDER])
        self.assertEqual(store.state.desired,'RUN')
        self.assertIsNone(store.state.pending);self.assertIsNone(store.state.health_wait)

    def test_h6_reverse_stop_through_real_production_host_preserves_logger(self):
        from harbor_recovery_control import OperatorControl,state_hash
        from test_operator_control import Ledger
        from types import SimpleNamespace
        f,core,store,executor=self.setup_components();running=list(f.engine.ids);calls=[];ledger=Ledger()
        def stop(cid,deadline):
            self.assertEqual(store.state.desired,'HOLD')
            calls.append(cid);running.remove(next(s for s,i in f.engine.ids.items() if i==cid))
            f.running(running);return 'ack'
        control=OperatorControl(executor,lambda _:None,SimpleNamespace(stop=stop),ledger=ledger,
                                lease=lambda:nullcontext(),clock=lambda:10)
        result=control.stop(state_hash(store.state),100,per_container_seconds=30,explicit=True)
        self.assertEqual(result.reason,'APPS_STOPPED_LOGGER_PRESERVED')
        self.assertEqual(calls,[f.engine.ids[s] for s in reversed(c.ORDER)])
        self.assertEqual(running,['log']);self.assertEqual(len(ledger.receipts),9)

    def test_h6_unknown_stops_sequence_and_cannot_be_replayed(self):
        from harbor_recovery_control import OperatorControl,state_hash
        from test_operator_control import Ledger
        from types import SimpleNamespace
        f,core,store,executor=self.setup_components();calls=[];ledger=Ledger()
        def unknown(cid,deadline):calls.append(cid);raise TimeoutError('synthetic')
        control=OperatorControl(executor,lambda _:None,SimpleNamespace(stop=unknown),ledger=ledger,
                                lease=lambda:nullcontext(),clock=lambda:10)
        result=control.stop(state_hash(store.state),100,per_container_seconds=30,explicit=True)
        self.assertEqual(result.reason,'STOP_INTERRUPTED_OR_UNKNOWN');self.assertEqual(len(calls),1)
        with self.assertRaisesRegex(ValueError,'STOP_UNRESOLVED'):
            control.stop(state_hash(store.state),100,per_container_seconds=30,explicit=True)
        self.assertEqual(len(calls),1);self.assertEqual(len(ledger.acks),0)


if __name__=='__main__':unittest.main()
