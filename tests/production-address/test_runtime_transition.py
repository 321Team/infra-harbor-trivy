"""Synthetic reproduction of r2 transitions; no production inputs or Docker."""
from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/production'),str(ROOT/'scripts/recovery')]
import harbor_address_sequence as seq
import harbor_address_compose as compose
import harbor_address_network as net
import harbor_address_host as host
import harbor_address_session as session
import test_sequence as sq
import test_compose_backend as cb
import test_protected_runtime as rt


def plan_v2():
    p=sq.fixture()
    p.update(schema=seq.TRANSITION_SCHEMA,recreate_seconds={s:240 for s in seq.ORDER},
             db_shutdown={'strategy':'preserve-smart','effective_signal':'SIGTERM',
                          'on_timeout':'stop-and-handoff-no-retry'})
    p['io_seconds']=20
    p['health_seconds']={s:120 for s in seq.ORDER}
    for r in p['baseline'].values():
        r.update(status='running',health='healthy',exit_code=0,error_sha256=seq.hashlib.sha256(b'').hexdigest())
    return p


class BudgetTests(unittest.TestCase):
    def setup_run(self,p=None):
        self.p=p or plan_v2();self.j=sq.MemoryJournal();self.b=sq.Backend(self.p,self.j)
        self.s=seq.Sequence(self.p,self.b,self.j,clock=self.b.clock,sleep=self.b.sleep)
    def test_slow_smart_shutdown_is_not_limited_to_read_budget(self):
        self.setup_run();self.b.delay=178
        result=self.s.run(deadline_mono=2000)
        self.assertEqual(result['reason'],'COMPLETE')
        self.assertEqual(self.b.calls,list(seq.ORDER))
    def test_health_gets_full_budget_after_timely_recreate_ack(self):
        self.setup_run();self.b.delay=178;self.b.health='starting';ack=[None]
        original=self.b.recreate
        def recreate(**kw):
            result=original(**kw);ack[0]=self.b.time;return result
        self.b.recreate=recreate
        def observed(o):
            if ack[0] is not None and self.b.time>=ack[0]+90:
                for r in self.b.rows.values():r['health']='healthy'
                o['rows']=deepcopy(self.b.rows)
        self.b.on_read=observed
        self.assertEqual(self.s.run(deadline_mono=3000)['reason'],'COMPLETE')
    def test_absolute_end_does_not_expand_with_per_service_budgets(self):
        self.setup_run();self.b.delay=178
        result=self.s.run(deadline_mono=100)
        self.assertEqual(result['status'],'STOP_RECOVERY_REQUIRED')
        self.assertEqual(self.b.calls,['postgresql'])
        self.assertEqual(self.j.records[-2]['outcome'],'LATE')
    def test_late_daemon_shutdown_never_triggers_retry(self):
        self.setup_run();self.b.exception=TimeoutError('simulated CLI expired')
        result=self.s.run(deadline_mono=2000)
        self.assertEqual(result['reason'],'RECREATE_OUTCOME_UNKNOWN')
        # Delayed daemon shutdown after the collector's first healthy snapshot.
        self.b.rows['postgresql'].update(status='exited',health='unhealthy')
        self.assertEqual(result['status'],'STOP_RECOVERY_REQUIRED')
        self.assertTrue(result['this_invocation_may_have_changed'])
        with self.assertRaisesRegex(seq.Stop,'SPENT'):self.s.run(deadline_mono=2100)
        self.assertEqual(self.b.calls,['postgresql'])
    def test_missing_invalid_or_unreviewed_transition_inputs_rejected(self):
        mutations=[lambda p:p.pop('recreate_seconds'),lambda p:p['recreate_seconds'].pop('proxy'),
            lambda p:p['recreate_seconds'].update(postgresql=True),
            lambda p:p['recreate_seconds'].update(postgresql=float('inf')),
            lambda p:p['recreate_seconds'].update(postgresql=0),
            lambda p:p['db_shutdown'].update(effective_signal='SIGINT'),
            lambda p:p['db_shutdown'].update(on_timeout='retry'),
            lambda p:p.pop('db_shutdown')]
        for change in mutations:
            p=plan_v2();change(p)
            with self.subTest(p=p['schema']),self.assertRaises(ValueError):seq.validate_plan(p)
    def test_render_and_prewrite_remain_bounded_by_read_budget(self):
        f=cb.fixture();tick=[10.];calls=[]
        class Process:
            def call(self,operation,model,**kw):
                calls.append((operation,kw['deadline']))
                tick[0]+=21
                return 0
        ids={s:r['Id'] for s,r in f['before'].items()}
        transport=compose.ComposeTransport(f['model'],model_sha256=seq.fingerprint(f['model']),
            plan_sha256='a'*64,ids=ids,process=Process(),verify=lambda d:ids,
            clock=lambda:tick[0],preflight_seconds=20)
        with self.assertRaisesRegex(ValueError,'DEADLINE'):
            transport.recreate(service='postgresql',expected_id=ids['postgresql'],plan_sha256='a'*64,deadline_mono=250)
        self.assertEqual(calls,[('render',30.)])
    def test_prewrite_timeout_never_reaches_mutation(self):
        f=cb.fixture();tick=[10.];calls=[]
        class Process:
            def call(self,operation,model,**kw):
                calls.append(operation);tick[0]+=5;return 0
        ids={s:r['Id'] for s,r in f['before'].items()}
        def verify(deadline):
            self.assertEqual(deadline,30.);tick[0]=31.;return ids
        transport=compose.ComposeTransport(f['model'],model_sha256=seq.fingerprint(f['model']),
            plan_sha256='a'*64,ids=ids,process=Process(),verify=verify,
            clock=lambda:tick[0],preflight_seconds=20)
        with self.assertRaisesRegex(ValueError,'DEADLINE'):
            transport.recreate(service='postgresql',expected_id=ids['postgresql'],plan_sha256='a'*64,deadline_mono=250)
        self.assertEqual(calls,['render'])
    def test_transition_package_binds_new_host_and_preserved_db_signal(self):
        values=rt.host_fixture()['package']
        p=values['plan.json'];new=plan_v2()
        p.update({k:new[k] for k in ('schema','recreate_seconds','db_shutdown')})
        policy=values['host-policy.json'];policy.update(schema='fds.harbor.production-address-host.v3',bind_sources={})
        for key in ('base.json','candidate.json'):
            for row in values[key]['services'].values():row['volumes']=[]
        values['model.json']=compose.execution_model(values['base.json'],values['candidate.json'],
            resource_names={'networks':{'default':'harbor_default'},'volumes':{}},
            legacy_bindings={s:[] for s in seq.SERVICES})
        p['binding_sha256']=seq.fingerprint(policy)
        values['profile.json']['host_binding_sha256']=p['binding_sha256']
        session.assemble(values)
        # Rebind the complete synthetic fixture so the rejection is specifically
        # the new shutdown contract, not a stale hash elsewhere.
        for signal in ('SIGINT','SIGQUIT'):
            bad=deepcopy(values)
            for key in ('base.json','candidate.json','model.json'):
                bad[key]['services']['postgresql']['stop_signal']=signal
            with self.assertRaisesRegex(ValueError,'DB_SHUTDOWN_MISMATCH'):session.assemble(bad)
        policy['schema']='fds.harbor.production-address-host.v2'
        p['binding_sha256']=seq.fingerprint(policy)
        values['profile.json']['host_binding_sha256']=p['binding_sha256']
        with self.assertRaisesRegex(ValueError,'TRANSITION_HOST_REQUIRED'):session.assemble(values)
    def test_old_actual_package_refused_before_evidence_or_claim(self):
        values=rt.host_fixture()['package']
        args=dict(package_path='/synthetic/p',journal_path='/synthetic/j',evidence_path='/synthetic/e',
            private_path='/synthetic/t',package_sha256='a'*64,package_context=b'x',journal_context=b'x',
            evidence_context=b'x',private_context=b'x',preparation_deadline=100)
        with patch.object(session,'load_package',return_value=values),patch.object(session,'Evidence') as evidence:
            with self.assertRaisesRegex(ValueError,'TRANSITION_PLAN_REQUIRED'):session.ProtectedSession(**args)
            evidence.assert_not_called()


def routes_for(link):
    octets=bytearray.fromhex(link['address'].replace(':',''));octets[0]^=2
    eui=octets[:3]+bytes([255,254])+octets[3:]
    addr=str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('fe80::'))|int.from_bytes(eui,'big')))
    common=dict(dev=link['ifname'],protocol='kernel',flags=[],pref='medium')
    return [dict(common,dst='fe80::/64',metric=256),
            dict(common,type='local',dst=addr,table='local',metric=0),
            dict(common,type='multicast',dst='ff00::/8',table='local',metric=256)]


def topology():
    bridge=dict(ifindex=2,ifname='br-synthetic',linkinfo={'info_kind':'bridge'})
    hostlink=dict(ifindex=30,ifname='vethsynthetic',address='6e:20:5f:22:f3:30',
                  link_index=7,master=bridge['ifname'],linkinfo={'info_kind':'veth'})
    peer=dict(ifindex=7,ifname='eth0',address='02:42:ac:12:00:02',link_index=30,linkinfo={'info_kind':'veth'})
    return [bridge,hostlink],{'a'*64:peer['address']},{'a'*64:[peer]}


class NetworkProjectionTests(unittest.TestCase):
    def test_counter_transition_preserves_config_unknown_fields_and_input(self):
        old=dict(Id='a'*64,Containers={},Peers=[],Status={'IPAM':{'Subnets':{
            '172.18.0.0/16':{'IPsInUse':13,'DynamicIPsAvailable':65523,'Unknown':'keep'}}}},
            IPAM={'Config':[{'Subnet':'172.18.0.0/16'}]},Future={'keep':True})
        original=deepcopy(old);new=deepcopy(old)
        new['Status']['IPAM']['Subnets']['172.18.0.0/16'].update(IPsInUse=12,DynamicIPsAvailable=65524)
        self.assertEqual(net.network_projection(old),net.network_projection(new));self.assertEqual(old,original)
        for change in (lambda r:r['Future'].update(keep=False),
                       lambda r:r['Status']['IPAM']['Subnets']['172.18.0.0/16'].update(Unknown='changed'),
                       lambda r:r['IPAM']['Config'][0].update(Subnet='10.2.0.0/16')):
            changed=deepcopy(new);change(changed)
            self.assertNotEqual(net.network_projection(old),net.network_projection(changed))
        for bad in (True,-1,'12',None):
            changed=deepcopy(old);changed['Status']['IPAM']['Subnets']['172.18.0.0/16']['IPsInUse']=bad
            with self.assertRaises(ValueError):net.network_projection(changed)
    def test_proven_peer_rename_and_kernel_routes_do_not_change_stable_hash(self):
        links,endpoints,peers=topology()
        fixed=[dict(dst='default',dev='ens160',gateway='10.0.0.1')]
        owned=net.owned_links(links,endpoints,peers,bridge='br-synthetic')
        self.assertEqual(net.route_projection(fixed+routes_for(links[1]),owned),fixed)
        links[1].update(ifname='vethnew',ifindex=31,address='6e:20:5f:22:f3:40')
        peers['a'*64][0]['link_index']=31
        owned=net.owned_links(links,endpoints,peers,bridge='br-synthetic')
        self.assertEqual(net.route_projection(routes_for(links[1])+fixed,owned),fixed)
    def test_name_count_or_bridge_only_is_not_ownership(self):
        changes=[lambda l,e,p:l[1].update(master='other'),
                 lambda l,e,p:l[1].update(link_index=8),
                 lambda l,e,p:p['a'*64][0].update(link_index=99),
                 lambda l,e,p:p['a'*64][0].update(address='02:42:ac:12:00:03'),
                 lambda l,e,p:l.append(dict(ifindex=40,ifname='rogue',master='br-synthetic')),
                 lambda l,e,p:l[1].update(linkinfo={'info_kind':'dummy'})]
        for change in changes:
            l,e,p=topology();change(l,e,p)
            with self.subTest(change=change),self.assertRaises(ValueError):
                net.owned_links(l,e,p,bridge='br-synthetic')
    def test_extra_gateway_local_address_flags_or_missing_route_refused(self):
        l,e,p=topology();owned=net.owned_links(l,e,p,bridge='br-synthetic')
        changes=[lambda r:r[0].update(gateway='fe80::1'),
                 lambda r:r[1].update(dst='fe80::99'),
                 lambda r:r[0].update(flags=['linkdown']),
                 lambda r:r.pop(),lambda r:r.append(deepcopy(r[0])),
                 lambda r:r.append(dict(dst='default',dev='vethsynthetic'))]
        for change in changes:
            rows=routes_for(l[1]);change(rows)
            with self.subTest(change=change),self.assertRaises(ValueError):net.route_projection(rows,owned)
    def test_unowned_routes_and_management_routes_remain_visible(self):
        l,e,p=topology();owned=net.owned_links(l,e,p,bridge='br-synthetic')
        extra=[dict(dst='default',dev='ens160',gateway='10.0.0.1'),
               dict(dst='fe80::/64',dev='vethunowned',protocol='kernel',metric=256,flags=[],pref='medium')]
        result=net.route_projection(routes_for(l[1])+extra,owned)
        self.assertEqual({seq.fingerprint(r) for r in result},{seq.fingerprint(r) for r in extra})


class HostTransitionTests(unittest.TestCase):
    def setUp(self):
        self.h=rt.HostTests();self.h.setUp();h=self.h
        p=h.x['policy'];p.update(schema='fds.harbor.production-address-host.v3',bind_sources={},
            network_scope={'harbor_default':{'id':'c'*64,'bridge':'br-synthetic'}})
        p['tools']['nsenter']=dict(p['tools']['ip'],path='/synthetic/bin/nsenter')
        network=h.data['network']
        network.update(Options={'com.docker.network.bridge.name':'br-synthetic'},
            Status={'IPAM':{'Subnets':{'172.20.0.0/16':{'IPsInUse':13,'DynamicIPsAvailable':65523}}}})
        self.links=[dict(ifname='br-synthetic',ifindex=2,linkinfo={'info_kind':'bridge'})]
        self.peers={};self.routes=[dict(dst='default',dev='ens160',gateway='10.0.0.1')]
        for n,(service,raw) in enumerate(h.engine.rows.items()):
            cid=raw['Id'];mac=f'02:42:ac:14:00:{n+2:02x}'
            endpoint=raw['NetworkSettings']['Networks']['harbor_default']
            endpoint.update(NetworkID='c'*64,EndpointID=f'{n+1:064x}',MacAddress=mac)
            raw['State'].update(Pid=100+n)
            network['Containers'][cid]={'EndpointID':endpoint['EndpointID'],'MacAddress':mac}
            l=dict(ifindex=30+n,ifname=f'veth{n}',address=f'6e:20:5f:22:f3:{n:02x}',link_index=7,
                   master='br-synthetic',linkinfo={'info_kind':'veth'})
            self.links.append(l);self.routes+=routes_for(l)
            self.peers[100+n]=[dict(ifindex=7,ifname='eth0',address=mac,link_index=30+n,linkinfo={'info_kind':'veth'})]
        p['routes_sha256']=seq.fingerprint([self.routes[0]])
        p['resources']['networks']['harbor_default']=seq.fingerprint(net.network_projection(network))
        h.x['f']['profile']['host_binding_sha256']=seq.fingerprint(p)
        h.x['f']['plan']['binding_sha256']=seq.fingerprint(p)
        h.data['package']['host-policy.json']=deepcopy(p);h.data['package']['profile.json']=deepcopy(h.x['f']['profile'])
        h.data['package']['plan.json']=deepcopy(h.x['f']['plan'])
        original=h.io.command
        def command(tool,args,deadline):
            if tool['path'].endswith('/ip') and 'route' in args:return 0,json.dumps(self.routes).encode()
            if tool['path'].endswith('/ip') and 'link' in args:return 0,json.dumps(self.links).encode()
            return original(tool,args,deadline)
        h.io.command=command;h.io.peer_links=lambda pid,tools,d:deepcopy(self.peers[pid])
        h.host=host.ProductionHost(p,profile=h.x['f']['profile'],package_path='/synthetic/package',
            package_sha256='a'*64,package_context=b'synthetic_t',model_sha256=seq.fingerprint(h.x['f']['model']),
            preservation_binding=seq.fingerprint(h.x['package']['preservation.json']),engine=h.engine,io=h.io,clock=lambda:10.)
    def test_real_guard_path_accepts_owned_peer_rotation_and_counter_change(self):
        self.h.read()
        self.h.data['network']['Status']['IPAM']['Subnets']['172.20.0.0/16'].update(IPsInUse=12,DynamicIPsAvailable=65524)
        link=self.links[1];old=link['ifname'];link.update(ifindex=91,ifname='vethreplacement',address='6e:20:5f:22:f3:ff')
        self.peers[100][0]['link_index']=91
        self.routes=[r for r in self.routes if r.get('dev')!=old]+routes_for(link)
        self.h.read()
    def test_rogue_endpoint_duplicate_service_config_or_physical_route_block(self):
        changes=[lambda:hset(self.h.data['network']['Containers'],'f'*64,{}),
            lambda:self.h.data['network'].update(Driver='overlay'),
            lambda:self.routes[0].update(gateway='10.0.0.2'),
            lambda:self.h.engine.rows['core']['State'].update(Pid=999),
            lambda:self.links[1].update(master='different')]
        for change in changes:
            with self.subTest(change=change):
                self.setUp();change()
                with self.assertRaises((ValueError,KeyError)):self.h.read()
    def test_running_container_pid_change_during_peer_read_blocks(self):
        original=self.h.io.peer_links
        def changed(pid,tools,d):
            result=original(pid,tools,d)
            for raw in self.h.engine.rows.values():
                if raw['State']['Pid']==pid:raw['State']['Pid']+=1000;break
            return result
        self.h.io.peer_links=changed
        with self.assertRaisesRegex(ValueError,'CONTAINER_CHANGED'):self.h.read()


def hset(mapping,key,value):
    mapping[key]=value


if __name__=='__main__':
    unittest.main()
