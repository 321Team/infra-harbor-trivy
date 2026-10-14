"""Synthetic boot drift, failure injection and v4 package contract; no host writes."""
from copy import deepcopy
import importlib
import unittest
from unittest.mock import patch

import test_daemon_lifecycle_contract as lifecycle
from test_production_recovery import BRIDGE, NID
from test_host_provider import raw, LABEL
from test_state_executor import MemoryStore
import harbor_recovery_host as h
import harbor_recovery_docker as d
import harbor_recovery_bundle as b
import harbor_recovery_core as c
from harbor_recovery_executor import Executor


def bridge_details(row):
    row.update(link_type='ether', inet6_addr_gen_mode='eui64', mtu=1500)
    data = row['linkinfo'].setdefault('info_data', {})
    data.update(stp_state=0, priority=32768, root_port=0, root_path_cost=0,
                bridge_id='8000.'+row['address'], root_id='8000.'+row['address'])


def bridge_routes(link):
    common=dict(dev=link['ifname'], protocol='kernel', flags=[], pref='medium')
    return [dict(common, dst='fe80::/64', metric=256),
            dict(common, type='local', dst=h._net_link_local(link), table='local', metric=0),
            dict(common, type='multicast', dst='ff00::/8', table='local', metric=256)]


class BootFixture(lifecycle.LifecycleFixture):
    def __init__(self, running=('log',)):
        super().__init__(running)
        bridge_details(self.links[2]); bridge_details(self.default_link)
        self.bridge_mode={BRIDGE:'eui64', 'docker0':'absent'}
        self.stable.extend(bridge_routes(self.links[2]))
        self.running(running)
        self.policy['version']=4
        self.policy['network']['bridge_ipv6']=deepcopy(self.bridge_mode)
        self.policy['network']['interfaces']={r['ifname']:d.digest(h.production_link_projection(
            r, bridge=r['ifname'] in self.bridge_mode, version=4))
            for r in self.links if r['ifname'] in self.policy['network']['interfaces']}
        self.policy['network']['routes_sha256']=d.digest(h.production_bridge_route_projection(
            self.stable,self.links,self.addresses,self.bridge_mode))
        self.host=h.host_provider(self.policy,self.engine,io=self.io,clock=lambda:10,network_reader=self.reader)

    def running(self, services):
        super().running(services)
        if hasattr(self, 'bridge_mode'):
            link=self.links[2]
            self.addresses.append(dict(ifindex=link['ifindex'],ifname=BRIDGE,
                addr_info=[dict(family='inet6',scope='link',prefixlen=64,local=h._net_link_local(link))]))

    def reboot(self):
        self.io.stamp['boot']='23456789-1234-1234-1234-123456789abc'
        self.links[2]['address']='76:b9:c8:0b:c2:94'
        self.default_link['address']='92:56:59:51:44:b4'
        bridge_details(self.links[2]);bridge_details(self.default_link)
        self.stable=[r for r in self.stable if not (r.get('dev')==BRIDGE and ':' in r.get('dst',''))]
        self.stable.extend(bridge_routes(self.links[2]))
        self.reload()


class BootBridgeTests(unittest.TestCase):
    def reject(self,f):
        with self.assertRaisesRegex(ValueError,'^HOST_VERIFICATION_FAILED$'):f.read()
        self.assertEqual(f.engine.posts,[])

    def test_new_boot_both_bridge_macs_eui64_and_daemon_change_recover_once(self):
        f=BootFixture(running=(*c.ORDER,'log'));plan=f.plan();core=c.Controller(plan);store=MemoryStore()
        backend=d.DockerBackend(plan,f.engine,f.host,f.host.binding,'harbor',fingerprint_version=2,
                                clock=lambda:10,probe=lambda _:True)
        before=backend.observe();store.state=core.arm(c.State(),before,10).state
        f.reboot();after=backend.observe()
        self.assertNotEqual(before.boot,after.boot);self.assertNotEqual(before.daemon,after.daemon)
        self.assertTrue(before.guards_ok and after.guards_ok)
        running=['log'];calls=[]
        def start(cid,deadline):
            calls.append(cid);running.append(next(s for s,i in f.engine.ids.items() if i==cid));f.running(running)
            return 'ok'
        f.engine.start=start
        executor=Executor(core,store,backend,clock=lambda:10,gate=lambda:None);executor.open()
        for _ in range(35):executor.tick()
        self.assertEqual(calls,[f.engine.ids[s] for s in c.ORDER]);self.assertEqual(len(store.claims),9)
        self.assertEqual(store.state.desired,'RUN');self.assertIsNone(store.state.pending);self.assertIsNone(store.state.health_wait)
        reopened=Executor(core,store,backend,clock=lambda:10,gate=lambda:None);reopened.open()
        for _ in range(10):reopened.tick()
        self.assertEqual(len(calls),9)

    def test_full_stop_partial_and_all_running_share_same_binding(self):
        f=BootFixture();binding=f.read().binding;f.reboot()
        for running in ([],['log'],['log','postgresql'],list(f.engine.ids)):
            f.running(running);self.assertEqual(f.read().binding,binding)

    def test_legacy_projection_stays_mac_sensitive_and_input_is_not_modified(self):
        f=BootFixture();row=deepcopy(f.links[2]);before=deepcopy(row)
        legacy=h.production_link_projection(row,bridge=True)
        new=h.production_link_projection(row,bridge=True,version=4)
        self.assertEqual(row,before)
        row['address']='76:b9:c8:0b:c2:94';bridge_details(row)
        row['linkinfo']['info_data'].update(bridge_id='8000.76:b9:c8:b:c2:94',root_id='8000.76:b9:c8:b:c2:94')
        self.assertNotEqual(legacy,h.production_link_projection(row,bridge=True))
        self.assertEqual(new,h.production_link_projection(row,bridge=True,version=4))
        self.assertEqual(legacy,h.production_link_projection(before,bridge=True,version=2))

    def test_bridge_and_physical_configuration_drift_still_rejected(self):
        changes=[lambda f:f.links[1].update(address='02:00:00:00:00:99'),
            lambda f:f.links[2].update(mtu=9000),lambda f:f.links[2].update(address='01:00:00:00:00:03'),
            lambda f:f.links[2].update(address='00:00:00:00:00:03'),
            lambda f:f.links[2].update(inet6_addr_gen_mode='stable_secret'),
            lambda f:f.links[2]['linkinfo']['info_data'].update(stp_state=1),
            lambda f:f.links[2]['linkinfo']['info_data'].update(root_port=1),
            lambda f:f.links[2]['linkinfo']['info_data'].update(root_path_cost=2),
            lambda f:f.links[2]['linkinfo']['info_data'].update(root_id='8000.02:00:00:00:00:99'),
            lambda f:f.links[2]['linkinfo']['info_data'].update(priority=1),
            lambda f:f.links[2]['linkinfo']['info_data'].update(bridge_id='broken'),
            lambda f:f.links[2].update(unknown_setting=True),
            lambda f:f.routes[0].update(gateway='192.0.2.99'),
            lambda f:f.network.update(IPAM={'Config':[{'Subnet':'172.20.0.0/16'}]}),
            lambda f:f.default['Containers'].update({'f'*64:{}}),
            lambda f:f.links.append(dict(ifindex=90,ifname='foreign',master=BRIDGE,linkinfo={'info_kind':'veth'}))]
        for i,change in enumerate(changes):
            with self.subTest(i=i):f=BootFixture();change(f);self.reject(f)

    def test_ipv6_dad_transition_is_proven_not_a_missing_route_exception(self):
        f=BootFixture();before=f.read().binding
        address=f.addresses[-1]['addr_info'][0];address['tentative']=True
        f.routes=[r for r in f.routes if not (r.get('dev')==BRIDGE and r.get('type')=='local')]
        self.assertEqual(f.read().binding,before)
        address['tentative']=False;self.reject(f)

    def test_ipv6_address_route_modes_and_unknown_metadata_rejected(self):
        changes=[lambda f:f.addresses[-1]['addr_info'][0].update(dadfailed=True),
            lambda f:f.addresses[-1]['addr_info'][0].update(optimistic=True),
            lambda f:f.addresses[-1]['addr_info'][0].update(local='fe80::dead'),
            lambda f:f.addresses[-1]['addr_info'][0].update(prefixlen=128),
            lambda f:f.addresses[-1]['addr_info'].append(deepcopy(f.addresses[-1]['addr_info'][0])),
            lambda f:f.addresses.pop(),
            lambda f:f.routes.append(dict(dev=BRIDGE,dst='fe80::dead',protocol='static')),
            lambda f:f.routes.append(dict(dev='docker0',dst='fe80::/64',protocol='kernel')),
            lambda f:f.routes.append(deepcopy(f.stable[-1])),
            lambda f:f.addresses.append(dict(ifindex=4,ifname='docker0',addr_info=[dict(local='fe80::1')]))]
        for kind in ('prefix','local','multicast'):
            def metadata(f,kind=kind):
                row=next(r for r in f.routes if r.get('dev')==BRIDGE and
                         (r.get('type')==kind if kind!='prefix' else r.get('dst')=='fe80::/64'))
                row['extra']=True
            changes.append(metadata)
        for i,change in enumerate(changes):
            with self.subTest(i=i):f=BootFixture();change(f);self.reject(f)

    def test_invalid_modes_and_legacy_schema_cannot_opt_in(self):
        for modes in ({}, {BRIDGE:'eui64'}, {BRIDGE:'auto','docker0':'absent'},
                      {BRIDGE:True,'docker0':'absent'}, {BRIDGE:'eui64','docker0':'absent','ens33':'eui64'}):
            f=BootFixture();f.policy['network']['bridge_ipv6']=modes
            with self.assertRaises(ValueError):h.validate_policy(f.policy)
        f=BootFixture();f.policy['version']=3
        with self.assertRaisesRegex(ValueError,'NETWORK_SCHEMA'):h.validate_policy(f.policy)

    def test_route_drift_after_first_start_holds_without_next_claim(self):
        f=BootFixture(running=(*c.ORDER,'log'));plan=f.plan();core=c.Controller(plan);store=MemoryStore()
        backend=d.DockerBackend(plan,f.engine,f.host,f.host.binding,'harbor',fingerprint_version=2,
                                clock=lambda:10,probe=lambda _:True)
        store.state=core.arm(c.State(),backend.observe(),10).state;f.reboot();calls=[]
        def start(cid,deadline):
            calls.append(cid);f.running(['log','postgresql']);f.routes[0]['gateway']='192.0.2.99';return 'ok'
        f.engine.start=start
        executor=Executor(core,store,backend,clock=lambda:10,gate=lambda:None);executor.open()
        for _ in range(12):executor.tick()
        self.assertEqual(calls,[f.engine.ids['postgresql']]);self.assertEqual(len(store.claims),1)
        self.assertEqual(store.state.desired,'HOLD')


class BootPackageTests(unittest.TestCase):
    def fixture(self):
        fixture=lifecycle.LifecyclePackageTests().fixture();obj=fixture.obj;f=BootFixture()
        obj['schema']=b.BOOT_SCHEMA;obj['host_policy']['version']=4
        obj['host_policy']['network']=deepcopy(f.policy['network'])
        obj['host_policy']['network']['ids']=deepcopy(obj['plan']['ids'])
        obj['plan']['execution_binding']=d.execution_binding(b.bound_host_digest(obj),'harbor',
            d.UnixEngine(obj['host_policy']['api_version'],socket_path=obj['host_policy']['socket']).binding,fingerprint_version=2)
        return fixture

    def test_v4_flows_through_package_bootstrap_preflight_and_runtime(self):
        from test_review_package import x
        from test_review_package_check import x as checker
        from test_verified_bootstrap import Reader,x as boot,BUNDLE,clean_project_imports
        from test_approved_bundle import Pins
        from test_file_install import x as install
        from test_host_provider import FakeIO
        fixture=self.fixture();obj=fixture.obj;files,plan=fixture.prepare()
        self.assertEqual(checker.verify_bytes(files,x.sha(files['INSTALL_PLAN.json']))['status'],'PACKAGE_BYTES_VERIFIED')
        self.assertIn('network-online.target',files['manager.service'].decode())
        reader=Reader(deepcopy(obj),actual=True)
        code,_=boot.collect(BUNDLE,reader.sha,LABEL,30,reader=reader,clock=lambda:10)
        with clean_project_imports(),boot.VerifiedImporter(code):
            module=importlib.import_module('harbor_recovery_bundle')
            self.assertEqual(module.fingerprint_version(module.parse_bundle(raw(reader.obj))),2)
        self.assertEqual(install.Preflight(obj,{'external_existing_inputs':{}},io=FakeIO(obj['host_policy']),clock=lambda:10).host._policy['version'],4)
        pins=Pins(obj);loaded=b.load_bundle('/etc/bundle.json',pins.sha,LABEL,30,io=pins,clock=lambda:10)
        with patch.object(b,'ProtectedStore',return_value=MemoryStore()):parts=b.build(loaded,30,clock=lambda:10)
        self.assertEqual(parts['executor'].backend.fingerprint_version,2)
        self.assertEqual(parts['transition'].backend.fingerprint_version,2)

    def test_mismatched_schema_and_host_cannot_prepare_or_bootstrap(self):
        from test_verified_bootstrap import Reader,x as boot,BUNDLE
        for schema in (b.SCHEMA,b.PRODUCTION_SCHEMA,b.LIFECYCLE_SCHEMA):
            fixture=self.fixture();fixture.obj['schema']=schema
            with self.assertRaises(ValueError):fixture.prepare()
            reader=Reader(fixture.obj,actual=True)
            with self.assertRaisesRegex(ValueError,'HOST_SCOPE'):
                boot.collect(BUNDLE,reader.sha,LABEL,30,reader=reader,clock=lambda:10)


if __name__=='__main__':unittest.main()
