"""PR55 review regressions. SYNTHETIC platform, real v2+v3 constructor/call graph.

No guest/Docker or real package values. File/engine/process primitives are doubles;
Linux kernel tests separately exercise real pinned namespace and _routes reads.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import json
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/production'),str(ROOT/'scripts/recovery')]
import harbor_address_network as net
import harbor_address_host as host
import harbor_address_sequence as seq
import harbor_address_session as session
import harbor_address_compose as compose
import harbor_address_journal as journal
import harbor_address_evidence as evidence
import harbor_address_inspect as inspect
import test_runtime_transition as t
import test_sequence as sq
import test_compose_backend as cb


class MemoryEvidence:
    def __init__(self,path,**kw):
        self.path=path;self.records=[];self.failed=False;self.used=False
    @contextmanager
    def locked(self,deadline):
        if self.used:raise FileExistsError('EVIDENCE_SPENT')
        self.used=True;self.deadline=deadline
        yield self
    def save(self,**kw):
        self.records.append(deepcopy(kw))


class ConstructorFixture:
    def __init__(self):
        self.fixture=t.HostTransitionTests();self.fixture.setUp()
        self.h=self.fixture.h;self.time=10.;self.calls=[];self.sleeps=[]
        self.on_render=lambda:None;self.on_write=lambda service:None;self.on_sleep=lambda:None
        self.journal=sq.MemoryJournal()
        append=self.journal.append
        self.journal.append=lambda event:append(journal.validate_event(event))
        values=deepcopy(self.h.data['package'])
        for key in ('base.json','candidate.json'):
            for row in values[key]['services'].values():row['volumes']=[]
        values['model.json']=compose.execution_model(values['base.json'],values['candidate.json'],
            resource_names={'networks':{'default':'harbor_default'},'volumes':{}},
            legacy_bindings={s:[] for s in seq.SERVICES})
        projection=values['preservation.json']
        projection['baseline']=deepcopy(self.h.engine.rows)
        full=inspect.FullPreservation(projection['baseline'],after_labels=projection['after_labels'],
            after_host_mounts=projection['after_host_mounts'],auto_hostnames=projection['auto_hostnames'],
            auto_addresses=projection['auto_addresses'])
        plan=values['plan.json']
        transition=t.plan_v2()
        plan.update({k:transition[k] for k in ('schema','recreate_seconds','db_shutdown','io_seconds','health_seconds')})
        plan['baseline']={s:full.row(s,r,recreated=False,mounts_verified=r['Mounts']) for s,r in projection['baseline'].items()}
        policy=values['host-policy.json']
        self.path_for=lambda value:'/synthetic/source/'+Path(value).name
        for value in [sys.modules[n].__file__ for n in session.SOURCE_MODULES]+[sys.executable]:
            policy['pinned_files'][self.path_for(value)]={'mode':0o755,'gid':0,'selinux':'synthetic_t','sha256':'a'*64}
        plan['binding_sha256']=seq.fingerprint(policy)
        values['profile.json']['host_binding_sha256']=plan['binding_sha256']
        self.values=values;self.plan=plan
        self.h.data['package']=deepcopy(values)
        self.h.data['policy']=deepcopy(policy)
        self.f=self.h.x['f']
        self.f['before']=deepcopy(projection['baseline'])
        self.f['model']=values['model.json']
        self.fixture.pending=set()
        self.io_calls=0
        original=self.h.io.command
        def command(tool,args,deadline):
            self.io_calls+=1
            rc,raw=original(tool,args,deadline)
            if tool['path'].endswith('/ip') and 'link' in args:
                links=json.loads(raw)
                links[0]['linkinfo']['info_data']={'gc_timer':300-self.io_calls/10000,'vlan_filtering':0}
                return rc,json.dumps(links).encode()
            return rc,raw
        self.h.io.command=command
        outer=self
        class Process:
            def __init__(self,**kw):self.audit=None
            def call(self,operation,model,*,deadline,service=None):
                outer.calls.append((operation,service,deadline))
                self.audit('PROCESS_INTENT',operation,service,{}, {},deadline)
                if operation=='render':outer.on_render()
                else:
                    outer.replace(service);outer.on_write(service)
                self.audit('PROCESS_RESULT',operation,service,{'rc':0},{},deadline)
                return 0
        self.Process=Process
    def replace(self,service):
        f=self.fixture
        old=self.h.engine.rows[service]
        cid=old['Id'];pid=old['State']['Pid']
        row=cb.recreated(self.f,service)
        row['State']['Pid']=pid+1000
        endpoint=row['NetworkSettings']['Networks']['harbor_default']
        n=seq.SERVICES.index(service)
        endpoint.update(EndpointID=f'{n+100:064x}',MacAddress=f'02:42:ac:14:01:{n+2:02x}')
        self.h.engine.rows[service]=row
        network=self.h.data['network']
        del network['Containers'][cid]
        network['Containers'][row['Id']]={'EndpointID':endpoint['EndpointID'],'MacAddress':endpoint['MacAddress']}
        link=f.links[n+1];oldname=link['ifname']
        link.update(ifindex=link['ifindex']+100,ifname='new'+oldname,address=f'6e:20:5f:22:f4:{n:02x}')
        f.peers[pid+1000]=[dict(ifindex=7,ifname='eth0',address=endpoint['MacAddress'],
            link_index=link['ifindex'],linkinfo={'info_kind':'veth'})]
        f.routes=[r for r in f.routes if r.get('dev')!=oldname]+t.routes_for(link)
    def sleep(self,value):
        self.sleeps.append(value);self.time+=value;self.on_sleep()
    def pending_current(self,service):
        link=self.fixture.links[seq.SERVICES.index(service)+1]
        self.fixture.pending={link['ifname']}
        self.fixture.routes=[r for r in self.fixture.routes if not(r.get('dev')==link['ifname'] and r.get('type')=='local')]
    def ready(self):
        for link in self.fixture.links[1:]:
            if link['ifname'] in self.fixture.pending:
                self.fixture.routes=[r for r in self.fixture.routes if r.get('dev')!=link['ifname']]+t.routes_for(link)
        self.fixture.pending=set()
    @contextmanager
    def constructed(self, storage=None):
        # Only platform boundaries are doubled; every constructor and coordinator is real.
        def disk_journal(path,**kw):
            self.journal=journal.Journal(path,expected_selinux=None)
            return self.journal
        def disk_evidence(path,**kw):
            kw['context']=None
            return evidence.Evidence(path,**kw)
        root='/synthetic' if storage is None else str(storage)
        with patch.object(session,'Path',side_effect=lambda v:SimpleNamespace(resolve=lambda:self.path_for(v))), \
             patch.object(session,'load_package',side_effect=lambda *a,**kw:deepcopy(self.values)), \
             patch.object(host,'load_package',side_effect=lambda *a,**kw:deepcopy(self.h.data['package'])), \
             patch.object(host,'logger_tcp',return_value=True), \
             patch.object(session,'ProductionReadOnly',return_value=self.h.io), \
             patch.object(session,'ReadOnlyEngine',return_value=self.h.engine), \
             patch.object(session,'PinnedCompose',self.Process), \
             patch.object(session,'Journal',side_effect=(disk_journal if storage is not None else lambda *a,**kw:self.journal)), \
             patch.object(session,'Evidence',disk_evidence if storage is not None else MemoryEvidence):
            obj=session.ProtectedSession(package_path='/synthetic/package',package_sha256='a'*64,
                package_context=b'synthetic_t',journal_path=root+'/journal',journal_context=b'synthetic_t',
                evidence_path=root+'/evidence',evidence_context=b'synthetic_t',
                private_path=root+'/private',private_context=b'synthetic_t',
                preparation_deadline=100,clock=lambda:self.time)
            obj.sequence._sleep=self.sleep
            yield obj
    def run(self,deadline=2000):
        with self.constructed() as obj:
            result=obj.run(mutation_deadline=deadline,collection_deadline=deadline+100)
            self.evidence=obj.evidence
            return result
    def writes(self):return [s for op,s,d in self.calls if op=='recreate']


class ConstructorIntegrationTests(unittest.TestCase):
    def test_supported_constructor_to_nine_acks_and_sealed_handoff(self):
        f=ConstructorFixture();r=f.run()
        self.assertEqual(r['sequence']['reason'],'COMPLETE')
        self.assertEqual(f.writes(),list(seq.ORDER));self.assertTrue(r['evidence_sealed'])
        self.assertFalse(r['daemon_effects_may_continue'])
        self.assertEqual(len([x for x in f.evidence.records if x['kind']=='PROCESS_INTENT' and x['operation']=='recreate']),9)
    def test_post_ack_dad_pending_is_read_only_until_ready(self):
        f=ConstructorFixture();f.on_write=f.pending_current;f.on_sleep=f.ready
        r=f.run()
        self.assertEqual(r['sequence']['reason'],'COMPLETE');self.assertEqual(f.writes(),list(seq.ORDER))
        self.assertEqual(len(f.sleeps),9)
    def test_initial_pending_is_rejected_before_any_process(self):
        f=ConstructorFixture();f.pending_current('postgresql');r=f.run()
        self.assertEqual(r['sequence']['reason'],'NETWORK_NOT_READY');self.assertEqual(f.calls,[])
        self.assertEqual(r['sequence']['status'],'STOP_BEFORE_CHANGE')
    def test_permanent_pending_obeys_absolute_deadline_no_next_app(self):
        f=ConstructorFixture();f.on_write=f.pending_current;r=f.run(deadline=15)
        self.assertEqual(r['sequence']['status'],'STOP_RECOVERY_REQUIRED')
        self.assertEqual(r['sequence']['reason'],'DEADLINE');self.assertEqual(f.writes(),['postgresql'])
        self.assertLessEqual(f.time,15)
    def test_management_drift_while_pending_is_not_retried(self):
        f=ConstructorFixture()
        def after(service):
            f.pending_current(service);f.fixture.routes[0]['gateway']='10.0.0.2'
        f.on_write=after;r=f.run()
        self.assertEqual(r['sequence']['status'],'STOP_RECOVERY_REQUIRED')
        self.assertEqual(f.writes(),['postgresql']);self.assertEqual(f.sleeps,[])
    def test_preservation_drift_while_pending_is_not_hidden(self):
        f=ConstructorFixture()
        def after(service):
            f.pending_current(service);f.h.engine.rows[service]['Config']['User']='unexpected'
        f.on_write=after;r=f.run()
        self.assertEqual(r['sequence']['status'],'STOP_RECOVERY_REQUIRED');self.assertEqual(f.sleeps,[])
        self.assertEqual(f.writes(),['postgresql'])
    def test_render_deadline_is_before_dispatch_and_claim_stays_spent(self):
        f=ConstructorFixture();f.on_render=lambda:setattr(f,'time',31)
        r=f.run()
        self.assertEqual(r['sequence']['reason'],'RECREATE_PREPARATION_FAILED')
        self.assertEqual(r['sequence']['status'],'STOP_BEFORE_CHANGE')
        self.assertFalse(r['sequence']['this_invocation_may_have_changed'])
        self.assertFalse(r['daemon_effects_may_continue'])
        self.assertEqual(f.writes(),[]);self.assertTrue(f.journal.spent)
    def test_recreate_budget_starts_after_preparation_even_when_smaller_than_io(self):
        f=ConstructorFixture();f.plan['recreate_seconds']={s:1 for s in seq.ORDER}
        f.h.data['package']['plan.json']=deepcopy(f.plan)
        f.on_render=lambda:setattr(f,'time',f.time+2)
        r=f.run()
        self.assertEqual(r['sequence']['reason'],'COMPLETE')
        self.assertEqual(f.calls[1][2],13)
    def test_late_ack_keeps_unknown_and_no_next_app(self):
        f=ConstructorFixture();f.on_write=lambda s:setattr(f,'time',f.time+241)
        r=f.run()
        self.assertEqual(r['sequence']['reason'],'RECREATE_OUTCOME_UNKNOWN')
        self.assertTrue(r['daemon_effects_may_continue']);self.assertEqual(f.writes(),['postgresql'])
    def test_second_preparation_failure_keeps_prior_change_recovery_status(self):
        f=ConstructorFixture()
        def render():
            if f.writes():f.time+=21
        f.on_render=render;r=f.run()
        self.assertEqual(r['sequence']['reason'],'RECREATE_PREPARATION_FAILED')
        self.assertEqual(r['sequence']['status'],'STOP_RECOVERY_REQUIRED')
        self.assertEqual(f.writes(),['postgresql'])
    def test_existing_journal_does_not_claim_prior_daemon_idle(self):
        f=ConstructorFixture();f.journal.spent=True;r=f.run()
        self.assertEqual(r['sequence']['status'],'STOP_EXISTING_HISTORY_REQUIRES_REVIEW')
        self.assertFalse(r['sequence']['this_invocation_may_have_changed'])
        self.assertTrue(r['daemon_effects_may_continue']);self.assertEqual(f.calls,[])


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0, 'Linux root concrete storage only')
class ConstructorStorageTests(unittest.TestCase):
    def exercise(self, fail_render):
        f=ConstructorFixture()
        if fail_render:f.on_render=lambda:setattr(f,'time',31)
        else:
            f.on_write=f.pending_current;f.on_sleep=f.ready
        with tempfile.TemporaryDirectory(prefix='pr55-constructor-',dir='/root') as path:
            base=Path(path)
            for name in ('journal','evidence','private'):
                p=base/name;p.mkdir(mode=0o700)
                self.assertNotIn('security.selinux',os.listxattr(p),'this CI fixture needs an unlabeled runner')
            with f.constructed(storage=base) as obj:
                result=obj.run(mutation_deadline=2000,collection_deadline=2100)
            self.assertTrue(result['evidence_sealed'])
            self.assertEqual(result['sequence']['reason'],'RECREATE_PREPARATION_FAILED' if fail_render else 'COMPLETE')
            digest=seq.fingerprint(f.plan)
            checked=journal.inspect_history(str(base/'journal'),expected_selinux=None,expected_plan_sha256=digest)
            self.assertEqual(checked['status'],'VALID_TERMINAL_HISTORY')
            self.assertEqual(checked['recorded_healthy_services'],[] if fail_render else list(seq.ORDER))
            checked=evidence.inspect_evidence(str(base/'evidence'),context=None,plan_sha256=digest,
                deadline=2200,clock=lambda:f.time)
            self.assertTrue(checked['valid'])
            with journal.Journal(str(base/'journal'),expected_selinux=None).locked() as j:
                with self.assertRaises(FileExistsError):j.begin(digest)
    def test_nine_acks_pending_readiness_and_real_durable_handoff(self):self.exercise(False)
    def test_preparation_stop_is_readable_durable_and_non_reusable(self):self.exercise(True)


class NetworkRegressionTests(unittest.TestCase):
    def test_timer_only_changes_allowed_configuration_and_unknown_changes_visible(self):
        a=[dict(ifindex=1,ifname='br-test',linkinfo={'info_kind':'bridge','info_data':{
            'gc_timer':29.9,'hello_time':200,'vlan_filtering':0,'future':'keep'}})]
        b=deepcopy(a);b[0]['linkinfo']['info_data']['gc_timer']=28.9
        self.assertEqual(net.link_projection(a),net.link_projection(b))
        for key in ('hello_time','vlan_filtering','future'):
            b=deepcopy(a);b[0]['linkinfo']['info_data'][key]='changed'
            self.assertNotEqual(net.link_projection(a),net.link_projection(b))
        for bad in (True,-1,float('nan'),'20'):
            b=deepcopy(a);b[0]['linkinfo']['info_data']['gc_timer']=bad
            with self.assertRaisesRegex(ValueError,'NETWORK_LINK_TIMER'):net.link_projection(b)
    def test_pending_needs_address_proof_and_never_allows_unexpected_route(self):
        links,endpoints,peers=t.topology();owned=net.owned_links(links,endpoints,peers,bridge='br-synthetic')
        addresses=[dict(ifindex=30,ifname='vethsynthetic',addr_info=[dict(
            family='inet6',scope='link',prefixlen=64,local=net.link_local(links[1]),tentative=True)])]
        pending=net.address_readiness(addresses,owned)
        rows=[r for r in t.routes_for(links[1]) if r.get('type')!='local']
        self.assertEqual(net.route_projection(rows,owned,pending=pending),[])
        with self.assertRaisesRegex(ValueError,'NETWORK_DYNAMIC_ROUTE_SET'):net.route_projection(rows,owned)
        with self.assertRaisesRegex(ValueError,'NETWORK_DYNAMIC_ROUTE'):
            net.route_projection(rows+[dict(dev='vethsynthetic',dst='default')],owned,pending=pending)
        for bad in ('dadfailed','optimistic'):
            a=deepcopy(addresses);a[0]['addr_info'][0][bad]=True
            with self.assertRaisesRegex(ValueError,'NETWORK_ADDRESS_DAD_FAILED'):net.address_readiness(a,owned)
        for change in (lambda a:a[0]['addr_info'].clear(),lambda a:a[0]['addr_info'][0].update(local='fe80::99')):
            a=deepcopy(addresses);change(a)
            with self.assertRaises(ValueError):net.address_readiness(a,owned)
    def test_readiness_regression_and_identity_change_fail(self):
        pending=dict(topology_sha256='a'*64,pending_services=['postgresql'])
        ready=dict(pending,pending_services=[])
        self.assertEqual(net.network_progress(pending,ready),pending)
        with self.assertRaisesRegex(ValueError,'NETWORK_READINESS_REGRESSED'):net.network_progress(ready,pending)
        with self.assertRaisesRegex(ValueError,'NETWORK_READINESS_REGRESSED'):
            net.network_progress(pending,dict(ready,topology_sha256='b'*64))
    def test_production_peer_open_error_has_fixed_reason_not_fixture_keyerror(self):
        with patch.object(host.os,'O_CLOEXEC',0,create=True),patch.object(host.os,'open',side_effect=FileNotFoundError('private path')):
            with self.assertRaisesRegex(ValueError,'^HOST_PEER_UNAVAILABLE$'):
                host.ProductionReadOnly().peer_links(999,{},100)


if __name__=='__main__':unittest.main()
