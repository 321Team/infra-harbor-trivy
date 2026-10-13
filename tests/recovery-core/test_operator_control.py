"""Operator control simulations; no real daemon or systemd mutations."""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

import harbor_recovery_control as k
import harbor_recovery_core as c
from harbor_recovery_executor import Executor
from harbor_recovery_store import Store
from test_state_executor import MemoryStore, fixture


class Ledger(k.StopLedger):
    def __init__(self): self.claims, self.receipts, self.acks = {}, {}, {}
    def quiescent(self):
        if self.claims != self.receipts: raise ValueError('STOP_UNRESOLVED')
    def claim(self, value):
        if value['token'] in self.claims: raise FileExistsError('claim')
        self.claims[value['token']] = deepcopy(value)
    def done(self, value): self.receipts[value['token']] = deepcopy(value)
    def ack(self, value): self.acks[value['token']] = deepcopy(value)
    def max_token(self): return max(self.claims,default=0)
    def _records(self):
        values = {'claim':self.claims, 'done':self.receipts, 'ack':self.acks}
        return {kind:{token:(obj if kind=='claim' else {'claim':obj,'result':
                    'HTTP_204' if kind=='ack' else 'EXITED_READBACK'},
                    json.dumps(obj if kind=='claim' else {'claim':obj,'result':
                    'HTTP_204' if kind=='ack' else 'EXITED_READBACK'},sort_keys=True).encode())
                    for token,obj in items.items()} for kind,items in values.items()}


class ControlTests(unittest.TestCase):
    def setUp(self):
        core, rows = fixture()
        self.core, self.store, self.now = core, MemoryStore(), 10
        self.rows = {n:replace(row,status='running',health='healthy') for n,row in rows.items()}
        for name in ('proxy', 'portal'):
            self.rows[name] = replace(self.rows[name], stop_signal='SIGQUIT')
        self.calls, self.posts, self.ledger = [], [], Ledger()
        self.boot, self.daemon, self.tcp = 'boot-1','daemon-1',True
        self.on_observe = lambda: None
        def observe(deadline):
            self.calls.append('observe'); self.on_observe()
            return c.Observation(self.boot,self.daemon,self.now,deepcopy(self.rows),True,self.tcp)
        self.backend = SimpleNamespace(observe=observe)
        self.executor = Executor(core,self.store,self.backend,gate=lambda:self.calls.append('gate'))
        self.manager = lambda end: self.calls.append('manager')
        def stop(cid,deadline):
            self.assertEqual(self.store.state.desired,'HOLD')
            name = next(n for n,row in self.rows.items() if row.id == cid)
            self.assertEqual(self.ledger.claims[self.store.state.next_token-1]['service'],name)
            self.posts.append(cid)
            self.rows[name] = replace(self.rows[name],status='exited',health='unhealthy')
            return 'ack'
        self.stop_engine = SimpleNamespace(stop=stop)
        self.control = k.OperatorControl(self.executor,self.manager,self.stop_engine,ledger=self.ledger,
                                          lease=lambda:nullcontext(),clock=lambda:self.now)
        self.store.state = core.arm(c.State(),observe(20),self.now).state
        self.store.state.reason = 'HEALTHY'
        self.store.state.seen_healthy.update(c.ORDER)

    def stop(self, **kw):
        return self.control.stop(k.state_hash(self.store.state),100,per_container_seconds=30,explicit=True,**kw)

    def hold(self): self.store.state = self.core.hold(self.store.state).state

    def reconcile(self):
        return self.control.reconcile(k.state_hash(self.store.state),100,explicit=True)

    def test_state_read_never_resumes_or_rewrites(self):
        self.store.state.reason = 'WAIT_HEALTH'; self.store.state.episode_since = 10
        self.store.state.health_wait = ('core',40)
        before = deepcopy(self.store.state)
        self.assertTrue(self.control.inspect_state()['health_wait'])
        self.assertEqual(self.store.state,before)

    def test_exact_state_pin_and_explicit_required_without_write(self):
        before = deepcopy(self.store.state)
        with self.assertRaisesRegex(ValueError,'EXPLICIT'): self.control.reconcile('a'*64,100)
        with self.assertRaisesRegex(ValueError,'STATE_CHANGED'):
            self.control.stop('a'*64,100,per_container_seconds=30,explicit=True)
        self.assertEqual(self.store.state,before); self.assertEqual(self.posts,[])

    def test_reconcile_preserves_retry_history_tokens_and_audits_old_intent(self):
        self.hold()
        self.store.state.pending = c.Action(4,'core',self.core.plan.ids['core'],self.boot,self.daemon,30)
        self.store.state.next_token = 5; self.store.state.episode_since = 10
        self.store.state.retries['core'] = [5,7,9]
        before = deepcopy(self.store.state)
        state = self.reconcile()
        self.assertEqual(state.desired,'RUN'); self.assertIsNone(state.pending)
        self.assertEqual((state.retries,state.next_token),(before.retries,5))
        self.assertEqual(self.store.records,[('healthy-reconcile-request',before)])
        self.assertEqual(self.posts,[])

    def test_reconcile_rejects_unhealthy_clock_generation_logger_or_plan_change(self):
        self.hold(); before = deepcopy(self.store.state)
        for change in ('unhealthy','clock','boot','daemon','logger','plan'):
            self.store.state = deepcopy(before); self.boot,self.daemon,self.now,self.tcp='boot-1','daemon-1',10,True
            self.rows['core']=replace(self.rows['core'],health='healthy')
            if change=='unhealthy': self.rows['core']=replace(self.rows['core'],health='unhealthy')
            if change=='clock': self.now=9
            if change=='boot': self.boot='boot-2'
            if change=='daemon': self.daemon='daemon-2'
            if change=='logger': self.tcp=False
            if change=='plan': self.store.state.plan_digest='f'*64
            with self.assertRaises(ValueError): self.reconcile()
        self.assertEqual(self.store.records,[])

    def test_stop_exact_reverse_nine_and_keeps_logger_healthy(self):
        before_token = self.store.state.next_token
        state = self.stop()
        self.assertEqual(self.posts,[self.core.plan.ids[n] for n in reversed(c.ORDER)])
        self.assertEqual((state.desired,state.reason),('HOLD','APPS_STOPPED_LOGGER_PRESERVED'))
        self.assertEqual(state.next_token,before_token+9)
        self.assertEqual(len(self.ledger.receipts),9)
        self.assertEqual(self.rows['log'].status,'running')
        with self.assertRaises(ValueError): self.reconcile()

    def test_unknown_stop_preserves_claim_blocks_replay_and_reconciliation(self):
        def unknown(cid,end): self.posts.append(cid); raise TimeoutError()
        self.stop_engine.stop=unknown
        state=self.stop()
        self.assertEqual(state.reason,'STOP_INTERRUPTED_OR_UNKNOWN')
        self.assertEqual((len(self.posts),len(self.ledger.claims),len(self.ledger.receipts)),(1,1,0))
        for action in (self.stop,self.reconcile):
            with self.assertRaisesRegex(ValueError,'STOP_UNRESOLVED'): action()
        self.assertEqual(len(self.posts),1)

    def test_ack_without_exited_readback_is_not_completed(self):
        self.stop_engine.stop=lambda cid,end:self.posts.append(cid) or 'ack'
        self.assertEqual(self.stop().reason,'STOP_INTERRUPTED_OR_UNKNOWN')
        self.assertEqual(len(self.posts),1); self.assertEqual(self.ledger.receipts,{})
        self.assertEqual(len(self.ledger.acks),1)

    def failed_readback(self, count=1):
        original = self.stop_engine.stop
        def ack_with_broken_read(cid,end):
            result = original(cid,end)
            if len(self.posts)==count: self.tcp=False
            return result
        self.stop_engine.stop=ack_with_broken_read
        self.assertEqual(self.stop().reason,'STOP_INTERRUPTED_OR_UNKNOWN')
        self.tcp=True
        records=self.ledger._records(); token=self.store.state.next_token-1
        self.claim_pin=hashlib.sha256(records['claim'][token][1]).hexdigest()
        self.ack_pin=hashlib.sha256(records['ack'][token][1]).hexdigest()

    def settle(self, **kw):
        args=dict(explicit=True); args.update(kw)
        return self.control.settle_acknowledged_stop(k.state_hash(self.store.state),
                                                    self.claim_pin,self.ack_pin,100,**args)

    def test_recorded_ack_readback_settles_only_hold_without_another_post(self):
        self.failed_readback(count=3); before=deepcopy(self.store.state)
        posts=list(self.posts); claims=deepcopy(self.ledger.claims); acks=deepcopy(self.ledger.acks)
        result=self.settle()
        self.assertEqual((result.desired,result.reason),('HOLD','ACKED_STOP_READBACK_SETTLED_HOLD'))
        self.assertEqual((result.next_token,result.retries,result.seen_healthy),
                         (before.next_token,before.retries,before.seen_healthy))
        self.assertEqual((self.posts,self.ledger.claims,self.ledger.acks),(posts,claims,acks))
        self.assertEqual(len(self.ledger.receipts),3)
        with self.assertRaisesRegex(ValueError,'NOT_INTERRUPTED'): self.settle()
        with self.assertRaisesRegex(ValueError,'APP_STATE'): self.reconcile()

    def test_resolution_never_infers_ack_from_exited_and_rejects_changed_pins(self):
        self.failed_readback(); before=deepcopy(self.store.state)
        ack=self.ledger.acks.pop(1)
        with self.assertRaisesRegex(ValueError,'ACK_NOT_RECORDED'):self.settle()
        self.ledger.acks[1]=ack
        for field,reason in [('claim_pin','CLAIM_CHANGED'),('ack_pin','ACK_CHANGED')]:
            original=getattr(self,field);setattr(self,field,'f'*64)
            with self.assertRaisesRegex(ValueError,reason):self.settle()
            setattr(self,field,original)
        self.assertEqual(self.store.state,before);self.assertEqual(self.ledger.receipts,{})

    def test_resolution_checks_exact_generation_ids_policy_logger_manager_gate_and_clock(self):
        self.failed_readback(); before=deepcopy(self.store.state)
        base=deepcopy(self.rows)
        for change in ('boot','daemon','id','fingerprint','policy','logger','running','other-exited',
                       'manager','gate','clock','stale'):
            with self.subTest(change=change):
                self.rows=deepcopy(base);self.boot,self.daemon,self.now,self.tcp='boot-1','daemon-1',10,True
                self.control.manager=self.manager;self.executor.gate=lambda:None
                if change=='boot': self.boot='boot-2'
                if change=='daemon': self.daemon='daemon-2'
                if change=='id': self.rows['proxy']=replace(self.rows['proxy'],id='f'*64)
                if change=='fingerprint': self.rows['proxy']=replace(self.rows['proxy'],fingerprint='f'*64)
                if change=='policy': self.rows['core']=replace(self.rows['core'],restart='always')
                if change=='logger': self.tcp=False
                if change=='running': self.rows['proxy']=replace(self.rows['proxy'],status='running',health='healthy')
                if change=='other-exited': self.rows['core']=replace(self.rows['core'],status='exited')
                if change=='manager': self.control.manager=lambda end:(_ for _ in ()).throw(ValueError('manager'))
                if change=='gate': self.executor.gate=lambda:(_ for _ in ()).throw(ValueError('gate'))
                if change=='clock': self.now=9
                if change=='stale': self.now=100
                with self.assertRaises(ValueError):self.settle()
                self.assertEqual(self.store.state,before);self.assertEqual(self.ledger.receipts,{})
        self.assertEqual(len(self.posts),1)

    def test_resolution_requires_explicit_interrupted_hold_and_no_start_episode(self):
        self.failed_readback(); base=deepcopy(self.store.state)
        with self.assertRaisesRegex(ValueError,'EXPLICIT'): self.settle(explicit=False)
        for field,value in [('desired','RUN'),('reason','OPERATOR_HOLD'),('episode_since',10),
                            ('health_wait',('core',30))]:
            self.store.state=deepcopy(base);setattr(self.store.state,field,value)
            with self.assertRaises(ValueError):self.settle()
        self.assertEqual(self.ledger.receipts,{});self.assertEqual(len(self.posts),1)

    def test_hard_interruption_after_durable_ack_can_settle_saved_stop_intent(self):
        self.failed_readback();self.store.state.reason='STOP_INTENT'
        self.assertEqual(self.settle().desired,'HOLD')
        self.assertEqual(len(self.posts),1)

    def test_ack_persistence_failure_keeps_claim_and_stops_next_post(self):
        self.ledger.ack=lambda value:(_ for _ in ()).throw(OSError('disk'))
        self.assertEqual(self.stop().reason,'STOP_INTERRUPTED_OR_UNKNOWN')
        self.assertEqual(len(self.posts),1);self.assertEqual(self.ledger.acks,{})
        self.assertEqual(self.ledger.receipts,{})

    def test_resolution_failure_before_receipt_and_after_receipt_preserves_originals(self):
        self.failed_readback(); original_done=self.ledger.done
        self.ledger.done=lambda value:(_ for _ in ()).throw(OSError('disk'))
        with self.assertRaises(OSError):self.settle()
        self.assertEqual(self.ledger.receipts,{})
        self.ledger.done=original_done; self.store.fail_reason='ACKED_STOP_READBACK_SETTLED_HOLD'
        with self.assertRaises(OSError):self.settle()
        self.assertEqual(self.store.state.reason,'STOP_INTERRUPTED_OR_UNKNOWN')
        self.assertEqual(len(self.ledger.receipts),1)
        with self.assertRaisesRegex(ValueError,'SINGLE_PENDING'):self.settle()
        self.assertEqual(len(self.posts),1)

    def test_drift_after_audit_before_receipt_does_not_settle(self):
        self.failed_readback(); observe_count=len(self.calls)
        def drift():
            if len(self.calls)>observe_count+2: self.boot='boot-2'
        self.on_observe=drift
        with self.assertRaises(ValueError):self.settle()
        self.assertEqual(self.ledger.receipts,{})

    def test_start_pending_or_wait_blocks_stop(self):
        self.store.state.episode_since=10; self.store.state.health_wait=('core',30)
        with self.assertRaisesRegex(ValueError,'QUIESCENT'): self.stop()
        self.assertEqual(self.ledger.claims,{})

    def test_manager_or_installation_gate_failure_before_mutation(self):
        for attr in ('manager','gate'):
            def fail(*args): raise ValueError('blocked')
            if attr=='manager': self.control.manager=fail
            else: self.control.manager=self.manager; self.executor.gate=fail
            with self.assertRaises(ValueError): self.stop()
        self.assertEqual(self.posts,[]); self.assertEqual(self.store.records,[])

    def test_persist_hold_failure_prevents_stop_and_keeps_audit(self):
        self.store.fail_reason='OPERATOR_STOP'
        with self.assertRaises(OSError): self.stop()
        self.assertEqual(self.posts,[]); self.assertEqual(len(self.store.records),1)

    def test_receipt_failure_prevents_next_service_and_preserves_unresolved(self):
        self.ledger.done=lambda value:(_ for _ in ()).throw(OSError('disk'))
        self.assertEqual(self.stop().reason,'STOP_INTERRUPTED_OR_UNKNOWN')
        self.assertEqual(len(self.posts),1); self.assertEqual(len(self.ledger.claims),1)

    def test_deadline_exhaustion_never_posts(self):
        self.on_observe=lambda:setattr(self,'now',100)
        with self.assertRaises(ValueError): self.stop()
        self.assertEqual(self.posts,[])

    def test_regressed_state_token_cannot_reconcile_or_stop(self):
        self.hold()
        claim=dict(token=self.store.state.next_token+5)
        self.ledger.claim(claim);self.ledger.done(claim)
        before=deepcopy(self.store.state)
        for action in (self.reconcile,self.stop):
            with self.assertRaisesRegex(ValueError,'TOKEN_HISTORY_REGRESSED'):action()
        self.assertEqual(self.store.state,before);self.assertEqual(self.posts,[])


    def test_unsuitable_signals_block_entire_stop_before_hold_or_claim(self):
        base=deepcopy(self.rows);before=deepcopy(self.store.state)
        for name,signal in (('proxy','SIGTERM'),('portal','15'),('postgresql','SIGQUIT'),
                            ('postgresql','3'),('redis','SIGKILL'),('registry','9'),('core','')):
            with self.subTest(service=name,signal=signal):
                self.rows=deepcopy(base);self.rows[name]=replace(self.rows[name],stop_signal=signal)
                with self.assertRaisesRegex(ValueError,'CONTROL_STOP_SIGNAL'):self.stop()
                self.assertEqual(self.store.state,before)
                self.assertEqual(self.store.records,[]);self.assertEqual(self.ledger.claims,{})
                self.assertEqual(self.posts,[])

    def test_numeric_equivalents_preserve_reverse_stop(self):
        for name in c.ORDER:
            self.rows[name]=replace(self.rows[name],stop_signal='3' if name in ('proxy','portal') else '15')
        self.assertEqual(self.stop().reason,'APPS_STOPPED_LOGGER_PRESERVED')
        self.assertEqual(len(self.posts),9)

    def test_signal_metadata_drift_after_claim_blocks_first_request(self):
        def drift():
            if self.ledger.claims:
                self.rows['proxy']=replace(self.rows['proxy'],stop_signal='SIGTERM',fingerprint='f'*64)
        self.on_observe=drift
        self.assertEqual(self.stop().reason,'STOP_INTERRUPTED_OR_UNKNOWN')
        self.assertEqual(self.posts,[]);self.assertEqual(len(self.ledger.claims),1)
        self.assertEqual(self.ledger.acks,{});self.assertEqual(self.ledger.receipts,{})

    def test_signal_only_drift_after_claim_blocks_first_request(self):
        # Isolate the signal guard from the existing fingerprint drift guard.
        fingerprint = self.rows['proxy'].fingerprint
        def drift():
            if self.ledger.claims:
                self.rows['proxy'] = replace(self.rows['proxy'], stop_signal='SIGTERM')
        self.on_observe = drift
        self.assertEqual(self.stop().reason, 'STOP_INTERRUPTED_OR_UNKNOWN')
        self.assertEqual(self.rows['proxy'].fingerprint, fingerprint)
        self.assertEqual(self.posts, [])
        self.assertEqual(len(self.ledger.claims), 1)
        self.assertEqual(self.ledger.acks, {})
        self.assertEqual(self.ledger.receipts, {})


class StopSignalProjectionTests(unittest.TestCase):
    def test_configured_signal_and_default_are_fingerprint_bound(self):
        from test_docker_adapter import inspect_row
        import harbor_recovery_docker as d
        cid='a'*64
        raw=inspect_row('proxy',cid)
        before=d.project(raw,'proxy',cid,'harbor')
        self.assertEqual(before.stop_signal,'SIGTERM')
        raw['Config']['StopSignal']='SIGQUIT'
        after=d.project(raw,'proxy',cid,'harbor')
        self.assertEqual(after.stop_signal,'SIGQUIT')
        self.assertNotEqual(before.fingerprint,after.fingerprint)
        raw['Config']['StopSignal']='SIGKILL'
        self.assertNotEqual(after.fingerprint,d.project(raw,'proxy',cid,'harbor').fingerprint)
        for bad in (False,0,3,[],{}):
            raw['Config']['StopSignal']=bad
            with self.assertRaisesRegex(ValueError,'INSPECT_STOP_SIGNAL'):
                d.project(raw,'proxy',cid,'harbor')


class StopTransportTests(unittest.TestCase):
    def test_only_configured_signal_no_kill_timeout_endpoint_for_app_ids(self):
        core,_=fixture(); ids=[core.plan.ids[n] for n in c.ORDER]
        engine=k.StopEngine('1.53',ids)
        good='/containers/'+ids[0]+'/stop?t=-1'
        engine._validate_request('POST',good,b'')
        for path in (good.replace('-1','5'),good+'&signal=SIGKILL',good+'&signal=SIGTERM',
                     good.replace('?t=', '?signal=SIGQUIT&t='),good.replace('?t=-1',''),
                     good.replace(ids[0],core.plan.ids['log']),'/containers/create',
                     '/containers/'+ids[0]+'/start'):
            with self.assertRaises(ValueError): engine._validate_request('POST',path,b'')
        with self.assertRaises(ValueError):engine._validate_request('GET',good,b'')
        with self.assertRaises(ValueError):engine._validate_request('POST',good,b'{}')

    def test_stop_keeps_default_signal_endpoint_and_ack_semantics(self):
        core,_=fixture(); ids=[core.plan.ids[n] for n in c.ORDER]
        engine=k.StopEngine('1.53',ids); calls=[]
        def request(method,path,deadline):
            engine._validate_request(method,path,b'');calls.append((method,path,deadline))
            return 204,b''
        engine._request=request
        self.assertEqual(engine.stop(ids[0],100),'ack')
        self.assertEqual(calls,[('POST','/containers/'+ids[0]+'/stop?t=-1',100)])
        engine._request=lambda *args:(304,b'')
        self.assertEqual(engine.stop(ids[0],100),'unknown')


@unittest.skipUnless(sys.platform=='linux','POSIX durable stop records')
class LedgerFileTests(unittest.TestCase):
    def test_missing_and_mismatched_receipt_blocks_without_deleting_claim(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as folder:
            store=Store(folder,uid=os.getuid()); ledger=k.StopLedger(store)
            with store.locked():
                store.initialize(); ledger.quiescent()
                value=dict(token=1,service='proxy',id='a'*64)
                ledger.claim(value)
                with self.assertRaisesRegex(ValueError,'UNRESOLVED'):ledger.quiescent()
                ledger.done(value); ledger.quiescent()
                self.assertEqual(ledger.max_token(),1)
                store.claim(c.Action(7,'core','b'*64,'boot-1','daemon-1',40))
                self.assertEqual(ledger.max_token(),7)
                with self.assertRaises(FileExistsError):ledger.claim(value)
                with self.assertRaises(FileExistsError):ledger.done(value)
            self.assertEqual(len(list(Path(folder).glob('stop-*.json'))),2)


if __name__=='__main__':unittest.main()
