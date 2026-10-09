"""Operator control simulations; no real daemon or systemd mutations."""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
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


class Ledger:
    def __init__(self): self.claims, self.receipts = {}, {}
    def quiescent(self):
        if self.claims != self.receipts: raise ValueError('STOP_UNRESOLVED')
    def claim(self, value):
        if value['token'] in self.claims: raise FileExistsError('claim')
        self.claims[value['token']] = deepcopy(value)
    def done(self, value): self.receipts[value['token']] = deepcopy(value)
    def max_token(self): return max(self.claims,default=0)


class ControlTests(unittest.TestCase):
    def setUp(self):
        core, rows = fixture()
        self.core, self.store, self.now = core, MemoryStore(), 10
        self.rows = {n:replace(row,status='running',health='healthy') for n,row in rows.items()}
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


class StopTransportTests(unittest.TestCase):
    def test_only_fixed_sigterm_no_kill_timeout_endpoint_for_app_ids(self):
        core,_=fixture(); ids=[core.plan.ids[n] for n in c.ORDER]
        engine=k.StopEngine('1.53',ids)
        good='/containers/'+ids[0]+'/stop?signal=SIGTERM&t=-1'
        engine._validate_request('POST',good,b'')
        for path in (good.replace('-1','5'),good.replace('SIGTERM','SIGKILL'),
                     good.replace(ids[0],core.plan.ids['log']),'/containers/create',
                     '/containers/'+ids[0]+'/start'):
            with self.assertRaises(ValueError): engine._validate_request('POST',path,b'')
        with self.assertRaises(ValueError):engine._validate_request('GET',good,b'')


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
