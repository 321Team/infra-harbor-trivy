"""Durable stop evidence rejection/replay tests. Temporary files, no daemon."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import harbor_recovery_control as k
from harbor_recovery_protected_store import NAMES
from harbor_recovery_store import Store
from test_state_executor import fixture


class NameTests(unittest.TestCase):
    def test_new_record_names_are_narrow_and_existing_names_remain_valid(self):
        for name in ('stop-ack-'+('0'*19)+'1.json','stop-readback-request-'+('a'*32)+'.json',
                     'stop-claim-'+('0'*19)+'1.json','stop-done-'+('0'*19)+'1.json'):
            self.assertIsNotNone(NAMES.fullmatch(name))
        for name in ('../stop-ack-'+('0'*19)+'1.json','stop-ack-1.json',
                     'stop-ack-'+('0'*20)+'.json.bak','stop-readback-request-x.json'):
            self.assertIsNone(NAMES.fullmatch(name))


@unittest.skipUnless(sys.platform=='linux','Linux descriptor storage')
class DurableTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path.home()); self.addCleanup(self.temp.cleanup)
        self.store=Store(self.temp.name,uid=os.getuid()); self.ledger=k.StopLedger(self.store)
        self.core,rows=fixture()
        from harbor_recovery_core import State
        self.state=State(desired='HOLD',reason='STOP_INTERRUPTED_OR_UNKNOWN',boot='boot-1',daemon='daemon-1',
                         next_token=4,plan_digest=self.core.plan_digest(),last_now=10)
        self.values=[{'version':1,'plan':self.state.plan_digest,'boot':'boot-1','daemon':'daemon-1',
                      'token':i+1,'service':service,'id':self.core.plan.ids[service]}
                     for i,service in enumerate(tuple(reversed(k.ORDER))[:3])]

    def prepare(self):
        self.store.initialize()
        for value in self.values:
            self.ledger.claim(value);self.ledger.ack(value)
            if value['token']<3:self.ledger.done(value)
        self.pins=[hashlib.sha256(self.ledger._bytes('stop-'+kind+'-'+f'{3:020}'+'.json')).hexdigest()
                   for kind in ('claim','ack')]

    def pending(self):
        return self.ledger.acknowledged_pending(self.state,self.core.plan,*self.pins)

    def test_durable_pinned_tail_and_prefix_preserved_with_exclusive_receipt(self):
        with self.store.locked():
            self.prepare(); before={p.name:p.read_bytes() for p in Path(self.temp.name).glob('stop-*.json')}
            value,prefix=self.pending()
            self.assertEqual(prefix,tuple(reversed(k.ORDER))[:3])
            self.ledger.done(value);self.ledger.quiescent()
            for name,raw in before.items():self.assertEqual((Path(self.temp.name)/name).read_bytes(),raw)
            for method in (self.ledger.claim,self.ledger.ack,self.ledger.done):
                with self.assertRaises(FileExistsError):method(value)
            with self.assertRaisesRegex(ValueError,'SINGLE_PENDING'):self.pending()

    def test_legacy_unfinished_has_no_ack_and_is_not_upgraded(self):
        with self.store.locked():
            self.store.initialize();self.ledger.claim(self.values[0])
            self.state.next_token=2
            self.pins=[hashlib.sha256(self.ledger._bytes('stop-claim-'+f'{1:020}'+'.json')).hexdigest(),'a'*64]
            with self.assertRaisesRegex(ValueError,'ACK_NOT_RECORDED'):self.pending()
            self.assertEqual(len(list(Path(self.temp.name).glob('stop-*.json'))),1)

    def test_legacy_completed_remains_quiescent_without_new_ack_file(self):
        with self.store.locked():
            self.store.initialize();self.ledger.claim(self.values[0]);self.ledger.done(self.values[0])
            self.ledger.quiescent()
            self.assertEqual(len(list(Path(self.temp.name).glob('stop-*.json'))),2)

    def test_orphan_ack_done_partial_json_and_duplicate_key_are_rejected(self):
        for kind,raw in (('ack',json.dumps({'claim':self.values[0],'result':'HTTP_204'}).encode()),
                         ('done',b'{}'),('claim',b'{'),('claim',b'{"token":1,"token":1}')):
            with self.subTest(kind=kind,raw=raw),tempfile.TemporaryDirectory(dir=Path.home()) as directory:
                store=Store(directory,uid=os.getuid());ledger=k.StopLedger(store)
                with store.locked():
                    store.initialize();store._new('stop-'+kind+'-'+f'{1:020}'+'.json',raw)
                    with self.assertRaises(ValueError):ledger.quiescent()
                self.assertEqual((Path(directory)/('stop-'+kind+'-'+f'{1:020}'+'.json')).read_bytes(),raw)

    def test_mismatched_record_wrong_pin_and_reversed_prefix_rejected(self):
        with self.store.locked():
            self.prepare()
            for index in (0,1):
                old=self.pins[index];self.pins[index]='f'*64
                with self.assertRaisesRegex(ValueError,'CHANGED'):self.pending()
                self.pins[index]=old
            records=self.ledger._records()
            for change in ('ack-result','ack-claim','prefix-id','prefix-bool','extra-unresolved','next-token'):
                table=deepcopy(records);state=deepcopy(self.state)
                if change=='ack-result':table['ack'][3][0]['result']='EXITED_READBACK'
                if change=='ack-claim':table['ack'][3][0]['claim']['daemon']='other'
                if change in ('ack-result','ack-claim'):
                    # Real byte read must reject mismatched ACK before pin checks.
                    raw=json.dumps(table['ack'][3][0]).encode()
                    original=self.ledger._bytes
                    def changed(name,raw=raw):
                        return raw if name=='stop-ack-'+f'{3:020}'+'.json' else original(name)
                    with patch.object(self.ledger,'_bytes',side_effect=changed):
                        with self.assertRaisesRegex(ValueError,'MISMATCH'):self.pending()
                    continue
                if change=='prefix-id':table['claim'][1][0]['id']='f'*64
                if change=='prefix-bool':table['claim'][1][0]['version']=True
                if change=='extra-unresolved':table['done'].pop(1)
                if change=='next-token':state.next_token=5
                with patch.object(self.ledger,'_records',return_value=table):
                    with self.assertRaises(ValueError):
                        self.ledger.acknowledged_pending(state,self.core.plan,*self.pins)

    def test_pending_save_or_symlink_is_preserved_and_rejected(self):
        with self.store.locked():
            self.prepare();pending='state-'+('a'*32)+'.pending';self.store._new(pending,b'{}')
            with self.assertRaisesRegex(ValueError,'UNCOMMITTED'):self.pending()
            self.assertTrue((Path(self.temp.name)/pending).exists())
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            store=Store(directory,uid=os.getuid());ledger=k.StopLedger(store)
            with store.locked():
                store.initialize();target=Path(directory)/'original';target.write_bytes(b'{}')
                (Path(directory)/('stop-ack-'+f'{1:020}'+'.json')).symlink_to(target)
                with self.assertRaises(OSError):ledger.quiescent()
                self.assertEqual(target.read_bytes(),b'{}')


if __name__=='__main__':unittest.main()
