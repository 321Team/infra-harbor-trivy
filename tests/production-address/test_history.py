"""Synthetic histories and Linux private temp files; no production or Docker."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('history_journal',Path(__file__).resolve().parents[2]/'scripts/production/harbor_address_journal.py')
j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)
PLAN='a'*64
CLAIM=j.encode({'schema':'fds.harbor.address-claim.v1','plan_sha256':PLAN})+b'\n'
BEGIN=dict(kind='BEGIN',plan_sha256=PLAN)
INTENT=dict(kind='RECREATE_INTENT',service='postgresql',old_id='b'*64)


def stop(entered=False):
    return dict(kind='STOP',reason='DEADLINE',claimed_services=['postgresql'],
                transport_entered_services=['postgresql'] if entered else [],healthy_services=[])


def records(events):
    result=[];previous='0'*64
    for i,event in enumerate(events):
        row=dict(sequence=i,previous_sha256=previous,event=event)
        row['sha256']=hashlib.sha256(j.encode(row)).hexdigest()
        previous=row['sha256'];result.append(j.encode(row)+b'\n')
    return b''.join(result)


def full_events():
    events=[BEGIN]
    for i,service in enumerate(j.ORDER):
        events.extend([dict(kind='RECREATE_INTENT',service=service,old_id=f'{i+1:064x}'),
                       dict(kind='RECREATE_RESULT',service=service,outcome='ACK'),
                       dict(kind='APP_HEALTHY',service=service,new_id=f'{i+101:064x}')])
    return events+[dict(kind='COMPLETE',healthy_services=list(j.ORDER))]


class ParseTests(unittest.TestCase):
    def parse(self,events,claim=CLAIM):
        return j.inspect_bytes(claim,events,expected_plan_sha256=PLAN)

    def test_complete_chain_is_only_a_recorded_result(self):
        r=self.parse(records(full_events()))
        self.assertEqual((r['status'],r['valid_records'],r['terminal']),('VALID_TERMINAL_HISTORY',29,'COMPLETE'))
        self.assertEqual(r['recorded_healthy_services'],list(j.ORDER))
        self.assertEqual(r['runtime_outcome'],'NOT_INFERRED');self.assertFalse(r['may_resume'])

    def test_absent_empty_and_partial_claim_differ(self):
        self.assertEqual(self.parse(None,None)['status'],'EMPTY_UNCLAIMED')
        self.assertEqual(self.parse(b'',None)['status'],'EVENTS_WITHOUT_CLAIM')
        for value in (b'',CLAIM[:-1],b'{"plan_sha256":"SYNTHETIC_SECRET'):
            r=self.parse(None,value)
            self.assertEqual(r['status'],'INVALID_OR_PARTIAL_CLAIM')
            self.assertNotIn('SYNTHETIC_SECRET',json.dumps(r))

    def test_claim_without_missing_or_empty_events_requires_handoff(self):
        for raw in (None,b''):
            r=self.parse(raw);self.assertEqual(r['status'],'CLAIM_WITHOUT_EVENT_RECORD');self.assertFalse(r['may_resume'])

    def test_different_plan_refused(self):
        r=j.inspect_bytes(CLAIM,records([BEGIN]),expected_plan_sha256='f'*64)
        self.assertEqual(r['status'],'PLAN_MISMATCH');self.assertEqual(r['valid_records'],0)

    def test_begin_and_intent_prefix_are_not_proof_of_no_execution(self):
        for events,stage in [([BEGIN],'READY'),([BEGIN,INTENT],'INTENT')]:
            r=self.parse(records(events))
            self.assertEqual(r['status'],'VALID_INCOMPLETE_HISTORY');self.assertEqual(r['last_valid_stage'],stage)
            self.assertEqual(r['runtime_outcome'],'NOT_INFERRED')

    def test_pre_send_stop_and_late_callback_stop_valid(self):
        for events in ([BEGIN,INTENT,stop()],
                       [BEGIN,INTENT,dict(kind='RECREATE_RESULT',service='postgresql',outcome='LATE'),stop(True)]):
            r=self.parse(records(events));self.assertEqual(r['status'],'VALID_TERMINAL_HISTORY');self.assertEqual(r['terminal'],'STOP')

    def test_torn_tail_keeps_only_valid_prefix_and_hash(self):
        raw=records([BEGIN,INTENT])+b'{"e'
        r=self.parse(raw);self.assertEqual(r['status'],'TORN_EVENT_TAIL');self.assertEqual(r['valid_records'],2)
        self.assertEqual(r['events_sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(r['invalid_record_index'],2)

    def test_corrupt_or_reordered_chain_refused(self):
        raw=records([BEGIN,INTENT])
        lines=raw.splitlines(keepends=True)
        for bad in (lines[1]+lines[0],raw.replace(b'b'*64,b'c'*64),lines[0]+lines[0]):
            r=self.parse(bad);self.assertEqual(r['status'],'INVALID_EVENT_RECORD')

    def test_rehashed_invalid_sequence_and_service_order_refused(self):
        for events in ([BEGIN,dict(kind='APP_HEALTHY',service='postgresql',new_id='c'*64)],
                       [BEGIN,dict(kind='RECREATE_INTENT',service='redis',old_id='b'*64)],
                       [BEGIN,BEGIN],full_events()+[stop(True)]):
            self.assertEqual(self.parse(records(events))['status'],'INVALID_EVENT_RECORD')

    def test_result_followed_by_not_entered_stop_is_contradiction(self):
        raw=records([BEGIN,INTENT,dict(kind='RECREATE_RESULT',service='postgresql',outcome='FAILED'),stop()])
        r=self.parse(raw);self.assertEqual(r['status'],'INVALID_EVENT_RECORD');self.assertEqual(r['valid_records'],3)

    def test_invalid_claim_duplicate_key_and_extra_fields_refused(self):
        for raw in (CLAIM.replace(b'"schema":',b'"plan_sha256":"'+PLAN.encode()+b'","schema":'),
                    j.encode(dict(schema='fds.harbor.address-claim.v1',plan_sha256=PLAN,secret='synthetic'))+b'\n'):
            self.assertEqual(self.parse(None,raw)['status'],'INVALID_OR_PARTIAL_CLAIM')

    def test_duplicate_record_key_bool_sequence_and_oversized_line_refused(self):
        raw=records([BEGIN])
        for value in (raw.replace(b'"sequence":0',b'"sequence":0,"sequence":0'),
                      raw.replace(b'"sequence":0',b'"sequence":false'),b' '*4096+b'\n'):
            self.assertEqual(self.parse(value)['status'],'INVALID_EVENT_RECORD')

    def test_bounded_input_sizes_and_invalid_expected_hash(self):
        for claim,events,expected in [(b'x'*4097,None,PLAN),(CLAIM,b'x'*(128*1024+1),PLAN),(CLAIM,None,'bad')]:
            with self.assertRaisesRegex(ValueError,'JOURNAL_CONTRACT'):
                j.inspect_bytes(claim,events,expected_plan_sha256=expected)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Linux root private file tests only')
class ReadTests(unittest.TestCase):
    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='address-history-test-',dir='/root'))
        self.path=self.base/'run';self.path.mkdir(mode=0o700)
        self.context=os.getxattr(self.path,'security.selinux').rstrip(b'\0') if 'security.selinux' in os.listxattr(self.path) else None

    def tearDown(self):
        assert self.base.parent==Path('/root') and self.base.name.startswith('address-history-test-')
        shutil.rmtree(self.base)

    def read(self):
        return j.inspect_history(str(self.path),expected_selinux=self.context,expected_plan_sha256=PLAN)

    def writer(self):return j.Journal(str(self.path),expected_selinux=self.context)

    def create(self,late=False):
        with self.writer().locked() as w:
            w.begin(PLAN);w.append(INTENT)
            if late:w.append(dict(kind='RECREATE_RESULT',service='postgresql',outcome='LATE'))
            w.append(stop(late))

    def bytes(self):return {p.name:(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in self.path.iterdir()}

    def test_empty_and_missing_paths_create_nothing(self):
        self.assertEqual(self.read()['status'],'EMPTY_UNCLAIMED');self.assertEqual(list(self.path.iterdir()),[])
        self.path=self.base/'absent'
        with self.assertRaisesRegex(ValueError,'HISTORY_UNAVAILABLE'):self.read()
        self.assertFalse(self.path.exists())

    def test_real_writer_readback_preserves_original_files(self):
        self.create(True);before=self.bytes();r=self.read()
        self.assertEqual(r['status'],'VALID_TERMINAL_HISTORY');self.assertEqual(r['valid_records'],4)
        self.assertEqual(before,self.bytes())
        with self.writer().locked() as w:
            with self.assertRaises(FileExistsError):w.begin(PLAN)

    def test_reader_never_uses_writer_or_creating_open(self):
        self.create();original=os.open;flags=[]
        def tracked(path,mode,*a,**k):flags.append(mode);return original(path,mode,*a,**k)
        with (patch.object(j.os,'open',side_effect=tracked),
              patch.object(j.os,'fsync',side_effect=AssertionError('write')),
              patch.object(j.Journal,'begin',side_effect=AssertionError('write'))):
            self.read()
        self.assertTrue(flags);self.assertFalse(any(f & (os.O_CREAT|os.O_TRUNC|os.O_WRONLY|os.O_RDWR) for f in flags))

    def test_busy_writer_refused_then_released_reader_succeeds(self):
        with self.writer().locked() as w:
            w.begin(PLAN)
            with self.assertRaisesRegex(ValueError,'HISTORY_UNAVAILABLE'):self.read()
        self.assertEqual(self.read()['status'],'VALID_INCOMPLETE_HISTORY')

    def test_partial_and_torn_files_remain_exact(self):
        self.create();p=self.path/'events.jsonl'
        with p.open('ab') as f:f.write(b'{"e')
        before=self.bytes();r=self.read()
        self.assertEqual(r['status'],'TORN_EVENT_TAIL');self.assertEqual(before,self.bytes())

    def test_unknown_inventory_or_missing_lock_refused_without_repair(self):
        (self.path/'private-synthetic-name').write_text('keep')
        before=self.bytes()
        with self.assertRaisesRegex(ValueError,'HISTORY_UNAVAILABLE'):self.read()
        self.assertEqual(before,self.bytes())
        (self.path/'private-synthetic-name').unlink();(self.path/'run.claim').write_bytes(CLAIM)
        with self.assertRaisesRegex(ValueError,'HISTORY_UNAVAILABLE'):self.read()
        self.assertFalse((self.path/'writer.lock').exists())

    def test_symlink_hardlink_wrong_mode_or_xattr_refused(self):
        self.create();p=self.path/'run.claim';saved=p.read_bytes()
        p.rename(self.base/'target');p.symlink_to(self.base/'target')
        with self.assertRaises(ValueError):self.read()
        p.unlink();os.link(self.base/'target',p)
        with self.assertRaises(ValueError):self.read()
        (self.base/'target').unlink();p.chmod(0o640)
        with self.assertRaises(ValueError):self.read()
        p.chmod(0o600);os.setxattr(p,'user.extra',b'x')
        with self.assertRaises(ValueError):self.read()
        self.assertEqual(p.read_bytes(),saved)

    def test_wrong_context_and_writable_parent_refused(self):
        self.create()
        with self.assertRaises(ValueError):j.inspect_history(str(self.path),expected_selinux=b'wrong',expected_plan_sha256=PLAN)
        self.base.chmod(0o777)
        with self.assertRaises(ValueError):self.read()

    def test_non_regular_or_oversized_file_refused_before_read(self):
        self.create();p=self.path/'events.jsonl';p.unlink();os.mkfifo(p,0o600)
        with self.assertRaises(ValueError):self.read()
        p.unlink();p.write_bytes(b'x'*(128*1024+1));p.chmod(0o600)
        with self.assertRaises(ValueError):self.read()

    def test_external_change_during_read_is_not_stable_evidence(self):
        self.create();original=os.read;changed=[]
        def racing(fd,count):
            value=original(fd,count)
            if not changed:
                changed.append(True)
                with (self.path/'events.jsonl').open('ab') as f:f.write(b'external')
            return value
        with patch.object(j.os,'read',side_effect=racing):
            # Change before events open is parsed as torn rather than silently
            # treated as the earlier complete history.
            r=self.read()
        self.assertEqual(r['status'],'TORN_EVENT_TAIL');self.assertFalse(r['may_resume'])

    def test_append_while_event_fd_is_read_refused(self):
        self.create();original=os.read;changed=[];inode=(self.path/'events.jsonl').stat().st_ino
        def racing(fd,count):
            value=original(fd,count)
            if not changed and os.fstat(fd).st_ino==inode:
                changed.append(True)
                with (self.path/'events.jsonl').open('ab') as f:f.write(b'external')
            return value
        with patch.object(j.os,'read',side_effect=racing):
            with self.assertRaisesRegex(ValueError,'HISTORY_UNAVAILABLE'):self.read()


if __name__=='__main__':unittest.main()
