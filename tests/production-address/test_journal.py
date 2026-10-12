"""Real Linux temporary files/fsync/flock; no Docker, VM or production input."""
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

spec = importlib.util.spec_from_file_location('address_journal',
    Path(__file__).resolve().parents[2] / 'scripts/production/harbor_address_journal.py')
j = importlib.util.module_from_spec(spec)
spec.loader.exec_module(j)


class SchemaTests(unittest.TestCase):
    def test_extra_secret_field_and_untrusted_reason_rejected(self):
        for event in [dict(kind='BEGIN', plan_sha256='a'*64, secret='TOKEN'),
                      dict(kind='STOP', reason='TOKEN', claimed_services=[], transport_entered_services=[], healthy_services=[])]:
            with self.assertRaisesRegex(ValueError, '^JOURNAL_CONTRACT$'):
                j.validate_event(event)

    def test_invalid_id_order_and_false_complete_rejected(self):
        for event in [dict(kind='RECREATE_INTENT', service='log', old_id='a'*64),
                      dict(kind='APP_HEALTHY', service='core', new_id='id'),
                      dict(kind='COMPLETE', healthy_services=['core']),
                      dict(kind='STOP', reason='DEADLINE', claimed_services=[], transport_entered_services=['postgresql'], healthy_services=[])]:
            with self.assertRaises(ValueError):
                j.validate_event(event)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root temporary journal only')
class DiskTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='address-journal-test-', dir='/root'))
        self.path = self.base / 'run'
        self.path.mkdir(mode=0o700)
        attrs = os.listxattr(self.path)
        self.context = os.getxattr(self.path, 'security.selinux').rstrip(b'\0') if 'security.selinux' in attrs else None
        self.journal = self.new()

    def tearDown(self):
        assert self.base.parent == Path('/root') and self.base.name.startswith('address-journal-test-')
        shutil.rmtree(self.base)

    def new(self):
        return j.Journal(str(self.path), expected_selinux=self.context)

    def intent(self):
        self.journal.append(dict(kind='RECREATE_INTENT', service='postgresql', old_id='b'*64))

    def stop(self, *, entered=False):
        self.journal.append(dict(kind='STOP', reason='DEADLINE', claimed_services=['postgresql'],
                                transport_entered_services=['postgresql'] if entered else [], healthy_services=[]))

    def records(self):
        return [json.loads(line) for line in (self.path / 'events.jsonl').read_bytes().splitlines()]

    def test_sequence_integration_nine_ordered_services_and_chain(self):
        import test_sequence as t
        p=t.fixture()
        class Backend(t.Backend):
            def observe(self, deadline):
                self.journal.spent=True
                return super().observe(deadline)
            def recreate(self, **kwargs):
                # Real journal has a count, synthetic backend needs event list.
                self.rows[kwargs['service']].update(
                    id=f'{t.m.ORDER.index(kwargs["service"])+101:064x}',
                    logging=t.m.logging_candidate(self.rows[kwargs['service']]['logging']),
                    status='running', health='healthy', exit_code=0, error_sha256='e'*64)
                self.calls.append(kwargs['service'])
                return 0
        b=Backend(p,self.journal)
        s=t.m.Sequence(p,b,self.journal,clock=b.clock,sleep=b.sleep)
        result=s.run(deadline_mono=200)
        self.assertEqual(result['status'],'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        records=self.records()
        self.assertEqual(len(records),29)
        previous='0'*64
        for i,r in enumerate(records):
            self.assertEqual(r['sequence'],i)
            self.assertEqual(r['previous_sha256'],previous)
            previous=r.pop('sha256')
            self.assertEqual(hashlib.sha256(j.encode(r)).hexdigest(),previous)
        self.assertEqual(records[-1]['event']['kind'],'COMPLETE')
        with self.new().locked() as other:
            with self.assertRaises(FileExistsError): other.begin('a'*64)

    def test_existing_partial_claim_is_never_truncated(self):
        p=self.path/'run.claim'; p.write_bytes(b'partial');p.chmod(0o600)
        with self.journal.locked():
            with self.assertRaises(FileExistsError): self.journal.begin('a'*64)
        self.assertEqual(p.read_bytes(),b'partial')
        self.assertFalse((self.path/'events.jsonl').exists())

    def test_unexpected_inventory_refuses_begin(self):
        (self.path/'unknown').write_text('existing')
        with self.journal.locked():
            with self.assertRaises(FileExistsError): self.journal.begin('a'*64)
        self.assertFalse((self.path/'run.claim').exists())

    def test_two_instances_contend_before_claim(self):
        with self.journal.locked():
            with self.assertRaises(BlockingIOError):
                with self.new().locked(): pass
            self.journal.begin('a'*64)
        self.assertEqual(len(self.records()),1)

    def test_forked_instance_refused(self):
        with patch.object(j.os,'getpid',return_value=os.getpid()+1):
            with self.assertRaises(ValueError):
                with self.journal.locked(): pass

    def test_claim_fsync_failure_retains_claim_and_disables_writer(self):
        with self.journal.locked():
            with patch.object(j.os,'fsync',side_effect=OSError('injected')):
                with self.assertRaises(OSError): self.journal.begin('a'*64)
            self.assertTrue(self.journal.failed)
            with self.assertRaises(ValueError): self.intent()
        self.assertTrue((self.path/'run.claim').exists())
        with self.new().locked() as other:
            with self.assertRaises(FileExistsError): other.begin('a'*64)

    def test_append_fsync_failure_is_not_repaired_or_followed_by_stop(self):
        with self.journal.locked():
            self.journal.begin('a'*64)
            with patch.object(j.os,'fsync',side_effect=OSError('injected')):
                with self.assertRaises(OSError): self.intent()
            size=(self.path/'events.jsonl').stat().st_size
            with self.assertRaises(ValueError): self.stop()
            self.assertEqual((self.path/'events.jsonl').stat().st_size,size)

    def test_partial_write_failure_preserves_torn_tail(self):
        with self.journal.locked():
            self.journal.begin('a'*64)
            original=os.write
            calls=[]
            def write(fd, raw):
                if calls: raise OSError('injected')
                calls.append(True);return original(fd,raw[:3])
            with patch.object(j.os,'write',side_effect=write):
                with self.assertRaises(OSError): self.intent()
            self.assertTrue(self.journal.failed)
        self.assertEqual((self.path/'events.jsonl').read_bytes().splitlines()[-1],b'{"e')
        with self.new().locked() as other:
            with self.assertRaises(FileExistsError): other.begin('a'*64)

    def test_lock_symlink_refused_without_touching_target(self):
        target=self.base/'target';target.write_text('keep');target.chmod(0o600)
        (self.path/'writer.lock').symlink_to(target)
        with self.assertRaises(OSError):
            with self.journal.locked(): pass
        self.assertEqual(target.read_text(),'keep')

    def test_hardlinked_lock_refused(self):
        p=self.path/'writer.lock';p.write_bytes(b'');p.chmod(0o600)
        os.link(p,self.base/'alias')
        with self.assertRaises(ValueError):
            with self.journal.locked(): pass

    def test_directory_symlink_refused(self):
        alias=self.base/'alias';alias.symlink_to(self.path,target_is_directory=True)
        with self.assertRaises(OSError):
            with j.Journal(str(alias),expected_selinux=self.context).locked():pass

    def test_permissions_and_context_must_match_without_repair(self):
        self.path.chmod(0o750)
        with self.assertRaises(ValueError):
            with self.journal.locked():pass
        self.assertEqual(self.path.stat().st_mode & 0o777,0o750)
        self.path.chmod(0o700)
        with self.assertRaises(ValueError):
            with j.Journal(str(self.path),expected_selinux=b'wrong').locked():pass

    def test_unexpected_xattr_refused(self):
        os.setxattr(self.path,'user.extra',b'value')
        with self.assertRaises(ValueError):
            with self.journal.locked():pass

    def test_external_append_or_inode_replacement_refused(self):
        with self.journal.locked():
            self.journal.begin('a'*64)
            with (self.path/'events.jsonl').open('ab') as f:f.write(b'external')
            with self.assertRaises(ValueError):self.intent()
        other=self.base/'second';other.mkdir(mode=0o700)
        instance=j.Journal(str(other),expected_selinux=self.context)
        with instance.locked():
            instance.begin('a'*64)
            (other/'writer.lock').rename(other/'old.lock')
            (other/'writer.lock').touch(mode=0o600)
            with self.assertRaises(ValueError):instance.append(dict(kind='STOP',reason='DEADLINE',claimed_services=[],transport_entered_services=[],healthy_services=[]))

    def test_pre_send_stop_and_late_result_are_distinct(self):
        with self.journal.locked():
            self.journal.begin('a'*64);self.intent();self.stop()
        self.assertEqual([r['event']['kind'] for r in self.records()],['BEGIN','RECREATE_INTENT','STOP'])

    def test_terminal_record_rejects_further_append(self):
        with self.journal.locked():
            self.journal.begin('a'*64);self.intent()
            self.journal.append(dict(kind='RECREATE_RESULT',service='postgresql',outcome='LATE'))
            self.stop(entered=True)
            before=(self.path/'events.jsonl').read_bytes()
            with self.assertRaises(ValueError):self.stop(entered=True)
            self.assertEqual(before,(self.path/'events.jsonl').read_bytes())

    def test_success_record_requires_actual_intent_ack_order(self):
        with self.journal.locked():
            self.journal.begin('a'*64)
            with self.assertRaises(ValueError):
                self.journal.append(dict(kind='APP_HEALTHY',service='postgresql',new_id='b'*64))
        self.assertEqual(len(self.records()),1)

    def test_claim_and_events_are_exclusive_root_private_files(self):
        with self.journal.locked():self.journal.begin('a'*64)
        for name in ['writer.lock','run.claim','events.jsonl']:
            s=(self.path/name).stat()
            self.assertEqual((s.st_uid,s.st_gid,s.st_nlink,s.st_mode & 0o777),(0,0,1,0o600))


if __name__ == '__main__':
    unittest.main()
