import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_clone_trial import t

ROOT = Path(__file__).resolve().parents[2]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts/verify'/file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
a = module('a3', 'clone-daemon-restart.py')
o = module('observer_a3', 'observe-harbor-startup.py')
UNIT = 'ActiveState=active\nSubState=running\nMainPID=100\nInvocationID='+'a'*32+'\nExecMainStartTimestampMonotonic=100\n'
CURRENT = json.loads((Path(__file__).parent/'observed-a2r1-result.json').read_text())['after']


class A3Guards(unittest.TestCase):
    def test_hgfs_mount_blocks_even_if_host_share_disabled(self):
        for mount in ('fuse.vmhgfs-fuse', 'vmhgfs'):
            with self.subTest(mount=mount), self.assertRaisesRegex(ValueError, 'HGFS_MOUNT_PRESENT'):
                a.no_hgfs('1 2 0:3 / /mnt/hbr-check rw - '+mount+' .host:/HBR_CHECK rw')

    def test_local_mounts_allowed_and_malformed_fail_closed(self):
        a.no_hgfs('1 2 0:3 / / rw - xfs /dev/sda rw')
        with self.assertRaises(ValueError): a.no_hgfs('incomplete')

    def test_unit_running_identity_required(self):
        self.assertEqual(a.unit_state(UNIT)['MainPID'], '100')
        for old, new in [('active', 'inactive'), ('running', 'failed'), ('MainPID=100', 'MainPID=0'), ('a'*32, '')]:
            with self.subTest(new=new), self.assertRaises(ValueError): a.unit_state(UNIT.replace(old,new))

    def test_same_current_metadata_accepted(self):
        a.preserved(CURRENT, copy.deepcopy(CURRENT))

    def test_post_restart_drift_never_passes(self):
        for key, value in [('id','0'*64), ('image','other'), ('restart',{}), ('ports',{}),
                           ('logging',{}), ('health','starting'), ('mounts',[])]:
            with self.subTest(key=key):
                after=copy.deepcopy(CURRENT)
                # nginx has published ports, unlike some app containers.
                after['proxy'][key]=value
                with self.assertRaises(ValueError): a.preserved(CURRENT,after)

    def records(self):
        rows=[{'id':r['id'],'name':r['name'],'status':'running','health':'healthy',
               'started_at':'2026-10-08T09:00:00Z','exit_code':0} for r in CURRENT.values()]
        return [{'kind':'header','source_sha256':a.PINS['observer.py'],'host':'harbor01','uid':0,
                 'samples':a.SAMPLES,'interval_seconds':a.INTERVAL,'commands':{'docker':o.DOCKER,'listener':o.LISTENER}},
                {'kind':'sample','index':0,'docker':{'rc':0,'value':rows},'listener':{'rc':0,'value':True}}]

    def test_first_sample_requires_exact_identity_health_listener(self):
        a.ready_sample(self.records(),o,CURRENT)
        for change in ('id','health','listener','query-error','source'):
            r=self.records()
            if change=='id': r[1]['docker']['value'][0]['id']='f'*64
            if change=='health': r[1]['docker']['value'][0]['health']='starting'
            if change=='listener': r[1]['listener']['value']=False
            if change=='query-error': r[1]['docker']['error']='TIMEOUT'
            if change=='source': r[0]['source_sha256']='0'*64
            with self.subTest(change=change), self.assertRaises(ValueError): a.ready_sample(r,o,CURRENT)

    def test_command_timeout_and_interrupt_recorded_without_retry(self):
        for exc, expected in [(subprocess.TimeoutExpired(['mock'],90),124),(KeyboardInterrupt(),130),(OSError(),127)]:
            with self.subTest(rc=expected), tempfile.TemporaryDirectory() as td:
                s=a.Session(Path(td),t,o)
                with patch.object(a.subprocess,'run',side_effect=exc) as run:
                    rc,_=s.command('restart-once',a.RESTART,90,False)
                self.assertEqual(rc,expected);self.assertEqual(run.call_count,1)
                self.assertEqual(s.result['commands'][0]['rc'],expected)

    def test_global_claim_blocks_second_work_folder(self):
        with tempfile.TemporaryDirectory() as td:
            claim=Path(td)/'one.claim'
            with patch.object(a,'CLAIM',claim), patch.object(a,'boot_id',return_value='boot'):
                for i in range(2):
                    work=Path(td)/str(i);work.mkdir();s=a.Session(work,t,o)
                    s.current=CURRENT;s.result.update(boot_before='boot',unit_before=a.unit_state(UNIT))
                    s.process=SimpleNamespace(poll=lambda:None)
                    state='\n'.join(json.dumps(row) for row in CURRENT.values())
                    with patch.object(s,'guard'),patch.object(s,'read',side_effect=[state,UNIT]):
                        if i==0:s.claim()
                        else:
                            with self.assertRaises(FileExistsError):s.claim()
            self.assertTrue(claim.exists())

    def test_observer_query_gaps_are_preserved_not_autostart_pass(self):
        with tempfile.TemporaryDirectory() as td:
            s=a.Session(Path(td),t,o);s.capture=Path(td)/'observation.jsonl'
            s.process=SimpleNamespace(wait=lambda timeout:2);s.observer_deadline=a.time.monotonic()+30
            summary={'source_sha256':a.PINS['observer.py'],'error_sample_indices':[1,2], 'AUTOSTART':'NOT_EVALUATED'}
            with patch.object(o,'summarize',return_value=summary):s.finish_observer()
            self.assertEqual(s.result['observer_rc'],2)
            self.assertEqual(s.result['AUTOSTART'],'NOT_EVALUATED')

    def test_observer_exit_before_ready_stops_preparation(self):
        with tempfile.TemporaryDirectory() as td:
            s=a.Session(Path(td),t,o);s.current=CURRENT
            proc=SimpleNamespace(poll=lambda:1)
            with patch.object(a.subprocess,'Popen',return_value=proc) as launch:
                with self.assertRaisesRegex(ValueError,'OBSERVER_EXITED_BEFORE_READY'):s.start_observer()
            self.assertTrue(launch.call_args.kwargs['start_new_session'])
            self.assertNotIn('t0',s.result)

    def test_observer_timeout_preserves_incomplete_capture(self):
        with tempfile.TemporaryDirectory() as td:
            s=a.Session(Path(td),t,o);s.capture=Path(td)/'observation.jsonl'
            s.capture.write_bytes(b'{"kind":"header"}\n')
            s.process=SimpleNamespace(wait=lambda timeout:(_ for _ in ()).throw(subprocess.TimeoutExpired(['observer'],500)))
            s.observer_deadline=a.time.monotonic()+1
            with patch.object(s,'stop_observer') as stop,patch.object(o,'summarize') as summary:
                with self.assertRaisesRegex(ValueError,'OBSERVER_TIMEOUT'):s.finish_observer()
                stop.assert_called_once();summary.assert_not_called()
            self.assertEqual(s.capture.read_bytes(),b'{"kind":"header"}\n')


class A3Journal(unittest.TestCase):
    BOOT = 'ec7a9c3c-3a91-4d4a-8d42-f68ce23ce92b'

    def test_real_incident_boot_uses_exact_field_and_original_time_window(self):
        with tempfile.TemporaryDirectory() as td:
            s = a.Session(Path(td), t, o)
            s.result.update(boot_before=self.BOOT, t0={'epoch': 1791455773.5666983})
            def journalctl(argv, **kwargs):
                self.assertEqual(argv, ['journalctl', '--no-pager', '-u', 'docker.service',
                    '_BOOT_ID=ec7a9c3c3a914d4a8d42f68ce23ce92b', '--since', '@1791455773',
                    '--until', '@1791455959', '-o', 'short-iso-precise'])
                self.assertEqual(kwargs['timeout'], 30)
                kwargs['stdout'].write(b'2026-10-08T19:36:24+0900 preserved journal\n')
                return SimpleNamespace(returncode=0)
            with patch.object(a.time, 'time', return_value=1791455958.95), \
                 patch.object(a.subprocess, 'run', side_effect=journalctl) as run:
                s.journal()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(s.result['commands'][0]['rc'], 0)
            self.assertIn('preserved journal', (Path(td)/'0-docker-journal-private.stdout').read_text())
            self.assertEqual(s.result['AUTOSTART'], 'NOT_EVALUATED')

    def test_invalid_recorded_boot_never_broadens_query(self):
        for value in ('', '0', '-1', self.BOOT+' ', 'g'+self.BOOT[1:], '-'*36, None):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as td:
                s = a.Session(Path(td), t, o)
                s.result.update(boot_before=value, t0={'epoch': 1})
                with patch.object(s, 'command') as command:
                    with self.assertRaisesRegex(ValueError, 'JOURNAL_BOOT_ID_INVALID'):
                        s.journal()
                    command.assert_not_called()

    def test_failed_or_empty_journal_stays_failure_without_fallback(self):
        for rc, raw, error in ((1, 'partial', 'JOURNAL_COLLECTION_FAILED'),
                               (124, 'partial', 'JOURNAL_COLLECTION_FAILED'),
                               (0, '', 'JOURNAL_EMPTY'), (0, '-- No entries --\n', 'JOURNAL_EMPTY')):
            with self.subTest(rc=rc, raw=raw), tempfile.TemporaryDirectory() as td:
                s = a.Session(Path(td), t, o)
                s.result.update(boot_before=self.BOOT, t0={'epoch': 1})
                with patch.object(s, 'command', return_value=(rc, raw)) as command:
                    with self.assertRaisesRegex(ValueError, error): s.journal()
                    command.assert_called_once()

    def test_no_tzero_does_not_query_historical_logs(self):
        with tempfile.TemporaryDirectory() as td:
            s = a.Session(Path(td), t, o)
            with patch.object(s, 'command') as command:
                s.journal()
                command.assert_not_called()


class A3PostCollection(unittest.TestCase):
    def exercise(self, unhealthy=False, failed_query=None, bad_state=False, bad_unit=False,
                 xattr_error=False, changed_boot=False, changed_profile=False, guard_error=False,
                 full_flow=False):
        historical=json.loads((Path(__file__).parent/'observed-a2r1-result.json').read_text())['before']
        mounts=t.volume_mounts(historical)
        engine={'Version':'29.8.0','GitCommit':'3ce5872'}
        security={'security_options':['name=seccomp,profile=builtin','name=cgroupns'],'root':'/var/lib/docker','driver':'overlayfs'}
        labels=[{'id':CURRENT[k]['id'],'mount_label':'','process_label':'','security_opt':None,'privileged':False} for k in t.A2R1_TARGETS]
        after=copy.deepcopy(CURRENT)
        if unhealthy:after['core'].update(status='exited',health='unhealthy')
        unit=UNIT.replace('a'*32,'b'*32)
        if bad_unit:unit=unit.replace('active','inactive')
        responses={'unit-after':unit,
                   'state-after':'invalid json' if bad_state else '\n'.join(json.dumps(r) for r in after.values()),
                   'profile-engine-after':json.dumps(engine),'profile-compose-after':'5.5.2' if changed_profile else '5.5.1',
                   'profile-security-after':json.dumps(security),'profile-enforcing-after':'Enforcing',
                   'profile-labels-after':'\n'.join(json.dumps(r) for r in labels),
                   'listener-after':'' if changed_profile else 'LISTEN 0 4096 127.0.0.1:1514 0.0.0.0:*',
                   'live-restore-after':'true' if changed_profile else 'false','restart-once':''}
        for name,m in mounts.items():
            responses['volume-'+name]=json.dumps({'name':name,'driver':'local','mountpoint':m['Source'],'scope':'local','has_options':False})
        with tempfile.TemporaryDirectory() as td:
            s=a.Session(Path(td),t,o);s.current=CURRENT;s.historical=historical
            s.result.update(boot_before='boot',unit_before=a.unit_state(UNIT),t0={'monotonic_ns':1},
                            profile_before={'engine':engine,'security':security,'volume_xattrs':{m['Source']:'system_u:object_r:container_file_t:s0' for m in mounts.values()}})
            calls=[];xattrs=[];original_command=s.command
            def command(name,*args,**kwargs):
                calls.append(name);return original_command(name,*args,**kwargs)
            def run(argv,**kwargs):
                name=calls[-1];failed=name==failed_query
                kwargs['stdout'].write((('PARTIAL_OUTPUT' if failed else responses[name])).encode())
                return SimpleNamespace(returncode=1 if failed else 0)
            def getxattr(path,key):
                xattrs.append(path)
                if xattr_error and len(xattrs)==1:raise OSError('mock unreadable xattr')
                return b'system_u:object_r:container_file_t:s0\0'
            with patch.object(s,'command',side_effect=command),patch.object(a.subprocess,'run',side_effect=run), \
                 patch.object(a,'boot_id',return_value='changed' if changed_boot else 'boot'), \
                 patch.object(a.os,'getxattr',side_effect=getxattr,create=True), \
                 patch.object(s,'guard',return_value=None,side_effect=ValueError('HGFS_MOUNT_PRESENT') if guard_error else None) as guard:
                if full_flow:
                    def claim():s.result['status']='RESTART_CLAIMED_REQUIRES_REVIEW'
                    with patch.object(s,'preflight'),patch.object(s,'start_observer'),patch.object(s,'claim',side_effect=claim), \
                         patch.object(s,'finish_observer'),patch.object(s,'journal') as journal,patch.object(s,'stop_observer'):
                        rc=a.execute(s);self.assertEqual(journal.call_count,1)
                else:
                    try:s.postcheck();rc=0
                    except ValueError as exc:self.assertEqual(str(exc),'POSTCHECK_FAILED');rc=2
                self.assertEqual(guard.call_count,1)
            self.assertEqual(len(xattrs),9)
            self.assertEqual(len([n for n in calls if n.startswith('volume-')]),9)
            for name in ('profile-engine-after','profile-compose-after','profile-security-after','profile-enforcing-after',
                         'profile-labels-after','listener-after','live-restore-after'):
                self.assertIn(name,calls)
            self.assertEqual(len(s.result['postcheck_capture']),29)
            # Production command() stores selected partial stdout even on query failure.
            if failed_query:
                record=next(c for c in s.result['commands'] if c['name']==failed_query)
                self.assertEqual((Path(td)/record['stdout_file']).read_bytes(),b'PARTIAL_OUTPUT')
            saved=json.loads((Path(td)/'result.json').read_text())
            self.assertEqual(saved['postchecks'],s.result['postchecks'])
            return rc,s.result,calls

    def test_healthy_complete_snapshot_passes(self):
        rc,r,_=self.exercise();self.assertEqual((rc,r['postchecks']),(0,'PASS'))
        self.assertEqual(r['postcheck_errors'],[])

    def test_exited_app_still_collects_all_and_journal_after_one_restart(self):
        rc,r,calls=self.exercise(unhealthy=True,full_flow=True)
        self.assertEqual((rc,r['status']),(2,'STOP_RECOVERY_REQUIRED'))
        self.assertEqual(calls.count('restart-once'),1)
        self.assertEqual(r['postcheck_validation']['preservation']['error_code'],'POST_NOT_ALL_HEALTHY')
        self.assertEqual(r['postcheck_validation']['listener']['status'],'PASS')

    def test_unit_failure_does_not_skip_other_captures(self):
        rc,r,_=self.exercise(bad_unit=True);self.assertEqual(rc,2)
        self.assertEqual(r['postcheck_validation']['unit']['status'],'FAIL')
        self.assertEqual(r['postcheck_validation']['preservation']['status'],'PASS')

    def test_failed_or_malformed_state_does_not_skip_known_id_queries(self):
        for args in ({'failed_query':'state-after'},{'bad_state':True}):
            with self.subTest(args=args):
                rc,r,_=self.exercise(**args);self.assertEqual(rc,2)
                self.assertEqual(r['postcheck_validation']['preservation']['status'],'NOT_EVALUATED')
                self.assertEqual(r['postcheck_validation']['labels']['status'],'PASS')

    def test_failed_label_query_keeps_partial_raw_and_other_metadata(self):
        rc,r,_=self.exercise(failed_query='profile-labels-after');self.assertEqual(rc,2)
        self.assertEqual(r['postcheck_validation']['labels']['status'],'NOT_EVALUATED')
        self.assertEqual(r['postcheck_validation']['live_restore']['status'],'PASS')

    def test_one_volume_or_xattr_failure_does_not_skip_the_remaining_eight(self):
        name=next(iter(t.volume_mounts(json.loads((Path(__file__).parent/'observed-a2r1-result.json').read_text())['before'])))
        for args in ({'failed_query':'volume-'+name},{'xattr_error':True}):
            with self.subTest(args=args):
                rc,r,_=self.exercise(**args);self.assertEqual(rc,2)
                self.assertEqual(r['postcheck_validation']['listener']['status'],'PASS')

    def test_multiple_failures_are_reported_together(self):
        rc,r,_=self.exercise(changed_boot=True,changed_profile=True,guard_error=True)
        self.assertEqual(rc,2)
        items={e['item'] for e in r['postcheck_errors']}
        self.assertTrue({'boot','compose','listener','live_restore','final_guard'}.issubset(items))
        self.assertEqual(r['AUTOSTART'],'NOT_EVALUATED')


class Flow:
    def __init__(self, fail=None, restart_rc=0):
        self.result={'status':'PRECHECK','AUTOSTART':'NOT_EVALUATED'};self.calls=[]
        self.fail=fail;self.rc=restart_rc
    def call(self,name):
        self.calls.append(name)
        if name==self.fail:raise ValueError('INJECTED_FAILURE')
    def preflight(self):self.call('preflight')
    def start_observer(self):self.call('observer-start')
    def claim(self):self.call('claim');self.result['status']='RESTART_CLAIMED_REQUIRES_REVIEW'
    def restart(self):self.call('restart');self.result['restart_rc']=self.rc
    def finish_observer(self):self.call('observe-finish')
    def postcheck(self):self.call('postcheck')
    def journal(self):self.call('journal')
    def stop_observer(self):self.call('observer-cleanup')
    def save(self):pass


class A3Flow(unittest.TestCase):
    def test_success_is_review_required_and_one_restart(self):
        s=Flow();self.assertEqual(a.execute(s),0)
        self.assertEqual(s.calls,['preflight','observer-start','claim','restart','observe-finish','postcheck','journal','observer-cleanup'])
        self.assertEqual(s.result['status'],'OBSERVATION_COMPLETE_REVIEW_REQUIRED')
        self.assertEqual(s.result['AUTOSTART'],'NOT_EVALUATED')

    def test_preconditions_never_restart(self):
        for fail in ('preflight','observer-start','claim'):
            s=Flow(fail=fail);self.assertEqual(a.execute(s),2)
            self.assertNotIn('restart',s.calls);self.assertEqual(s.result['status'],'STOP_BEFORE_RESTART')

    def test_restart_nonzero_or_timeout_still_collects(self):
        for rc in (1,124,130,127):
            s=Flow(restart_rc=rc);self.assertEqual(a.execute(s),2)
            self.assertEqual(s.calls.count('restart'),1)
            for name in ('observe-finish','postcheck','journal'):self.assertIn(name,s.calls)
            self.assertEqual(s.result['status'],'STOP_RECOVERY_REQUIRED')

    def test_failed_capture_still_attempts_other_captures(self):
        for fail in ('observe-finish','postcheck','journal'):
            s=Flow(fail=fail);self.assertEqual(a.execute(s),2)
            self.assertEqual(s.calls.count('restart'),1)
            for name in ('observe-finish','postcheck','journal'):self.assertIn(name,s.calls)
            self.assertEqual(s.result['status'],'STOP_RECOVERY_REQUIRED')


if __name__=='__main__':unittest.main()
