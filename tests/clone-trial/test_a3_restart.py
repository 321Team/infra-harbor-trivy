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
