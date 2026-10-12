"""CI-only actual systemd lifecycle; synthetic payload, no Docker or guest access.

The generated unit and UnitGuard are real. Pin checks below use real bytes/owner/
mode; SELinux context is synthetic on Ubuntu CI, not production attestation.
FDS_TEST_SYSTEMD=1 explicitly opts into temporary CI unit installation/start/stop.
When opted in, missing root/systemd/cgroup-v2 is a failure rather than a skip.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from test_address_entrypoint import fixture, launch


class SystemdIO:
    def pinned(self, path, spec, kind, deadline):
        assert kind == 'file' and time.monotonic() < deadline
        p = Path(path)
        s = p.lstat()
        assert stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and s.st_nlink == 1
        assert stat.S_IMODE(s.st_mode) == spec['mode']
        assert hashlib.sha256(p.read_bytes()).hexdigest() == spec['sha256']

    def command(self, spec, args, deadline):
        result = subprocess.run(['/usr/bin/systemctl', *args], capture_output=True,
            timeout=max(.01, deadline-time.monotonic()), env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        return result.returncode, result.stdout

    def cgroup(self):
        return Path('/proc/self/cgroup').read_text().splitlines()


def make_guard(path):
    value = json.loads(path.read_bytes())
    return launch.UnitGuard(value, launch_path=str(path),
        launch_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        launch_context='synthetic_t', systemctl={}, io=SystemdIO())


def run_helper():
    path = Path(sys.argv[sys.argv.index('--launch')+1])
    receipt = path.parent/'running.json'
    try:
        guard = make_guard(path)
        deadlines = guard.verify(time.monotonic()+3)
        # A separate session/process group must still be terminated with the unit.
        child = subprocess.Popen([sys.executable,'-I','-S','-B','-c','import time;time.sleep(60)'],
            start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        guard.verify(time.monotonic()+3)
        receipt.write_text(json.dumps(dict(status='VERIFIED',pid=os.getpid(),child=child.pid,
            cgroup=SystemdIO().cgroup(),deadlines=deadlines)), encoding='utf-8')
        while True:
            time.sleep(1)
    except Exception as exc:
        receipt.write_text(json.dumps(dict(status='FAILED',reason=str(exc))), encoding='utf-8')
        raise


@unittest.skipUnless(os.environ.get('FDS_TEST_SYSTEMD')=='1','explicit disposable systemd CI only')
class SystemdLifecycleTests(unittest.TestCase):
    def test_generated_unit_real_readiness_identity_and_deadline(self):
        self.assertEqual(sys.platform,'linux')
        self.assertEqual(os.geteuid(),0)
        self.assertTrue(Path('/run/systemd/system').is_dir(),'CI requires booted systemd')
        self.assertTrue(Path('/sys/fs/cgroup/cgroup.controllers').is_file(),'CI requires cgroup v2')
        base = Path(tempfile.mkdtemp(prefix='address-systemd-test-',dir='/root'))
        unit_path = None
        created = False
        unit = 'fds-harbor-address-ci-'+base.name.removeprefix('address-systemd-test-').replace('_','-')+'.service'
        def ctl(*args, check=True):
            result = subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,timeout=15)
            if check:
                self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            return result
        def row():
            output = ctl('show',unit,'--property=ActiveState,SubState,MainPID,Result,NRestarts').stdout.decode()
            return dict(line.split('=',1) for line in output.splitlines())
        try:
            value = fixture()
            value['supervisor']['unit'] = unit
            value['budgets'] = dict(prepare_seconds=5,mutation_seconds=3,collection_seconds=2,termination_seconds=1)
            value['interpreter']['path'] = str(Path(sys.executable).resolve())
            helper = base/'helper.py'
            helper.write_text('import sys\nsys.path.insert(0,'+repr(str(Path(__file__).resolve().parent))+')\n'
                'from test_address_systemd import run_helper\nrun_helper()\n',encoding='utf-8')
            helper.chmod(0o600)
            value['bootstrap']['path'] = str(helper)
            path = base/'launch.json'
            path.write_text(json.dumps(value),encoding='utf-8');path.chmod(0o600)
            guard = make_guard(path)
            unit_path = Path('/run/systemd/system')/unit
            # Never replace any pre-existing unit, even in disposable CI.
            with unit_path.open('x',encoding='utf-8',newline='\n') as stream:
                created = True
                stream.write(guard.text)
            unit_path.chmod(0o644)
            ctl('daemon-reload')
            self.assertEqual(guard.verify_installed(time.monotonic()+5)['lifecycle'],'NEVER_STARTED')
            started = time.monotonic()
            ctl('start',unit)
            receipt = base/'running.json'
            limit = started+8
            while not receipt.exists() and time.monotonic()<limit:
                time.sleep(.05)
            self.assertTrue(receipt.exists(),str(row()))
            result = json.loads(receipt.read_text())
            self.assertEqual(result['status'],'VERIFIED',result)
            self.assertEqual(result['cgroup'],['0::/system.slice/'+unit])
            self.assertEqual(result['deadlines'][2]-result['deadlines'][0],5)
            with self.assertRaises(ValueError):
                guard.verify_installed(time.monotonic()+3)
            limit = started+25
            state = row()
            while state['MainPID']!='0' and time.monotonic()<limit:
                time.sleep(.1)
                state = row()
            self.assertEqual(state['MainPID'],'0',state)
            self.assertEqual(state['Result'],'timeout',state)
            self.assertEqual(state['NRestarts'],'0',state)
            self.assertGreaterEqual(time.monotonic()-started,9)
            procs = Path('/sys/fs/cgroup/system.slice')/unit/'cgroup.procs'
            self.assertTrue(not procs.exists() or not procs.read_text().strip(),'unit left surviving child processes')
            child = Path('/proc')/str(result['child'])/'stat'
            self.assertTrue(not child.exists() or child.read_text().split()[2]=='Z','detached child survived deadline')
            with self.assertRaises(ValueError):
                guard.verify_installed(time.monotonic()+3)
        finally:
            # Only this randomly named CI unit and verified /root temp directory.
            if created and unit_path is not None and unit_path.exists():
                ctl('stop',unit,check=False)
                ctl('reset-failed',unit,check=False)
                unit_path.unlink()
                ctl('daemon-reload',check=False)
            assert base.parent==Path('/root') and base.name.startswith('address-systemd-test-')
            shutil.rmtree(base)


if __name__=='__main__':
    unittest.main()

