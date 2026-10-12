"""Explicit disposable CI only: real kernel veth/netns and PostgreSQL 16.

No Docker/Harbor or production credentials/data. Kernel and PostgreSQL semantics
are tested separately from the synthetic full sequence; not a Harbor rehearsal.
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
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/production'),str(ROOT/'scripts/recovery')]
from harbor_address_host import ProductionReadOnly
import harbor_address_host as host
from harbor_address_network import owned_links, route_projection
from harbor_address_compose import run_process


def command(argv,timeout=15,check=True):
    return subprocess.run(argv,capture_output=True,timeout=timeout,check=check)


@unittest.skipUnless(os.environ.get('FDS_TEST_TRANSITION_LINUX')=='1','explicit disposable Linux CI only')
class ActualTransitionTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform,'linux');self.assertEqual(os.geteuid(),0)

    def test_real_pinned_peer_read_and_kernel_pair_validation(self):
        suffix=os.urandom(4).hex();bridge='hb'+suffix;a='ha'+suffix;b='hc'+suffix
        child=None;created=[]
        ip=str(Path(shutil.which('ip')).resolve())
        enter=str(Path(shutil.which('nsenter')).resolve())
        tools={}
        for name,path in [('ip',ip),('nsenter',enter)]:
            tools[name]=dict(path=path,mode=stat.S_IMODE(Path(path).stat().st_mode),
                sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),selinux='synthetic_t')
        try:
            child=subprocess.Popen(['unshare','--net','--','sleep','60'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                self.assertIsNone(child.poll())
                if os.stat(f'/proc/{child.pid}/ns/net').st_ino!=os.stat('/proc/self/ns/net').st_ino:break
                time.sleep(.02)
            command([ip,'link','add',bridge,'type','bridge']);created.append(bridge)
            command([ip,'link','add',a,'type','veth','peer','name',b]);created.append(a)
            command([ip,'link','set',a,'master',bridge])
            command([ip,'link','set',b,'netns',str(child.pid)])
            # Actual pinned executable/hash/metadata/fd path. Only SELinux is
            # intentionally synthetic on Ubuntu CI; never an operational option.
            def ci_context(fd,expected):
                self.assertEqual(expected,b'synthetic_t')
                self.assertNotIn('security.selinux',os.listxattr(fd))
            with patch.object(host,'context_check',side_effect=ci_context):
                peers=ProductionReadOnly().peer_links(child.pid,tools,time.monotonic()+8)
            peer=next(x for x in peers if x['ifname']==b)
            links=json.loads(command([ip,'-j','-d','link','show']).stdout)
            owned=owned_links(links,{'a'*64:peer['address']},{'a'*64:peers},bridge=bridge)
            self.assertEqual(set(owned),{a})
            command([ip,'link','set',bridge,'up'])
            command([ip,'link','set',a,'up'])
            command([enter,'-t',str(child.pid),'-n','--',ip,'link','set',b,'up'])
            limit=time.monotonic()+5
            while True:
                routes=json.loads(command([ip,'-j','route','show','table','all']).stdout)
                if len([r for r in routes if r.get('dev')==a])==3 or time.monotonic()>=limit:break
                time.sleep(.05)
            stable=route_projection(routes,owned)
            self.assertEqual(stable,sorted([r for r in routes if r.get('dev')!=a],key=host.fingerprint))
            command([ip,'link','set',a,'name',a+'x']);created[-1]=a+'x'
            with patch.object(host,'context_check',side_effect=ci_context):
                peers2=ProductionReadOnly().peer_links(child.pid,tools,time.monotonic()+8)
            links2=json.loads(command([ip,'-j','-d','link','show']).stdout)
            self.assertEqual(set(owned_links(links2,{'a'*64:peer['address']},{'a'*64:peers2},bridge=bridge)),{a+'x'})
            # Wrong bridge cannot acquire ownership just because counts match.
            with self.assertRaises(ValueError):
                owned_links(links2,{'a'*64:peer['address']},{'a'*64:peers2},bridge='unrelated')
        finally:
            for name in reversed(created):command([ip,'link','delete',name],check=False)
            if child is not None:
                child.terminate();child.wait(timeout=5);child.stderr.close()

    def test_postgres_smart_wait_survives_client_timeout_then_cleanly_stops(self):
        import pwd
        user=pwd.getpwnam('postgres');binpath=Path('/usr/lib/postgresql/16/bin')
        self.assertTrue((binpath/'initdb').is_file(),'CI PostgreSQL 16 tools required')
        base=Path(tempfile.mkdtemp(prefix='harbor-pg-ci-',dir='/tmp'));base.chmod(0o700)
        os.chown(base,user.pw_uid,user.pw_gid)
        data=base/'data';log=base/'postgres.log';holder=None;started=False
        prefix=[str(Path(shutil.which('runuser')).resolve()),'-u','postgres','--']
        def pg(name,*args,check=True,timeout=20):
            return command([*prefix,str(binpath/name),*map(str,args)],check=check,timeout=timeout)
        try:
            pg('initdb','-D',data,'--no-locale','--auth-local=trust','--auth-host=reject')
            # Unique Unix socket, TCP disabled: no connection to an existing DB.
            pg('pg_ctl','-D',data,'-l',log,'-o',f"-k {base} -c listen_addresses='' -p 55439",'start','-w','-t','10')
            started=True
            holder=subprocess.Popen([*prefix,str(binpath/'psql'),'-h',str(base),'-p','55439',
                '-d','postgres','-X','-q','-A','-t'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            holder.stdin.write(b'SELECT 1;\n');holder.stdin.flush()
            import selectors
            with selectors.DefaultSelector() as selector:
                selector.register(holder.stdout,selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5),'active DB session not established')
                self.assertEqual(holder.stdout.readline().strip(),b'1')
            pid=int((data/'postmaster.pid').read_text().splitlines()[0])
            started_at=time.monotonic()
            # Same bounded client runner as Compose. Timing values here are CI
            # test stimuli, never an actual request's budget.
            result=run_process([*prefix,str(binpath/'pg_ctl'),'-D',str(data),'-m','smart',
                '-t','20','stop','-w'],b'',cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                pass_fds=(),deadline=time.monotonic()+1)
            self.assertEqual(result.reason,'COMPOSE_DEADLINE')
            os.kill(pid,0)  # killing the client did NOT undo smart shutdown
            self.assertIn('received smart shutdown request',log.read_text())
            holder.stdin.write(b'\\q\n');holder.stdin.flush()
            holder.communicate(timeout=5);holder=None
            limit=time.monotonic()+8
            while (data/'postmaster.pid').exists() and time.monotonic()<limit:time.sleep(.05)
            self.assertFalse((data/'postmaster.pid').exists())
            self.assertIn('database system is shut down',log.read_text())
            self.assertGreaterEqual(time.monotonic()-started_at,1)
            started=False
        finally:
            if holder is not None:
                try:holder.communicate(b'\\q\n',timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill();holder.communicate(timeout=5)
            if started:pg('pg_ctl','-D',data,'-m','fast','stop','-w','-t','10',check=False)
            assert base.parent==Path('/tmp') and base.name.startswith('harbor-pg-ci-')
            shutil.rmtree(base)


if __name__=='__main__':unittest.main()
