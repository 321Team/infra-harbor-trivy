"""Run only on ansible01 normal operator route. Secret bytes never leave this process upward."""
import os
from pathlib import Path
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import time
from orch_contract import *
from rotation_contract import Stop,parse_json

ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/home/server01_ansible','LANG':'C','LC_ALL':'C'}
SSH='/usr/bin/ssh'
KEY='/home/server01_ansible/.ssh/p1_ansible_ed25519'
KNOWN='/home/server01_ansible/.ssh/known_hosts'

def private_read(path):
    p=Path(path)
    need(p.is_absolute() and '..' not in p.parts,'RELAY_PATH')
    for parent in p.parents:
        s=parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022,'RELAY_PARENT')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and
             stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=1048576,'RELAY_FILE')
        raw=os.read(fd,1048577)
        need(len(raw)==s.st_size,'RELAY_READ_CHANGED')
        return raw
    finally:os.close(fd)

def command(r,host,action,manifest,target=None,until=None):
    need(host in HOSTS and action in ('stage','stage-status','supply-local','export','receive','retire'),'REMOTE_SCOPE')
    inv=nonce(r['plan']['invocation']);digest(manifest)
    # No variable shell fragments and no credential arguments/environment.
    args=['sudo','-n','/usr/bin/python3','-I','-S','-B',
          ROOT+'/orchestrator-'+inv+'/orch_launch.py',manifest,ROOT+'/code-'+inv,'endpoint',
          action,'--request',ROOT+'/orchestration-request-'+inv+'.json','--request-sha256',sha(encoded(r))]
    if target is not None:
        need(action=='export' and host==CP and target in NODES,'EXPORT_SCOPE')
        args+=['--target',target]
    need(isinstance(until,str),'OPERATION_DEADLINE_REQUIRED')
    timestamp(until)
    args+=['--operation-until',until]
    return [SSH,'-F','/dev/null','-T','-i',KEY,'-o','BatchMode=yes','-o','ConnectTimeout=8',
            '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+KNOWN,'-o','IdentitiesOnly=yes',
            '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','ControlMaster=no',
            '-o','ControlPath=none','-o','UpdateHostKeys=no','svc_ansible@'+IPS[host],
            ' '.join(shlex.quote(a) for a in args)]

def exchange(argv,data,seconds):
    """Bounded duplex PIPE, stderr discarded. No communicate() unbounded buffering."""
    need(seconds>0 and len(data)<=32768,'RELAY_BUDGET_OR_INPUT')
    process=None;sel=selectors.DefaultSelector();out=bytearray();end=time.monotonic()+seconds
    try:
        process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                 cwd='/',env=ENV,start_new_session=True)
        sent=0
        os.set_blocking(process.stdout.fileno(),False);sel.register(process.stdout,selectors.EVENT_READ,'out')
        if data:
            os.set_blocking(process.stdin.fileno(),False);sel.register(process.stdin,selectors.EVENT_WRITE,'in')
        else:process.stdin.close()
        while sel.get_map():
            left=end-time.monotonic();need(left>0,'RELAY_TIMEOUT')
            for key,_ in sel.select(min(left,.1)):
                if key.data=='in':
                    try:sent+=os.write(key.fileobj.fileno(),data[sent:sent+4096])
                    except BlockingIOError:continue
                    if sent==len(data):sel.unregister(key.fileobj);key.fileobj.close()
                else:
                    block=os.read(key.fileobj.fileno(),32769)
                    if not block:sel.unregister(key.fileobj);continue
                    out.extend(block);need(len(out)<=32768,'RELAY_OUTPUT_LIMIT')
        need(process.wait(timeout=max(.001,end-time.monotonic()))==0,'REMOTE_FAILED')
        need(time.monotonic()<=end,'RELAY_TIMEOUT')
        return bytes(out)
    except Stop:raise
    except BaseException:raise Stop('RELAY_INTERRUPTED_PRESERVE') from None
    finally:
        sel.close()
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
            for f in (process.stdin,process.stdout):
                if f is not None:f.close()

class Relay:
    def __init__(self,r,manifest,call=exchange,clock=time.monotonic,wall=time.time):
        self.r=r;self.manifest=digest(manifest);self.call=call;self.clock=clock;self.wall=wall
    def invoke(self,host,action,data=b'',target=None,limit=None):
        end=self.r['plan']['not_after'] if action=='retire' else self.r['supply_until']
        cap=self.r['stage_seconds'] if action=='stage' else self.r['retire_seconds'] if action=='retire' else self.r['transfer_seconds']
        if limit is not None:cap=min(cap,limit)
        seconds=min(cap,timestamp(end)-self.wall())
        need(seconds>0,'RELAY_DEADLINE')
        import datetime as dt
        until=dt.datetime.fromtimestamp(self.wall()+seconds,dt.timezone.utc).isoformat()
        return self.call(command(self.r,host,action,self.manifest,target,until),data,seconds)
    def returned(self,host,action,raw):
        expected={'status':'RETURNED','action':action,'host':host,'request_sha256':sha(encoded(self.r))}
        need(parse_json(raw)==expected,'REMOTE_RECEIPT_MISMATCH')
    def stage_all(self):
        for host in HOSTS:self.returned(host,'stage',self.invoke(host,'stage'))
    def supply_all(self):
        all_stages={}
        for host in HOSTS:
            raw=self.invoke(host,'stage-status',limit=self.r['plan']['budgets']['read'])
            all_stages[host]=parse_json(raw)
        stages(self.r['plan'],all_stages);public=encoded(all_stages)
        self.returned(CP,'supply-local',self.invoke(CP,'supply-local',public))
        for target in NODES:
            end=self.clock()+self.r['transfer_seconds']
            secret=None
            try:
                secret=self.invoke(CP,'export',public,target,limit=end-self.clock())
                transfer(self.r,target,parse_json(secret))
                self.returned(target,'receive',self.invoke(target,'receive',secret,limit=end-self.clock()))
            finally:secret=None  # Python memory erasure is not guaranteed; no intermediate file is created.
    def retire_all(self,c):
        closeout(self.r,c,self.wall());public=encoded(c)
        for host in HOSTS:self.returned(host,'retire',self.invoke(host,'retire',public))

def claim(r,action):
    home=Path('/home/server01_ansible')
    base=home/('hbr-rotation-'+nonce(r['plan']['invocation']))
    s=base.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'RELAY_WORKSPACE')
    # One invocation per action. Failure/interruption leaves this claim in place.
    fd=os.open(base/('claim-'+action+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600);data=encoded({'request_sha256':sha(encoded(r)),'action':action})
        with os.fdopen(os.dup(fd),'wb') as f:f.write(data);f.flush()
        os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def main(argv,manifest):
    import argparse
    import pwd
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['stage-all','supply-all','retire-all'])
    parser.add_argument('--request',required=True);parser.add_argument('--request-sha256',required=True)
    parser.add_argument('--closeout');parser.add_argument('--closeout-sha256')
    a=parser.parse_args(argv)
    raw=private_read(a.request);need(sha(raw)==digest(a.request_sha256),'INPUT_HASH_MISMATCH')
    r=parse_json(raw);need(raw==encoded(r),'CANONICAL_INPUT_REQUIRED');rotation_request(r,time.time())
    need(socket.gethostname()=='ansible01' and pwd.getpwuid(os.getuid()).pw_name=='server01_ansible' and
         os.getuid()==r['relay_uid'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==r['relay_boot_id'],'RELAY_IDENTITY')
    # Use only the known OpenSSH executable and the already established key/known_hosts.
    s=Path(SSH).stat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'SSH_EXECUTABLE')
    relay=Relay(r,manifest)
    if a.action=='retire-all':
        need(a.closeout is not None and a.closeout_sha256 is not None,'CLOSEOUT_REQUIRED')
        c_raw=private_read(a.closeout);need(sha(c_raw)==digest(a.closeout_sha256),'CLOSEOUT_HASH')
        c=parse_json(c_raw);closeout(r,c,time.time())
    claim(r,a.action)
    if a.action=='stage-all':relay.stage_all()
    elif a.action=='supply-all':relay.supply_all()
    else:relay.retire_all(c)
    return {'status':'RETURNED','action':a.action,'request_sha256':sha(encoded(r))}
