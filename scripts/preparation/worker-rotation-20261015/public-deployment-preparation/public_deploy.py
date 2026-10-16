"""Public-only, single-host no-overwrite deployment and separate read-only verification."""
import base64
import datetime as dt
import hashlib
import json
import os
import re
import signal
import socket
import stat
import sys
import time

ROOT='/root/fds-hbr-worker-rotation-20261015'
HOME='/home/server01_ansible'
HOSTS={'k8s-control01':'10.1.93.102','k8s-worker01':'10.1.93.105',
       'k8s-worker02':'10.1.93.107','k8s-worker03':'10.1.93.108','ansible01':None}
# Full external manifest pins. Never trust a transported manifest by itself.
MANIFESTS={'adapter':'0bf529d53e03cae160caebc4e3637c45502d8b621c0b08e8af49f62b75ccf247',
          'orchestrator':'08abcec219753ecd6d8ab622d706cb7b5cac08993911cd9cde4f2abd0e77191f'}
NAMES={'adapter':{'launch.py','rotation_contract.py','rotation_adapter.py','linux_host.py','input_supply.py','public-ca.pem'},
       'orchestrator':{'orch_launch.py','orch_contract.py','orch_endpoint.py','orch_relay.py'}}
MFILE={'adapter':'runtime-manifest.json','orchestrator':'orchestration-manifest.json'}
PHASES={'code','issue-input','rotation-input','closeout-input'}
FORBIDDEN={'password','secret','token','credential','credentials','private_key','authorization'}
class Stop(Exception):pass
def need(ok,code):
    if not ok:raise Stop(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def parse(b):
    need(isinstance(b,bytes) and len(b)<=1048576,'JSON_LIMIT')
    def pairs(xs):
        d={}
        for k,v in xs:need(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
        return d
    try:return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Stop('JSON_NONFINITE')))
    except Stop:raise
    except (ValueError,UnicodeError):raise Stop('INVALID_JSON') from None
def timestamp(v):
    need(isinstance(v,str),'TIME_TYPE')
    try:
        d=dt.datetime.fromisoformat(v.replace('Z','+00:00'))
        need(d.tzinfo is not None,'TIME_ZONE')
        return d.timestamp()
    except (ValueError,OverflowError):raise Stop('TIME_INVALID') from None
def integer(v):return type(v) is int and v>=0
def hexhash(v):return isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v)
def context(v):return isinstance(v,str) and re.fullmatch('[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:s0(?:[-:,A-Za-z0-9]+)?',v)
def chain(path):
    need(path.startswith('/') and '//' not in path and not path.endswith('/') and all(x not in ('.','..') for x in path.split('/')),'PATH')
    out=['/'];parts=path.strip('/').split('/')
    for i in range(len(parts)):out.append('/'+'/'.join(parts[:i+1]))
    return out
def layout(r):
    relay=r['host']=='ansible01';inv=r['invocation']
    base=HOME+'/hbr-rotation-'+inv if relay else ROOT
    dirs={'adapter':base+('/adapter' if relay else '/code-'+inv),
          'orchestrator':base+('/orchestrator' if relay else '/orchestrator-'+inv)}
    return base,dirs
def input_names(r):
    inv=r['invocation'];phase=r['phase'];relay=r['host']=='ansible01'
    if phase=='code':return set()
    if phase=='issue-input':
        need(r['host']=='k8s-control01','ISSUE_HOST')
        return {'prep-request-'+inv+'.json'}
    if phase=='rotation-input':
        return {'rotation-request.json'} if relay else {'orchestration-request-'+inv+'.json','request-'+inv+'.json'}
    need(relay,'CLOSEOUT_HOST')
    return {'closeout.json'}
def validate(r,now):
    fields={'version','state','phase','invocation','host','boot_id','uid','gid','not_before','deadline',
            'authorization_reference','parents','create_base','contexts','input_sha256'}
    need(isinstance(r,dict) and set(r)==fields and type(r['version']) is int and r['version']==1 and r['state']=='BOUND','REQUEST_FIELDS')
    need(r['phase'] in PHASES and r['host'] in HOSTS,'SCOPE')
    need(isinstance(r['invocation'],str) and re.fullmatch('[a-f0-9]{32}',r['invocation']),'INVOCATION')
    need(isinstance(r['boot_id'],str) and re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',r['boot_id']),'BOOT')
    need(integer(r['uid']) and integer(r['gid']),'OWNER')
    relay=r['host']=='ansible01'
    need((r['uid']>0 and r['gid']>0) if relay else r['uid']==r['gid']==0,'OWNER_SCOPE')
    need(timestamp(r['not_before'])<=now<timestamp(r['deadline']),'WINDOW')
    ref=r['authorization_reference']
    need(isinstance(ref,str) and 8<=len(ref)<=300 and not any(t in ref.upper() for t in ('TODO','PENDING','PLACEHOLDER')),'AUTH_REFERENCE')
    need(type(r['create_base']) is bool and (r['phase']=='code' or not r['create_base']),'CREATE_BASE_PHASE')
    need(not (relay and r['phase']=='code') or r['create_base'],'RELAY_BASE_MUST_BE_NEW')
    need(isinstance(r['contexts'],dict) and set(r['contexts'])=={'base','directory','file'} and all(context(v) for v in r['contexts'].values()),'CONTEXTS')
    base,_=layout(r);parents=chain(base)
    if r['create_base']:parents=parents[:-1]
    need(isinstance(r['parents'],dict) and set(r['parents'])==set(parents),'PARENT_SCOPE')
    for path,m in r['parents'].items():
        need(isinstance(m,dict) and set(m)=={'device','inode','uid','gid','mode','context'} and all(integer(m[k]) for k in ('device','inode','uid','gid','mode')) and context(m['context']),'PARENT_METADATA')
        need(m['uid'] in (0,r['uid']) and m['mode']<=0o777 and not m['mode']&0o022,'PARENT_PROTECTION')
        if path==base:need(m['uid']==r['uid'] and m['gid']==r['gid'] and m['mode']==0o700 and m['context']==r['contexts']['base'],'BASE_METADATA')
    need(isinstance(r['input_sha256'],dict) and set(r['input_sha256'])==input_names(r) and all(hexhash(v) for v in r['input_sha256'].values()),'INPUT_HASH_SCOPE')
    return r
def no_secret_keys(value):
    if isinstance(value,dict):
        need(all(isinstance(k,str) and k.lower() not in FORBIDDEN for k in value),'NOT_PUBLIC_INPUT')
        for v in value.values():no_secret_keys(v)
    elif isinstance(value,list):
        for v in value:no_secret_keys(v)
def public_input(name,raw,r):
    v=parse(raw);need(encoded(v)==raw and isinstance(v,dict) and v.get('state')=='BOUND','CANONICAL_BOUND_INPUT')
    no_secret_keys(v)
    if name.startswith('prep-request-'):
        need(set(v)=={'version','state','invocation','not_before','not_after','host_boot_ids','admin_username','operator','authorization_reference','api_seconds','baseline_sha256'},'PREP_SHAPE')
        need(v['invocation']==r['invocation'] and v['host_boot_ids'].get(r['host'])==r['boot_id'],'PREP_BINDING')
    elif name=='closeout.json':
        need(set(v)=={'version','state','request_sha256','decision_reference','observed_at','rollback_pending','credential_users_stopped','targets'},'CLOSEOUT_SHAPE')
    else:
        plan=v if name.startswith('request-') else v.get('plan')
        need(isinstance(plan,dict) and plan.get('invocation')==r['invocation'],'PLAN_BINDING')
        if r['host']=='ansible01':need(v.get('relay_uid')==r['uid'] and v.get('relay_boot_id')==r['boot_id'],'RELAY_BINDING')
        else:need(plan.get('host_boot_ids',{}).get(r['host'])==r['boot_id'],'PLAN_BOOT')
    return v
def bundle_rows(kind,raw):
    need(sha(raw)==MANIFESTS[kind],'MANIFEST_PIN')
    m=parse(raw);need(set(m)=={'version','files'} and m['version']==1 and set(m['files'])==NAMES[kind],'MANIFEST_SCOPE')
    rows={}
    for n,v in m['files'].items():
        need(set(v)=={'bytes','sha256'} and integer(v['bytes']) and v['bytes']<=1048576 and hexhash(v['sha256']),'MANIFEST_ROW')
        rows[n]=v
    rows[MFILE[kind]]={'bytes':len(raw),'sha256':sha(raw)}
    return rows
def payload_files(r,payload):
    need(isinstance(payload,dict),'PAYLOAD')
    base,dirs=layout(r);out={}
    if r['phase']=='code':
        need(set(payload)=={k+'/'+n for k in NAMES for n in NAMES[k]|{MFILE[k]}},'PAYLOAD_SCOPE')
        for k in NAMES:
            rows=bundle_rows(k,payload[k+'/'+MFILE[k]])
            for n,row in rows.items():
                b=payload[k+'/'+n];need(isinstance(b,bytes) and len(b)==row['bytes'] and sha(b)==row['sha256'],'PAYLOAD_HASH')
                out[dirs[k]+'/'+n]=b
    else:
        need(set(payload)==input_names(r),'PAYLOAD_SCOPE')
        values={}
        for n,b in payload.items():
            need(isinstance(b,bytes) and sha(b)==r['input_sha256'][n],'INPUT_PIN')
            values[n]=public_input(n,b,r);out[base+'/'+n]=b
        if r['phase']=='rotation-input' and r['host']!='ansible01':
            need(encoded(values['orchestration-request-'+r['invocation']+'.json']['plan'])==payload['request-'+r['invocation']+'.json'],'EMBEDDED_PLAN')
    return out

def supply_receipt(r,v):
    fields={'status','action','phase','host','boot_id','invocation','request_sha256','files','directories','created','credential_or_api_actions','observed_at'}
    need(isinstance(v,dict) and set(v)==fields and v['status']=='PUBLIC_SUPPLIED' and v['action']=='supply' and v['credential_or_api_actions']==0,'SUPPLY_RECEIPT_REQUIRED')
    need(v['request_sha256']==sha(encoded(r)) and all(v[k]==r[k] for k in ('phase','host','boot_id','invocation')),'SUPPLY_RECEIPT_REQUIRED')
    timestamp(v['observed_at']);base,dirs=layout(r)
    names={path+'/'+n for k,path in dirs.items() for n in NAMES[k]|{MFILE[k]}}
    names|={base+'/'+n for n in input_names(r)}
    need(isinstance(v['files'],dict) and set(v['files'])==names and isinstance(v['directories'],dict) and set(v['directories'])=={base,*dirs.values()},'RECEIPT_SCOPE')
    need(isinstance(v['created'],list) and all(isinstance(x,str) and x in names|{base,*dirs.values()} for x in v['created']),'RECEIPT_CREATED')
    for path,m in {**v['files'],**v['directories']}.items():
        keys={'device','inode','uid','gid','mode','context'}
        if path in v['files']:keys|={'bytes','sha256','nlink'}
        need(isinstance(m,dict) and set(m)==keys and all(integer(m[k]) for k in ('device','inode','uid','gid','mode')) and context(m['context']),'RECEIPT_METADATA')
        if path in v['files']:need(integer(m['bytes']) and m['bytes']<=1048576 and m['nlink']==1 and hexhash(m['sha256']),'RECEIPT_FILE')
    return v

class Deadline:
    def __init__(self,r,wall=time.time,mono=time.monotonic):
        self.wall=wall;self.mono=mono;self.end=timestamp(r['deadline'])
        now=wall();need(timestamp(r['not_before'])<=now<self.end,'WINDOW')
        self.mend=mono()+self.end-now
    def check(self):need(self.wall()<self.end and self.mono()<self.mend,'DEADLINE')
    def seconds(self):return min(self.end-self.wall(),self.mend-self.mono())

class LinuxFS:
    """All traversals anchored at /; no pathname-following mutation or relabeling."""
    def __init__(self,r,deadline):
        self.r=r;self.deadline=deadline;self.created=[];self.newdirs={}
    def tick(self):self.deadline.check()
    def meta(self,fd):
        s=os.fstat(fd)
        attrs=set(os.listxattr(fd))
        need(attrs=={'security.selinux'},'ACL_OR_UNEXPECTED_XATTR')
        label=os.getxattr(fd,'security.selinux').rstrip(b'\0').decode('ascii')
        return {'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,
                'mode':stat.S_IMODE(s.st_mode),'context':label}
    def dcheck(self,fd,path):
        s=os.fstat(fd);need(stat.S_ISDIR(s.st_mode),'NOT_DIRECTORY')
        m=self.meta(fd)
        expected=self.r['parents'].get(path) or self.newdirs.get(path)
        need(m['uid'] in (0,self.r['uid']) and not m['mode']&0o022,'UNPROTECTED_PARENT')
        if expected is not None:need(m==expected,'PARENT_CHANGED')
        return m
    def open_dir(self,path):
        self.tick();fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            self.dcheck(fd,'/')
            if path!='/':
                for full in chain(path)[1:]:
                    child=os.open(full.rsplit('/',1)[-1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    os.close(fd);fd=child;self.dcheck(fd,full);self.tick()
            return fd
        except BaseException:os.close(fd);raise
    def directory(self,path,mode,ctx):
        fd=self.open_dir(path)
        try:
            m=self.meta(fd);need(m['uid']==self.r['uid'] and m['gid']==self.r['gid'] and m['mode']==mode and m['context']==ctx,'DIRECTORY_METADATA')
            return m
        finally:os.close(fd)
    def parent(self,path):
        parent,name=path.rsplit('/',1);return self.open_dir(parent or '/'),name
    def absent(self,path):
        fd,n=self.parent(path)
        try:
            try:os.stat(n,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:return
            raise Stop('TARGET_EXISTS')
        finally:os.close(fd)
    def mkdir(self,path,ctx):
        self.tick();fd,n=self.parent(path)
        try:
            os.mkdir(n,0o700,dir_fd=fd);self.created.append(path);os.fsync(fd)
            child=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            try:
                m=self.meta(child)
                need(m['uid']==self.r['uid'] and m['gid']==self.r['gid'] and m['mode']==0o700 and m['context']==ctx,'CREATED_DIRECTORY_METADATA')
                self.newdirs[path]=m
            finally:os.close(child)
        finally:os.close(fd)
        self.directory(path,0o700,ctx);self.tick()
    def write_new(self,path,data,ctx):
        self.tick();pfd,n=self.parent(path)
        try:
            fd=os.open(n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=pfd)
            self.created.append(path)
            try:
                self.filemeta(fd,ctx)
                view=memoryview(data)
                while view:
                    self.tick();count=os.write(fd,view)
                    need(type(count) is int and 0<count<=len(view),'SHORT_WRITE_ZERO')
                    view=view[count:]
                os.fsync(fd);os.fsync(pfd);self.tick();self.filemeta(fd,ctx)
            finally:os.close(fd)
        finally:os.close(pfd)
        actual,_=self.read_file(path,ctx);need(actual==data,'WRITE_READBACK')
    def filemeta(self,fd,ctx):
        s=os.fstat(fd);m=self.meta(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=1048576 and m['uid']==self.r['uid'] and m['gid']==self.r['gid'] and m['mode']==0o600 and m['context']==ctx,'FILE_METADATA')
        return s,m
    def read_file(self,path,ctx):
        self.tick();pfd,n=self.parent(path)
        try:fd=os.open(n,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=pfd)
        finally:os.close(pfd)
        try:
            before,m=self.filemeta(fd,ctx);out=bytearray()
            while True:
                self.tick();b=os.read(fd,min(65536,1048577-len(out)))
                if not b:break
                out.extend(b);need(len(out)<=1048576,'FILE_LIMIT')
            after,_=self.filemeta(fd,ctx)
            attrs=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            need(attrs(before)==attrs(after) and len(out)==before.st_size,'READ_CHANGED')
            # Ensure the name still identifies the file, rather than a detached FD.
            pfd,n=self.parent(path)
            try:
                named=os.stat(n,dir_fd=pfd,follow_symlinks=False)
                need(stat.S_ISREG(named.st_mode) and attrs(named)==attrs(after),'FILE_NAME_CHANGED')
            finally:os.close(pfd)
            return bytes(out),dict(m,bytes=len(out),sha256=sha(out),nlink=after.st_nlink)
        finally:os.close(fd)
    def names(self,path):
        fd=self.open_dir(path)
        try:return set(os.listdir(fd))
        finally:os.close(fd)
    def parent_checks(self):
        for p,m in self.r['parents'].items():
            fd=self.open_dir(p)
            try:need(self.meta(fd)==m,'PARENT_CHANGED')
            finally:os.close(fd)
    def identity(self):
        need(sys.platform.startswith('linux') and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,'ISOLATED_LINUX_REQUIRED')
        need(os.getuid()==os.geteuid()==self.r['uid'] and os.getgid()==os.getegid()==self.r['gid'],'PROCESS_OWNER')
        need(socket.gethostname()==self.r['host'],'HOST_CHANGED')
        with open('/proc/sys/kernel/random/boot_id',encoding='ascii') as f:need(f.read().strip()==self.r['boot_id'],'BOOT_CHANGED')
        with open('/sys/fs/selinux/enforce','rb') as f:need(f.read().strip()==b'1','SELINUX_NOT_ENFORCING')
    def check_code(self):
        _,dirs=layout(self.r);result={}
        for kind,path in dirs.items():
            self.directory(path,0o700,self.r['contexts']['directory'])
            need(self.names(path)==NAMES[kind]|{MFILE[kind]},'FILE_SET')
            raw,_=self.read_file(path+'/'+MFILE[kind],self.r['contexts']['file'])
            for n,row in bundle_rows(kind,raw).items():
                b,m=self.read_file(path+'/'+n,self.r['contexts']['file'])
                need(len(b)==row['bytes'] and sha(b)==row['sha256'],'FILE_HASH')
                result[path+'/'+n]=m
        return result

def run(r,payload,action,fs,receipt=None):
    need(action in ('supply','verify'),'ACTION');fs.tick();fs.identity();fs.parent_checks()
    if action=='verify':
        supply_receipt(r,receipt)
    files=payload_files(r,payload);base,dirs=layout(r);ctx=r['contexts']
    if action=='supply':
        if r['phase']=='code':
            if r['create_base']:fs.absent(base)
            else:fs.directory(base,0o700,ctx['base'])
            # Missing parent is not an excuse to skip collision checks under an existing base.
            if not r['create_base']:
                for d in dirs.values():fs.absent(d)
            if r['create_base']:fs.mkdir(base,ctx['base'])
            for d in dirs.values():fs.mkdir(d,ctx['directory'])
        else:
            fs.directory(base,0o700,ctx['base']);fs.check_code()
            for path in files:fs.absent(path)
        for path,raw in sorted(files.items()):
            fs.parent_checks();fs.write_new(path,raw,ctx['file'])
    fs.directory(base,0o700,ctx['base']);result=fs.check_code()
    if r['phase']!='code':
        for path,expected in files.items():
            actual,meta=fs.read_file(path,ctx['file']);need(actual==expected,'INPUT_READBACK');result[path]=meta
    directories={path:fs.directory(path,0o700,ctx['base'] if path==base else ctx['directory']) for path in (base,*dirs.values())}
    if action=='verify':need(result==receipt.get('files') and directories==receipt.get('directories'),'SUPPLY_GENERATION_CHANGED')
    fs.parent_checks();fs.identity();fs.tick()
    return {'status':'PUBLIC_SUPPLIED' if action=='supply' else 'PUBLIC_READ_VERIFIED',
            'action':action,'phase':r['phase'],'host':r['host'],'boot_id':r['boot_id'],
            'invocation':r['invocation'],'request_sha256':sha(encoded(r)),'files':result,
            'directories':directories,'created':list(fs.created),'credential_or_api_actions':0,
            'observed_at':dt.datetime.fromtimestamp(fs.deadline.wall(),dt.timezone.utc).isoformat()}

def entry(action,r,payload,receipt=None):
    """Called only by an externally hash-verified generated public script."""
    fs=None;timer=False;previous=None
    try:
        validate(r,time.time());need(sys.platform.startswith('linux'),'LINUX_ONLY')
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
        deadline=Deadline(r);fs=LinuxFS(r,deadline);fs.identity()
        need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'TIMER_ACTIVE')
        previous=signal.getsignal(signal.SIGALRM)
        def expired(*_):raise Stop('DEADLINE')
        signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,deadline.seconds());timer=True
        result=run(r,payload,action,fs,receipt)
        print(json.dumps(result,sort_keys=True,separators=(',',':')));return 0
    except BaseException as exc:
        code=str(exc) if isinstance(exc,Stop) else 'INTERRUPTED_OR_OS_FAILURE'
        print(json.dumps({'status':'STOP_PRESERVE_PARTIAL','code':code,'created':[] if fs is None else fs.created,
                          'retry':False,'cleanup_performed':False},sort_keys=True))
        return 2
    finally:
        if timer:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)

