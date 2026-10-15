"""Linux effects for the bounded rotation adapter. Never imported to perform I/O."""
import base64
from contextlib import contextmanager
import hashlib
import http.client
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import time
import urllib.parse
from rotation_contract import *

ROOT = Path('/root/fds-hbr-worker-rotation-20261015')
RUN = Path('/run/fds-hbr-worker-rotation-20261015')

def framed_body(response):
    """Bounded RFC 9112 length/chunk framing; EOF alone never proves completion.

    HTTPResponse.read(amt) permits short Content-Length bodies, and its chunk
    trailer reader accepts EOF. Read the existing buffered body stream ourselves.
    The caller closes this one-request connection and enforces the absolute timer.
    """
    limit=1024*1024;line_limit=8192;framing_limit=65536
    token=rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    value=rb'[\t\x20-\x7e\x80-\xff]*'
    quoted=rb'"(?:[\t\x20\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t\x20-\x7e\x80-\xff])*"'
    extension=rb'(?:[ \t]*;[ \t]*'+token+rb'(?:[ \t]*=[ \t]*(?:'+token+rb'|'+quoted+rb'))?)*'
    critical={'content-length','transfer-encoding','content-type','docker-content-digest',
              'content-encoding','trailer','location','www-authenticate'}
    forbidden=critical|{'authorization','proxy-authorization','proxy-authenticate','host',
                        'connection','keep-alive','te','upgrade'}
    need(not response.headers.defects,'REGISTRY_HEADER_INVALID')
    headers={};seen=set();header_bytes=0
    for name,raw in response.getheaders():
        nb=name.encode('latin1');vb=raw.encode('latin1');key=name.lower()
        header_bytes+=len(nb)+len(vb)+4
        need(header_bytes<=framing_limit and re.fullmatch(token,nb) and re.fullmatch(value,vb),'REGISTRY_HEADER_INVALID')
        need(key not in critical or key not in seen,'REGISTRY_HEADER_DUPLICATE')
        seen.add(key);headers[key]=raw.strip(' \t')
    need('content-encoding' not in headers,'REGISTRY_CONTENT_ENCODING')
    cl=headers.get('content-length');te=headers.get('transfer-encoding')
    need(not (cl is not None and te is not None),'REGISTRY_FRAMING_AMBIGUOUS')
    need(response.fp is not None,'REGISTRY_BODY_INCOMPLETE')
    def exact(n):
        out=bytearray()
        while len(out)<n:
            block=response.fp.read(min(n-len(out),65536))
            need(bool(block),'REGISTRY_BODY_INCOMPLETE');out.extend(block)
        return bytes(out)
    if te is None:
        need(cl is not None and re.fullmatch('[0-9]{1,16}',cl),'REGISTRY_LENGTH_REQUIRED')
        length=int(cl);need(length<=limit,'REGISTRY_BODY_LIMIT')
        need('trailer' not in headers,'REGISTRY_TRAILER_INVALID')
        return headers,exact(length)
    need(te.lower()=='chunked' and response.version==11,'REGISTRY_TRANSFER_ENCODING')
    declared=set()
    if 'trailer' in headers:
        names=headers['trailer'].split(',')
        for name in names:
            key=name.strip(' \t').lower()
            need(re.fullmatch(token,key.encode('latin1')) and key not in forbidden and
                 not key.startswith('content-') and key not in declared,'REGISTRY_TRAILER_INVALID')
            declared.add(key)
    framing=0
    def line():
        nonlocal framing
        raw=response.fp.readline(line_limit+1);framing+=len(raw)
        need(len(raw)<=line_limit and framing<=framing_limit,'REGISTRY_FRAMING_LIMIT')
        need(raw.endswith(b'\r\n'),'REGISTRY_BODY_INCOMPLETE')
        return raw[:-2]
    body=bytearray()
    while True:
        raw=line()
        match=re.fullmatch(rb'([0-9A-Fa-f]{1,16})('+extension+rb')',raw)
        need(match is not None,'REGISTRY_CHUNK_INVALID')
        size=int(match[1],16)
        need(len(body)+size<=limit,'REGISTRY_BODY_LIMIT')
        if size==0:break
        body.extend(exact(size))
        need(exact(2)==b'\r\n','REGISTRY_CHUNK_INVALID')
        framing+=2;need(framing<=framing_limit,'REGISTRY_FRAMING_LIMIT')
    trailers=set()
    while True:
        raw=line()
        if raw==b'':break
        name,sep,contents=raw.partition(b':')
        need(sep and re.fullmatch(token,name) and re.fullmatch(value,contents),'REGISTRY_TRAILER_INVALID')
        key=name.decode('ascii').lower()
        need(len(trailers)<100 and key not in trailers and key not in seen and
             key not in forbidden and not key.startswith('content-'),'REGISTRY_TRAILER_INVALID')
        trailers.add(key)
    # Valid trailers are consumed, never merged into security/representation headers.
    return headers,bytes(body)

@contextmanager
def alarm_deadline(seconds):
    """Absolute Linux main-thread bound, including slow HTTP headers/body reads."""
    need(seconds>0,'REGISTRY_TIMEOUT')
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'TIMER_ALREADY_ACTIVE')
    previous=signal.getsignal(signal.SIGALRM)
    def expired(*_):raise Stop('REGISTRY_TIMEOUT')
    signal.signal(signal.SIGALRM,expired)
    signal.setitimer(signal.ITIMER_REAL,seconds)
    try:yield
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)

def protected_parents(path):
    p=Path(path)
    need(p.is_absolute() and '..' not in p.parts,'PATH_INVALID')
    for directory in reversed(p.parents):
        s=directory.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'PARENT_NOT_PROTECTED')

def regular_bytes(path,limit=1024*1024,owner=0,private=True):
    path=Path(path);protected_parents(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and (owner is None or s.st_uid==owner) and
             s.st_size<=limit and (not private or stat.S_IMODE(s.st_mode)==0o600),'FILE_NOT_PROTECTED')
        out=bytearray()
        while True:
            b=os.read(fd,min(65536,limit+1-len(out)))
            if not b:break
            out.extend(b);need(len(out)<=limit,'FILE_LIMIT')
        end=os.fstat(fd)
        need((s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns),'FILE_CHANGED_DURING_READ')
        return bytes(out),s
    finally:os.close(fd)

def fsync_parent(path):
    fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def write_new(path,data,mode=0o600,context=None):
    path=Path(path);protected_parents(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        os.fchmod(fd,mode)
        if context is not None:os.setxattr(fd,'security.selinux',context.encode()+b'\0')
        with os.fdopen(os.dup(fd),'wb',closefd=True) as f:f.write(data);f.flush()
        os.fsync(fd)
    finally:os.close(fd)
    fsync_parent(path)

def directory(path,exclusive=False):
    path=Path(path);protected_parents(path)
    try:path.mkdir(mode=0o700)
    except FileExistsError:need(not exclusive,'DIRECTORY_ALREADY_EXISTS')
    s=path.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'DIRECTORY_NOT_PRIVATE')
    return path

class LinuxHost:
    def __init__(self,plan,create=False):
        need(os.name=='posix' and os.geteuid()==0 and os.getegid()==0 and Path('/proc/self/fd').is_dir(),'LINUX_ROOT_REQUIRED')
        self.name=socket.gethostname();self.boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        validate_plan(plan,time.time());need(self.name in plan['host_boot_ids'] and self.boot_id==plan['host_boot_ids'][self.name],'HOST_BOOT_CHANGED')
        self.plan=plan;self.inv=nonce(plan['invocation'])
        if create:
            directory(ROOT);directory(RUN)
            self.root=directory(ROOT/self.inv,exclusive=True)
            self.runroot=directory(RUN/self.inv,exclusive=True)
            for name in ('claims','receipts','private','incoming'):directory(self.root/name,exclusive=True)
            directory(self.runroot/'tools',exclusive=True)
            write_new(self.root/'plan.json',encoded(plan))
        else:
            self.root=directory(ROOT/self.inv);self.runroot=directory(RUN/self.inv)
            original,_=regular_bytes(self.root/'plan.json')
            need(original==encoded(plan),'PLAN_CHANGED')

    wall_time=staticmethod(time.time)
    monotonic=staticmethod(time.monotonic)
    sleep=staticmethod(time.sleep)

    def stage(self,public_ca):
        """Explicit stage command only. Source bytes are detached before any credential is read."""
        pins=self.plan['tool_pins'][self.name]
        for tool,pin in pins.items():
            need(time.time()<timestamp(self.plan['mutation_until']),'DEADLINE_EXPIRED')
            # The source may be uid1001. Its expected hash/provenance must come from independently approved supply.
            raw,_=regular_bytes(pin['source'],128*1024*1024,owner=None,private=False)
            tool_bytes(raw,pin)
            target=self.runroot/'tools'/tool
            write_new(target,raw,0o700,pin['context'])
            fd=self.open_tool(tool);os.close(fd)
            args=['version','--client','-o','json'] if tool=='kubectl' else ['--version']
            rc,_=self.run(tool,args,None,None,min(self.plan['budgets']['read'],timestamp(self.plan['mutation_until'])-time.time()))
            need(rc==0,'STAGED_TOOL_PROBE_FAILED')
        der=ssl.PEM_cert_to_DER_cert(public_ca.decode('ascii'))
        need(hashlib.sha256(der).hexdigest()==CA_DER_SHA256,'CA_PIN_MISMATCH')
        need(time.time()<timestamp(self.plan['mutation_until']),'DEADLINE_EXPIRED')
        write_new(self.root/'ca.pem',public_ca)
        self.record('stage',{'status':'PASS','invocation':self.inv,'host':self.name,'plan_sha256':hashlib.sha256(encoded(self.plan)).hexdigest(),'robot_id':self.plan['new_robot']['id']})

    def open_tool(self,tool):
        need(tool in self.plan['tool_pins'][self.name],'TOOL_SCOPE')
        path=self.runroot/'tools'/tool;protected_parents(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'TOOL_NOT_PROTECTED')
            hasher=hashlib.sha256()
            while b:=os.read(fd,65536):hasher.update(b)
            pin=self.plan['tool_pins'][self.name][tool]
            need(hasher.hexdigest()==pin['sha256'],'STAGED_TOOL_CHANGED')
            need(os.getxattr(fd,'security.selinux').decode().rstrip('\0')==pin['context'],'TOOL_CONTEXT_CHANGED')
            os.lseek(fd,0,os.SEEK_SET);return fd
        except Exception:os.close(fd);raise

    def claim(self,key,context):
        need(re.fullmatch('[a-z0-9-]+',key),'RECORD_KEY')
        try:write_new(self.root/'claims'/(key+'.json'),encoded(context))
        except FileExistsError:raise Stop('OPERATION_ALREADY_CLAIMED') from None

    def record(self,key,value):
        need(re.fullmatch('[a-z0-9-]+',key),'RECORD_KEY')
        write_new(self.root/'receipts'/(key+'.json'),encoded(value))

    def receipt(self,key):
        need(re.fullmatch('[a-z0-9-]+',key),'RECORD_KEY')
        for folder in ('receipts','incoming'):
            try:return parse_json(regular_bytes(self.root/folder/(key+'.json'))[0])
            except FileNotFoundError:pass
        raise Stop('PREREQUISITE_MISSING')

    def save_private(self,key,value):
        need(re.fullmatch('[a-z0-9-]+',key),'RECORD_KEY');write_new(self.root/'private'/(key+'.json'),encoded(value))

    def load_private(self,key):
        need(re.fullmatch('[a-z0-9-]+',key),'RECORD_KEY');return parse_json(regular_bytes(self.root/'private'/(key+'.json'))[0])

    def run(self,tool,args,stdin,env,timeout):
        started=time.monotonic();need(timeout>0,'CHILD_TIMEOUT')
        fd=self.open_tool(tool)
        child=None;selector=selectors.DefaultSelector();out=bytearray();err=bytearray()
        try:
            clean={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C','LC_ALL':'C'}
            if env:
                need(set(env)=={'DOCKER_CONFIG'},'CHILD_ENV_SCOPE')
                auth=env['DOCKER_CONFIG']
                need(auth=='/root/.docker' or (Path(auth).parent==self.runroot and Path(auth).name.startswith('auth-')),'AUTH_PATH_SCOPE')
                clean.update(env)
            data=stdin or b'';need(len(data)<=32768,'STDIN_LIMIT')
            end=started+timeout;need(time.monotonic()<end,'CHILD_TIMEOUT')
            child=subprocess.Popen(['/proc/self/fd/'+str(fd),*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   env=clean,cwd='/',pass_fds=(fd,),start_new_session=True)
            sent=0
            if data:
                os.set_blocking(child.stdin.fileno(),False);selector.register(child.stdin,selectors.EVENT_WRITE,None)
            else:child.stdin.close()
            for stream,buf in ((child.stdout,out),(child.stderr,err)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,buf)
            while selector.get_map():
                left=end-time.monotonic();need(left>0,'CHILD_TIMEOUT')
                for k,_ in selector.select(min(left,0.2)):
                    if k.data is None:
                        try:sent+=os.write(k.fileobj.fileno(),data[sent:sent+4096])
                        except BlockingIOError:continue
                        if sent==len(data):selector.unregister(k.fileobj);k.fileobj.close()
                        continue
                    block=os.read(k.fileobj.fileno(),65536)
                    if not block:selector.unregister(k.fileobj);continue
                    k.data.extend(block);need(len(out)+len(err)<=2*1024*1024,'CHILD_OUTPUT_LIMIT')
            rc=child.wait(timeout=max(0.001,end-time.monotonic()))
            return rc,bytes(out if rc==0 else err+out)
        except Stop:raise
        except Exception:raise Stop('CHILD_ERROR') from None
        finally:
            selector.close()
            if child is not None:
                if child.poll() is None:
                    os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=2)
                for f in (child.stdin,child.stdout,child.stderr):
                    if f is not None:f.close()
            os.close(fd)

    def kube(self,method,path,body,timeout,allow_absent=False):
        need(self.name=='k8s-control01','CONTROL_HOST_REQUIRED')
        base=['--kubeconfig=/etc/kubernetes/admin.conf','--context=kubernetes-admin@kubernetes','--request-timeout='+str(max(1,int(timeout)))+'s']
        match=re.fullmatch('/api/v1/namespaces/([a-z-]+)/(pods|secrets|serviceaccounts)(?:/([a-z0-9-]+))?',path)
        need(match is not None and match[1] in SCOPE,'API_SCOPE')
        ns,kind,name=match.groups()
        if method=='GET' and allow_absent:
            need(kind=='pods' and name,'ABSENT_SCOPE');args=['get','pod',name,'-n',ns,'--ignore-not-found','-o','json']
        elif method=='GET':args=['get','--raw='+path]
        elif method=='POST':
            need(kind=='pods' and name is None,'POST_SCOPE');args=['create','--raw='+path,'-f','-']
        elif method=='DELETE':
            need(kind=='pods' and name and set(body['preconditions'])=={'uid'},'DELETE_SCOPE');args=['delete','--raw='+path,'-f','-']
        elif method=='PATCH':
            need(kind=='secrets' and name==SECRET_NAME,'PATCH_SCOPE')
            args=['patch','secret',name,'-n',ns,'--type=json','--patch-file=/dev/stdin','-o','json']
        else:raise Stop('API_METHOD_SCOPE')
        rc,out=self.run('kubectl',base+args,encoded(body) if body is not None else None,None,timeout)
        need(rc==0,'KUBERNETES_RESPONSE_UNCERTAIN')
        if allow_absent and not out.strip():return None
        return parse_json(out)

    def registry_manifest(self,c,timeout):
        with alarm_deadline(timeout):self._registry_manifest(c,timeout)

    def _registry_manifest(self,c,timeout):
        """Fixed token endpoint; bearer/Basic credentials never leave the fixed TLS peer."""
        raw,_=regular_bytes(self.root/'ca.pem');der=ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))
        need(hashlib.sha256(der).hexdigest()==CA_DER_SHA256,'CA_PIN_MISMATCH')
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_verify_locations(cadata=raw.decode('ascii'))
        end=time.monotonic()+timeout
        def get(path,headers):
            left=end-time.monotonic();need(left>0,'REGISTRY_TIMEOUT')
            con=http.client.HTTPSConnection(REGISTRY,443,context=ctx,timeout=left)
            r=None
            try:
                con.request('GET',path,headers=headers);r=con.getresponse()
                need(r.status==200,'REGISTRY_GET_FAILED')
                return framed_body(r)
            except Stop:raise
            except Exception:raise Stop('REGISTRY_TRANSPORT_FAILED') from None
            finally:
                if r is not None:r.close()
                con.close()
        basic=base64.b64encode((c['username']+':'+c['password']).encode()).decode()
        _,data=get('/service/token?'+urllib.parse.urlencode({'service':'harbor-registry','scope':'repository:fds/test:pull','account':c['username'],'client_id':'fds-worker-rotation'}),{'Authorization':'Basic '+basic})
        tokens=parse_json(data);token=tokens.get('token',tokens.get('access_token'))
        need(isinstance(token,str) and 0<len(token)<32768 and '\r' not in token and '\n' not in token,'TOKEN_INVALID')
        need('refresh_token' not in tokens and ('token' not in tokens or 'access_token' not in tokens or tokens['token']==tokens['access_token']),'TOKEN_FIELDS')
        # Only the fixed, CA-verified Harbor issuer is used; registry verifies the token signature.
        try:claims=parse_json(base64.urlsafe_b64decode(token.split('.')[1]+'='*(-len(token.split('.')[1])%4)))
        except Exception:raise Stop('TOKEN_SUBJECT_UNVERIFIED') from None
        need(claims.get('sub')==c['username'],'TOKEN_SUBJECT_UNVERIFIED')
        headers,body=get('/v2/fds/test/manifests/'+DIGEST,{'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'})
        need(headers.get('docker-content-digest')==DIGEST and 'sha256:'+hashlib.sha256(body).hexdigest()==DIGEST,'REGISTRY_DIGEST_MISMATCH')
        need(headers.get('content-type','').split(';')[0] in ('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'),'REGISTRY_MEDIA_TYPE')

    def new_auth_dir(self,key):
        p=directory(self.runroot/('auth-'+key),exclusive=True)
        write_new(p/'owner.json',encoded({'invocation':self.inv,'path':str(p),'inode':p.stat().st_ino}))
        return str(p)

    def verify_auth_dir(self,path,c):
        raw,_=regular_bytes(Path(path)/'config.json');d=decode_docker(raw)
        need(set(d['auths'])=={REGISTRY},'REGISTRY_SCOPE');verify_entry(d['auths'][REGISTRY],NEW_USER,c['password'])

    def remove_auth_dir(self,path):
        p=Path(path);need(p.parent==self.runroot and p.name.startswith('auth-'),'AUTH_PATH_SCOPE')
        directory(p);owner=parse_json(regular_bytes(p/'owner.json')[0])
        need(owner=={'invocation':self.inv,'path':str(p),'inode':p.stat().st_ino},'AUTH_DIR_REPLACED')
        need({x.name for x in p.iterdir()}<={'owner.json','config.json'},'AUTH_DIR_EXTRA_FILES')
        for name in ('config.json','owner.json'):
            target=p/name
            if target.exists():regular_bytes(target);target.unlink()
        p.rmdir();fsync_parent(p)

    def read_worker_file(self):
        need(self.name=='k8s-worker01','WORKER01_REQUIRED');p=Path('/root/.docker/config.json')
        raw,s=regular_bytes(p);need(s.st_gid==0,'WORKER_FILE_GROUP_CHANGED');context=os.getxattr(p,'security.selinux').decode().rstrip('\0')
        return raw,{'inode':s.st_ino,'device':s.st_dev,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'context':context}

    def replace_worker_file(self,expected,metadata,new):
        current,meta=self.read_worker_file();need(current==expected and meta==metadata,'WORKER_FILE_CHANGED')
        target=Path('/root/.docker/config.json');temp=target.parent/('.rotation-'+self.inv)
        write_new(temp,new,0o600,metadata['context'])
        current,meta=self.read_worker_file();need(current==expected and meta==metadata,'WORKER_FILE_CHANGED')
        os.replace(temp,target);fsync_parent(target)

def main():
    import argparse
    from rotation_adapter import Adapter
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['validate','stage','node','pod','secret','worker-file','rollback-secret','rollback-worker-file'])
    parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--credential');parser.add_argument('--ca');parser.add_argument('--namespace');parser.add_argument('--node');parser.add_argument('--recovery')
    args=parser.parse_args()
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        raw,_=regular_bytes(args.plan);need(hashlib.sha256(raw).hexdigest()==args.plan_sha256,'PLAN_HASH_MISMATCH')
        plan=parse_json(raw);validate_plan(plan,time.time())
        if args.action=='validate':print('{"status":"VALID_INPUT_ONLY"}');return 0
        h=LinuxHost(plan,create=args.action=='stage')
        if args.action=='stage':
            need(args.ca is not None,'CA_REQUIRED');ca,_=regular_bytes(args.ca);h.stage(ca)
        else:
            a=Adapter(plan,h)
            if args.credential:need(Path(args.credential)==h.runroot/'credential.json','CREDENTIAL_PATH_SCOPE')
            c=credential(regular_bytes(args.credential,32768)[0]) if args.credential else None
            if args.action in ('node','pod','secret','worker-file','rollback-secret'):need(c is not None,'CREDENTIAL_REQUIRED')
            if args.action=='node':a.worker_test(c)
            elif args.action=='pod':a.test_pod(args.namespace,args.node,c)
            elif args.action=='secret':a.patch_secret(args.namespace,c)
            elif args.action=='worker-file':a.update_worker_file(c)
            else:
                need(args.recovery is not None,'RECOVERY_RECORD_REQUIRED');auth=parse_json(regular_bytes(args.recovery)[0])
                if args.action=='rollback-secret':a.rollback_secret(args.namespace,c,auth)
                else:a.rollback_worker_file(auth)
        print('{"status":"OPERATION_RETURNED"}');return 0
    except Stop as exc:print(json.dumps({'status':'STOP','code':exc.code}));return 2
    except BaseException:print('{"status":"STOP","code":"UNEXPECTED_ERROR_PRESERVE_STATE"}');return 2

if __name__=='__main__':raise SystemExit(main())
