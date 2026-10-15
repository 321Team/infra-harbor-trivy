"""Root-only endpoints. Importing performs no I/O; no rollback or Robot deletion."""
import base64
import getpass
import http.client
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import sys
import time
import warnings
from contextlib import contextmanager
from orch_contract import *
from rotation_contract import Stop,parse_json,CA_DER_SHA256
from linux_host import LinuxHost,regular_bytes,write_new,directory,framed_body
from input_supply import import_credential,retire_credential

@contextmanager
def deadline(seconds):
    need(seconds>0,'DEADLINE_EXPIRED')
    old=signal.getitimer(signal.ITIMER_REAL);previous=signal.getsignal(signal.SIGALRM)
    started=time.monotonic()
    if old[0]>0:seconds=min(seconds,old[0])
    def expired(*_):raise Stop('ORCHESTRATION_TIMEOUT')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,seconds)
    try:yield
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        if old[0]>0:signal.setitimer(signal.ITIMER_REAL,max(0.000001,old[0]-(time.monotonic()-started)),old[1])

def read_input(path,expected):
    raw,_=regular_bytes(path)
    need(sha(raw)==digest(expected),'INPUT_HASH_MISMATCH')
    value=parse_json(raw)
    need(raw==encoded(value),'CANONICAL_INPUT_REQUIRED')
    return value

def identity(bootmap):
    name=socket.gethostname()
    need(name in bootmap and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==bootmap[name],'HOST_BOOT_CHANGED')
    return name

def bounded_stdin(limit=32768):
    need(not sys.stdin.isatty() and stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode),'PIPE_STDIN_REQUIRED')
    raw=sys.stdin.buffer.read(limit+1)
    need(len(raw)<=limit,'PIPE_INPUT_LIMIT')
    return raw

class Journal:
    def __init__(self,path):
        self.path=path
    def write(self,key,value):
        write_new(self.path/(key+'.json'),encoded(value))
    def claim(self,key,value):
        self.write('claim-'+key,value)
    def read(self,key):
        return parse_json(regular_bytes(self.path/(key+'.json'))[0])

class Capture:
    def __init__(self,fp):
        self.fp=fp;self.raw=bytearray()
    def save(self,b):
        self.raw.extend(b)
        need(len(self.raw)<=1114112,'RESPONSE_WIRE_LIMIT')
        return b
    def read(self,n):return self.save(self.fp.read(n))
    def readline(self,n):return self.save(self.fp.readline(n))

class HarborAPI:
    """Fixed CA/host, no redirects/retries. Only GET Robot metadata and one create."""
    def __init__(self,request,password,ca,journal):
        self.r=request;self.j=journal;self.number=0;self.posted=False
        der=ssl.PEM_cert_to_DER_cert(ca.decode('ascii'))
        need(sha(der)==CA_DER_SHA256,'CA_PIN_MISMATCH')
        self.ctx=ssl.create_default_context(cadata=ca.decode('ascii'))
        self.ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        need(isinstance(password,str) and password and not any(c in password for c in '\r\n\0'),'ADMIN_PASSWORD_INVALID')
        self.auth='Basic '+base64.b64encode((request['admin_username']+':'+password).encode()).decode()
    def call(self,method,path,body=None):
        need((method=='GET' and (path=='/api/v2.0/robots?page=1&page_size=100' or
             __import__('re').fullmatch('/api/v2.0/robots/[1-9][0-9]*',path))) or
             (method=='POST' and path=='/api/v2.0/robots' and body==create_body(self.r['invocation'])),'API_SCOPE')
        if method=='POST':
            need(not self.posted,'POST_ALREADY_ATTEMPTED');self.posted=True
        left=timestamp(self.r['not_after'])-time.time()
        need(left>0,'PREP_WINDOW_EXPIRED')
        self.number+=1;key='http-'+str(self.number)
        self.j.claim(key,{'method':method,'path':path,'started_at':time.time()})
        conn=None;capture=None;response=None;body_saved=False
        try:
            with deadline(min(self.r['api_seconds'],left)):
                conn=http.client.HTTPSConnection('10.1.93.54',443,context=self.ctx,timeout=min(self.r['api_seconds'],left))
                headers={'Authorization':self.auth,'Accept':'application/json','Connection':'close'}
                raw=None if body is None else encoded(body)
                if raw is not None:headers['Content-Type']='application/json'
                conn.request(method,path,body=raw,headers=headers)
                response=conn.getresponse()
                self.j.write(key+'-status',{'status':response.status,'received_at':time.time()})
                for name in ('X-Total-Count','Location'):
                    need(len(response.headers.get_all(name,[]))<=1,'API_HEADER_DUPLICATE')
                capture=Capture(response.fp);response.fp=capture
                h,data=framed_body(response)
                # Bodies stay in this protected issuance directory, never stdout or the relay.
                write_new(self.j.path/(key+'-body.bin'),data)
                body_saved=True
                self.j.write(key+'-headers',{k:v for k,v in h.items() if k in
                    ('content-type','content-length','transfer-encoding','location','x-total-count')})
                need(h.get('content-type','').split(';')[0].strip().lower()=='application/json','API_CONTENT_TYPE')
                need(response.status==(201 if method=='POST' else 200),'API_HTTP_STATUS')
                result=parse_json(data)
                if method=='POST' and 'location' in h:
                    rid=result.get('id') if isinstance(result,dict) else None
                    need(h['location'] in ('/api/v2.0/robots/'+str(rid),'https://10.1.93.54/api/v2.0/robots/'+str(rid)),'API_LOCATION')
                if path.endswith('page_size=100'):
                    need(isinstance(result,list) and len(result)<=100 and
                         h.get('x-total-count')==str(len(result)),'ROBOT_LIST_INCOMPLETE')
                return result
        finally:
            # Keep even an incomplete wire body; a lost reply never authorizes another POST.
            try:
                if capture is not None:
                    try:
                        if not body_saved:write_new(self.j.path/(key+'-wire.bin'),bytes(capture.raw))
                    finally:response.fp=capture.fp
            finally:
                try:
                    if response is not None:response.close()
                finally:
                    if conn is not None:conn.close()
    def forget(self):self.auth=None

def issue(r,api,j,now=time.time):
    prep_request(r,now())
    before={}
    rows=api.call('GET','/api/v2.0/robots?page=1&page_size=100')
    need(sorted(x.get('id') for x in rows)==[2,3],'ROBOT_LIST_CHANGED')
    for rid,user in ((2,'robot$worker'),(3,'robot$push')):
        m=metadata(api.call('GET','/api/v2.0/robots/'+str(rid)))
        need(m['id']==rid and m['name']==user and m['level']=='system' and m['disable'] is False and
             m['expires_at']>timestamp(r['not_after'])+4500,'BASELINE_IDENTITY')
        need(baseline_hash(m)==r['baseline_sha256'][str(rid)],'BASELINE_CHANGED')
        before[rid]=m
    j.write('before',before)
    # This claim is durable before the sole mutating HTTP call.
    j.claim('post',{'invocation':r['invocation'],'request_sha256':sha(encoded(r)),'body':create_body(r['invocation'])})
    prep_request(r,now())
    reply=api.call('POST','/api/v2.0/robots',create_body(r['invocation']))
    j.write('created-private',reply)
    created(reply,now(),timestamp(r['not_before']),timestamp(r['not_after']))
    new=verify_new(api.call('GET','/api/v2.0/robots/'+str(reply['id'])),reply,r['invocation'])
    for rid in (2,3):
        need(metadata(api.call('GET','/api/v2.0/robots/'+str(rid)))==before[rid],'EXISTING_ROBOT_CHANGED')
    rows=api.call('GET','/api/v2.0/robots?page=1&page_size=100')
    need(len(rows)==3 and sorted(x.get('id') for x in rows)==[2,3,reply['id']],'POST_LIST_CHANGED')
    byid={x['id']:x for x in rows}
    for rid in (2,3):need(metadata(byid[rid])==before[rid],'EXISTING_ROBOT_CHANGED')
    need(verify_new(byid[reply['id']],reply,r['invocation'])==new,'NEW_METADATA_MISMATCH')
    prep_request(r,now())
    j.write('verified',{'status':'ISSUED_VERIFIED','prep_sha256':sha(encoded(r)),'robot':new,
                        'verified_at':now()})
    return new

def run_issue(r,adapter_dir):
    prep_request(r,time.time());need(identity(r['host_boot_ids'])==CP,'CONTROL_HOST_REQUIRED')
    need(sys.stdin.isatty() and sys.stderr.isatty(),'PRIVATE_CONSOLE_REQUIRED')
    directory(ROOT)
    # Name-scoped claim, not only an invocation claim, prevents a second create under a new nonce.
    write_new(Path(ROOT)/'worker-20261015-r1-issuance-claim.json',
              encoded({'invocation':r['invocation'],'prep_sha256':sha(encoded(r))}))
    j=Journal(directory(Path(ROOT)/('issuance-'+r['invocation']),exclusive=True))
    j.write('request',r)
    api=None
    try:
        with deadline(timestamp(r['not_after'])-time.time()):
            with warnings.catch_warnings():
                warnings.simplefilter('error',getpass.GetPassWarning)
                password=getpass.getpass('Harbor password (not saved): ')
        ca,_=regular_bytes(adapter_dir/'public-ca.pem')
        api=HarborAPI(r,password,ca,j);password=None
        issue(r,api,j)
    finally:
        if api is not None:api.forget()

def context(r):
    rotation_request(r,time.time());p=r['plan'];name=identity(p['host_boot_ids'])
    base=Path(ROOT)/('orchestration-'+p['invocation'])
    return p,name,base

def bound_journal(r,create=False):
    p,name,path=context(r)
    if create:
        directory(ROOT);directory(path,exclusive=True)
        j=Journal(path);j.write('request',r)
    else:
        directory(path);j=Journal(path)
        need(j.read('request')==r,'ORCHESTRATION_INPUT_CHANGED')
    return p,name,j

def stage(r,ca):
    need(time.time()<timestamp(r['supply_until']),'SUPPLY_DEADLINE')
    p,name,j=bound_journal(r,True)
    j.claim('stage',{'request_sha256':sha(encoded(r))})
    with deadline(min(r['stage_seconds'],timestamp(r['supply_until'])-time.time())):
        h=LinuxHost(p,create=True);h.stage(ca)
        need(h.receipt('stage')==stage_receipt(p,name),'STAGE_NOT_VERIFIED')
    j.write('stage',stage_receipt(p,name))

def stage_status(r):
    p,name,j=bound_journal(r);h=LinuxHost(p)
    expected=stage_receipt(p,name)
    need(j.read('stage')==expected and h.receipt('stage')==expected,'STAGE_NOT_VERIFIED')
    return expected

def issued_credential(r):
    p=r['plan'];j=Journal(Path(ROOT)/('issuance-'+p['invocation']))
    need(j.read('request')==r['prep'],'ISSUANCE_INPUT_CHANGED')
    verified=j.read('verified')
    need(verified['status']=='ISSUED_VERIFIED' and verified['prep_sha256']==sha(encoded(r['prep'])) and
         verified['robot']==p['new_robot'],'ISSUANCE_PLAN_MISMATCH')
    need(verified['verified_at']<=timestamp(p['not_before']),'ISSUANCE_NOT_FINISHED_BEFORE_ROTATION')
    raw=j.read('created-private')
    need(raw['id']==p['new_robot']['id'] and raw['name']==NEW_USER,'ISSUANCE_ID_MISMATCH')
    return credential(encoded({'username':NEW_USER,'password':raw['secret']}))

def export_credential(r,target,all_stages):
    p,name,j=bound_journal(r)
    need(name==CP and target in NODES,'EXPORT_SCOPE')
    stages(p,all_stages);stage_status(r)
    need(time.time()<timestamp(r['supply_until']),'SUPPLY_DEADLINE')
    c=issued_credential(r)
    j.claim('export-'+target,{'request_sha256':sha(encoded(r)),'target':target})
    return {'invocation':p['invocation'],'request_sha256':sha(encoded(r)),'target':target,
            'boot_id':p['host_boot_ids'][target],'robot_id':p['new_robot']['id'],'credential':c}

def receive_credential(r,raw):
    p,name,j=bound_journal(r);stage_status(r)
    need(name in NODES and time.time()<timestamp(r['supply_until']),'SUPPLY_DEADLINE')
    c=transfer(r,name,parse_json(raw))
    j.claim('supply',{'request_sha256':sha(encoded(r))})
    import_credential(LinuxHost(p),encoded(c))
    j.write('supply',{'status':'SUPPLIED','host':name,'request_sha256':sha(encoded(r))})

def local_credential(r,all_stages):
    p,name,j=bound_journal(r);need(name==CP,'CONTROL_HOST_REQUIRED')
    stages(p,all_stages);stage_status(r)
    need(time.time()<timestamp(r['supply_until']),'SUPPLY_DEADLINE')
    c=issued_credential(r);j.claim('supply',{'request_sha256':sha(encoded(r))})
    import_credential(LinuxHost(p),encoded(c))
    j.write('supply',{'status':'SUPPLIED','host':name,'request_sha256':sha(encoded(r))})

def retire(r,c):
    p,name,j=bound_journal(r);closeout(r,c,time.time())
    need(j.read('supply')=={'status':'SUPPLIED','host':name,'request_sha256':sha(encoded(r))},'SUPPLY_NOT_CONFIRMED')
    j.claim('retire',{'closeout':c})
    retire_credential(LinuxHost(p))
    j.write('retire',{'status':'RETIRED','host':name,'request_sha256':sha(encoded(r))})

def main(argv,adapter_dir):
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['issue','stage','stage-status','supply-local','export','receive','retire'])
    parser.add_argument('--request',required=True);parser.add_argument('--request-sha256',required=True)
    parser.add_argument('--target',choices=NODES)
    parser.add_argument('--operation-until')
    a=parser.parse_args(argv)
    r=read_input(a.request,a.request_sha256)
    if a.action=='issue':
        prep_request(r,time.time())
        with deadline(timestamp(r['not_after'])-time.time()):run_issue(r,adapter_dir)
        return {'status':'ISSUED_VERIFIED'}
    rotation_request(r,time.time())
    cap=r['stage_seconds'] if a.action=='stage' else r['retire_seconds'] if a.action=='retire' else r['transfer_seconds']
    end=r['plan']['not_after'] if a.action=='retire' else r['supply_until']
    need(a.operation_until is not None,'OPERATION_DEADLINE_REQUIRED')
    # Derived at relay dispatch, so a late receiver cannot acquire a new full timeout.
    operation_end=timestamp(a.operation_until)
    need(time.time()<operation_end<=min(timestamp(end),time.time()+cap),'OPERATION_DEADLINE_INVALID')
    with deadline(min(cap,operation_end-time.time())):
        if a.action=='stage':
            ca,_=regular_bytes(adapter_dir/'public-ca.pem');stage(r,ca)
        elif a.action=='stage-status':return stage_status(r)
        elif a.action=='supply-local':local_credential(r,parse_json(bounded_stdin()))
        elif a.action=='receive':receive_credential(r,bounded_stdin())
        elif a.action=='retire':retire(r,parse_json(bounded_stdin()))
        else:
            need(a.target is not None and not sys.stdout.isatty() and
                 stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode),'PRIVATE_PIPE_REQUIRED')
            result=export_credential(r,a.target,parse_json(bounded_stdin()))
            sys.stdout.buffer.write(encoded(result));sys.stdout.buffer.flush()
            return None
    return {'status':'RETURNED','action':a.action,'host':socket.gethostname(),'request_sha256':sha(encoded(r))}
