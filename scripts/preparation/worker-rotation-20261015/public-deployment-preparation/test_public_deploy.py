"""Local synthetic FD/syscall fault tests. No network, host access, or runtime inputs."""
import ast
import copy
import datetime as dt
import io
import json
from pathlib import Path
import posixpath
import stat
import sys
import types
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import public_deploy as p
import prepare_delivery as render
sys.path[:0]=[str(HERE.parent/'rotation-orchestration'),str(HERE.parent/'rotation-adapter-r2')]
from test_orchestration import request as orch_request,prep as orch_prep,closeout,NOW,BOOT,iso
CTX='unconfined_u:object_r:admin_home_t:s0' # MOCK ONLY, never approved actual context.
class Node:
    def __init__(self,inode,kind,uid=0,gid=0,mode=0o700,data=b''):
        self.inode=inode;self.kind=kind;self.uid=uid;self.gid=gid;self.mode=mode
        self.data=bytearray(data);self.nlink=1;self.time=1;self.attrs={'security.selinux':CTX.encode()+b'\0'}
    def snapshot(self):
        return types.SimpleNamespace(st_dev=1,st_ino=self.inode,st_uid=self.uid,st_gid=self.gid,
            st_mode=self.kind|self.mode,st_size=len(self.data),st_nlink=self.nlink,st_mtime_ns=self.time,st_ctime_ns=self.time)
class Posix:
    O_RDONLY=0;O_WRONLY=1;O_CREAT=64;O_EXCL=128;O_NOFOLLOW=131072;O_DIRECTORY=65536;O_CLOEXEC=524288;O_NONBLOCK=2048
    def __init__(self,relay=False,existing=False):
        self.uid=1001 if relay else 0;self.gid=self.uid;self.tree={};self.fds={};self.nextinode=1;self.nextfd=20
        self.limit=None;self.zero=False;self.error_write=False;self.interrupt=False;self.fail_sync=False
        self.hook=None;self.writes=[];self.events=[];self.created=[];self.wall=NOW;self.mono=0
        self.add('/',stat.S_IFDIR,uid=0,mode=0o755)
        if relay:
            self.add('/home',stat.S_IFDIR,uid=0,mode=0o755);self.add(p.HOME,stat.S_IFDIR,uid=1001)
        else:
            self.add('/root',stat.S_IFDIR)
            if existing:self.add(p.ROOT,stat.S_IFDIR)
        self.host='ansible01' if relay else 'k8s-control01';self.boot=BOOT
    def add(self,path,kind,uid=None,mode=0o700,data=b''):
        uid=self.uid if uid is None else uid
        n=Node(self.nextinode,kind,uid,uid,mode,data);self.nextinode+=1;self.tree[path]=n;return n
    def path(self,path,fd=None):
        if path.startswith('/'):return path
        parent=self.fds[fd][0];return posixpath.join(parent,path)
    def event(self,action,path):
        self.events.append((action,path))
        if self.hook:self.hook(action,path)
    def open(self,path,flags,mode=0o777,dir_fd=None):
        path=self.path(path,dir_fd);self.event('open',path)
        n=self.tree.get(path)
        if flags & self.O_CREAT:
            if n and flags & self.O_EXCL:raise FileExistsError()
            if not n:n=self.add(path,stat.S_IFREG,mode=mode);self.created.append(path)
        if n is None:raise FileNotFoundError(path)
        if n.kind==stat.S_IFLNK and flags & self.O_NOFOLLOW:raise OSError('ELOOP')
        if flags & self.O_DIRECTORY and n.kind!=stat.S_IFDIR:raise NotADirectoryError()
        fd=self.nextfd;self.nextfd+=1;self.fds[fd]=[path,n,0];return fd
    def close(self,fd):del self.fds[fd]
    def fstat(self,fd):return self.fds[fd][1].snapshot()
    def stat(self,path,dir_fd=None,follow_symlinks=False):
        path=self.path(path,dir_fd);self.event('stat',path)
        if path not in self.tree:raise FileNotFoundError()
        return self.tree[path].snapshot()
    def listxattr(self,fd):return list(self.fds[fd][1].attrs)
    def getxattr(self,fd,key):return self.fds[fd][1].attrs[key]
    def mkdir(self,path,mode,dir_fd=None):
        path=self.path(path,dir_fd);self.event('mkdir',path)
        if path in self.tree:raise FileExistsError()
        self.add(path,stat.S_IFDIR,mode=mode);self.created.append(path)
    def fsync(self,fd):
        self.event('fsync',self.fds[fd][0])
        if self.fail_sync:raise OSError('ENOSPC')
    def write(self,fd,data):
        path,n,offset=self.fds[fd];self.event('write',path)
        if self.interrupt:raise KeyboardInterrupt()
        if self.error_write:raise OSError('ENOSPC')
        count=0 if self.zero else min(len(data),self.limit or len(data))
        n.data[offset:offset+count]=data[:count];n.time+=1;self.fds[fd][2]+=count
        self.writes.append((path,count));return count
    def read(self,fd,limit):
        path,n,offset=self.fds[fd];self.event('read',path)
        data=bytes(n.data[offset:offset+limit]);self.fds[fd][2]+=len(data);return data
    def listdir(self,fd):
        path=self.fds[fd][0];self.event('listdir',path)
        return [q.rsplit('/',1)[-1] for q in self.tree if q!=path and posixpath.dirname(q)==path]
    def getuid(self):return self.uid
    geteuid=getuid
    def getgid(self):return self.gid
    getegid=getgid

class Harness(p.LinuxFS):
    def identity(self):
        p.need(self.r['host']==self.fake.host and self.r['boot_id']==self.fake.boot,'IDENTITY_CHANGED')
        p.need(self.fake.uid==self.r['uid'] and self.fake.gid==self.r['gid'],'OWNER_CHANGED')
def req(fake,phase='code'):
    r={'version':1,'state':'BOUND','phase':phase,'invocation':'1'*32,'host':fake.host,'boot_id':BOOT,
       'uid':fake.uid,'gid':fake.gid,'not_before':iso(NOW-1),'deadline':iso(NOW+1000),
       'authorization_reference':'SYNTHETIC_TEST_ONLY','create_base':phase=='code' and (fake.host=='ansible01' or p.ROOT not in fake.tree),
       'contexts':{'base':CTX,'directory':CTX,'file':CTX},'parents':{},'input_sha256':{}}
    base,_=p.layout(r)
    for path in p.chain(base)[:-1] if r['create_base'] else p.chain(base):
        n=fake.tree[path]
        r['parents'][path]={'device':1,'inode':n.inode,'uid':n.uid,'gid':n.gid,'mode':n.mode,'context':CTX}
    return r
def fs(fake,r):
    d=p.Deadline(r,lambda:fake.wall,lambda:fake.mono)
    h=Harness(r,d);h.fake=fake;return h

class DeployTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.payload=render.sources()
    def execute(self,f,r,action='supply',payload=None,receipt=None):
        p.validate(r,f.wall);h=fs(f,r)
        with patch.object(p,'os',f):return p.run(r,self.payload if payload is None else payload,action,h,receipt)
    def supplied(self,relay=False):
        f=Posix(relay);r=req(f);receipt=self.execute(f,r);return f,r,receipt
    def test_root_supply_and_independent_read(self):
        f,r,receipt=self.supplied();count=len(f.writes)
        v=self.execute(f,r,'verify',receipt=receipt)
        self.assertEqual(v['status'],'PUBLIC_READ_VERIFIED');self.assertEqual(len(v['files']),12)
        self.assertEqual(len(f.writes),count);self.assertFalse(v['created']);self.assertFalse(f.fds)
    def test_relay_owner_model_and_read(self):
        f,r,out=self.supplied(True);self.assertTrue(all(x['uid']==1001 for x in out['files'].values()))
        self.execute(f,r,'verify',receipt=out);self.assertFalse(f.fds)
    def test_existing_root_base_preserved(self):
        f=Posix(existing=True);inode=f.tree[p.ROOT].inode;self.execute(f,req(f));self.assertEqual(f.tree[p.ROOT].inode,inode)
    def test_repeat_supply_rejected_no_extra_write(self):
        f,r,out=self.supplied();n=len(f.writes)
        with self.assertRaises((p.Stop,FileExistsError)):self.execute(f,r)
        self.assertEqual(len(f.writes),n)
    def test_short_writes_completed(self):
        f=Posix();f.limit=113;r=req(f);out=self.execute(f,r)
        self.assertEqual(len(out['files']),12);self.assertGreater(len(f.writes),12)
    def test_zero_write_preserves_partial(self):
        f=Posix();f.zero=True;r=req(f)
        with self.assertRaisesRegex(p.Stop,'SHORT_WRITE_ZERO'):self.execute(f,r)
        self.assertEqual(len(f.writes),1);self.assertTrue(f.created);self.assertFalse(f.fds)
    def test_disk_error_preserves_created_file(self):
        f=Posix();f.error_write=True
        with self.assertRaises(OSError):self.execute(f,req(f))
        self.assertEqual(sum(n.kind==stat.S_IFREG for n in f.tree.values()),1);self.assertFalse(f.fds)
    def test_interrupt_preserves_partial(self):
        f=Posix();f.interrupt=True
        with self.assertRaises(KeyboardInterrupt):self.execute(f,req(f))
        self.assertEqual(sum(n.kind==stat.S_IFREG for n in f.tree.values()),1);self.assertFalse(f.fds)
    def test_fsync_failure_stops_at_first_created_dir(self):
        f=Posix();f.fail_sync=True
        with self.assertRaises(OSError):self.execute(f,req(f))
        self.assertEqual(f.created,[p.ROOT]);self.assertEqual(f.writes,[])
    def test_symlink_parent_rejected(self):
        f=Posix();r=req(f);f.tree['/root'].kind=stat.S_IFLNK
        with self.assertRaises((p.Stop,OSError)):self.execute(f,r)
        self.assertEqual(f.created,[])
    def test_dangling_target_collision(self):
        f=Posix();r=req(f);f.add(p.ROOT,stat.S_IFLNK)
        with self.assertRaisesRegex(p.Stop,'TARGET_EXISTS'):self.execute(f,r)
        self.assertEqual(f.created,[])
    def test_existing_target_file_not_overwritten(self):
        f=Posix(existing=True);r=req(f);_,dirs=p.layout(r);f.add(dirs['adapter'],stat.S_IFREG,data=b'KEEP')
        with self.assertRaises(p.Stop):self.execute(f,r)
        self.assertEqual(bytes(f.tree[dirs['adapter']].data),b'KEEP');self.assertEqual(f.writes,[])
    def test_acl_parent_rejected(self):
        for acl in ('system.posix_acl_access','system.posix_acl_default','user.test','security.capability'):
            f=Posix();r=req(f);f.tree['/root'].attrs[acl]=b'x'
            with self.subTest(acl=acl),self.assertRaisesRegex(p.Stop,'ACL_OR_UNEXPECTED_XATTR'):self.execute(f,r)
            self.assertEqual(f.created,[])
    def test_parent_metadata_change_rejected(self):
        for field,val in [('uid',33),('gid',33),('mode',0o777),('inode',999)]:
            f=Posix();r=req(f);setattr(f.tree['/root'],field,val)
            with self.subTest(field=field),self.assertRaises(p.Stop):self.execute(f,r)
            self.assertEqual(f.writes,[])
    def test_parent_replaced_between_writes(self):
        f=Posix();r=req(f);f.hook=lambda a,path: f.add('/root',stat.S_IFDIR) if a=='write' and not f.writes else None
        with self.assertRaisesRegex(p.Stop,'PARENT_CHANGED'):self.execute(f,r)
        self.assertLessEqual(len(f.writes),1);self.assertTrue(f.created);self.assertFalse(f.fds)
    def test_name_replacement_during_read_rejected(self):
        f,r,out=self.supplied();file=next(iter(out['files']));done=[]
        def hook(a,path):
            if a=='read' and path==file and not done:
                old=f.tree[file];f.add(file,stat.S_IFREG,mode=0o600,data=bytes(old.data));done.append(True)
        f.hook=hook
        with self.assertRaisesRegex(p.Stop,'FILE_NAME_CHANGED'):self.execute(f,r,'verify',receipt=out)
        self.assertFalse(f.fds)
    def test_deadline_during_short_write(self):
        f=Posix();f.limit=10;r=req(f)
        def hook(a,path):
            if a=='write':f.mono+=1001
        f.hook=hook
        with self.assertRaisesRegex(p.Stop,'DEADLINE'):self.execute(f,r)
        self.assertEqual(len(f.writes),1);self.assertTrue(f.created);self.assertFalse(f.fds)
    def test_wall_clock_rollback_does_not_extend(self):
        f=Posix();d=p.Deadline(req(f),lambda:f.wall,lambda:f.mono);f.wall-=9999;f.mono+=1001
        with self.assertRaisesRegex(p.Stop,'DEADLINE'):d.check()
    def test_hash_mismatch_after_supply(self):
        f,r,out=self.supplied();file=next(iter(out['files']));f.tree[file].data.extend(b'x')
        with self.assertRaises(p.Stop):self.execute(f,r,'verify',receipt=out)
    def test_unexpected_code_file(self):
        f,r,out=self.supplied();_,dirs=p.layout(r);f.add(dirs['adapter']+'/extra',stat.S_IFREG)
        with self.assertRaisesRegex(p.Stop,'FILE_SET'):self.execute(f,r,'verify',receipt=out)
    def test_missing_code_file(self):
        f,r,out=self.supplied();del f.tree[next(iter(out['files']))]
        with self.assertRaises(p.Stop):self.execute(f,r,'verify',receipt=out)
    def test_hardlink_mode_owner_label_rejected(self):
        for field,val in [('nlink',2),('mode',0o644),('uid',1001),('gid',1001)]:
            f,r,out=self.supplied();setattr(f.tree[next(iter(out['files']))],field,val)
            with self.subTest(field=field),self.assertRaises(p.Stop):self.execute(f,r,'verify',receipt=out)
        f,r,out=self.supplied();f.tree[next(iter(out['files']))].attrs['security.selinux']=b'unconfined_u:object_r:wrong_t:s0'
        with self.assertRaises(p.Stop):self.execute(f,r,'verify',receipt=out)
    def test_same_bytes_new_inode_rejected_by_receipt(self):
        f,r,out=self.supplied();file=next(iter(out['files']));old=f.tree[file];f.add(file,stat.S_IFREG,mode=0o600,data=bytes(old.data))
        with self.assertRaisesRegex(p.Stop,'SUPPLY_GENERATION_CHANGED'):self.execute(f,r,'verify',receipt=out)
    def test_extra_receipt_fields_or_paths_rejected(self):
        f,r,out=self.supplied();bad=copy.deepcopy(out);bad['password']='SYNTHETIC_ONLY'
        with self.assertRaisesRegex(p.Stop,'SUPPLY_RECEIPT_REQUIRED'):self.execute(f,r,'verify',receipt=bad)
        bad=copy.deepcopy(out);bad['files']['/etc/forbidden']=next(iter(bad['files'].values()))
        with self.assertRaisesRegex(p.Stop,'RECEIPT_SCOPE'):self.execute(f,r,'verify',receipt=bad)
    def test_same_content_new_directory_rejected(self):
        f,r,out=self.supplied();_,dirs=p.layout(r);f.add(dirs['adapter'],stat.S_IFDIR)
        with self.assertRaisesRegex(p.Stop,'SUPPLY_GENERATION_CHANGED'):self.execute(f,r,'verify',receipt=out)
    def test_verify_requires_actual_bound_receipt(self):
        f,r,out=self.supplied()
        for receipt in (None,{},dict(out,request_sha256='0'*64),dict(out,status='STOP')):
            with self.subTest(receipt=bool(receipt)),self.assertRaisesRegex(p.Stop,'SUPPLY_RECEIPT_REQUIRED'):self.execute(f,r,'verify',receipt=receipt)
    def test_boot_and_owner_change_before_work(self):
        for change in ('boot','uid','host'):
            f=Posix();r=req(f);setattr(f,change,999 if change=='uid' else 'wrong')
            with self.subTest(change=change),self.assertRaises(p.Stop):self.execute(f,r)
            self.assertEqual(f.created,[])
    def test_malformed_payload_before_write(self):
        for mutate in ('extra','missing','hash','manifest'):
            f=Posix();r=req(f);data=dict(self.payload)
            if mutate=='extra':data['adapter/extra.py']=b'x'
            elif mutate=='missing':data.pop('adapter/launch.py')
            elif mutate=='hash':data['adapter/launch.py']+=b'x'
            else:data['adapter/runtime-manifest.json']=b'{}'
            with self.subTest(mutate=mutate),self.assertRaises(p.Stop):self.execute(f,r,payload=data)
            self.assertEqual(f.created,[])
    def test_issue_input_after_code_and_read(self):
        f,_,_=self.supplied();r=req(f,'issue-input');name='prep-request-'+r['invocation']+'.json';raw=p.encoded(orch_prep())
        r['input_sha256']={name:p.sha(raw)};out=self.execute(f,r,payload={name:raw})
        self.assertEqual(len(out['files']),13);self.execute(f,r,'verify',{name:raw},out)
    def test_rotation_root_plan_exact_and_public(self):
        f,_,_=self.supplied();r=req(f,'rotation-input');v=orch_request();inv=r['invocation']
        data={'orchestration-request-'+inv+'.json':p.encoded(v),'request-'+inv+'.json':p.encoded(v['plan'])}
        r['input_sha256']={n:p.sha(b) for n,b in data.items()}
        out=self.execute(f,r,payload=data);self.assertEqual(len(out['files']),14)
        self.execute(f,r,'verify',data,out)
    def test_rotation_relay_input(self):
        f,_,_=self.supplied(True);r=req(f,'rotation-input');data={'rotation-request.json':p.encoded(orch_request())}
        r['input_sha256']={n:p.sha(b) for n,b in data.items()}
        out=self.execute(f,r,payload=data);self.execute(f,r,'verify',data,out)
    def test_closeout_relay_input(self):
        f,_,_=self.supplied(True);r=req(f,'closeout-input');data={'closeout.json':p.encoded(closeout(orch_request()))}
        r['input_sha256']={n:p.sha(b) for n,b in data.items()}
        out=self.execute(f,r,payload=data);self.execute(f,r,'verify',data,out)
    def test_input_existing_conflict_before_any_write(self):
        f,_,_=self.supplied();r=req(f,'issue-input');n='prep-request-'+r['invocation']+'.json';raw=p.encoded(orch_prep());r['input_sha256']={n:p.sha(raw)}
        f.add(p.ROOT+'/'+n,stat.S_IFREG,mode=0o600,data=b'KEEP');count=len(f.writes)
        with self.assertRaises(p.Stop):self.execute(f,r,payload={n:raw})
        self.assertEqual(len(f.writes),count)
    def test_input_rejects_secret_and_noncanonical(self):
        for change in ('secret','noncanonical','boot'):
            f,_,_=self.supplied();r=req(f,'issue-input');v=orch_prep();n='prep-request-'+r['invocation']+'.json'
            if change=='secret':v['password']='SYNTHETIC_ONLY'
            if change=='boot':v['host_boot_ids'][r['host']]='0'*36
            raw=json.dumps(v).encode() if change=='noncanonical' else p.encoded(v);r['input_sha256']={n:p.sha(raw)};count=len(f.writes)
            with self.subTest(change=change),self.assertRaises(p.Stop):self.execute(f,r,payload={n:raw})
            self.assertEqual(len(f.writes),count)
    def test_mismatched_embedded_plan_rejected(self):
        f,_,_=self.supplied();r=req(f,'rotation-input');v=orch_request();inv=r['invocation'];plan=copy.deepcopy(v['plan']);plan['scope_reference']='DIFFERENT_SYNTHETIC'
        data={'orchestration-request-'+inv+'.json':p.encoded(v),'request-'+inv+'.json':p.encoded(plan)};r['input_sha256']={n:p.sha(b) for n,b in data.items()};count=len(f.writes)
        with self.assertRaisesRegex(p.Stop,'EMBEDDED_PLAN'):self.execute(f,r,payload=data)
        self.assertEqual(len(f.writes),count)


    def test_new_directory_label_mismatch_stops_before_files(self):
        f=Posix();r=req(f)
        def hook(action,path):
            if action=='fsync' and p.ROOT in f.tree:
                f.tree[p.ROOT].attrs['security.selinux']=b'unconfined_u:object_r:wrong_t:s0'
        f.hook=hook
        with self.assertRaisesRegex(p.Stop,'CREATED_DIRECTORY_METADATA'):self.execute(f,r)
        self.assertEqual(f.writes,[]);self.assertEqual(f.created,[p.ROOT])
    def test_file_acl_injected_at_creation_stops_before_write(self):
        f=Posix();r=req(f)
        original=f.open
        def opened(path,flags,mode=0o777,dir_fd=None):
            fd=original(path,flags,mode,dir_fd)
            if flags & f.O_CREAT:f.fds[fd][1].attrs['system.posix_acl_access']=b'bad'
            return fd
        f.open=opened
        with self.assertRaisesRegex(p.Stop,'ACL_OR_UNEXPECTED_XATTR'):self.execute(f,r)
        self.assertEqual(f.writes,[]);self.assertTrue(f.created)
    def test_post_supply_boot_change_rejects_success(self):
        f=Posix();r=req(f);last='orchestrator-'+r['invocation']+'/orchestration-manifest.json'
        def hook(action,path):
            if action=='write' and path.endswith(last):f.boot='changed'
        f.hook=hook
        with self.assertRaisesRegex(p.Stop,'IDENTITY_CHANGED'):self.execute(f,r)
        self.assertGreater(len(f.writes),0)
    def test_readonly_failure_does_not_create_or_modify(self):
        f,r,out=self.supplied();file=next(iter(out['files']));f.tree[file].mode=0o644
        before=(list(f.writes),list(f.created),set(f.tree))
        with self.assertRaises(p.Stop):self.execute(f,r,'verify',receipt=out)
        self.assertEqual(before,(f.writes,f.created,set(f.tree)))

class ContractTests(unittest.TestCase):
    def test_invalid_fields_scope_and_types(self):
        for k,v in [('state','DRAFT'),('invocation',None),('boot_id',None),('uid',True),('gid',4),('phase','delete'),('authorization_reference','PENDING_INPUT'),('deadline',iso(NOW)),('not_before',iso(NOW+1))]:
            r=req(Posix());r[k]=v
            with self.subTest(k=k),self.assertRaises(p.Stop):p.validate(r,NOW)
    def test_parent_scope_and_acl_mode(self):
        r=req(Posix());r['parents']['/tmp']=copy.deepcopy(r['parents']['/'])
        with self.assertRaises(p.Stop):p.validate(r,NOW)
        r=req(Posix());r['parents']['/root']['mode']=0o777
        with self.assertRaises(p.Stop):p.validate(r,NOW)
    def test_duplicate_json_and_nonfinite_rejected(self):
        for b in (b'{"x":1,"x":2}',b'{"x":NaN}',b'not-json'):
            with self.assertRaises(p.Stop):p.parse(b)
    def test_wrong_stage_host_rejected(self):
        for phase,relay in [('issue-input',True),('closeout-input',False)]:
            f=Posix(relay);r=req(f);r['phase']=phase;r['create_base']=False
            with self.assertRaises(p.Stop):p.validate(r,NOW)
    def test_renderer_full_five_hosts_and_no_real_execution(self):
        rows=[]
        for host in p.HOSTS:
            f=Posix(host=='ansible01');f.host=host;rows.append(req(f))
        plan={'version':1,'state':'BOUND','phase':'code','requests':rows}
        result=render.prepare(plan,HERE,'supply',None,NOW)
        self.assertEqual(len(result),5)
        for name,raw in result.items():ast.parse(raw.decode(),filename=name)
        self.assertFalse(any('secret' in n for n in result))
    def test_renderer_missing_duplicate_or_mixed_host_rejected(self):
        rows=[]
        for host in p.HOSTS:
            f=Posix(host=='ansible01');f.host=host;rows.append(req(f))
        for value in (rows[:-1],rows+[rows[0]],rows[:-1]+[rows[0]]):
            with self.assertRaises(p.Stop):render.request_set({'version':1,'state':'BOUND','phase':'code','requests':value},NOW)
        rows[-1]['invocation']='2'*32
        with self.assertRaises(p.Stop):render.request_set({'version':1,'state':'BOUND','phase':'code','requests':rows},NOW)
    def test_verification_render_does_not_synthesize_receipt(self):
        with self.assertRaisesRegex(p.Stop,'ACTUAL_RECEIPT_REQUIRED'):render.make_script(b'x',req(Posix()),{},'verify')
    def test_cross_host_public_semantics(self):
        v=orch_request();inv=v['plan']['invocation'];values={'orchestration-request-'+inv+'.json':v,'rotation-request.json':v,'request-'+inv+'.json':v['plan']}
        render.validate_semantics('rotation-input',values,NOW)
        values['rotation-request.json']=dict(v,relay_uid=2002)
        with self.assertRaises(p.Stop):render.validate_semantics('rotation-input',values,NOW)
if __name__=='__main__':unittest.main()

