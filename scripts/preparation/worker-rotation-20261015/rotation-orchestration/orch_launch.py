"""Verify both complete public bundles before local imports; suppress child/error text."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

OWN={'orch_launch.py','orch_contract.py','orch_endpoint.py','orch_relay.py'}
ADAPTER={'launch.py','rotation_contract.py','rotation_adapter.py','linux_host.py','input_supply.py','public-ca.pem'}
ADAPTER_SHA='0bf529d53e03cae160caebc4e3637c45502d8b621c0b08e8af49f62b75ccf247'

def verify(root,manifest_name,expected,names,owner):
    if not root.is_absolute() or '..' in root.parts:raise ValueError()
    for path in (root,*root.parents):
        s=path.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0,owner) or s.st_mode&0o022:raise ValueError()
    if root.lstat().st_uid!=owner or stat.S_IMODE(root.lstat().st_mode)!=0o700:raise ValueError()
    if {p.name for p in root.iterdir()}!=names|{manifest_name}:raise ValueError()
    def read(name):
        fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=owner or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>1048576:raise ValueError()
            with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(1048577)
            after=os.fstat(fd)
            if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(raw)!=s.st_size:raise ValueError()
            return raw
        finally:os.close(fd)
    raw=read(manifest_name)
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError()
    m=json.loads(raw)
    if set(m)!={'version','files'} or m['version']!=1 or set(m['files'])!=names:raise ValueError()
    for name,row in m['files'].items():
        raw=read(name)
        if set(row)!={'bytes','sha256'} or len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError()

def main():
    try:
        if os.name!='posix' or not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode) or len(sys.argv)<6:raise ValueError()
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
        manifest,adapter,mode=sys.argv[1:4]
        if mode not in ('endpoint','relay'):raise ValueError()
        if mode=='endpoint' and (os.geteuid()!=0 or os.getegid()!=0):raise ValueError()
        if mode=='relay' and os.getuid()==0:raise ValueError()
        owner=0 if mode=='endpoint' else os.getuid()
        root=Path(__file__).absolute().parent;adapter=Path(adapter)
        verify(root,'orchestration-manifest.json',manifest,OWN,owner)
        verify(adapter,'runtime-manifest.json',ADAPTER_SHA,ADAPTER,owner)
        os.environ.clear();os.environ.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME':'/root' if mode=='endpoint' else '/home/server01_ansible','LANG':'C','LC_ALL':'C'})
        sys.path[:0]=[str(root),str(adapter)]
        if mode=='endpoint':
            from orch_endpoint import main as entry
            result=entry(sys.argv[4:],adapter)
        else:
            from orch_relay import main as entry
            result=entry(sys.argv[4:],manifest)
        if result is not None:print(json.dumps(result,sort_keys=True,separators=(',',':')))
        return 0
    except BaseException:
        # Export writes only into a pipe; any mixed/truncated output is rejected by receiver.
        print('{"status":"STOP","code":"ORCHESTRATION_STOP_PRESERVE"}')
        return 2

if __name__=='__main__':raise SystemExit(main())
