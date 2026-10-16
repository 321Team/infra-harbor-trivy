"""Root-owned, isolated Python entrypoint. Verify the complete runtime directory first."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

FILES={'launch.py','rotation_contract.py','rotation_adapter.py','linux_host.py','input_supply.py','public-ca.pem'}

def verify_bundle(root,expected):
    # No imports from this directory until all bytes and ownership checks have passed.
    if not root.is_absolute():raise ValueError()
    for p in (root,*root.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError()
    if stat.S_IMODE(root.lstat().st_mode)!=0o700:raise ValueError()
    if {p.name for p in root.iterdir()}!=FILES|{'runtime-manifest.json'}:raise ValueError()
    def read(name):
        fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>1048576:raise ValueError()
            with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(1048577)
            if len(raw)!=s.st_size or len(raw)>1048576:raise ValueError()
            return raw
        finally:os.close(fd)
    raw=read('runtime-manifest.json')
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError()
    m=json.loads(raw)
    if set(m)!={'version','files'} or m['version']!=1 or set(m['files'])!=FILES:raise ValueError()
    for name,row in m['files'].items():
        raw=read(name)
        if set(row)!={'sha256','bytes'} or len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError()

def main():
    try:
        if os.name!='posix' or os.geteuid()!=0 or os.getegid()!=0 or not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):raise ValueError()
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
        os.environ.clear();os.environ.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C','LC_ALL':'C'})
        if len(sys.argv)<4 or sys.argv[2] not in ('adapter','supply'):raise ValueError()
        root=Path(__file__).absolute().parent;verify_bundle(root,sys.argv[1])
        entry=sys.argv[2];sys.argv=[sys.argv[0],*sys.argv[3:]];sys.path.insert(0,str(root))
        if entry=='adapter':from linux_host import main as entry_main
        else:from input_supply import main as entry_main
        return entry_main()
    except BaseException:
        print('{"status":"STOP","code":"LAUNCH_INPUT_OR_BUNDLE_INVALID"}');return 2

if __name__=='__main__':raise SystemExit(main())
