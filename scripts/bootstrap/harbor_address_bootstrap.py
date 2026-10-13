#!/usr/bin/env python3
"""Trusted one-shot address entry point. No installer or implicit apply.

Interpreter/stdlib/bootstrap must ALREADY be trusted. A post-start self hash
cannot undo unsafe startup. All project modules are verified before import.
"""
import sys
if __name__ == '__main__' and not (
    sys.platform == 'linux' and sys.version_info >= (3,10) and
    sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize):
    print('{"stage":"STOP","reason":"BOOTSTRAP_FLAGS_OR_PLATFORM"}')
    raise SystemExit(2)
import os
if __name__ == '__main__' and (os.geteuid()!=0 or os.getegid()!=0):
    print('{"stage":"STOP","reason":"BOOTSTRAP_ROOT"}')
    raise SystemExit(2)
import argparse
from contextlib import contextmanager
import hashlib
import importlib
import importlib.abc
import importlib.util
import json
import math
from pathlib import PurePosixPath
import re
import stat
import time

PREFIXES=('harbor_address_','harbor_recovery_')
MODULES=frozenset('harbor_address_'+n for n in
    ('backend','compose','continuation','evidence','host','input','inspect','journal','network','package','preservation','sequence','session','launch')
) | frozenset('harbor_recovery_'+n for n in ('core','docker','host'))
MAX_JSON=1024*1024
MAX_SOURCE=1024*1024

class Stop(ValueError):pass
def require(value,reason):
    if not value:raise Stop(reason)
def remaining(deadline,clock=time.monotonic):
    require(type(deadline) in (int,float) and math.isfinite(deadline) and clock()<deadline,'BOOTSTRAP_DEADLINE')
def absolute(path):
    return type(path) is str and re.fullmatch('/[A-Za-z0-9_./-]+',path) and path!='/' and str(PurePosixPath(path))==path and '..' not in path.split('/')
def context(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_:.,-]+',value),'BOOTSTRAP_CONTEXT');return value
def digest(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value)
def parse(raw):
    require(type(raw) is bytes and len(raw)<=MAX_JSON,'BOOTSTRAP_JSON_SIZE')
    def pairs(rows):
        result={}
        for k,v in rows:
            require(k not in result,'BOOTSTRAP_DUPLICATE_KEY');result[k]=v
        return result
    def nonfinite(value):raise Stop('BOOTSTRAP_NONFINITE')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=nonfinite)
def spec(value):
    require(type(value) is dict and set(value)=={'sha256','mode','gid','selinux'} and digest(value['sha256']) and
        type(value['mode']) is int and 0<=value['mode']<=0o777 and not value['mode']&0o022 and
        type(value['gid']) is int and value['gid']==0,'BOOTSTRAP_FILE_SPEC')
    context(value['selinux']);return value
def signature(row):
    return tuple(getattr(row,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

class Reader:
    def __init__(self,clock=time.monotonic):self.clock=clock
    @contextmanager
    def opened(self,path):
        require(sys.platform=='linux' and absolute(path),'BOOTSTRAP_PATH')
        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
        chain=[]
        try:
            fd=os.open('/',flags|os.O_DIRECTORY);chain.append((fd,None,'/'))
            parts=PurePosixPath(path).parts[1:]
            for index,part in enumerate(parts):
                row=os.fstat(fd)
                require(stat.S_ISDIR(row.st_mode) and row.st_uid==0 and not row.st_mode&0o022 and
                        set(os.listxattr(fd))<={'security.selinux'},'BOOTSTRAP_PARENT')
                child=os.open(part,flags|(os.O_DIRECTORY if index<len(parts)-1 else 0),dir_fd=fd)
                chain.append((child,fd,part));fd=child
            yield fd
            for current,parent,name in chain[1:]:
                a,b=os.fstat(current),os.stat(name,dir_fd=parent,follow_symlinks=False)
                require((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'BOOTSTRAP_PATH_CHANGED')
        finally:
            for fd,_,_ in reversed(chain):os.close(fd)
    def metadata(self,fd,wanted,limit):
        row=os.fstat(fd)
        require(stat.S_ISREG(row.st_mode) and row.st_nlink==1 and row.st_uid==row.st_gid==0 and
            stat.S_IMODE(row.st_mode)==wanted['mode'] and 0<row.st_size<=limit and
            set(os.listxattr(fd))=={'security.selinux'},'BOOTSTRAP_FILE')
        require(os.getxattr(fd,'security.selinux').rstrip(b'\0').decode('ascii')==wanted['selinux'],'BOOTSTRAP_LABEL')
        return signature(row)
    def read(self,path,wanted,deadline,limit):
        spec(wanted);remaining(deadline,self.clock)
        with self.opened(path) as fd:
            before=self.metadata(fd,wanted,limit);parts=[];total=0
            while True:
                remaining(deadline,self.clock)
                block=os.read(fd,65536)
                if not block:break
                total+=len(block);require(total<=limit,'BOOTSTRAP_SIZE');parts.append(block)
            require(before==self.metadata(fd,wanted,limit),'BOOTSTRAP_CHANGED')
        raw=b''.join(parts)
        require(hashlib.sha256(raw).hexdigest()==wanted['sha256'],'BOOTSTRAP_HASH')
        remaining(deadline,self.clock);return raw

def collect(path,pin,label,deadline,*,reader=None,clock=time.monotonic):
    require(absolute(path) and digest(pin),'BOOTSTRAP_EXTERNAL_PIN')
    reader=reader or Reader(clock)
    wanted={'sha256':pin,'mode':0o600,'gid':0,'selinux':context(label)}
    raw=reader.read(path,wanted,deadline,MAX_JSON);launch=parse(raw)
    require(type(launch) is dict and launch.get('schema')=='fds.harbor.address-launch.v1','BOOTSTRAP_SCHEMA')
    source=launch.get('source')
    require(type(source) is dict and set(source)=={'revision','directory','files'} and
        re.fullmatch('[0-9a-f]{40}',source['revision']) and absolute(source['directory']) and
        type(source['files']) is dict and set(source['files'])==MODULES,'BOOTSTRAP_SOURCE')
    code={}
    for name in sorted(MODULES):
        filename=source['directory']+'/'+name+'.py'
        payload=reader.read(filename,spec(source['files'][name]),deadline,MAX_SOURCE)
        code[name]=compile(payload.decode('utf-8'),filename,'exec',dont_inherit=True)
    require(reader.read(path,wanted,deadline,MAX_JSON)==raw,'BOOTSTRAP_LAUNCH_CHANGED')
    remaining(deadline,clock);return launch,code

class VerifiedImporter(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def __init__(self,code):
        require(set(code)==MODULES,'BOOTSTRAP_MODULE_SET');self.code=dict(code)
    def find_spec(self,fullname,path=None,target=None):
        if fullname.startswith(PREFIXES):
            require(fullname in self.code and path is None and target is None,'BOOTSTRAP_IMPORT')
            return importlib.util.spec_from_loader(fullname,self,origin=self.code[fullname].co_filename)
        return None
    def create_module(self,spec):return None
    def exec_module(self,module):
        module.__file__=self.code[module.__name__].co_filename
        exec(self.code[module.__name__],module.__dict__)
    def __enter__(self):
        require(not any(n.startswith(PREFIXES) for n in sys.modules),'BOOTSTRAP_PREIMPORTED')
        require(not any(isinstance(v,VerifiedImporter) for v in sys.meta_path),'BOOTSTRAP_NESTED')
        sys.meta_path.insert(0,self);return self
    def __exit__(self,*args):
        sys.meta_path.remove(self)
        for name in tuple(sys.modules):
            if name.startswith(PREFIXES):del sys.modules[name]

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('operation',choices=('verify','preflight','ready','unit','apply','inspect'))
    parser.add_argument('--launch',required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--context',required=True)
    parser.add_argument('--timeout',type=float,required=True)
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args(argv)
    try:
        require(sys.platform=='linux' and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and
                sys.dont_write_bytecode and not sys.flags.optimize,'BOOTSTRAP_RUNTIME')
        require(math.isfinite(args.timeout) and 0<args.timeout<=86400,'BOOTSTRAP_TIMEOUT')
        require(args.execute == (args.operation=='apply'),'BOOTSTRAP_EXECUTE')
        deadline=time.monotonic()+args.timeout
        launch,code=collect(args.launch,args.sha256,args.context,deadline)
        with VerifiedImporter(code):
            module=importlib.import_module('harbor_address_launch')
            rc,result=module.operate(launch,operation=args.operation,launch_path=args.launch,launch_sha256=args.sha256,
                launch_context=args.context,deadline=deadline,execute=args.execute,
                bootstrap_path=os.path.abspath(__file__),interpreter_path=os.path.realpath(sys.executable))
        # Unit is deterministic public configuration; all other output is a
        # fixed-schema sanitized summary. Private bytes are never returned.
        print(result if args.operation=='unit' else json.dumps(result,sort_keys=True))
        return rc
    except KeyboardInterrupt:
        print('{"stage":"STOP","reason":"INTERRUPTED","runtime_acceptance":false}');return 130
    except Exception:
        print('{"stage":"STOP","reason":"INPUT_OR_RUNTIME_FAILURE","runtime_acceptance":false}');return 2

if __name__=='__main__':raise SystemExit(main())
