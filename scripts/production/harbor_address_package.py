"""Root-only exact-byte supply/consumption, not an input or approval generator.

The caller supplies private bytes and independently reviewed hashes/context.
Original user-owned Compose/env files are never opened, chmod'ed or overwritten.
Partial packages remain on disk and cannot be installed/loaded/resumed.
"""
import hashlib
import os
import re
import stat
import time

from harbor_address_compose import MAX_OUTPUT, _signature, parse, protected_path, remaining, require
from harbor_address_evidence import context_check, encode, write_all

FILES = {'plan.json','base.json','candidate.json','model.json','preservation.json','profile.json','host-policy.json'}


def _file(directory, name, context, *, create=False):
    flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags | (os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY),
                 0o600, dir_fd=directory)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and
                s.st_nlink==1 and set(os.listxattr(fd)) <= {'security.selinux'}, 'PACKAGE_METADATA')
        context_check(fd,context)
        return fd
    except BaseException:
        os.close(fd);raise


def seal_package(path, *, contents, hashes, context, deadline, clock=time.monotonic):
    """Explicit write action. No real inputs/default labels are provided here."""
    require(type(contents) is dict and type(hashes) is dict and set(contents)==set(hashes)==FILES, 'PACKAGE_FILES')
    for name, raw in contents.items():
        require(type(raw) is bytes and len(raw)<=MAX_OUTPUT and hashlib.sha256(raw).hexdigest()==hashes[name], 'PACKAGE_HASH')
        require(type(parse(raw)) is dict, 'PACKAGE_JSON')
    with protected_path(path,directory=True,exact_mode=0o700) as directory:
        context_check(directory,context)
        require(os.listdir(directory)==[], 'PACKAGE_EXISTING')
        def new(name,raw):
            remaining(deadline,clock)
            fd=_file(directory,name,context,create=True)
            try: write_all(fd,raw,deadline,clock)
            finally: os.close(fd)
            os.fsync(directory);remaining(deadline,clock)
        # Claim first, manifest last. Any partial state prevents reuse.
        new('supply.claim',encode({'schema':'fds.harbor.address-supply.v1','files':hashes}))
        for name in sorted(FILES): new(name,contents[name])
        manifest=encode({'schema':'fds.harbor.address-package.v1','files':hashes})
        new('manifest.json',manifest)
    # Independently read every delivered byte and final metadata, not just the
    # pre-write in-memory buffers. No stdout contains content or JSON values.
    digest=hashlib.sha256(manifest).hexdigest()
    load_package(path,manifest_sha256=digest,context=context,deadline=deadline,clock=clock)
    return {'manifest_sha256':digest,'files':dict(hashes),'runtime_apply':False}


def load_package(path, *, manifest_sha256, context, deadline, clock=time.monotonic):
    require(type(manifest_sha256) is str and re.fullmatch('[0-9a-f]{64}',manifest_sha256), 'PACKAGE_MANIFEST_PIN')
    with protected_path(path,directory=True,exact_mode=0o700) as directory:
        context_check(directory,context)
        names=FILES|{'manifest.json','supply.claim'}
        require(set(os.listdir(directory))==names, 'PACKAGE_INVENTORY')
        signatures={}
        def read(name):
            fd=_file(directory,name,context)
            try:
                before=os.fstat(fd);raw=bytearray()
                require(before.st_size<=MAX_OUTPUT, 'PACKAGE_SIZE')
                while True:
                    remaining(deadline,clock)
                    block=os.read(fd,65536)
                    if not block: break
                    raw.extend(block);require(len(raw)<=MAX_OUTPUT,'PACKAGE_SIZE')
                require(_signature(before)==_signature(os.fstat(fd)) and len(raw)==before.st_size,'PACKAGE_CHANGED')
                signatures[name]=_signature(before)
                return bytes(raw)
            finally: os.close(fd)
        raw=read('manifest.json')
        require(hashlib.sha256(raw).hexdigest()==manifest_sha256,'PACKAGE_MANIFEST_HASH')
        manifest=parse(raw)
        require(type(manifest) is dict and set(manifest)=={'schema','files'} and
                manifest['schema']=='fds.harbor.address-package.v1' and type(manifest['files']) is dict and
                set(manifest['files'])==FILES and all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v)
                                                    for v in manifest['files'].values()),'PACKAGE_MANIFEST')
        require(parse(read('supply.claim'))=={'schema':'fds.harbor.address-supply.v1','files':manifest['files']},'PACKAGE_CLAIM')
        values={}
        for name in sorted(FILES):
            data=read(name)
            require(hashlib.sha256(data).hexdigest()==manifest['files'][name],'PACKAGE_CONTENT_HASH')
            values[name]=parse(data);require(type(values[name]) is dict,'PACKAGE_JSON')
        require(set(os.listdir(directory))==names,'PACKAGE_INVENTORY')
        for name,signature in signatures.items():
            require(_signature(os.stat(name,dir_fd=directory,follow_symlinks=False))==signature,'PACKAGE_CHANGED')
        remaining(deadline,clock)
    return values
