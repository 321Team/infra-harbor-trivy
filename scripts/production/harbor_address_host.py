"""Read-only production guards, explicitly distinct from isolated-clone policy.

No observed value becomes a policy/permission. All expected values and package
pins come from separately reviewed inputs. No service or security modifications.
The caller must load the reviewed recovery modules from a trusted source path.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import PurePosixPath
import re
import socket
import stat
import time
from urllib.parse import quote
import uuid

from harbor_address_compose import _signature, parse, protected_path, remaining, require, run_process
from harbor_address_evidence import context_check
from harbor_address_package import load_package
from harbor_address_preservation import validate_profile
from harbor_address_sequence import fingerprint
from harbor_recovery_docker import UnixEngine, logger_tcp
from harbor_recovery_host import LinuxReadOnly, engine_profile, nft_fingerprint, PROPERTIES, properties, unit_check, metadata_spec, absolute

GUARD='fds-harbor-ac04-guard.service'
MANAGER='fds-harbor-recovery.service'
TOOLS={'systemctl','nft','ip','getenforce','compose'}


class ReadOnlyEngine(UnixEngine):
    def _validate_request(self, method, path, body):
        require(method=='GET' and body==b'' and (path in ('/containers/json?all=true','/info','/version') or
            re.fullmatch(r'/containers/[0-9a-f]{64}/json',path) or
            re.fullmatch(r'/images/[A-Za-z0-9_.:%-]+/json',path) or
            re.fullmatch(r'/(networks|volumes)/[A-Za-z0-9_.-]+',path)), 'PRODUCTION_READ_ONLY')
    def image(self, ref, deadline):
        require(type(ref) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}',ref),'IMAGE_REFERENCE')
        return self._json('/images/'+quote(ref,safe='')+'/json',deadline)
    def resource(self, kind, name, deadline):
        require(kind in ('networks','volumes') and type(name) is str and
                re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',name),'RESOURCE_REFERENCE')
        return self._json('/'+kind+'/'+name,deadline)


def resource_projection(kind, row):
    require(type(row) is dict,'RESOURCE_SCHEMA')
    # Endpoint membership changes during intentional single-container recreate.
    # Every resource configuration/identity field remains in the comparison.
    return {k:v for k,v in row.items() if not (kind=='networks' and k in ('Containers','Peers'))}


class ProductionReadOnly(LinuxReadOnly):
    def identity(self):
        value=super().identity()
        return {k:value[k] for k in ('hostname','product_uuid','boot')}
    def physical_interfaces(self):
        return sorted(n for n in os.listdir('/sys/class/net') if os.path.exists('/sys/class/net/'+n+'/device'))
    def command(self, tool, args, deadline):
        with protected_path(tool['path'],directory=False,exact_mode=tool['mode']) as fd:
            context_check(fd,tool['selinux'].encode())
            before=os.fstat(fd);hashed=hashlib.sha256();total=0
            require(before.st_mode & 0o111 and before.st_size <= 256*1024*1024,'HOST_EXECUTABLE')
            while True:
                remaining(deadline,self.clock)
                block=os.read(fd,65536)
                if not block:break
                total+=len(block);require(total<=256*1024*1024,'HOST_EXECUTABLE_SIZE');hashed.update(block)
            require(hashed.hexdigest()==tool['sha256'] and _signature(before)==_signature(os.fstat(fd)), 'HOST_TOOL_CHANGED')
            result=run_process([f'/proc/self/fd/{fd}',*args],b'',cwd='/',
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},pass_fds=(fd,),deadline=deadline,clock=self.clock)
            require(_signature(before)==_signature(os.fstat(fd)) and result.reason=='COMPLETED','HOST_COMMAND_UNKNOWN')
            return result.rc,result.stdout
    def source(self, path, spec, deadline):
        """Read-only hash of old user-parented sources, NEVER an executable/input.

        Every component is opened without symlinks. Parent owners may be users;
        final metadata/hash are exact. Protected package bytes are consumed by
        Compose instead; this check only detects drift in the original sources.
        """
        require(type(path) is str and path.startswith('/') and str(PurePosixPath(path))==path and
                '..' not in PurePosixPath(path).parts and len(PurePosixPath(path).parts)>2,'SOURCE_PATH')
        chain=[]
        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
        try:
            fd=os.open('/',flags|os.O_DIRECTORY);chain.append((fd,None,'/'))
            parts=PurePosixPath(path).parts[1:]
            for index,part in enumerate(parts):
                s=os.fstat(fd)
                require(stat.S_ISDIR(s.st_mode) and not s.st_mode & 0o022 and
                        set(os.listxattr(fd)) <= {'security.selinux'},'SOURCE_PARENT')
                child=os.open(part,flags|(os.O_DIRECTORY if index<len(parts)-1 else 0),dir_fd=fd)
                chain.append((child,fd,part));fd=child
            s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==spec['uid'] and s.st_gid==spec['gid'] and
                    stat.S_IMODE(s.st_mode)==spec['mode'] and set(os.listxattr(fd)) <= {'security.selinux'} and
                    s.st_size<=8*1024*1024,'SOURCE_METADATA')
            context_check(fd,spec['selinux'].encode())
            h=hashlib.sha256();size=0
            while True:
                remaining(deadline,self.clock)
                block=os.read(fd,65536)
                if not block:break
                size+=len(block);require(size<=8*1024*1024,'SOURCE_SIZE');h.update(block)
            require(h.hexdigest()==spec['sha256'] and size==s.st_size and _signature(s)==_signature(os.fstat(fd)), 'SOURCE_CHANGED')
            for current,parent,name in chain[1:]:
                a,b=os.fstat(current),os.stat(name,dir_fd=parent,follow_symlinks=False)
                require((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'SOURCE_PATH_CHANGED')
        finally:
            for fd,_,_ in reversed(chain):os.close(fd)
        remaining(deadline,self.clock)
    def volume_metadata(self, path, deadline):
        remaining(deadline,self.clock)
        with protected_path(path,directory=True) as fd:
            s=os.fstat(fd);attrs=sorted(os.listxattr(fd))
            label=os.getxattr(fd,'security.selinux').rstrip(b'\0').decode('ascii') if 'security.selinux' in attrs else None
            result=dict(uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode),directory=True,
                        symlink=False,xattrs=attrs,selinux=label)
        remaining(deadline,self.clock);return result


class ProductionHost:
    def __init__(self, policy, *, profile, package_path, package_sha256, package_context,
                 model_sha256, preservation_binding, engine, io=None, clock=time.monotonic):
        keys={'schema','identity','physical_interfaces','interfaces','routes_sha256','tools','pinned_files',
              'source_files','socket_spec','engine_profile','units','manager','nft_sha256','images','resources',
              'inputs_sha256','compose_version'}
        require(type(policy) is dict and set(policy)==keys and policy['schema']=='fds.harbor.production-address-host.v1','HOST_POLICY_SCHEMA')
        require(policy['identity']['hostname']=='harbor01' and
                set(policy['identity'])=={'hostname','product_uuid','boot'} and
                all(str(uuid.UUID(policy['identity'][k]))==policy['identity'][k] for k in ('product_uuid','boot')), 'HOST_IDENTITY')
        require(type(policy['physical_interfaces']) is list and len(set(policy['physical_interfaces']))==len(policy['physical_interfaces']) and
                policy['physical_interfaces'] and set(policy['interfaces'])==set(policy['physical_interfaces'])|{'lo'} and
                all(re.fullmatch('[A-Za-z0-9_.-]{1,15}',n) for n in policy['interfaces']), 'HOST_INTERFACES')
        require(set(policy['tools'])==TOOLS and set(policy['units'])=={'docker.service',GUARD} and
                policy['compose_version']=='5.6.0' and set(policy['resources'])=={'networks','volumes'},'HOST_POLICY_SCOPE')
        for tool in policy['tools'].values():
            require(type(tool) is dict and set(tool)=={'path','mode','selinux','sha256'} and
                    re.fullmatch('[0-9a-f]{64}',tool['sha256']) and type(tool['mode']) is int and
                    not tool['mode'] & 0o022 and tool['mode'] & 0o100,'HOST_TOOL_POLICY')
            require(absolute(tool['path']),'HOST_TOOL_PATH')
            metadata_spec({k:v for k,v in dict(tool,gid=0).items() if k!='path'},file=True)
        unit_sources=set()
        for wanted in policy['units'].values():
            require(set(wanted)==set(PROPERTIES.split(',')),'HOST_UNIT_POLICY')
            unit_sources.add(wanted['FragmentPath']);unit_sources.update(wanted['DropInPaths'].split())
        require(unit_sources <= set(policy['pinned_files']),'HOST_UNPINNED_UNIT')
        require(type(policy['source_files']) is dict and policy['source_files'] and
                type(policy['pinned_files']) is dict and policy['pinned_files'],'HOST_SOURCE_POLICY')
        metadata_spec(policy['socket_spec'],socket=True)
        for path,spec in policy['pinned_files'].items():
            require(absolute(path),'HOST_PIN_PATH');metadata_spec(spec,file=True)
        for spec in policy['source_files'].values():
            require(type(spec) is dict and set(spec)=={'uid','gid','mode','selinux','sha256'} and
                    spec['uid']==0 and spec['gid']==0 and type(spec['mode']) is int and
                    not spec['mode'] & 0o022 and re.fullmatch('[0-9a-f]{64}',spec['sha256']), 'HOST_SOURCE_POLICY')
            metadata_spec({k:v for k,v in spec.items() if k!='uid'},file=True)
        for value in [policy['routes_sha256'],policy['nft_sha256'],policy['inputs_sha256'],model_sha256,preservation_binding,
                      *policy['interfaces'].values(), *policy['resources']['networks'].values(),*policy['resources']['volumes'].values()]:
            require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'HOST_DIGEST')
        require(type(policy['images']) is dict and policy['images'] and
                all(re.fullmatch('sha256:[0-9a-f]{64}',v) for v in policy['images'].values()),'HOST_IMAGES')
        self.policy,self.profile=deepcopy(policy),validate_profile(profile)
        require({k:policy['engine_profile']['version'][k] for k in ('Version','GitCommit','ApiVersion')}==self.profile['engine'] and
                policy['engine_profile']['info']['SecurityOptions']==self.profile['security_options'] and
                set(self.profile['volume_inventory']) <= set(policy['resources']['volumes']),'HOST_PROFILE_POLICY')
        self.binding=fingerprint(policy)
        require(self.profile['host_binding_sha256']==self.binding,'HOST_PROFILE_BINDING')
        require(engine.path=='/run/docker.sock' and engine.prefix=='/v1.56' and engine.peer_uid==0,'HOST_ENGINE_TRANSPORT')
        self.engine,self.io,self.clock=engine,io or ProductionReadOnly(clock=clock),clock
        self.package_path,self.package_sha,self.package_context=package_path,package_sha256,package_context
        self.model_sha,self.preservation_binding=model_sha256,preservation_binding

    def _run(self, tool, args, deadline, allowed=(0,)):
        rc,raw=self.io.command(self.policy['tools'][tool],args,deadline)
        require(rc in allowed,'HOST_COMMAND_FAILED');return raw
    def _guards(self, deadline):
        p=self.policy
        require(self.io.identity()==p['identity'],'HOST_GENERATION_CHANGED')
        require(self.io.physical_interfaces()==sorted(p['physical_interfaces']),'HOST_NIC_CHANGED')
        require(self._run('getenforce',[],deadline).strip()==b'Enforcing','HOST_SELINUX_CHANGED')
        require(self._run('compose',['version','--short'],deadline).strip()==b'5.6.0','HOST_COMPOSE_VERSION')
        socket_pin=self.io.pinned('/run/docker.sock',p['socket_spec'],'socket',deadline)
        for path,spec in p['pinned_files'].items():self.io.pinned(path,spec,'file',deadline)
        for path,spec in p['source_files'].items():self.io.source(path,spec,deadline)
        for name,wanted in p['units'].items():
            row=properties(self._run('systemctl',['show',name,'--no-pager','--property='+PROPERTIES],deadline))
            unit_check(row,{'fragment':wanted['FragmentPath'],'dropins':wanted['DropInPaths'].split()},docker=name=='docker.service')
            require(row==wanted,'HOST_UNIT_CHANGED')
        raw=self._run('systemctl',['show',MANAGER,'--no-pager','--property=LoadState,ActiveState,SubState,MainPID,UnitFileState'],deadline,allowed=(0,1))
        manager={}
        for line in raw.decode().splitlines():
            k,v=line.split('=',1);require(k not in manager,'HOST_MANAGER_DUPLICATE');manager[k]=v
        require(manager==p['manager'] and manager.get('LoadState')=='not-found' and
                manager.get('ActiveState')=='inactive' and manager.get('MainPID')=='0','HOST_MANAGER_CHANGED')
        require(nft_fingerprint(self._run('nft',['-j','list','table','inet','p1_hbr_ac04'],deadline))==p['nft_sha256'],'HOST_NFT_CHANGED')
        for name,digest in p['interfaces'].items():
            rows=parse(self._run('ip',['-j','address','show','dev',name],deadline))
            require(fingerprint(rows)==digest,'HOST_ADDRESS_CHANGED')
        require(fingerprint(parse(self._run('ip',['-j','route','show','table','all'],deadline)))==p['routes_sha256'],'HOST_ROUTE_CHANGED')
        observed=engine_profile(self.engine.profile(deadline))
        require(observed==p['engine_profile'],'HOST_ENGINE_CHANGED')
        for ref,cid in p['images'].items(): require(self.engine.image(ref,deadline).get('Id')==cid,'HOST_IMAGE_CHANGED')
        inventories={}
        for kind,pins in p['resources'].items():
            for name,digest in pins.items():
                row=self.engine.resource(kind,name,deadline)
                require(row.get('Name')==name and fingerprint(resource_projection(kind,row))==digest,'HOST_RESOURCE_CHANGED')
                if kind=='volumes': inventories[name]=dict(name=row['Name'],driver=row['Driver'],mountpoint=row['Mountpoint'],
                                                       scope=row['Scope'],has_options=bool(row.get('Options')))
        current_inventory={name:inventories[name] for name in self.profile['volume_inventory']}
        metadata={path:self.io.volume_metadata(path,deadline) for path in self.profile['source_metadata']}
        require(metadata==self.profile['source_metadata'] and current_inventory==self.profile['volume_inventory'],'HOST_VOLUME_CHANGED')
        return socket_pin,observed,metadata,current_inventory

    def __call__(self, deadline):
        start=self.clock();remaining(deadline,self.clock)
        before=load_package(self.package_path,manifest_sha256=self.package_sha,context=self.package_context,deadline=deadline,clock=self.clock)
        require(before['host-policy.json']==self.policy and before['profile.json']==self.profile and
                fingerprint(before['model.json'])==self.model_sha and
                fingerprint(before['preservation.json'])==self.preservation_binding and
                before['plan.json']['binding_sha256']==self.binding and
                before['plan.json']['inputs_sha256']==self.policy['inputs_sha256'],'HOST_PACKAGE_BINDING')
        model=before['model.json']
        require(set(self.policy['images'])=={v['image'] for v in model['services'].values()} and
                set(self.policy['resources']['networks'])=={v['name'] for v in model.get('networks',{}).values()} and
                {v['name'] for v in model.get('volumes',{}).values()} <= set(self.policy['resources']['volumes']), 'HOST_MODEL_RESOURCES')
        first=self._guards(deadline)
        tcp=logger_tcp(deadline,self.clock)
        last=self._guards(deadline)
        require(first==last and tcp,'HOST_OBSERVATION_CHANGED')
        after=load_package(self.package_path,manifest_sha256=self.package_sha,context=self.package_context,deadline=deadline,clock=self.clock)
        require(before==after and self.io.identity()==self.policy['identity'],'HOST_PACKAGE_CHANGED')
        require(self.clock()<deadline,'HOST_DEADLINE')
        return dict(binding_sha256=self.binding,inputs_sha256=self.policy['inputs_sha256'],at=start,logger_ipv4=True,
                    model_sha256=self.model_sha,preservation_binding=self.preservation_binding,
                    mount_inputs=dict(current_metadata=last[2],current_inventory=last[3],host_binding_sha256=self.binding,
                      authorization_sha256=self.profile['authorization_sha256'],
                      engine={k:last[1]['version'][k] for k in ('Version','GitCommit','ApiVersion')},
                      compose_version=self.policy['compose_version'],security_options=last[1]['info']['SecurityOptions'],enforcing='Enforcing'))
