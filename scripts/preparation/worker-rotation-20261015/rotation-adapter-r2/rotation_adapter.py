"""One bounded operation per invocation. No Robot issuance, refresh or disposal."""
import base64
import hashlib
import time
from rotation_contract import *

def pod_step(inv,ns,node): return 'pod-'+ns+'-'+node
def node_step(node): return 'node-'+node

class Adapter:
    """Host methods are implemented by LinuxHost; tests use an in-memory fault host."""
    def __init__(self, plan, host):
        self.plan=validate_plan(plan,host.wall_time());self.h=host
        need(host.name in plan['host_boot_ids'] and host.boot_id==plan['host_boot_ids'][host.name],'HOST_BOOT_CHANGED')
        self.inv=plan['invocation'];self.pid=hashlib.sha256(encoded(plan)).hexdigest()
        self.context={'invocation':self.inv,'plan_sha256':self.pid,'robot_id':plan['new_robot']['id'],'host':host.name}
        self.deadline=host.monotonic()+timestamp(plan['not_after'])-host.wall_time()
        self.mutation_deadline=host.monotonic()+timestamp(plan['mutation_until'])-host.wall_time()

    def timeout(self, cap, cleanup=False):
        end=self.deadline if cleanup else min(self.deadline,self.mutation_deadline)
        remaining=end-self.h.monotonic();need(remaining>0,'DEADLINE_EXPIRED')
        return min(cap,remaining)

    def claim(self,key,cleanup=False):
        self.timeout(self.plan['budgets']['write'],cleanup);self.h.claim(key,self.context)

    def record(self,key,status,**fields):
        # No child output, request body, credential fingerprint, or exception text.
        need(set(fields)<={'uid','rv','code','namespace','node','cleanup_complete'},'PUBLIC_FIELDS')
        self.h.record(key,{**self.context,'operation':key,'observed_at_epoch':self.h.wall_time(),'status':status,**fields})

    def prerequisite(self,key):
        return receipt_binding(self.plan,key,self.h.receipt(key),self.h.wall_time())

    def call(self,tool,args,stdin=None,env=None,cleanup=False):
        return self.h.run(tool,args,stdin,env,self.timeout(self.plan['budgets']['node'] if tool in ('nerdctl','crictl') else self.plan['budgets']['read'],cleanup))

    def get(self,path,allow_absent=False,cleanup=False):
        return self.h.kube('GET',path,None,self.timeout(self.plan['budgets']['read'],cleanup),allow_absent)

    def mutate(self,method,path,body,cleanup=False):
        return self.h.kube(method,path,body,self.timeout(self.plan['budgets']['write'],cleanup),False)

    def control(self): need(self.h.name=='k8s-control01','CONTROL_HOST_REQUIRED')

    def worker_test(self,c):
        node=self.h.name;need(node in NODES,'WORKER_HOST_REQUIRED')
        key=node_step(node);self.claim(key)
        stop_at=self.h.monotonic()+self.timeout(self.plan['budgets']['node'])
        prior=self.deadline;self.deadline=min(prior,stop_at-self.plan['budgets']['cleanup'])
        tag=deny_tag(self.inv,node);auth=None;tagged=False;image_id=None;failure=None
        try:
            self.h.registry_manifest(c,self.timeout(self.plan['budgets']['read']))
            # No destructive cache removal: inspect collision with precise no-such-image classification.
            rc,out=self.call('nerdctl',['-n','k8s.io','image','inspect',tag])
            need(rc!=0 and b'no such image' in out.lower(),'DENY_TAG_NOT_ABSENT')
            auth=self.h.new_auth_dir(key)
            rc,_=self.call('nerdctl',['-n','k8s.io','login',REGISTRY,'--username',c['username'],'--password-stdin'],c['password'].encode(),{'DOCKER_CONFIG':auth})
            need(rc==0,'ROBOT_LOGIN_FAILED')
            # Check the emitted private config matches precisely the new identity, without exporting it.
            self.h.verify_auth_dir(auth,c)
            rc,_=self.call('nerdctl',['-n','k8s.io','--hosts-dir','/etc/containerd/certs.d','pull',IMAGE],env={'DOCKER_CONFIG':auth})
            need(rc==0,'AUTHENTICATED_PULL_FAILED')
            rc,out=self.call('crictl',['inspecti',IMAGE]);need(rc==0,'CRI_INSPECT_FAILED')
            need(IMAGE in parse_json(out).get('status',{}).get('repoDigests',[]),'CRI_DIGEST_MISMATCH')
            rc,out=self.call('nerdctl',['-n','k8s.io','image','inspect',IMAGE]);need(rc==0,'IMAGE_INSPECT_FAILED')
            rows=parse_json(out);need(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0].get('Id'),str),'IMAGE_ID_INVALID')
            image_id=rows[0]['Id']
            # A prior tag attempt can succeed with a lost response; mark ownership intent before sending.
            self.h.save_private(key+'-tag',{'tag':tag,'image_id':image_id,**self.context})
            tagged=True
            rc,_=self.call('nerdctl',['-n','k8s.io','tag',IMAGE,tag],env={'DOCKER_CONFIG':auth});need(rc==0,'TAG_RESULT_UNCERTAIN')
            rc,out=self.call('nerdctl',['-n','k8s.io','--hosts-dir','/etc/containerd/certs.d','push',tag],env={'DOCKER_CONFIG':auth})
            push_denied(rc,out)
        except Stop as exc: failure=exc
        except Exception: failure=Stop('WORKER_OPERATION_ERROR')
        except BaseException:
            failure=Stop('WORKER_INTERRUPTED')
            raise
        finally:
            self.deadline=min(prior,stop_at)
            clean=True
            try:
                if tagged:
                    rc,out=self.call('nerdctl',['-n','k8s.io','image','inspect',tag],cleanup=True)
                    if rc==0:
                        rows=parse_json(out);need(len(rows)==1 and rows[0].get('Id')==image_id,'DENY_TAG_REPLACED')
                        rc,_=self.call('nerdctl',['-n','k8s.io','image','rm',tag],cleanup=True);need(rc==0,'TAG_CLEANUP_UNCERTAIN')
                        rc,out=self.call('nerdctl',['-n','k8s.io','image','inspect',tag],cleanup=True)
                        need(rc!=0 and b'no such image' in out.lower(),'TAG_CLEANUP_UNCONFIRMED')
                    else:need(b'no such image' in out.lower(),'TAG_CLEANUP_READ_FAILED')
                if auth is not None:
                    self.timeout(self.plan['budgets']['cleanup'],cleanup=True);self.h.remove_auth_dir(auth)
            except Exception:clean=False
            if not clean and failure is None:failure=Stop('WORKER_CLEANUP_INCOMPLETE')
            self.record(key,'STOP' if failure else 'PASS',node=node,cleanup_complete=clean,**({'code':failure.code} if failure else {}))
            self.deadline=prior
        if failure:raise failure

    def patch_secret(self,ns,c):
        self.control();need(ns in SCOPE,'NAMESPACE_SCOPE')
        if ns=='fds-app':
            for n in NODES:self.prerequisite(node_step(n))
        elif ns=='monitoring-api':
            for n in NODES:self.prerequisite(pod_step(self.inv,'fds-app',n))
        else:self.prerequisite(pod_step(self.inv,'monitoring-api','k8s-worker03'))
        key='secret-'+ns;path='/api/v1/namespaces/'+ns+'/secrets/'+SECRET_NAME
        before=self.get(path);raw=secret_data(before,ns,OLD_USER)
        after_raw=transform_docker(raw,(REGISTRY,),c)
        self.h.save_private(key+'-backup',before)
        self.claim(key)
        try:
            self.mutate('PATCH',path,secret_patch(before,ns,after_raw))
            after=self.get(path);secret_data(after,ns,NEW_USER,c);compare_secret_metadata(before,after)
            self.h.save_private(key+'-after',after)
            self.record(key,'PASS',namespace=ns,uid=after['metadata']['uid'],rv=after['metadata']['resourceVersion'])
        except Exception as exc:
            code=exc.code if isinstance(exc,Stop) else 'SECRET_OPERATION_ERROR'
            self.record(key,'STOP',namespace=ns,code=code);raise Stop(code) from None

    def test_pod(self,ns,node,c):
        self.control();need(ns in SCOPE and node in SCOPE[ns]['nodes'],'POD_SCOPE')
        changed=self.prerequisite('secret-'+ns)
        sec=self.get('/api/v1/namespaces/'+ns+'/secrets/'+SECRET_NAME);secret_data(sec,ns,NEW_USER,c)
        need(sec['metadata']['resourceVersion']==changed['rv'],'SECRET_CHANGED_AFTER_PATCH')
        validate_sa(self.get('/api/v1/namespaces/'+ns+'/serviceaccounts/'+SCOPE[ns]['sa']),ns)
        # Independently bind the registry manifest; any schema/auth/HTTP mismatch stops before Pod create.
        self.h.registry_manifest(c,self.timeout(self.plan['budgets']['read']))
        inv=pod_nonce(self.inv,ns,node);key=pod_step(self.inv,ns,node)
        path='/api/v1/namespaces/'+ns+'/pods/'+pod_name(inv)
        need(self.get(path,True) is None,'POD_NAME_NOT_ABSENT')
        self.claim(key);uid=None;attempted=False;failure=None;clean=False
        stop_at=self.h.monotonic()+self.timeout(self.plan['budgets']['pod'])
        prior=self.deadline;self.deadline=min(prior,stop_at)
        try:
            attempted=True
            created=self.mutate('POST','/api/v1/namespaces/'+ns+'/pods',pod_manifest(inv,ns,node))
            uid=owned_pod(created,inv,ns,node)
            ready_end=min(self.deadline,self.h.monotonic()+self.plan['budgets']['ready'])
            while True:
                current=self.get(path);owned_pod(current,inv,ns,node,uid)
                try:ready_digest(current,inv,ns,node,uid);break
                except Stop as exc:
                    if exc.code!='POD_NOT_READY':raise
                need(self.h.monotonic()<ready_end,'POD_READY_TIMEOUT');self.h.sleep(min(1,ready_end-self.h.monotonic()))
            self.h.save_private(key+'-owned',{'uid':uid,'namespace':ns,'node':node,'pod_nonce':inv,**self.context})
        except Stop as exc:failure=exc
        except Exception:failure=Stop('POD_OPERATION_ERROR')
        except BaseException:
            failure=Stop('POD_INTERRUPTED')
            raise
        finally:
            self.deadline=min(prior,stop_at)
            try:
                if attempted:clean=self.cleanup_pod(path,inv,ns,node,uid)
            except Exception:clean=False
            if not clean and failure is None:failure=Stop('POD_CLEANUP_INCOMPLETE')
            self.record(key,'STOP' if failure else 'PASS',namespace=ns,node=node,cleanup_complete=clean,**({'code':failure.code} if failure else {}))
            self.deadline=prior
        if failure:raise failure

    def cleanup_pod(self,path,inv,ns,node,uid):
        current=self.get(path,True,cleanup=True)
        if current is None:
            # With no acknowledged UID a delayed create cannot be excluded.
            need(uid is not None,'CREATE_OUTCOME_UNKNOWN');return True
        found=owned_pod(current,inv,ns,node,uid)
        self.mutate('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':found}},cleanup=True)
        end=self.h.monotonic()+self.timeout(self.plan['budgets']['cleanup'],cleanup=True)
        while True:
            current=self.get(path,True,cleanup=True)
            if current is None:return True
            owned_pod(current,inv,ns,node,found)
            need(self.h.monotonic()<end,'POD_DELETE_TIMEOUT');self.h.sleep(min(1,end-self.h.monotonic()))

    def update_worker_file(self,c):
        need(self.h.name=='k8s-worker01','WORKER01_REQUIRED')
        self.prerequisite(pod_step(self.inv,'monitoring-node','k8s-worker01'))
        key='worker01-file'
        before,meta=self.h.read_worker_file();after=transform_docker(before,FILE_KEYS,c)
        self.h.save_private(key+'-backup',{'bytes':base64.b64encode(before).decode(),'metadata':meta})
        self.claim(key)
        prior=self.deadline;self.deadline=min(prior,self.h.monotonic()+self.timeout(self.plan['budgets']['node']))
        try:
            self.h.replace_worker_file(before,meta,after)
            raw,newmeta=self.h.read_worker_file();need(raw==after,'FILE_READBACK_MISMATCH')
            need(all(newmeta.get(k)==meta.get(k) for k in ('uid','gid','mode','context')),'FILE_PROTECTION_CHANGED')
            self.h.save_private(key+'-after',{'bytes':base64.b64encode(raw).decode(),'metadata':newmeta})
            # Existing persistent file is consumed directly; no temporary login replaces this proof.
            rc,_=self.call('nerdctl',['-n','k8s.io','--hosts-dir','/etc/containerd/certs.d','pull',IMAGE],env={'DOCKER_CONFIG':'/root/.docker'})
            need(rc==0,'PERSISTENT_AUTH_PULL_FAILED')
            rc,out=self.call('crictl',['inspecti',IMAGE]);need(rc==0 and IMAGE in parse_json(out).get('status',{}).get('repoDigests',[]),'PERSISTENT_DIGEST_MISMATCH')
            self.record(key,'PASS',node=self.h.name)
        except Exception as exc:
            code=exc.code if isinstance(exc,Stop) else 'FILE_OPERATION_ERROR'
            self.record(key,'STOP',node=self.h.name,code=code);raise Stop(code) from None
        finally:self.deadline=prior

    def recovery_gate(self,authorization):
        # Separate explicit recovery record, supplied only after failure assessment; never auto-generated.
        need(set(authorization)=={'invocation','reference','old_robot_id','disabled','expires_at','observed_at','allowed_operation'},'RECOVERY_FIELDS')
        need(authorization['invocation']==self.inv and authorization['old_robot_id']==2 and authorization['disabled'] is False and
             timestamp(authorization['expires_at'])>self.h.wall_time()+60 and
             0<=self.h.wall_time()-timestamp(authorization['observed_at'])<=self.plan['budgets']['read'] and
             isinstance(authorization['reference'],str) and len(authorization['reference'])>=8,'RECOVERY_NOT_CONFIRMED')

    def rollback_secret(self,ns,c,authorization):
        self.control();need(ns in SCOPE,'NAMESPACE_SCOPE');self.recovery_gate(authorization)
        need(authorization['allowed_operation']=='rollback-secret-'+ns,'RECOVERY_SCOPE')
        key='secret-'+ns;path='/api/v1/namespaces/'+ns+'/secrets/'+SECRET_NAME
        before=self.h.load_private(key+'-backup');secret_data(before,ns,OLD_USER)
        after=self.h.load_private(key+'-after');current=self.get(path,cleanup=True);secret_data(current,ns,NEW_USER,c)
        need(current==after,'RECOVERY_STATE_CHANGED')
        self.claim('rollback-'+key,cleanup=True)
        self.mutate('PATCH',path,secret_patch(current,ns,secret_data(before,ns,OLD_USER)),cleanup=True)
        restored=self.get(path,cleanup=True);secret_data(restored,ns,OLD_USER);compare_secret_metadata(current,restored)
        need(restored['data']==before['data'],'RECOVERY_READBACK_MISMATCH')
        self.record('rollback-'+key,'PASS',namespace=ns,uid=restored['metadata']['uid'],rv=restored['metadata']['resourceVersion'])

    def rollback_worker_file(self,authorization):
        need(self.h.name=='k8s-worker01','WORKER01_REQUIRED');self.recovery_gate(authorization)
        need(authorization['allowed_operation']=='rollback-worker01-file','RECOVERY_SCOPE')
        before=self.h.load_private('worker01-file-backup');after=self.h.load_private('worker01-file-after')
        current,meta=self.h.read_worker_file()
        need(current==base64.b64decode(after['bytes']) and meta==after['metadata'],'RECOVERY_STATE_CHANGED')
        self.claim('rollback-worker01-file',cleanup=True)
        self.h.replace_worker_file(current,meta,base64.b64decode(before['bytes']))
        restored,restored_meta=self.h.read_worker_file();need(restored==base64.b64decode(before['bytes']),'RECOVERY_READBACK_MISMATCH')
        need(all(restored_meta.get(k)==before['metadata'].get(k) for k in ('uid','gid','mode','context')),'FILE_PROTECTION_CHANGED')
        self.record('rollback-worker01-file','PASS',node=self.h.name)
