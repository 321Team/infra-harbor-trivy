"""Synthetic local fixtures only. No shell, network, LinuxHost construction, or real credential."""
import base64
import copy
import datetime as dt
import hashlib
import json
import unittest
from rotation_contract import *
from rotation_adapter import Adapter,node_step,pod_step

NOW=1792038600.0
C={'username':NEW_USER,'password':'SYNTHETIC_TEST_SECRET_NEVER_RUNTIME_123'}
def iso(epoch):return dt.datetime.fromtimestamp(epoch,dt.timezone.utc).isoformat()
def plan():
    return {'version':1,'state':'BOUND','invocation':'1'*32,'not_before':iso(NOW-1),'not_after':iso(NOW+4499),
            'mutation_until':iso(NOW+3599),'host_boot_ids':{h:'12345678-1234-1234-1234-123456789abc' for h in ('k8s-control01',*NODES)},
            'new_robot':{'id':42,'name':NEW_USER,'level':'system','project':'fds','resource':'repository','action':'pull','duration_days':30,'disabled':False,'expires_at':iso(NOW+2592000)},
            'tool_pins':{h:{t:{'sha256':'a'*64,'source':TOOLS[t],'context':'system_u:object_r:bin_t:s0','provenance':'SYNTHETIC_FIXTURE_ONLY'} for t in (('kubectl',) if h=='k8s-control01' else ('nerdctl','crictl'))} for h in ('k8s-control01',*NODES)},
            'budgets':{'read':10,'write':30,'node':300,'pod':180,'ready':60,'cleanup':60},
            'authorization_reference':'SYNTHETIC_TEST_ONLY','scope_reference':'SYNTHETIC_TEST_ONLY'}
def old_config(keys=(REGISTRY,)):
    return encoded({'auths':{k:auth_entry({'username':OLD_USER,'password':'SYNTHETIC_OLD'}) for k in keys}})
def secret(ns):
    return {'apiVersion':'v1','kind':'Secret','metadata':{'name':SECRET_NAME,'namespace':ns,'uid':SCOPE[ns]['secret_uid'],'resourceVersion':'1','labels':{'preserve':'yes'}},
            'type':'kubernetes.io/dockerconfigjson','data':{'.dockerconfigjson':base64.b64encode(old_config()).decode()}}
def ready_pod(inv,ns,node,uid='fixture-pod-uid'):
    p=pod_manifest(inv,ns,node);p['metadata']['uid']=uid
    p['status']={'conditions':[{'type':'Ready','status':'True'}],'containerStatuses':[{'name':'p1-hbr-verify','ready':True,'state':{'running':{}},'imageID':IMAGE}]}
    return p

class FakeHost:
    def __init__(self,name='k8s-control01',mode='normal'):
        self.name=name;self.boot_id=plan()['host_boot_ids'][name];self.mode=mode;self.tick=0;self.claims={};self.records={};self.private={};self.calls=[]
        self.secrets={ns:secret(ns) for ns in SCOPE};self.pods={};self.tags={};self.auth={};self.file=old_config(FILE_KEYS)
        self.filemeta={'inode':10,'uid':0,'gid':0,'mode':384,'context':'unconfined_u:object_r:admin_home_t:s0'}
    def wall_time(self):return NOW+self.tick
    def monotonic(self):return self.tick
    def sleep(self,s):self.tick+=s
    def claim(self,key,value):
        if key in self.claims:raise Stop('OPERATION_ALREADY_CLAIMED')
        self.claims[key]=copy.deepcopy(value)
    def record(self,key,value):self.records[key]=copy.deepcopy(value)
    def receipt(self,key):
        if key not in self.records:raise Stop('PREREQUISITE_MISSING')
        return copy.deepcopy(self.records[key])
    def save_private(self,key,value):
        if key in self.private:raise Stop('PRIVATE_ALREADY_EXISTS')
        self.private[key]=copy.deepcopy(value)
    def load_private(self,key):return copy.deepcopy(self.private[key])
    def new_auth_dir(self,key):self.auth[key]=copy.deepcopy(C);return key
    def verify_auth_dir(self,path,c):
        if self.mode=='auth_dir_wrong':raise Stop('AUTH_ACCOUNT_MISMATCH')
        assert self.auth[path]==c
    def remove_auth_dir(self,path):
        if self.mode=='auth_dir_replaced':raise Stop('AUTH_DIR_REPLACED')
        del self.auth[path]
    def run(self,tool,args,stdin,env,timeout):
        # Do not record stdin or env values; they may contain the synthetic secret.
        self.calls.append((tool,tuple(args)));self.tick+=0.05
        if self.mode=='timeout':raise Stop('CHILD_TIMEOUT')
        if tool=='crictl':
            return 0,encoded({'status':{'repoDigests':[IMAGE if self.mode!='digest_wrong' else 'wrong']}})
        if 'login' in args:
            if self.mode=='login_fail':return 1,C['password'].encode()+b' unauthorized'
            assert stdin==C['password'].encode();return 0,b'login ok'
        if 'pull' in args:
            if self.mode=='pull_fail':return 1,C['password'].encode()+b' error'
            if env and env.get('DOCKER_CONFIG')=='/root/.docker':
                if self.mode=='persistent_pull_fail':return 1,b'error'
                d=decode_docker(self.file)
                for v in d['auths'].values():verify_entry(v,NEW_USER,C['password'])
            return 0,b'pulled'
        if 'inspect' in args:
            target=args[-1]
            if target==IMAGE:return 0,encoded([{'Id':'sha256:fixture-image-id'}])
            if target in self.tags:
                return 0,encoded([{'Id':self.tags[target]}])
            if self.mode=='inspect_error':return 1,b'connection refused'
            return 1,b'no such image'
        if 'tag' in args:
            self.tags[args[-1]]='sha256:fixture-image-id'
            if self.mode=='tag_response_lost':raise Stop('CHILD_TIMEOUT')
            return 0,b''
        if 'push' in args:
            if self.mode=='push_success':return 0,b'uploaded'
            if self.mode=='push_ambiguous':return 1,b'denied: requested access; TLS error '+C['password'].encode()
            if self.mode=='tag_replaced':self.tags[args[-1]]='sha256:other-object'
            return 1,b'denied: requested access'
        if 'rm' in args:
            del self.tags[args[-1]];return 0,b''
        raise AssertionError((tool,args))
    def kube(self,method,path,body,timeout,allow_absent=False):
        self.calls.append((method,path));self.tick+=0.05
        p=path.split('/');ns=p[4];kind=p[5];name=p[6] if len(p)>6 else None
        if method=='GET' and kind=='serviceaccounts':
            d={'kind':'ServiceAccount','metadata':{'name':SCOPE[ns]['sa'],'namespace':ns,'uid':SCOPE[ns]['sa_uid']}}
            if self.mode=='sa_replaced':d['metadata']['uid']='other'
            return d
        if kind=='secrets':
            if method=='GET':return copy.deepcopy(self.secrets[ns])
            assert method=='PATCH'
            if self.mode=='secret_conflict':raise Stop('KUBERNETES_RESPONSE_UNCERTAIN')
            current=self.secrets[ns]
            assert body[0]['value']==current['metadata']['uid'] and body[1]['value']==current['metadata']['resourceVersion']
            current['data']['.dockerconfigjson']=body[2]['value'];current['metadata']['resourceVersion']=str(int(current['metadata']['resourceVersion'])+1)
            if self.mode=='secret_response_lost':raise Stop('KUBERNETES_RESPONSE_UNCERTAIN')
            if self.mode=='secret_metadata_changed':current['metadata']['labels']['unexpected']='yes'
            return copy.deepcopy(current)
        if method=='POST':
            inv=body['metadata']['labels']['harbor-rotation'];node=body['spec']['nodeName'];name=body['metadata']['name']
            d=ready_pod(inv,ns,node);self.pods[(ns,name)]=d
            if self.mode in ('pod_response_lost','pod_late_response'):
                if self.mode=='pod_late_response':del self.pods[(ns,name)]
                raise Stop('KUBERNETES_RESPONSE_UNCERTAIN')
            return copy.deepcopy(d)
        if method=='GET':
            d=copy.deepcopy(self.pods.get((ns,name)))
            if d is not None:
                if self.mode=='pod_replaced':d['metadata']['uid']='other-pod'
                if self.mode=='pod_wrong_image':d['status']['containerStatuses'][0]['imageID']=IMAGE[:-1]+'0'
                if self.mode=='pod_not_ready':d['status']['conditions'][0]['status']='False'
                if self.mode=='pod_spec_mutated':d['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation']=True
            return d
        if method=='DELETE':
            current=self.pods[(ns,name)];assert body['preconditions']['uid']==current['metadata']['uid']
            if self.mode=='delete_failure':raise Stop('KUBERNETES_RESPONSE_UNCERTAIN')
            del self.pods[(ns,name)];return {'kind':'Status','status':'Success'}
        raise AssertionError((method,path))
    def registry_manifest(self,c,timeout):
        self.calls.append(('registry','manifest'))
        if self.mode=='manifest_error':raise Stop('REGISTRY_GET_FAILED')
    def read_worker_file(self):return self.file,copy.deepcopy(self.filemeta)
    def replace_worker_file(self,expected,metadata,new):
        if self.mode=='file_conflict':raise Stop('WORKER_FILE_CHANGED')
        assert self.file==expected and self.filemeta==metadata
        self.file=new;self.filemeta['inode']+=1

def good_receipts(h,p):
    digest=hashlib.sha256(encoded(p)).hexdigest()
    def put(key,host,**extra):h.records[key]={'status':'PASS','operation':key,'observed_at_epoch':NOW,'invocation':p['invocation'],'plan_sha256':digest,'robot_id':42,'host':host,**extra}
    for n in NODES:put(node_step(n),n,node=n,cleanup_complete=True)
    for ns in SCOPE:
        for n in SCOPE[ns]['nodes']:put(pod_step(p['invocation'],ns,n),'k8s-control01',node=n,namespace=ns,cleanup_complete=True)

def patched_host(mode='normal'):
    h=FakeHost();p=plan();good_receipts(h,p);a=Adapter(p,h)
    for ns in SCOPE:a.patch_secret(ns,C)
    h.mode=mode;return h,p,a

class Contracts(unittest.TestCase):
    def reject(self,fn,code=None):
        with self.assertRaises(Stop) as caught:fn()
        if code:self.assertEqual(caught.exception.code,code)
    def test_plan_valid_fixture(self):self.assertEqual(validate_plan(plan(),NOW)['state'],'BOUND')
    def test_plan_draft_rejected(self):
        p=plan();p['state']='DRAFT';self.reject(lambda:validate_plan(p,NOW),'PLAN_NOT_BOUND')
    def test_budget_bool_rejected(self):
        p=plan();p['budgets']['read']=True;self.reject(lambda:validate_plan(p,NOW),'BUDGET_INVALID')
    def test_window_expired(self):self.reject(lambda:validate_plan(plan(),NOW+5000),'WINDOW_INVALID')
    def test_cleanup_time_after_mutation_allowed(self):validate_plan(plan(),NOW+4000)
    def test_cleanup_reserve_required(self):
        p=plan();p['budgets']['pod']=60;self.reject(lambda:validate_plan(p,NOW),'CLEANUP_BUDGET_REQUIRED')
    def test_old_robot_cannot_be_new(self):
        p=plan();p['new_robot']['id']=2;self.reject(lambda:validate_plan(p,NOW),'ROBOT_SCOPE')
    def test_push_permission_rejected(self):
        p=plan();p['new_robot']['action']='push';self.reject(lambda:validate_plan(p,NOW),'ROBOT_SCOPE')
    def test_duplicate_json_rejected(self):self.reject(lambda:parse_json('{"x":1,"x":2}'),'DUPLICATE_JSON_KEY')
    def test_credential_controls_rejected(self):
        for char in ('\n','\r','\0'):
            self.reject(lambda:credential(encoded({**C,'password':'x'+char})),'CREDENTIAL_FORMAT')
    def test_auth_dual_values_conflict(self):
        entry=auth_entry(C);entry['password']='another';self.reject(lambda:verify_entry(entry,NEW_USER),'AUTH_VALUES_CONFLICT')
    def test_credential_helper_rejected(self):self.reject(lambda:decode_docker(encoded({'auths':{},'credsStore':'helper'})),'DOCKER_CONFIG_SCOPE')
    def test_only_two_file_registry_entries(self):
        raw=transform_docker(old_config(FILE_KEYS),FILE_KEYS,C);d=decode_docker(raw)
        self.assertEqual(set(d['auths']),set(FILE_KEYS))
        for e in d['auths'].values():verify_entry(e,NEW_USER,C['password'])
    def test_extra_registry_preserved_by_rejection(self):self.reject(lambda:transform_docker(old_config((*FILE_KEYS,'other')),FILE_KEYS,C),'REGISTRY_SCOPE')
    def test_secret_uid_replaced(self):
        s=secret('fds-app');s['metadata']['uid']='other';self.reject(lambda:secret_data(s,'fds-app',OLD_USER),'SECRET_IDENTITY')
    def test_secret_patch_has_uid_rv_tests(self):
        s=secret('fds-app');ops=secret_patch(s,'fds-app',old_config())
        self.assertEqual([x['path'] for x in ops],['/metadata/uid','/metadata/resourceVersion','/data/.dockerconfigjson'])
    def test_mon_cross_namespace_sa_rejected(self):
        self.reject(lambda:validate_sa({'kind':'ServiceAccount','metadata':{'namespace':'monitoring-node','name':'prometheus-sa','uid':SCOPE['monitoring-api']['sa_uid']}},'monitoring-node'),'SA_IDENTITY')
    def test_pod_only_five_pairs(self):
        self.assertEqual(sum(len(s['nodes']) for s in SCOPE.values()),5)
        self.reject(lambda:pod_manifest('1'*32,'monitoring-api','k8s-worker01'),'POD_SCOPE')
    def test_each_pod_nonce_unique(self):
        values={pod_nonce('1'*32,ns,n) for ns in SCOPE for n in SCOPE[ns]['nodes']};self.assertEqual(len(values),5)
    def test_new_invocation_new_deny_tag(self):self.assertNotEqual(deny_tag('1'*32,NODES[0]),deny_tag('2'*32,NODES[0]))
    def test_pod_replacement_denies_cleanup_binding(self):self.reject(lambda:owned_pod(ready_pod('1'*32,'fds-app',NODES[0]),'1'*32,'fds-app',NODES[0],'other'),'POD_REPLACED')
    def test_tool_source_changed(self):self.reject(lambda:tool_bytes(b'\x7fELFbad',{'sha256':'a'*64}),'TOOL_SOURCE_PIN_MISMATCH')
    def test_tool_detached_copy_matches_expected(self):
        raw=b'\x7fELFfixture';self.assertEqual(tool_bytes(raw,{'sha256':hashlib.sha256(raw).hexdigest()}),raw)
    def test_script_cannot_replace_elf(self):
        raw=b'#!/bin/sh';self.reject(lambda:tool_bytes(raw,{'sha256':hashlib.sha256(raw).hexdigest()}),'TOOL_SOURCE_PIN_MISMATCH')

class Operations(unittest.TestCase):
    reject=Contracts.reject
    # unittest inheritance also exercises pure contracts in the integrated import context.
    def test_worker_normal_cleanup(self):
        h=FakeHost(NODES[0]);Adapter(plan(),h).worker_test(C)
        self.assertEqual(h.records[node_step(NODES[0])]['status'],'PASS');self.assertFalse(h.tags);self.assertFalse(h.auth)
    def test_worker_failures_do_not_leak(self):
        for mode in ('login_fail','pull_fail','digest_wrong','push_success','push_ambiguous','auth_dir_wrong'):
            with self.subTest(mode=mode):
                h=FakeHost(NODES[0],mode);self.reject(lambda:Adapter(plan(),h).worker_test(C))
                self.assertNotIn(C['password'],json.dumps(h.records));self.assertFalse(h.auth)
    def test_inspect_failure_not_absence(self):
        h=FakeHost(NODES[0],'inspect_error');self.reject(lambda:Adapter(plan(),h).worker_test(C),'DENY_TAG_NOT_ABSENT')
        self.assertFalse(any('login' in c[1] for c in h.calls))
    def test_tag_lost_response_owned_cleanup(self):
        h=FakeHost(NODES[0],'tag_response_lost');self.reject(lambda:Adapter(plan(),h).worker_test(C),'CHILD_TIMEOUT')
        self.assertFalse(h.tags);self.assertFalse(any('push' in c[1] for c in h.calls))
    def test_replaced_tag_preserved(self):
        h=FakeHost(NODES[0],'tag_replaced');self.reject(lambda:Adapter(plan(),h).worker_test(C),'WORKER_CLEANUP_INCOMPLETE')
        self.assertTrue(h.tags);self.assertFalse(any('rm' in c[1] for c in h.calls))
    def test_node_duplicate_claim_no_retry(self):
        h=FakeHost(NODES[0]);a=Adapter(plan(),h);a.worker_test(C);count=len(h.calls)
        self.reject(lambda:a.worker_test(C),'OPERATION_ALREADY_CLAIMED');self.assertEqual(len(h.calls),count)
    def test_no_secret_patch_without_worker_receipts(self):
        h=FakeHost();self.reject(lambda:Adapter(plan(),h).patch_secret('fds-app',C),'PREREQUISITE_MISSING');self.assertFalse(h.calls)
    def test_receipt_wrong_host_rejected(self):
        h=FakeHost();p=plan();good_receipts(h,p);h.records[node_step(NODES[0])]['host']=NODES[1]
        self.reject(lambda:Adapter(p,h).patch_secret('fds-app',C),'PREREQUISITE_MISSING')
    def test_secret_three_updates_preserve_metadata(self):
        h,p,a=patched_host()
        for ns in SCOPE:
            secret_data(h.secrets[ns],ns,NEW_USER,C);self.assertEqual(h.secrets[ns]['metadata']['labels'],{'preserve':'yes'})
        self.assertNotIn(C['password'],json.dumps(h.records))
    def test_secret_conflict_stops_once(self):
        h=FakeHost(mode='secret_conflict');p=plan();good_receipts(h,p);a=Adapter(p,h)
        self.reject(lambda:a.patch_secret('fds-app',C));self.assertEqual(sum(x[0]=='PATCH' for x in h.calls),1)
        secret_data(h.secrets['fds-app'],'fds-app',OLD_USER)
    def test_secret_response_lost_partial_state_preserved(self):
        h=FakeHost(mode='secret_response_lost');p=plan();good_receipts(h,p);a=Adapter(p,h)
        self.reject(lambda:a.patch_secret('fds-app',C));secret_data(h.secrets['fds-app'],'fds-app',NEW_USER,C)
        self.assertIn('secret-fds-app-backup',h.private);self.assertNotIn('secret-fds-app-after',h.private)
        self.assertEqual(sum(x[0]=='PATCH' for x in h.calls),1)
    def test_secret_metadata_mutation_stops(self):
        h=FakeHost(mode='secret_metadata_changed');p=plan();good_receipts(h,p)
        self.reject(lambda:Adapter(p,h).patch_secret('fds-app',C),'SECRET_METADATA_CHANGED')
    def test_all_five_pods_ready_cleanup(self):
        h,p,a=patched_host()
        for ns in SCOPE:
            for n in SCOPE[ns]['nodes']:a.test_pod(ns,n,C)
        self.assertFalse(h.pods);self.assertEqual(sum(x[0]=='POST' for x in h.calls),5);self.assertEqual(sum(x[0]=='DELETE' for x in h.calls),5)
    def test_mon_sa_replaced_before_create(self):
        h,p,a=patched_host('sa_replaced');self.reject(lambda:a.test_pod('monitoring-api',NODES[2],C),'SA_IDENTITY')
        self.assertFalse(any(x[0]=='POST' for x in h.calls))
    def test_manifest_auth_failure_before_create(self):
        h,p,a=patched_host('manifest_error');self.reject(lambda:a.test_pod('fds-app',NODES[0],C),'REGISTRY_GET_FAILED')
        self.assertFalse(any(x[0]=='POST' for x in h.calls))
    def test_lost_create_response_owned_cleanup_no_retry(self):
        h,p,a=patched_host('pod_response_lost');self.reject(lambda:a.test_pod('fds-app',NODES[0],C))
        self.assertFalse(h.pods);self.assertEqual(sum(x[0]=='POST' for x in h.calls),1);self.assertEqual(sum(x[0]=='DELETE' for x in h.calls),1)
    def test_late_create_unknown_not_reported_clean(self):
        h,p,a=patched_host('pod_late_response');self.reject(lambda:a.test_pod('fds-app',NODES[0],C))
        self.assertFalse(h.records[pod_step(p['invocation'],'fds-app',NODES[0])]['cleanup_complete'])
    def test_replaced_pod_not_deleted(self):
        h,p,a=patched_host('pod_replaced');self.reject(lambda:a.test_pod('fds-app',NODES[0],C),'POD_REPLACED')
        self.assertTrue(h.pods);self.assertFalse(any(x[0]=='DELETE' for x in h.calls))
    def test_pod_wrong_digest_cleaned_but_not_pass(self):
        h,p,a=patched_host('pod_wrong_image');self.reject(lambda:a.test_pod('fds-app',NODES[0],C),'POD_DIGEST_MISMATCH');self.assertFalse(h.pods)
    def test_pod_security_change_preserved(self):
        h,p,a=patched_host('pod_spec_mutated');self.reject(lambda:a.test_pod('fds-app',NODES[0],C),'POD_CONTAINER_CHANGED');self.assertTrue(h.pods)
    def test_ready_timeout_no_recreate(self):
        h,p,a=patched_host('pod_not_ready');self.reject(lambda:a.test_pod('fds-app',NODES[0],C),'POD_READY_TIMEOUT')
        self.assertFalse(h.pods);self.assertEqual(sum(x[0]=='POST' for x in h.calls),1)
    def test_delete_failed_preserved(self):
        h,p,a=patched_host('delete_failure');self.reject(lambda:a.test_pod('fds-app',NODES[0],C),'POD_CLEANUP_INCOMPLETE');self.assertTrue(h.pods)
    def test_no_mutation_after_cutoff(self):
        h=FakeHost();p=plan();good_receipts(h,p);h.tick=4000;a=Adapter(p,h)
        self.reject(lambda:a.patch_secret('fds-app',C),'DEADLINE_EXPIRED');self.assertFalse(any(x[0]=='PATCH' for x in h.calls))
    def test_worker_file_both_keys_and_actual_file_pull(self):
        h=FakeHost(NODES[0]);p=plan();good_receipts(h,p);Adapter(p,h).update_worker_file(C)
        for entry in decode_docker(h.file)['auths'].values():verify_entry(entry,NEW_USER,C['password'])
        self.assertEqual(h.records['worker01-file']['status'],'PASS')
    def test_worker_file_conflict_preserves_original(self):
        h=FakeHost(NODES[0],'file_conflict');p=plan();good_receipts(h,p);old=h.file
        self.reject(lambda:Adapter(p,h).update_worker_file(C),'WORKER_FILE_CHANGED');self.assertEqual(h.file,old)
    def test_persistent_pull_failure_preserves_new_and_old(self):
        h=FakeHost(NODES[0],'persistent_pull_fail');p=plan();good_receipts(h,p)
        self.reject(lambda:Adapter(p,h).update_worker_file(C),'PERSISTENT_AUTH_PULL_FAILED')
        self.assertIn('worker01-file-backup',h.private);self.assertIn('worker01-file-after',h.private)
    def test_secret_explicit_recovery_and_rv_preserved(self):
        h,p,a=patched_host();auth=self.recovery(h,'rollback-secret-fds-app');a.rollback_secret('fds-app',C,auth)
        secret_data(h.secrets['fds-app'],'fds-app',OLD_USER);self.assertEqual(h.secrets['fds-app']['metadata']['resourceVersion'],'3')
    def recovery(self,h,op):return {'invocation':plan()['invocation'],'reference':'SYNTHETIC_EXPLICIT_RECOVERY','old_robot_id':2,'disabled':False,'expires_at':iso(NOW+5000),'observed_at':iso(h.wall_time()),'allowed_operation':op}
    def test_expired_old_account_cannot_rollback(self):
        h,p,a=patched_host();auth=self.recovery(h,'rollback-secret-fds-app');auth['expires_at']=iso(NOW-1)
        self.reject(lambda:a.rollback_secret('fds-app',C,auth),'RECOVERY_NOT_CONFIRMED')
    def test_concurrent_secret_change_cannot_rollback(self):
        h,p,a=patched_host();h.secrets['fds-app']['metadata']['resourceVersion']='999'
        self.reject(lambda:a.rollback_secret('fds-app',C,self.recovery(h,'rollback-secret-fds-app')),'RECOVERY_STATE_CHANGED')
    def test_worker_file_explicit_recovery(self):
        h=FakeHost(NODES[0]);p=plan();good_receipts(h,p);a=Adapter(p,h);old=h.file;a.update_worker_file(C)
        a.rollback_worker_file(self.recovery(h,'rollback-worker01-file'));self.assertEqual(h.file,old)
    def test_wrong_recovery_scope_rejected(self):
        h,p,a=patched_host();self.reject(lambda:a.rollback_secret('fds-app',C,self.recovery(h,'rollback-secret-monitoring-api')),'RECOVERY_SCOPE')

if __name__=='__main__':unittest.main(verbosity=2)
