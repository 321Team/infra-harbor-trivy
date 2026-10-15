"""Real function boundary tests; all OS privilege, network and child effects are mocked."""
import base64
import contextlib
import copy
import hashlib
import io
from pathlib import Path
import ssl
import tempfile
import stat
import types
import unittest
from unittest.mock import patch
import test_rotation as fx
import rotation_contract as rc
import linux_host as lh
import input_supply as supply

class Boundaries(unittest.TestCase):
    reject=fx.Contracts.reject
    def test_nonfinite_json_rejected(self):self.reject(lambda:rc.parse_json(b'{"x":NaN}'),'JSON_NONFINITE')
    def test_pod_root_security_mutated(self):
        inv='a'*32;p=fx.ready_pod(inv,'monitoring-node',rc.NODES[0]);p['spec']['securityContext']['runAsUser']=0
        self.reject(lambda:rc.owned_pod(p,inv,'monitoring-node',rc.NODES[0]),'POD_SPEC_CHANGED')
    def test_pod_extra_command_argument_rejected(self):
        inv='a'*32;p=fx.ready_pod(inv,'fds-app',rc.NODES[0]);p['spec']['containers'][0]['args']=['extra']
        self.reject(lambda:rc.owned_pod(p,inv,'fds-app',rc.NODES[0]),'POD_EXTRA_SCOPE')
    def test_pod_env_injection_rejected(self):
        inv='a'*32;p=fx.ready_pod(inv,'fds-app',rc.NODES[0]);p['spec']['containers'][0]['envFrom']=[{'secretRef':{'name':'unrelated'}}]
        self.reject(lambda:rc.owned_pod(p,inv,'fds-app',rc.NODES[0]),'POD_EXTRA_SCOPE')
    def test_node_auth_manifest_failure_no_login(self):
        h=fx.FakeHost(rc.NODES[0],'manifest_error');a=fx.Adapter(fx.plan(),h)
        self.reject(lambda:a.worker_test(fx.C),'REGISTRY_GET_FAILED');self.assertFalse(any('login' in c[1] for c in h.calls));self.assertFalse(h.auth)
    def test_expired_cleanup_keeps_auth_and_stop(self):
        h=fx.FakeHost(rc.NODES[0]);a=fx.Adapter(fx.plan(),h);original=h.run
        def run(*args):
            value=original(*args)
            if 'push' in args[1]:h.tick=10000
            return value
        h.run=run;self.reject(lambda:a.worker_test(fx.C),'WORKER_CLEANUP_INCOMPLETE')
        self.assertTrue(h.auth);self.assertFalse(h.records[fx.node_step(h.name)]['cleanup_complete'])
    def test_incomplete_cleanup_blocks_secret(self):
        h=fx.FakeHost();p=fx.plan();fx.good_receipts(h,p);h.records[fx.node_step(rc.NODES[0])]['cleanup_complete']=False
        self.reject(lambda:fx.Adapter(p,h).patch_secret('fds-app',fx.C),'PREREQUISITE_CLEANUP_INCOMPLETE')
        self.assertFalse(h.claims)
    def test_mismatched_receipt_node_blocks_secret(self):
        h=fx.FakeHost();p=fx.plan();fx.good_receipts(h,p);h.records[fx.node_step(rc.NODES[0])]['node']=rc.NODES[1]
        self.reject(lambda:fx.Adapter(p,h).patch_secret('fds-app',fx.C),'RECEIPT_TARGET_CHANGED')
    def test_public_receipt_extra_secret_field_rejected(self):
        h=fx.FakeHost();p=fx.plan();fx.good_receipts(h,p);k=fx.node_step(rc.NODES[0]);r=h.records[k];r['password']=fx.C['password']
        self.reject(lambda:rc.receipt_binding(p,k,r,fx.NOW),'RECEIPT_PUBLIC_FIELDS')
    def test_fresh_explicit_recovery_inside_reserved_period(self):
        h,p,a=fx.patched_host();h.tick=4000
        auth=fx.Operations().recovery(h,'rollback-secret-fds-app');a.rollback_secret('fds-app',fx.C,auth)
        rc.secret_data(h.secrets['fds-app'],'fds-app',rc.OLD_USER)
    def test_recovery_cannot_exceed_total_window(self):
        h,p,a=fx.patched_host();h.tick=4500
        self.reject(lambda:a.rollback_secret('fds-app',fx.C,fx.Operations().recovery(h,'rollback-secret-fds-app')),'DEADLINE_EXPIRED')
    def test_stale_old_robot_read_blocks_recovery(self):
        h,p,a=fx.patched_host();auth=fx.Operations().recovery(h,'rollback-secret-fds-app');h.tick+=11
        self.reject(lambda:a.rollback_secret('fds-app',fx.C,auth),'RECOVERY_NOT_CONFIRMED')
    def test_worker_file_metadata_change_stops_before_pull(self):
        h=fx.FakeHost(rc.NODES[0]);p=fx.plan();fx.good_receipts(h,p);original=h.replace_worker_file
        def replace(*args):original(*args);h.filemeta['mode']=0o644
        h.replace_worker_file=replace
        self.reject(lambda:fx.Adapter(p,h).update_worker_file(fx.C),'FILE_PROTECTION_CHANGED')
        self.assertFalse(any('pull' in c[1] for c in h.calls));self.assertIn('worker01-file-backup',h.private)
    def test_persistent_file_phase_has_shared_deadline(self):
        h=fx.FakeHost(rc.NODES[0]);p=fx.plan();fx.good_receipts(h,p);original=h.run
        def run(*args):
            value=original(*args)
            if 'pull' in args[1]:h.tick+=301
            return value
        h.run=run;self.reject(lambda:fx.Adapter(p,h).update_worker_file(fx.C),'DEADLINE_EXPIRED')
        self.assertFalse(any(c[0]=='crictl' for c in h.calls))

class Supply(unittest.TestCase):
    reject=fx.Contracts.reject
    def host(self,name='k8s-control01'):
        h=fx.FakeHost(name);h.plan=fx.plan();h.inv=h.plan['invocation'];h.root=Path('/root/fixture');h.runroot=Path('/run/fixture')
        h.records['stage']={'status':'PASS','invocation':h.inv,'host':h.name,'plan_sha256':hashlib.sha256(rc.encoded(h.plan)).hexdigest(),'robot_id':h.plan['new_robot']['id']}
        return h
    def receipt(self,h):
        fx.good_receipts(h,h.plan);key=fx.node_step(rc.NODES[0]);raw=rc.encoded(h.records[key]);return key,raw,hashlib.sha256(raw).hexdigest()
    def test_receipt_import_exact_round_and_hash(self):
        h=self.host();k,r,sha=self.receipt(h)
        with patch.object(supply,'write_new') as writer:supply.import_receipt(h,k,r,sha)
        self.assertEqual(writer.call_count,1);self.assertEqual(writer.call_args.args[0],h.root/'incoming'/(k+'.json'))
    def test_receipt_hash_rejects_before_write(self):
        h=self.host();k,r,sha=self.receipt(h)
        with patch.object(supply,'write_new') as writer:self.reject(lambda:supply.import_receipt(h,k,r,'0'*64),'RECEIPT_HASH_MISMATCH')
        writer.assert_not_called()
    def test_receipt_wrong_destination_rejected(self):
        h=self.host(rc.NODES[1]);k,r,sha=self.receipt(h)
        self.reject(lambda:supply.import_receipt(h,k,r,sha),'RECEIPT_DESTINATION_SCOPE')
    def test_receipt_old_invocation_rejected(self):
        h=self.host();k,r,sha=self.receipt(h);d=rc.parse_json(r);d['invocation']='2'*32;r=rc.encoded(d)
        self.reject(lambda:supply.import_receipt(h,k,r,hashlib.sha256(r).hexdigest()),'PREREQUISITE_MISSING')
    def test_credential_import_private_owned_and_no_public_fingerprint(self):
        h=self.host()
        with tempfile.TemporaryDirectory() as tmp:
            h.runroot=Path(tmp)
            def writer(p,data,*args):
                with p.open('xb') as f:f.write(data)
            with patch.object(supply,'write_new',side_effect=writer):supply.import_credential(h,rc.encoded(fx.C))
            raw=(h.runroot/'credential.json').read_bytes();self.assertEqual(rc.credential(raw),fx.C)
            owner=(h.runroot/'credential-owner.json').read_bytes();self.assertNotIn(fx.C['password'].encode(),owner);self.assertNotIn(b'sha256',owner)
    def test_credential_copy_not_overwritten(self):
        h=self.host()
        with patch.object(supply,'write_new',side_effect=FileExistsError):
            with self.assertRaises(FileExistsError):supply.import_credential(h,rc.encoded(fx.C))
    def test_credential_cannot_precede_verified_stage(self):
        h=self.host();h.records['stage']['status']='STOP'
        with patch.object(supply,'write_new') as writer:self.reject(lambda:supply.import_credential(h,rc.encoded(fx.C)),'STAGE_NOT_VERIFIED')
        writer.assert_not_called()
    def test_old_account_not_supplied(self):
        h=self.host();c=dict(fx.C,username=rc.OLD_USER)
        with patch.object(supply,'write_new') as writer:self.reject(lambda:supply.import_credential(h,rc.encoded(c)),'CREDENTIAL_ACCOUNT')
        writer.assert_not_called()
    def test_supply_after_mutation_deadline_rejected(self):
        h=self.host();h.tick=4000
        self.reject(lambda:supply.import_credential(h,rc.encoded(fx.C)),'DEADLINE_EXPIRED')
    def test_console_does_not_echo_or_accept_pipe(self):
        h=self.host()
        with patch('sys.stdin.isatty',return_value=False),patch.object(supply,'import_credential') as writer:
            self.reject(lambda:supply.console_credential(h),'PRIVATE_CONSOLE_REQUIRED')
        writer.assert_not_called()
    def test_console_supplies_fixed_username(self):
        h=self.host()
        with patch('sys.stdin.isatty',return_value=True),patch('getpass.getpass',return_value=fx.C['password']),patch.object(supply,'import_credential') as writer:
            supply.console_credential(h)
        self.assertEqual(rc.credential(writer.call_args.args[1]),fx.C)
    def test_console_echo_fallback_stops(self):
        import getpass
        h=self.host()
        with patch('sys.stdin.isatty',return_value=True),patch('getpass.getpass',side_effect=getpass.GetPassWarning),patch.object(supply,'import_credential') as writer:
            with self.assertRaises(getpass.GetPassWarning):supply.console_credential(h)
        writer.assert_not_called()
    def test_retire_replaced_credential_preserved(self):
        h=self.host();s=types.SimpleNamespace(st_dev=1,st_ino=2)
        owner={'invocation':h.inv,'device':1,'inode':3,'username':rc.NEW_USER}
        with patch.object(supply,'regular_bytes',side_effect=[(rc.encoded(owner),s),(rc.encoded(fx.C),s)]):
            self.reject(lambda:supply.retire_credential(h),'CREDENTIAL_OWNER_CHANGED')
    def test_retire_only_owned_two_files(self):
        h=self.host()
        with tempfile.TemporaryDirectory() as tmp:
            h.runroot=Path(tmp);p=h.runroot/'credential.json';p.write_bytes(rc.encoded(fx.C));s=p.stat()
            marker=h.runroot/'credential-owner.json';marker.write_bytes(rc.encoded({'invocation':h.inv,'device':s.st_dev,'inode':s.st_ino,'username':rc.NEW_USER}))
            sentinel=h.runroot/'preserve-claim';sentinel.write_bytes(b'unchanged')
            with patch.object(supply,'regular_bytes',side_effect=lambda p,*_:(p.read_bytes(),p.stat())),patch.object(supply,'fsync_parent'):
                supply.retire_credential(h)
            self.assertFalse(p.exists());self.assertFalse(marker.exists());self.assertEqual(sentinel.read_bytes(),b'unchanged')

class Transport(unittest.TestCase):
    reject=fx.Contracts.reject
    def invoke(self,mode='normal'):
        h=object.__new__(lh.LinuxHost);h.root=Path('/root/fixture')
        ca=(Path(__file__).parent/'public-ca.pem').read_bytes();body=b'{"schemaVersion":2,"MOCK":"not a real manifest"}'
        digest='sha256:'+hashlib.sha256(body).hexdigest();requests=[];connections=[]
        sub=rc.OLD_USER if mode=='wrong_subject' else rc.NEW_USER
        payload=base64.urlsafe_b64encode(rc.encoded({'sub':sub})).decode().rstrip('=');token='fixture.'+payload+'.fixture'
        tok={'token':token}
        if mode=='token_conflict':tok['access_token']='different'
        if mode=='refresh':tok['refresh_token']='SYNTHETIC_DO_NOT_RECORD'
        def response(index):
            import io
            data=rc.encoded(tok) if index==0 else body+(b'altered' if mode=='body_changed' else b'')
            size=1024*1024+1 if mode=='oversize' else len(data)
            status=401 if mode=='unauthorized' else 302 if mode=='redirect' else 200
            media='text/html' if mode=='bad_media' else 'application/vnd.oci.image.manifest.v1+json'
            wire=(f'HTTP/1.1 {status} Test\r\nContent-Length: {size}\r\nDocker-Content-Digest: {digest}\r\nContent-Type: {media}\r\n\r\n').encode()+data
            r=lh.http.client.HTTPResponse(types.SimpleNamespace(makefile=lambda *a,**kw:io.BytesIO(wire)));r.begin();return r
        class Connection:
            def __init__(self,host,port,context,timeout):
                self.index=len(connections);connections.append(self);self.host=host;self.port=port;self.context=context;self.closed=False
            def request(self,method,path,headers):requests.append((self.host,self.port,method,path,headers))
            def getresponse(self):
                if mode=='transport_secret':raise OSError(fx.C['password'])
                return response(self.index)
            def close(self):self.closed=True
        try:
            with patch.object(lh,'regular_bytes',return_value=(ca,None)),patch.object(lh.http.client,'HTTPSConnection',Connection),patch.object(lh,'DIGEST',digest),patch.object(lh,'alarm_deadline',side_effect=lambda _:contextlib.nullcontext()):
                h.registry_manifest(fx.C,10)
        finally:
            self.assertTrue(all(c.closed for c in connections))
            for c in connections:
                self.assertEqual(c.context.verify_mode,ssl.CERT_REQUIRED);self.assertTrue(c.context.check_hostname)
            self.requests=requests
        return requests
    def test_fixed_tls_peer_and_token_scope(self):
        req=self.invoke();self.assertEqual(len(req),2)
        self.assertTrue(all(r[:3]==(rc.REGISTRY,443,'GET') for r in req))
        self.assertIn('scope=repository%3Afds%2Ftest%3Apull',req[0][3]);self.assertNotIn('offline_token',req[0][3]);self.assertNotIn(fx.C['password'],repr([r[:4] for r in req]))
        self.assertTrue(req[0][4]['Authorization'].startswith('Basic '));self.assertTrue(req[1][4]['Authorization'].startswith('Bearer '))
    def test_anonymous_token_not_pass(self):self.reject(lambda:self.invoke('wrong_subject'),'TOKEN_SUBJECT_UNVERIFIED')
    def test_token_conflict_not_pass(self):self.reject(lambda:self.invoke('token_conflict'),'TOKEN_FIELDS')
    def test_refresh_token_rejected(self):self.reject(lambda:self.invoke('refresh'),'TOKEN_FIELDS')
    def test_manifest_body_must_match_digest(self):self.reject(lambda:self.invoke('body_changed'),'REGISTRY_DIGEST_MISMATCH')
    def test_manifest_media_checked(self):self.reject(lambda:self.invoke('bad_media'),'REGISTRY_MEDIA_TYPE')
    def test_redirect_not_followed(self):
        self.reject(lambda:self.invoke('redirect'),'REGISTRY_GET_FAILED');self.assertEqual(len(self.requests),1)
    def test_unauthorized_no_retry(self):
        self.reject(lambda:self.invoke('unauthorized'),'REGISTRY_GET_FAILED');self.assertEqual(len(self.requests),1)
    def test_response_size_bound(self):self.reject(lambda:self.invoke('oversize'),'REGISTRY_BODY_LIMIT')
    def test_transport_exception_secret_suppressed(self):
        with self.assertRaises(rc.Stop) as found:self.invoke('transport_secret')
        self.assertNotIn(fx.C['password'],str(found.exception));self.assertEqual(found.exception.code,'REGISTRY_TRANSPORT_FAILED')
    def test_secret_patch_uses_stdin_not_argv(self):
        h=object.__new__(lh.LinuxHost);h.name='k8s-control01';calls=[]
        def run(*args):calls.append(args);return 0,b'{}'
        h.run=run;body=[{'op':'replace','path':'/data/.dockerconfigjson','value':fx.C['password']}]
        h.kube('PATCH','/api/v1/namespaces/fds-app/secrets/'+rc.SECRET_NAME,body,10)
        self.assertNotIn(fx.C['password'],repr(calls[0][1]));self.assertIn(fx.C['password'].encode(),calls[0][2]);self.assertIn('--patch-file=/dev/stdin',calls[0][1])
    def test_delete_uses_uid_precondition_body(self):
        h=object.__new__(lh.LinuxHost);h.name='k8s-control01';calls=[];h.run=lambda *a:(calls.append(a) or (0,b'{}'))
        h.kube('DELETE','/api/v1/namespaces/monitoring-node/pods/p1-hbr-fixture',{'preconditions':{'uid':'fixture-uid'}},10)
        self.assertIn(b'fixture-uid',calls[0][2]);self.assertNotIn('--force',calls[0][1])

class ProtectedTools(unittest.TestCase):
    reject=fx.Contracts.reject
    def open(self,mode='normal'):
        raw=b'\x7fELFsynthetic-tool-no-execution';h=object.__new__(lh.LinuxHost);h.name=rc.NODES[0];h.plan=fx.plan();h.runroot=Path('/run/fixture')
        pin=h.plan['tool_pins'][h.name]['nerdctl'];pin['sha256']=hashlib.sha256(raw).hexdigest()
        s=types.SimpleNamespace(st_mode=stat.S_IFREG|0o700,st_nlink=1,st_uid=0)
        if mode=='not_root':s.st_uid=1001
        if mode=='hardlink':s.st_nlink=2
        if mode=='writable':s.st_mode=stat.S_IFREG|0o777
        context=pin['context'] if mode!='context_changed' else 'other:context'
        with patch.object(lh,'protected_parents'),patch.object(lh.os,'O_NOFOLLOW',0,create=True),patch.object(lh.os,'O_CLOEXEC',0,create=True),patch.object(lh.os,'open',return_value=42),patch.object(lh.os,'fstat',return_value=s),patch.object(lh.os,'read',side_effect=[raw if mode!='hash_changed' else raw+b'bad',b'']),patch.object(lh.os,'getxattr',return_value=context.encode()+b'\0',create=True),patch.object(lh.os,'lseek') as seek,patch.object(lh.os,'close') as close:
            try:
                got=h.open_tool('nerdctl');self.assertEqual(got,42);seek.assert_called_once_with(42,0,lh.os.SEEK_SET);close.assert_not_called()
            except rc.Stop:close.assert_called_once_with(42);raise
    def test_pinned_protected_descriptor_returned(self):self.open()
    def test_changed_staged_tool_rejected(self):self.reject(lambda:self.open('hash_changed'),'STAGED_TOOL_CHANGED')
    def test_changed_selinux_context_rejected(self):self.reject(lambda:self.open('context_changed'),'TOOL_CONTEXT_CHANGED')
    def test_unprotected_staged_uid_rejected(self):self.reject(lambda:self.open('not_root'),'TOOL_NOT_PROTECTED')
    def test_hardlink_tool_rejected(self):self.reject(lambda:self.open('hardlink'),'TOOL_NOT_PROTECTED')
    def test_writable_tool_rejected(self):self.reject(lambda:self.open('writable'),'TOOL_NOT_PROTECTED')

if __name__=='__main__':unittest.main(verbosity=2)
