"""B1/B2 fault reproductions: synthetic credentials, real HTTPResponse, zero network."""
import base64
import contextlib
import hashlib
import http.client
import io
from pathlib import Path
import types
import unittest
from unittest.mock import patch
import rotation_contract as rc
import rotation_adapter as ra
import linux_host as lh
import test_rotation as fx


class Interruptions(unittest.TestCase):
    def check_interrupt(self,kind,exception_type,cleanup_failure=False):
        original=exception_type('synthetic interruption')
        def interrupt(*args,**kwargs):raise original
        if kind.startswith('worker'):
            h=fx.FakeHost(rc.NODES[0]);a=ra.Adapter(fx.plan(),h)
            if kind=='worker_manifest':h.registry_manifest=interrupt
            else:
                run=h.run
                def interrupted(tool,args,*rest):
                    if 'push' in args:
                        h.calls.append((tool,tuple(args)))
                        raise original
                    return run(tool,args,*rest)
                h.run=interrupted
            op=lambda:a.worker_test(fx.C);key=ra.node_step(h.name);code='WORKER_INTERRUPTED'
            if cleanup_failure:h.remove_auth_dir=lambda _:(_ for _ in ()).throw(rc.Stop('TEST_CLEANUP_FAILURE'))
        else:
            h,p,a=fx.patched_host();kube=h.kube;raised=[False]
            def interrupted(method,path,*rest):
                if method=='GET' and '/pods/' in path and h.pods and not raised[0]:
                    raised[0]=True;raise original
                if cleanup_failure and method=='DELETE':raise rc.Stop('TEST_CLEANUP_FAILURE')
                return kube(method,path,*rest)
            h.kube=interrupted
            op=lambda:a.test_pod('fds-app',rc.NODES[0],fx.C)
            key=ra.pod_step(a.inv,'fds-app',rc.NODES[0]);code='POD_INTERRUPTED'
        deadline=a.deadline
        with self.assertRaises(exception_type) as found:op()
        self.assertIs(found.exception,original)
        self.assertEqual(a.deadline,deadline)
        receipt=h.records[key]
        self.assertEqual(receipt['status'],'STOP');self.assertEqual(receipt['code'],code)
        self.assertEqual(receipt['cleanup_complete'],not cleanup_failure)
        self.assertIn(key,h.claims)
        with self.assertRaises(rc.Stop):rc.receipt_binding(a.plan,key,receipt,h.wall_time())
        with self.assertRaises(rc.Stop):a.prerequisite(key)
        self.assertNotIn(fx.C['password'],repr(receipt))
        if kind=='worker_manifest':self.assertEqual(h.calls,[])
        elif kind=='worker_push':
            self.assertEqual(h.tags,{})
            if not cleanup_failure:self.assertEqual(h.auth,{})
            self.assertEqual(sum('push' in call[1] for call in h.calls),1)
        else:
            self.assertEqual(sum(call[0]=='POST' for call in h.calls),1)
            if not cleanup_failure:
                self.assertEqual(h.pods,{})
                self.assertEqual(sum(call[0]=='DELETE' for call in h.calls),1)


for _kind in ('worker_manifest','worker_push','pod_ready'):
    for _exception in (KeyboardInterrupt,SystemExit):
        def _test(self,kind=_kind,exception=_exception):self.check_interrupt(kind,exception)
        setattr(Interruptions,'test_'+_kind+'_'+_exception.__name__,_test)
for _kind in ('worker_push','pod_ready'):
    def _test(self,kind=_kind):self.check_interrupt(kind,KeyboardInterrupt,True)
    setattr(Interruptions,'test_'+_kind+'_cleanup_failure',_test)


BODY=b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}'
DIGEST='sha256:'+hashlib.sha256(BODY).hexdigest()
TOKEN='fixture.'+base64.urlsafe_b64encode(rc.encoded({'sub':rc.NEW_USER})).decode().rstrip('=')+'.fixture'
TOKEN_BODY=rc.encoded({'token':TOKEN})


def wire(data,mode='valid_cl',manifest=False):
    media=b'application/vnd.oci.image.manifest.v1+json' if manifest else b'application/json'
    headers=b'Content-Type: '+media+b'\r\n'
    if manifest:headers+=b'Docker-Content-Digest: '+DIGEST.encode()+b'\r\n'
    framing=b'Content-Length: '+str(len(data)).encode()+b'\r\n';payload=data
    chunk=hex(len(data))[2:].encode()+b'\r\n'+data+b'\r\n0\r\n\r\n'
    if mode in ('valid_chunk','valid_trailer','valid_extensions','short_chunk','missing_last_chunk',
                'missing_last_blank','missing_data_crlf','bad_chunk_size','bad_chunk_extension',
                'bad_trailer','trailer_controls','duplicate_trailer','forbidden_trailer',
                'long_chunk_line','framing_limit','chunk_limit','body_limit','te_cl','duplicate_te',
                'bad_declared_trailer','unterminated_trailer','valid_fragmented'):
        framing=b'Transfer-Encoding: chunked\r\n';payload=chunk
    if mode=='valid_trailer':
        framing+=b'Trailer: X-Trace\r\n';payload=chunk[:-2]+b'X-Trace: synthetic\r\n\r\n'
    elif mode=='valid_extensions':
        payload=b'1 ; n = "escaped\\\"value"\r\n'+data[:1]+b'\r\n'+hex(len(data)-1)[2:].encode()+b'; x=ok; flag\r\n'+data[1:]+b'\r\n00; done=yes\r\nX-Trace: done\r\n\r\n'
    elif mode=='short_cl':framing=b'Content-Length: '+str(len(data)+9).encode()+b'\r\n'
    elif mode=='short_chunk':payload=hex(len(data)+9)[2:].encode()+b'\r\n'+data
    elif mode=='missing_last_blank':payload=chunk[:-2]
    elif mode=='missing_last_chunk':payload=chunk[:-5]
    elif mode=='missing_data_crlf':payload=hex(len(data))[2:].encode()+b'\r\n'+data+b'0\r\n\r\n'
    elif mode=='bad_chunk_size':payload=b'+1\r\nx\r\n0\r\n\r\n'
    elif mode=='bad_chunk_extension':payload=hex(len(data))[2:].encode()+b'; bad="unfinished\r\n'+data+b'\r\n0\r\n\r\n'
    elif mode=='bad_trailer':payload=chunk[:-2]+b'Bad trailer\r\n\r\n'
    elif mode=='trailer_controls':payload=chunk[:-2]+b'X-Trace: bad\x00value\r\n\r\n'
    elif mode=='duplicate_trailer':payload=chunk[:-2]+b'X-Trace: one\r\nx-trace: two\r\n\r\n'
    elif mode=='forbidden_trailer':payload=chunk[:-2]+b'Docker-Content-Digest: '+DIGEST.encode()+b'\r\n\r\n'
    elif mode=='unterminated_trailer':payload=chunk[:-2]+b'X-Trace: one\r\n'
    elif mode=='bad_declared_trailer':framing+=b'Trailer: Content-Length\r\n'
    elif mode=='long_chunk_line':payload=b'1; x='+b'a'*8192+b'\r\nx\r\n0\r\n\r\n'
    elif mode=='framing_limit':payload=b'1; x='+b'a'*8000+b'\r\nx\r\n';payload=payload*9+b'0\r\n\r\n'
    elif mode=='chunk_limit':payload=b'100001\r\n'
    elif mode=='body_limit':payload=(b'90000\r\n'+b'x'*0x90000+b'\r\n')*2+b'0\r\n\r\n'
    elif mode=='te_cl':framing+=b'Content-Length: '+str(len(data)).encode()+b'\r\n'
    elif mode=='duplicate_te':framing+=b'transfer-encoding: chunked\r\n'
    elif mode=='duplicate_cl':framing+=framing
    elif mode=='conflicting_cl':framing+=b'content-length: 1\r\n'
    elif mode=='list_cl':framing=b'Content-Length: '+str(len(data)).encode()+b', '+str(len(data)).encode()+b'\r\n'
    elif mode=='negative_cl':framing=b'Content-Length: -1\r\n'
    elif mode=='missing_framing':framing=b''
    elif mode=='unsupported_te':framing=b'Transfer-Encoding: gzip, chunked\r\n';payload=chunk
    elif mode=='encoding':headers+=b'Content-Encoding: gzip\r\n'
    elif mode=='duplicate_type':headers+=b'content-type: '+media+b'\r\n'
    elif mode=='duplicate_digest':headers+=b'Docker-Content-Digest: '+DIGEST.encode()+b'\r\nDocker-Content-Digest: '+DIGEST.encode()+b'\r\n'
    elif mode=='header_controls':headers+=b'X-Trace: bad\x00value\r\n'
    elif mode=='folded_header':headers+=b'X-Trace: one\r\n two\r\n'
    return b'HTTP/1.1 200 OK\r\n'+headers+framing+b'\r\n'+payload


class Framing(unittest.TestCase):
    def exercise(self,mode,target,success=False):
        wires=[wire(TOKEN_BODY,mode if target==0 else 'valid_cl'),wire(BODY,mode if target==1 else 'valid_cl',True)]
        calls=[];connections=[];responses=[]
        class Fragmented(io.BytesIO):
            def read(self,n=-1):return super().read(min(n,3) if n>=0 else 3)
        class Conn:
            def __init__(self,host,port,**kw):
                self.closed=False;connections.append(self)
                assert host==rc.REGISTRY and port==443
            def request(self,method,path,headers):calls.append((method,path))
            def getresponse(self):
                index=len(responses)
                raw=wires.pop(0);stream=Fragmented(raw) if mode=='valid_fragmented' else io.BytesIO(raw)
                if mode=='timeout' and index==target:
                    class TimeoutStream(io.BytesIO):
                        def read(self,n=-1):raise TimeoutError(fx.C['password'])
                    stream=TimeoutStream(raw)
                r=http.client.HTTPResponse(types.SimpleNamespace(makefile=lambda *a,**kw:stream))
                r.begin();responses.append(r);return r
            def close(self):self.closed=True
        h=object.__new__(lh.LinuxHost);h.root=Path('/synthetic/root')
        ca=(Path(__file__).parent/'public-ca.pem').read_bytes()
        with patch.object(lh,'regular_bytes',return_value=(ca,None)),patch.object(lh.http.client,'HTTPSConnection',Conn),patch.object(lh,'DIGEST',DIGEST),patch.object(lh,'alarm_deadline',side_effect=lambda _:contextlib.nullcontext()):
            if success:h.registry_manifest(fx.C,10)
            else:
                with self.assertRaises(rc.Stop) as found:h.registry_manifest(fx.C,10)
                self.assertNotIn(fx.C['password'],str(found.exception))
        self.assertTrue(all(c.closed for c in connections))
        self.assertTrue(all(r.isclosed() for r in responses))
        self.assertEqual(len(calls),2 if success else target+1)
        self.assertTrue(all(method=='GET' for method,_ in calls))


for _mode in ('valid_cl','valid_chunk','valid_trailer','valid_extensions','valid_fragmented'):
    for _target in (0,1):
        def _test(self,mode=_mode,target=_target):self.exercise(mode,target,True)
        setattr(Framing,'test_'+_mode+'_'+str(_target),_test)
for _mode in ('short_cl','short_chunk','missing_last_chunk','missing_last_blank','missing_data_crlf',
              'bad_chunk_size','bad_chunk_extension','bad_trailer','trailer_controls','duplicate_trailer',
              'forbidden_trailer','long_chunk_line','framing_limit','chunk_limit','body_limit',
              'te_cl','duplicate_te','duplicate_cl','conflicting_cl','list_cl','negative_cl','missing_framing',
              'unsupported_te','encoding','duplicate_type','duplicate_digest','header_controls','folded_header',
              'bad_declared_trailer','unterminated_trailer','timeout'):
    for _target in (0,1):
        def _test(self,mode=_mode,target=_target):self.exercise(mode,target)
        setattr(Framing,'test_'+_mode+'_'+str(_target),_test)


if __name__=='__main__':unittest.main()
