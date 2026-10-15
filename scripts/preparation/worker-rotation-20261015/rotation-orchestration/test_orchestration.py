"""Synthetic local checks only. No production network, SSH, credential or Linux stage."""
import copy
import datetime as dt
import io
import json
import unittest
from unittest.mock import patch,Mock
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'rotation-adapter-r2')]
import orch_contract as c
import orch_endpoint as e
import orch_relay as r
from rotation_contract import Stop,encoded,parse_json
from test_rotation import plan as adapter_plan,NOW,iso

SECRET='SYNTHETIC_ORCHESTRATION_TEST_ONLY'
BOOT='12345678-1234-1234-1234-123456789abc'

def robot(rid,name):
    return {'id':rid,'name':name,'description':'existing','level':'system','duration':30,
            'disable':False,'editable':True,'expires_at':int(NOW)+2592000,
            'permissions':copy.deepcopy(c.PERMISSIONS),'creation_time':iso(NOW),'update_time':iso(NOW)}

def prep():
    return {'version':1,'state':'BOUND','invocation':'1'*32,'not_before':iso(NOW-1),
            'not_after':iso(NOW+1799),'host_boot_ids':{h:BOOT for h in c.HOSTS},
            'admin_username':'synthetic_admin','operator':'synthetic_operator',
            'authorization_reference':'SYNTHETIC_TEST_ONLY','api_seconds':30,
            'baseline_sha256':{str(i):c.baseline_hash(robot(i,name)) for i,name in ((2,'robot$worker'),(3,'robot$push'))}}

def request():
    p=adapter_plan()
    # Public tool pins only; all identities/times/credential in this fixture are synthetic.
    pins=HERE.parent/'TOOL_PROVENANCE_20261015/TOOL_PINS_CANDIDATE.json'
    p['tool_pins']=json.loads(pins.read_text(encoding='utf-8-sig'))['tool_pins']
    return {'version':1,'state':'BOUND','prep':prep(),'plan':p,'input_review_reference':'SYNTHETIC_REVIEW_ONLY',
            'relay_boot_id':BOOT,'relay_uid':1001,'stage_seconds':60,'transfer_seconds':60,
            'retire_seconds':60,'supply_until':iso(NOW+599)}

def closeout(req):
    return {'version':1,'state':'BOUND','request_sha256':c.sha(encoded(req)),
            'decision_reference':'SYNTHETIC_CLOSEOUT_ONLY','observed_at':iso(NOW),
            'rollback_pending':False,'credential_users_stopped':True,'targets':list(c.HOSTS)}

class J:
    def __init__(self):self.data={}
    def write(self,k,v):
        if k in self.data:raise FileExistsError(k)
        self.data[k]=copy.deepcopy(v)
    def claim(self,k,v):self.write('claim-'+k,v)
    def read(self,k):return copy.deepcopy(self.data[k])

class API:
    def __init__(self,fail=None):
        self.calls=[];self.fail=fail;self.robots={2:robot(2,'robot$worker'),3:robot(3,'robot$push')}
        self.reply={'id':42,'name':c.NEW_USER,'secret':SECRET,'creation_time':iso(NOW),'expires_at':int(NOW)+2592000}
    def call(self,method,path,body=None):
        self.calls.append((method,path,copy.deepcopy(body)))
        if len(self.calls)==self.fail:raise TimeoutError('synthetic lost response')
        if method=='POST':
            new=robot(42,c.NEW_USER);new['description']=body['description'];self.robots[42]=new
            return copy.deepcopy(self.reply)
        if '?' in path:return copy.deepcopy(list(self.robots.values()))
        return copy.deepcopy(self.robots[int(path.rsplit('/',1)[1])])

class Contracts(unittest.TestCase):
    def test_draft_and_missing_actor_rejected(self):
        for key,value in [('state','DRAFT'),('admin_username',None),('operator',None),
                          ('authorization_reference','PENDING_INPUT'),('api_seconds',31)]:
            with self.subTest(key=key):
                x=prep();x[key]=value
                with self.assertRaises(Stop):c.prep_request(x,NOW)
    def test_prep_window(self):
        for value in (NOW-2,NOW+1801):
            x=prep();x['not_after']=iso(value)
            with self.assertRaises(Stop):c.prep_request(x,NOW)
        c.prep_request(prep(),NOW)
    def test_expired_prep_can_bind_plan_but_cannot_issue(self):
        x=prep();x['not_before']=iso(NOW-1801);x['not_after']=iso(NOW-1)
        c.prep_request(x,NOW,False)
        with self.assertRaises(Stop):c.prep_request(x,NOW)
    def test_rotation_windows_and_caps(self):
        for key,value in [('stage_seconds',61),('transfer_seconds',0),('retire_seconds',True),
                          ('input_review_reference','TODO_REVIEW'),('supply_until',iso(NOW+601))]:
            with self.subTest(key=key):
                x=request();x[key]=value
                with self.assertRaises(Stop):c.rotation_request(x,NOW)
    def test_boot_drift(self):
        x=request();x['plan']['host_boot_ids'][c.CP]='2'+BOOT[1:]
        with self.assertRaises(Stop):c.rotation_request(x,NOW)
    def test_create_body_no_secret_or_extra_permission(self):
        b=c.create_body('1'*32)
        self.assertNotIn('secret',b);self.assertEqual(b['name'],'worker-20261015-r1')
        self.assertEqual(b['permissions'],c.PERMISSIONS);self.assertFalse(b['disable']);self.assertEqual(b['duration'],30)
    def test_bad_created(self):
        for key,value in [('id',2),('name','robot$other'),('expires_at',int(NOW)-1),
                          ('creation_time',iso(NOW-200)),('secret','bad\n')]:
            with self.subTest(key=key):
                v=API().reply;v[key]=value
                with self.assertRaises(Stop):c.created(v,NOW)
    def test_new_scope_changed(self):
        api=API();api.call('POST','/api/v2.0/robots',c.create_body('1'*32));good=api.robots[42]
        for key,value in [('disable',True),('duration',-1),('expires_at',int(NOW)+2591990),
                          ('description','other'),('level','project')]:
            with self.subTest(key=key):
                obj=copy.deepcopy(good);obj[key]=value
                with self.assertRaises(Stop):c.verify_new(obj,api.reply,'1'*32)
    def test_extra_push_rejected(self):
        api=API();api.call('POST','x',c.create_body('1'*32))
        api.robots[42]['permissions'][0]['access'].append({'resource':'repository','action':'push','effect':'allow'})
        with self.assertRaises(Stop):c.verify_new(api.robots[42],api.reply,'1'*32)
    def test_metadata_omits_secret(self):
        x=robot(2,'robot$worker');x['secret']=SECRET
        self.assertNotIn(SECRET,encoded(c.metadata(x)).decode())
    def test_stage_gate(self):
        p=adapter_plan();good={h:c.stage_receipt(p,h) for h in c.HOSTS};c.stages(p,good)
        for host in c.HOSTS:
            bad=copy.deepcopy(good);bad[host]['robot_id']=99
            with self.assertRaises(Stop):c.stages(p,bad)
    def test_transfer_bindings(self):
        req=request();host=c.NODES[0]
        good={'invocation':req['plan']['invocation'],'request_sha256':c.sha(encoded(req)),'target':host,
              'boot_id':BOOT,'robot_id':42,'credential':{'username':c.NEW_USER,'password':SECRET}}
        self.assertEqual(c.transfer(req,host,good)['password'],SECRET)
        for key,value in [('invocation','2'*32),('request_sha256','a'*64),('target',c.NODES[1]),('boot_id','2'+BOOT[1:]),('robot_id',43)]:
            with self.subTest(key=key):
                x=copy.deepcopy(good);x[key]=value
                with self.assertRaises(Stop):c.transfer(req,host,x)
    def test_closeout_requires_decision_and_no_pending_users(self):
        req=request();good=closeout(req);c.closeout(req,good,NOW)
        for key,value in [('rollback_pending',True),('credential_users_stopped',False),
                          ('observed_at',iso(NOW-301)),('targets',[c.CP]),('request_sha256','a'*64)]:
            with self.subTest(key=key):
                x=copy.deepcopy(good);x[key]=value
                with self.assertRaises(Stop):c.closeout(req,x,NOW)

class Issuance(unittest.TestCase):
    def test_normal_one_post_seven_get_no_secret_in_public_verified(self):
        api=API();j=J();new=e.issue(prep(),api,j,lambda:NOW)
        self.assertEqual([x[0] for x in api.calls].count('POST'),1)
        self.assertEqual([x[0] for x in api.calls].count('GET'),7)
        self.assertEqual(new['id'],42)
        self.assertNotIn(SECRET,encoded(j.data['verified']).decode())
        self.assertIn('claim-post',j.data);self.assertIn('created-private',j.data)
    def test_loss_at_each_request_stops_no_retry(self):
        for index in range(1,9):
            with self.subTest(index=index):
                api=API(index);j=J()
                with self.assertRaises(TimeoutError):e.issue(prep(),api,j,lambda:NOW)
                self.assertEqual(len(api.calls),index)
                self.assertNotIn('verified',j.data)
                self.assertLessEqual(sum(m=='POST' for m,_,_ in api.calls),1)
                if index>=4:self.assertIn('claim-post',j.data)
    def test_duplicate_claim_blocks_second_post(self):
        api=API();j=J();j.claim('post',{})
        with self.assertRaises(FileExistsError):e.issue(prep(),api,j,lambda:NOW)
        self.assertFalse(any(m=='POST' for m,_,_ in api.calls))
    def test_baseline_changed_blocks_post(self):
        api=API();api.robots[2]['disable']=True
        with self.assertRaises(Stop):e.issue(prep(),api,J(),lambda:NOW)
        self.assertFalse(any(m=='POST' for m,_,_ in api.calls))
    def test_unknown_new_id_or_duplicate_list_blocks_post(self):
        api=API();api.robots[4]=robot(4,'other')
        with self.assertRaises(Stop):e.issue(prep(),api,J(),lambda:NOW)
        self.assertEqual(len(api.calls),1)
    def test_keyboard_interrupt_is_never_success(self):
        api=API();original=api.call;j=J()
        def interrupt(m,p,b=None):
            if m=='POST':raise KeyboardInterrupt()
            return original(m,p,b)
        api.call=interrupt
        with self.assertRaises(KeyboardInterrupt):e.issue(prep(),api,j,lambda:NOW)
        self.assertIn('claim-post',j.data);self.assertNotIn('verified',j.data)
    def test_post_verified_secret_not_in_creation_intent(self):
        api=API();j=J();e.issue(prep(),api,j,lambda:NOW)
        self.assertNotIn(SECRET,encoded(j.data['claim-post']).decode())
    def test_name_claim_precedes_console_and_is_not_deleted(self):
        r0=prep();events=[]
        def write(p,data):events.append('global-claim')
        with patch.object(e,'identity',return_value=c.CP),patch.object(e.time,'time',return_value=NOW),\
             patch.object(e.sys.stdin,'isatty',return_value=True),patch.object(e.sys.stderr,'isatty',return_value=True),\
             patch.object(e,'directory',side_effect=[None,RuntimeError('synthetic mkdir stop')]),patch.object(e,'write_new',side_effect=write):
            with self.assertRaises(RuntimeError):e.run_issue(r0,HERE)
        self.assertEqual(events,['global-claim'])

class MockExchange:
    def __init__(self,req,fail=None):
        self.r=req;self.calls=[];self.fail=fail
    def __call__(self,argv,data,seconds):
        import shlex
        remote=shlex.split(argv[-1]);idx=remote.index('endpoint');action=remote[idx+1]
        host=next(h for h,ip in c.IPS.items() if argv[-2]=='svc_ansible@'+ip)
        self.calls.append((host,action,data,argv,seconds))
        if len(self.calls)==self.fail:raise Stop('MOCK_RESPONSE_LOST')
        if action=='stage-status':return encoded(c.stage_receipt(self.r['plan'],host))
        if action=='export':
            target=remote[remote.index('--target')+1]
            return encoded({'invocation':self.r['plan']['invocation'],'request_sha256':c.sha(encoded(self.r)),
                'target':target,'boot_id':BOOT,'robot_id':42,'credential':{'username':c.NEW_USER,'password':SECRET}})
        return encoded({'status':'RETURNED','action':action,'host':host,'request_sha256':c.sha(encoded(self.r))})

class RelayTests(unittest.TestCase):
    def relay(self,req,fake):
        return r.Relay(req,'b'*64,fake,clock=lambda:10,wall=lambda:NOW)
    def test_stage_four_only(self):
        req=request();fake=MockExchange(req);self.relay(req,fake).stage_all()
        self.assertEqual([(h,a) for h,a,*_ in fake.calls],[(h,'stage') for h in c.HOSTS])
    def test_supply_four_destinations_no_secret_in_argv_or_environment(self):
        req=request();fake=MockExchange(req);self.relay(req,fake).supply_all()
        self.assertEqual(len(fake.calls),11) # four probes, local supply, three export/receive pairs
        self.assertEqual(sum(a=='export' for _,a,*_ in fake.calls),3)
        self.assertEqual(sum(a in ('supply-local','receive') for _,a,*_ in fake.calls),4)
        for host,action,data,argv,seconds in fake.calls:
            self.assertNotIn(SECRET,str(argv));self.assertNotIn(SECRET,str(r.ENV))
            self.assertEqual(SECRET.encode() in data,action=='receive')
            self.assertIn('--operation-until',argv[-1])
            self.assertGreater(seconds,0);self.assertLessEqual(seconds,60)
    def test_each_supply_failure_stops_remaining_destinations(self):
        for i in range(1,12):
            with self.subTest(i=i):
                req=request();fake=MockExchange(req,i)
                with self.assertRaises(Stop):self.relay(req,fake).supply_all()
                self.assertEqual(len(fake.calls),i)
    def test_wrong_export_target_never_reaches_receiver(self):
        req=request();fake=MockExchange(req);original=fake.__call__
        def bad(*args):
            raw=original(*args)
            if fake.calls[-1][1]=='export':
                x=parse_json(raw);x['target']=c.NODES[2];return encoded(x)
            return raw
        with self.assertRaises(Stop):self.relay(req,bad).supply_all()
        self.assertFalse(any(a=='receive' for _,a,*_ in fake.calls))
    def test_retire_four_and_partial_failure_stops(self):
        for fail in (None,1,2,3,4):
            req=request();fake=MockExchange(req,fail);relay=self.relay(req,fake)
            if fail:
                with self.assertRaises(Stop):relay.retire_all(closeout(req))
                self.assertEqual(len(fake.calls),fail)
            else:
                relay.retire_all(closeout(req))
                self.assertEqual([(h,a) for h,a,*_ in fake.calls],[(h,'retire') for h in c.HOSTS])
    def test_remote_scope_and_deadline_required(self):
        for host,action in [('evil','receive'),(c.CP,'delete'),(c.CP,'issue')]:
            with self.assertRaises(Stop):r.command(request(),host,action,'b'*64,until=iso(NOW+10))
        with self.assertRaises(Stop):r.command(request(),c.CP,'stage','b'*64)
    def test_ssh_security_options(self):
        args=r.command(request(),c.CP,'stage','b'*64,until=iso(NOW+10))
        for value in ('StrictHostKeyChecking=yes','BatchMode=yes','ForwardAgent=no','ClearAllForwardings=yes','ControlMaster=no'):
            self.assertIn(value,args)
        self.assertIn('sudo -n /usr/bin/python3 -I -S -B',args[-1])
    def test_expired_supply_does_not_call_child(self):
        req=request();fake=MockExchange(req)
        relay=r.Relay(req,'b'*64,fake,wall=lambda:NOW+601)
        with self.assertRaises(Stop):relay.supply_all()
        self.assertEqual(fake.calls,[])

class Endpoints(unittest.TestCase):
    def test_receive_claim_before_import_and_no_success_after_exception(self):
        req=request();host=c.NODES[0];j=J()
        envelope={'invocation':req['plan']['invocation'],'request_sha256':c.sha(encoded(req)),
             'target':host,'boot_id':BOOT,'robot_id':42,'credential':{'username':c.NEW_USER,'password':SECRET}}
        def importing(*_):
            self.assertIn('claim-supply',j.data);raise KeyboardInterrupt()
        with patch.object(e,'bound_journal',return_value=(req['plan'],host,j)),patch.object(e,'stage_status'),\
             patch.object(e.time,'time',return_value=NOW),patch.object(e,'LinuxHost'),patch.object(e,'import_credential',side_effect=importing):
            with self.assertRaises(KeyboardInterrupt):e.receive_credential(req,encoded(envelope))
        self.assertNotIn('supply',j.data)
    def test_export_second_attempt_refused(self):
        req=request();j=J();all_stages={h:c.stage_receipt(req['plan'],h) for h in c.HOSTS}
        with patch.object(e,'bound_journal',return_value=(req['plan'],c.CP,j)),patch.object(e,'stage_status'),\
             patch.object(e.time,'time',return_value=NOW),patch.object(e,'issued_credential',return_value={'username':c.NEW_USER,'password':SECRET}):
            e.export_credential(req,c.NODES[0],all_stages)
            with self.assertRaises(FileExistsError):e.export_credential(req,c.NODES[0],all_stages)
    def test_retire_not_allowed_while_rollback_pending(self):
        req=request();j=J();co=closeout(req);co['rollback_pending']=True
        with patch.object(e,'bound_journal',return_value=(req['plan'],c.CP,j)),patch.object(e.time,'time',return_value=NOW),patch.object(e,'retire_credential') as delete:
            with self.assertRaises(Stop):e.retire(req,co)
            delete.assert_not_called()
    def test_retire_preserves_record_on_delete_failure(self):
        req=request();j=J();j.write('supply',{'status':'SUPPLIED','host':c.CP,'request_sha256':c.sha(encoded(req))})
        with patch.object(e,'bound_journal',return_value=(req['plan'],c.CP,j)),patch.object(e.time,'time',return_value=NOW),\
             patch.object(e,'LinuxHost'),patch.object(e,'retire_credential',side_effect=RuntimeError('synthetic')):
            with self.assertRaises(RuntimeError):e.retire(req,closeout(req))
        self.assertIn('claim-retire',j.data);self.assertNotIn('retire',j.data)


class HTTPIntegration(unittest.TestCase):
    def invoke(self,status=201,body=None,headers=None,tail=None,method='POST',failure=None):
        import contextlib,http.client
        j=J();j.path=Path('/synthetic-private')
        data=encoded(API().reply if body is None else body)
        hs=headers if headers is not None else {'Content-Type':'application/json','Content-Length':str(len(data))}
        wire=('HTTP/1.1 '+str(status)+' Synthetic\r\n'+''.join(k+': '+v+'\r\n' for k,v in hs.items())+'\r\n').encode()+(data if tail is None else tail)
        class Sock:
            def makefile(self,*_):return io.BytesIO(wire)
        response=http.client.HTTPResponse(Sock());response.begin()
        conn=Mock();conn.getresponse.return_value=response
        if failure:conn.request.side_effect=failure
        files={}
        def saved(path,raw,*_):
            if str(path) in files:raise FileExistsError()
            files[str(path)]=raw
        ca=(HERE.parent/'rotation-adapter-r2/public-ca.pem').read_bytes()
        api=e.HarborAPI(prep(),'SYNTHETIC_ADMIN_PASSWORD',ca,j)
        with patch.object(e.http.client,'HTTPSConnection',return_value=conn),patch.object(e,'deadline',side_effect=lambda _:contextlib.nullcontext()),\
             patch.object(e.time,'time',return_value=NOW),patch.object(e,'write_new',side_effect=saved):
            try:
                result=api.call(method,'/api/v2.0/robots',c.create_body('1'*32))
                err=None
            except BaseException as exc:result=None;err=exc
        return api,j,conn,files,result,err
    def test_actual_http_201_parser_preserves_private_body(self):
        api,j,conn,files,result,err=self.invoke()
        self.assertIsNone(err);self.assertEqual(result['id'],42)
        self.assertTrue(any(SECRET.encode() in raw for raw in files.values()))
        self.assertNotIn('SYNTHETIC_ADMIN_PASSWORD',str(j.data))
        self.assertNotIn('SYNTHETIC_ADMIN_PASSWORD',str(files))
        self.assertTrue(api.ctx.check_hostname);self.assertEqual(api.ctx.verify_mode,__import__('ssl').CERT_REQUIRED)
        conn.close.assert_called_once()
    def test_non_201_never_success_no_redirect_retry(self):
        for status in (200,202,301,302,400,401,403,409,500):
            with self.subTest(status=status):
                api,j,conn,files,result,err=self.invoke(status=status)
                self.assertIsInstance(err,Stop);self.assertIsNone(result)
                conn.request.assert_called_once();conn.close.assert_called_once()
                self.assertTrue(api.posted)
    def test_short_content_length_preserves_partial_and_stops(self):
        api,j,conn,files,result,err=self.invoke(headers={'Content-Type':'application/json','Content-Length':'1000'},tail=b'{"secret":"synthetic')
        self.assertIsInstance(err,Stop);self.assertIsNone(result)
        self.assertEqual(files[str(Path('/synthetic-private/http-1-wire.bin'))],b'{"secret":"synthetic')
    def test_incomplete_chunk_terminator_stops(self):
        _,_,_,files,result,err=self.invoke(headers={'Content-Type':'application/json','Transfer-Encoding':'chunked'},tail=b'2\r\n{}\r\n0\r\n')
        self.assertIsInstance(err,Stop);self.assertIsNone(result)
    def test_location_outside_fixed_host_stops(self):
        data=encoded(API().reply)
        _,_,conn,_,result,err=self.invoke(headers={'Content-Type':'application/json','Content-Length':str(len(data)),'Location':'https://attacker.invalid/x'})
        self.assertIsInstance(err,Stop);conn.request.assert_called_once()
    def test_response_lost_consumes_post_attempt(self):
        api,j,conn,_,_,err=self.invoke(failure=TimeoutError('synthetic'))
        self.assertIsInstance(err,TimeoutError)
        with self.assertRaises(Stop):api.call('POST','/api/v2.0/robots',c.create_body('1'*32))
        conn.request.assert_called_once()
    def test_api_mutation_allowlist(self):
        api,_,_,_,_,_=self.invoke()
        for method,path in [('DELETE','/api/v2.0/robots/2'),('PUT','/api/v2.0/robots/2'),('PATCH','/api/v2.0/robots/42')]:
            with self.assertRaises(Stop):api.call(method,path,{})
    def test_non_json_content_stops(self):
        _,_,_,_,result,err=self.invoke(headers={'Content-Type':'text/html','Content-Length':'2'},tail=b'{}')
        self.assertIsInstance(err,Stop);self.assertIsNone(result)

class ExtraGuards(unittest.TestCase):
    def test_delayed_rotation_cannot_extend_preparation(self):
        req=request();req['prep']['not_before']=iso(NOW-2000);req['prep']['not_after']=iso(NOW-200)
        with self.assertRaises(Stop):c.rotation_request(req,NOW)
    def test_commands_are_offline_and_drafts_fail(self):
        from prepare_commands import render
        req=request()
        out=render('rotation',req,'b'*64,NOW)
        self.assertIn('stage-all',out['stage_command'])
        self.assertNotIn('retire_command',out)
        out=render('rotation',req,'b'*64,NOW,closeout(req))
        self.assertIn('retire-all',out['retire_command'])
        out=render('issue',prep(),'b'*64,NOW)
        self.assertTrue(out['console_only'])
        self.assertNotIn(SECRET,str(out))
        draft=prep();draft['state']='DRAFT'
        with self.assertRaises(Stop):render('issue',draft,'b'*64,NOW)
    def test_permission_order_is_not_a_metadata_change(self):
        a=robot(3,'robot$push')
        a['permissions'][0]['access'].append({'resource':'repository','action':'push','effect':'allow'})
        b=copy.deepcopy(a);b['permissions'][0]['access'].reverse()
        self.assertEqual(c.metadata(a),c.metadata(b))
    def test_server_creation_delay_does_not_invent_two_second_failure(self):
        api=API();api.call('POST','x',c.create_body('1'*32))
        api.reply['creation_time']=iso(NOW+4);api.robots[42]['creation_time']=iso(NOW+4)
        self.assertEqual(c.verify_new(api.robots[42],api.reply,'1'*32)['id'],42)
    def test_reviewed_tool_pins_are_fixed(self):
        req=request();c.rotation_request(req,NOW)
        req['plan']['tool_pins'][c.CP]['kubectl']['sha256']='a'*64
        with self.assertRaises(Stop):c.rotation_request(req,NOW)
    def test_no_plan_larger_than_frozen_75_minutes(self):
        req=request();req['plan']['not_after']=iso(NOW+4501)
        with self.assertRaises(Stop):c.rotation_request(req,NOW)
    def test_new_request_is_not_approved_by_prep_reference_alone(self):
        req=request();req['input_review_reference']=None
        with self.assertRaises(Stop):c.rotation_request(req,NOW)

if __name__=='__main__':unittest.main(verbosity=2)
