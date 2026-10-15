"""Public-only orchestration contracts; frozen adapter remains authoritative."""
import copy
import datetime as dt
import hashlib
import re
from rotation_contract import need,nonce,timestamp,encoded,credential,validate_plan,NEW_USER,NODES

CP='k8s-control01'
HOSTS=(CP,*NODES)
IPS=dict(zip(HOSTS,('10.1.93.102','10.1.93.105','10.1.93.107','10.1.93.108')))
ADAPTER_SHA='0bf529d53e03cae160caebc4e3637c45502d8b621c0b08e8af49f62b75ccf247'
ROOT='/root/fds-hbr-worker-rotation-20261015'
PINS_CANONICAL_SHA='3e92bf4692d1d5e82361b9f6c08a1de3a9dc2164768f71a17fdfca51727e7870'
PERMISSIONS=[{'kind':'project','namespace':'fds','access':[{'resource':'repository','action':'pull','effect':'allow'}]}]

def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(v):
    need(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v),'HASH_INVALID')
    return v
def reference(v):
    need(isinstance(v,str) and 8<=len(v)<=300 and not any(x in v.upper() for x in ('PENDING','TODO','PLACEHOLDER')),'REFERENCE_REQUIRED')
def actor(v):
    need(isinstance(v,str) and re.fullmatch('[A-Za-z0-9_.@-]{1,80}',v),'ACTOR_REQUIRED')
def boots(v):
    need(isinstance(v,dict) and set(v)==set(HOSTS),'HOST_SCOPE')
    need(all(isinstance(s,str) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',s) for s in v.values()),'BOOT_ID_INVALID')

def prep_request(r,now,active=True):
    need(isinstance(r,dict) and set(r)=={'version','state','invocation','not_before','not_after','host_boot_ids',
         'admin_username','operator','authorization_reference','api_seconds','baseline_sha256'},'PREP_FIELDS')
    need(r['version']==1 and r['state']=='BOUND','PREP_NOT_BOUND')
    nonce(r['invocation']);boots(r['host_boot_ids']);actor(r['admin_username']);actor(r['operator']);reference(r['authorization_reference'])
    begin,end=timestamp(r['not_before']),timestamp(r['not_after'])
    need(0<end-begin<=1800 and (not active or begin<=now<end),'PREP_WINDOW')
    need(type(r['api_seconds']) is int and 0<r['api_seconds']<=30,'API_BUDGET')
    need(set(r['baseline_sha256'])=={'2','3'},'BASELINE_SCOPE')
    for v in r['baseline_sha256'].values():digest(v)
    return r

def rotation_request(r,now):
    need(isinstance(r,dict) and set(r)=={'version','state','prep','plan','input_review_reference','relay_boot_id',
         'relay_uid','stage_seconds','transfer_seconds','retire_seconds','supply_until'},'ROTATION_FIELDS')
    need(r['version']==1 and r['state']=='BOUND','ROTATION_NOT_BOUND');prep_request(r['prep'],now,False)
    p=validate_plan(r['plan'],now)
    need(sha(encoded(p['tool_pins']))==PINS_CANONICAL_SHA,'REVIEWED_TOOL_PINS_CHANGED')
    need(p['invocation']==r['prep']['invocation'] and p['host_boot_ids']==r['prep']['host_boot_ids'],'PREP_PLAN_BINDING')
    need(timestamp(r['prep']['not_before'])<=timestamp(p['not_before'])<=timestamp(r['prep']['not_after']),'PREPARATION_EXPIRED_BEFORE_ROTATION')
    reference(r['input_review_reference'])
    need(type(r['relay_uid']) is int and r['relay_uid']>0,'RELAY_UID')
    need(isinstance(r['relay_boot_id'],str) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',r['relay_boot_id']),'RELAY_BOOT')
    for f in ('stage_seconds','transfer_seconds','retire_seconds'):
        need(type(r[f]) is int and 0<r[f]<=60,'ORCHESTRATION_BUDGET')
    need(timestamp(p['not_before'])<timestamp(r['supply_until'])<=min(timestamp(p['mutation_until']),timestamp(p['not_before'])+600),'SUPPLY_WINDOW')
    return r

def create_body(inv):
    return {'name':NEW_USER.removeprefix('robot$'),'description':'Phase1 worker rotation '+nonce(inv),
            'level':'system','disable':False,'duration':30,'permissions':copy.deepcopy(PERMISSIONS)}

def metadata(obj):
    need(isinstance(obj,dict),'ROBOT_OBJECT')
    fields={'id','name','description','level','duration','editable','disable','expires_at','permissions','creator_type','creator_ref','creation_time','update_time'}
    need(set(obj)<=fields|{'secret'},'ROBOT_UNKNOWN_FIELDS')
    need({'id','name','level','duration','disable','expires_at','permissions'}<=set(obj),'ROBOT_FIELDS')
    need(type(obj['id']) is int and type(obj['duration']) is int and type(obj['expires_at']) is int and type(obj['disable']) is bool,'ROBOT_TYPES')
    result=copy.deepcopy({k:v for k,v in obj.items() if k!='secret'})
    need(isinstance(result['permissions'],list),'PERMISSIONS_TYPE')
    for permission in result['permissions']:
        need(isinstance(permission,dict) and set(permission)=={'kind','namespace','access'} and isinstance(permission['access'],list),'PERMISSIONS_FIELDS')
        for access in permission['access']:
            need(isinstance(access,dict) and set(access)=={'resource','action','effect'} and all(isinstance(v,str) for v in access.values()),'ACCESS_FIELDS')
        permission['access']=sorted(permission['access'],key=lambda x:encoded(x))
    # The controller builds permission groups from a Go map. Order is not policy.
    result['permissions']=sorted(result['permissions'],key=lambda x:encoded(x))
    return result

def permissions(v):
    need(isinstance(v,list) and len(v)==1,'NEW_PERMISSION_SCOPE');p=v[0]
    need(isinstance(p,dict) and set(p)=={'kind','namespace','access'} and p['kind']=='project' and p['namespace']=='fds' and isinstance(p['access'],list) and len(p['access'])==1,'NEW_PERMISSION_SCOPE')
    need(p['access'][0]==PERMISSIONS[0]['access'][0],'NEW_PERMISSION_SCOPE')

def baseline_hash(obj):
    m=metadata(obj)
    # Public observed identity/scope, not a credential hash or volatile update timestamp.
    keys=('id','name','level','duration','disable','expires_at','permissions')
    return sha(encoded({k:m[k] for k in keys}))

def created(reply,now,begin=None,end=None):
    need(isinstance(reply,dict) and set(reply)=={'id','name','secret','creation_time','expires_at'},'CREATE_RESPONSE_FIELDS')
    need(type(reply['id']) is int and reply['id']>3 and reply['name']==NEW_USER and type(reply['expires_at']) is int and reply['expires_at']>now+4500,'CREATE_RESPONSE_IDENTITY')
    need((now if begin is None else begin)<=timestamp(reply['creation_time'])<=(now if end is None else end),'CREATE_TIME')
    return credential(encoded({'username':reply['name'],'password':reply['secret']}))

def verify_new(obj,reply,inv):
    m=metadata(obj);body=create_body(inv)
    need(m['id']==reply['id'] and m['name']==reply['name'] and m['level']=='system' and m['duration']==30 and m['disable'] is False and m['expires_at']==reply['expires_at'] and m.get('description')==body['description'] and m.get('creation_time')==reply['creation_time'],'NEW_METADATA_MISMATCH')
    permissions(m['permissions'])
    # Harbor calculates expiry before the database creates its timestamp; do not
    # invent a two-second equality tolerance. Duration=30 and POST/GET expiry are bound above.
    need(m['expires_at']>timestamp(m['creation_time']),'NEW_DURATION')
    return {'id':m['id'],'name':m['name'],'level':'system','project':'fds','resource':'repository','action':'pull','duration_days':30,'disabled':False,'expires_at':dt.datetime.fromtimestamp(m['expires_at'],dt.timezone.utc).isoformat()}

def stage_receipt(p,host):
    return {'status':'PASS','invocation':p['invocation'],'host':host,'plan_sha256':sha(encoded(p)),'robot_id':p['new_robot']['id']}
def stages(p,v):
    need(isinstance(v,dict) and set(v)==set(HOSTS) and all(v[h]==stage_receipt(p,h) for h in HOSTS),'ALL_STAGES_REQUIRED')
def transfer(r,target,raw):
    p=r['plan']
    need(target in HOSTS and isinstance(raw,dict) and set(raw)=={'invocation','request_sha256','target','boot_id','robot_id','credential'},'TRANSFER_FIELDS')
    need(raw['invocation']==p['invocation'] and raw['request_sha256']==sha(encoded(r)) and raw['target']==target and raw['boot_id']==p['host_boot_ids'][target] and raw['robot_id']==p['new_robot']['id'],'TRANSFER_BINDING')
    return credential(encoded(raw['credential']))
def closeout(r,c,now):
    need(isinstance(c,dict) and set(c)=={'version','state','request_sha256','decision_reference','observed_at','rollback_pending','credential_users_stopped','targets'},'CLOSEOUT_FIELDS')
    need(c['version']==1 and c['state']=='BOUND' and c['request_sha256']==sha(encoded(r)) and c['rollback_pending'] is False and c['credential_users_stopped'] is True and c['targets']==list(HOSTS),'RETIRE_NOT_DECIDED')
    reference(c['decision_reference']);need(0<=now-timestamp(c['observed_at'])<=300,'CLOSEOUT_STALE')
    return c
