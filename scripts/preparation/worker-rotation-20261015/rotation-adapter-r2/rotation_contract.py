"""Worker rotation contracts. Pure transformations; importing performs no I/O."""
import base64
import copy
import datetime as dt
import hashlib
import json
import re

REGISTRY = '10.1.93.54'
IMAGE = REGISTRY + '/fds/test@sha256:7a3b263c938493c827d8295e64f23d9386ffcbea75516ea03a6b65196636bfc6'
DIGEST = IMAGE.split('@')[1]
CA_DER_SHA256 = '6a75baf4dbe03ef24cce944e616384d318f7ca919cd7bd914624b4cebac06b10'
NODES = ('k8s-worker01', 'k8s-worker02', 'k8s-worker03')
SCOPE = {
    'fds-app': {'sa': 'transaction-api-sa', 'sa_uid': 'c718b3be-9548-418c-97cd-52d5fa28e32c',
                'secret_uid': '0f3772b6-c230-40bd-9e38-f27a21df7b88', 'nodes': NODES},
    'monitoring-api': {'sa': 'prometheus-sa', 'sa_uid': '0f44a3b1-a567-46c0-b0c9-8d5bc39701a8',
                       'secret_uid': 'c0f0bc4b-fd88-4ec6-879b-71a4bd7ed172', 'nodes': ('k8s-worker03',)},
    'monitoring-node': {'sa': 'node-exporter-sa', 'sa_uid': 'f67c1df2-7298-4215-961d-8d8a75a55a5b',
                        'secret_uid': '616deba6-b104-4420-9e59-4c7cf962317c', 'nodes': ('k8s-worker01',)},
}
SECRET_NAME = 'harbor-pull-secret'
OLD_USER = 'robot$worker'
NEW_USER = 'robot$worker-20261015-r1'
FILE_KEYS = (REGISTRY, REGISTRY + ':443')
TOOLS = {'kubectl': '/usr/bin/kubectl', 'nerdctl': '/usr/bin/nerdctl', 'crictl': '/usr/bin/crictl'}

class Stop(Exception):
    """Only static codes may reach public output; never raw exception/child text."""
    def __init__(self, code):
        assert re.fullmatch('[A-Z0-9_]+', code)
        self.code = code
        super().__init__(code)

def need(ok, code):
    if not ok: raise Stop(code)

def parse_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            need(k not in result, 'DUPLICATE_JSON_KEY'); result[k] = v
        return result
    def constant(_):raise Stop('JSON_NONFINITE')
    try: return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except Stop: raise
    except Exception: raise Stop('JSON_INVALID') from None

def encoded(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def nonce(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value) is not None, 'INVOCATION_INVALID')
    return value

def timestamp(value):
    try: result = dt.datetime.fromisoformat(value)
    except Exception: raise Stop('TIME_INVALID') from None
    need(result.tzinfo is not None, 'TIME_ZONE_REQUIRED'); return result.timestamp()

def validate_plan(plan, now):
    fields = {'version','state','invocation','not_before','not_after','mutation_until','host_boot_ids',
              'new_robot','tool_pins','budgets','authorization_reference','scope_reference'}
    need(isinstance(plan, dict) and set(plan) == fields, 'PLAN_FIELDS')
    need(plan['version'] == 1 and plan['state'] == 'BOUND', 'PLAN_NOT_BOUND')
    nonce(plan['invocation'])
    begin, end, mutation = (timestamp(plan[k]) for k in ('not_before','not_after','mutation_until'))
    need(begin <= now < end and begin < mutation <= end and end-begin <= 4500, 'WINDOW_INVALID')
    need(mutation-begin <= 3600, 'MUTATION_WINDOW_INVALID')
    for field in ('authorization_reference','scope_reference'):
        need(isinstance(plan[field], str) and 8 <= len(plan[field]) <= 300 and not any(x in plan[field] for x in ('PENDING','TODO','PLACEHOLDER')), 'DECISION_REFERENCE_REQUIRED')
    need(set(plan['host_boot_ids']) == {'k8s-control01', *NODES}, 'HOST_SCOPE')
    need(all(re.fullmatch('[0-9a-f-]{36}', s or '') for s in plan['host_boot_ids'].values()), 'BOOT_ID_INVALID')
    robot = plan['new_robot']
    need(set(robot) == {'id','name','level','project','resource','action','duration_days','disabled','expires_at'}, 'ROBOT_FIELDS')
    need(type(robot['id']) is int and robot['id'] > 3 and robot['name'] == NEW_USER and
         robot['level'] == 'system' and robot['project'] == 'fds' and robot['resource'] == 'repository' and
         robot['action'] == 'pull' and robot['duration_days'] == 30 and robot['disabled'] is False and
         timestamp(robot['expires_at']) > end, 'ROBOT_SCOPE')
    caps = {'read':10,'write':30,'node':300,'pod':180,'ready':60,'cleanup':60}
    need(set(plan['budgets']) == set(caps), 'BUDGET_FIELDS')
    for name, cap in caps.items():
        value = plan['budgets'][name]
        need(type(value) is int and 0 < value <= cap, 'BUDGET_INVALID')
    need(plan['budgets']['node']>plan['budgets']['cleanup']+plan['budgets']['read'] and
         plan['budgets']['pod']>=plan['budgets']['ready']+plan['budgets']['cleanup']+2*plan['budgets']['read'],'CLEANUP_BUDGET_REQUIRED')
    need(set(plan['tool_pins']) == {'k8s-control01', *NODES}, 'TOOL_HOST_SCOPE')
    for host, pins in plan['tool_pins'].items():
        expected = {'kubectl'} if host == 'k8s-control01' else {'nerdctl','crictl'}
        need(set(pins) == expected, 'TOOL_SCOPE')
        for tool, pin in pins.items():
            need(set(pin) == {'sha256','source','context','provenance'}, 'TOOL_PIN_FIELDS')
            need(pin['source'] == TOOLS[tool] and re.fullmatch('[0-9a-f]{64}', pin['sha256'] or ''), 'TOOL_PIN_INVALID')
            need(isinstance(pin['provenance'], str) and len(pin['provenance']) >= 8 and 'PENDING' not in pin['provenance'], 'TOOL_PROVENANCE_REQUIRED')
            need(re.fullmatch('[a-zA-Z0-9_:.,-]+', pin['context'] or '') is not None, 'TOOL_CONTEXT_INVALID')
    return plan

def credential(raw):
    d = parse_json(raw)
    need(isinstance(d, dict) and set(d) == {'username','password'} and d['username'] == NEW_USER, 'CREDENTIAL_ACCOUNT')
    password = d['password']
    need(isinstance(password, str) and 1 <= len(password.encode()) <= 4096 and not any(c in password for c in ('\x00','\r','\n')), 'CREDENTIAL_FORMAT')
    return d

def auth_entry(c):
    return {'username':c['username'],'password':c['password'],
            'auth':base64.b64encode((c['username']+':'+c['password']).encode()).decode()}

def decode_docker(raw):
    d = parse_json(raw)
    need(isinstance(d, dict) and set(d) == {'auths'} and isinstance(d['auths'], dict), 'DOCKER_CONFIG_SCOPE')
    return d

def verify_entry(entry, user, expected_password=None):
    need(isinstance(entry, dict) and set(entry) <= {'username','password','auth'}, 'AUTH_FIELDS')
    need(('auth' in entry) or {'username','password'} <= set(entry), 'AUTH_MISSING')
    values = []
    if 'auth' in entry:
        try: pair = base64.b64decode(entry['auth'], validate=True).decode().split(':', 1)
        except Exception: raise Stop('AUTH_ENCODING') from None
        need(len(pair) == 2, 'AUTH_ENCODING'); values.append(tuple(pair))
    if 'username' in entry or 'password' in entry:
        need({'username','password'} <= set(entry), 'AUTH_PARTIAL'); values.append((entry['username'],entry['password']))
    need(all(v[0] == user and isinstance(v[1], str) and v[1] for v in values), 'AUTH_ACCOUNT_MISMATCH')
    need(len(set(values)) == 1, 'AUTH_VALUES_CONFLICT')
    if expected_password is not None: need(values[0][1] == expected_password, 'AUTH_VALUE_MISMATCH')

def transform_docker(raw, keys, c, old=OLD_USER):
    d = decode_docker(raw); need(set(d['auths']) == set(keys), 'REGISTRY_SCOPE')
    for value in d['auths'].values(): verify_entry(value, old)
    return encoded({'auths':{k:auth_entry(c) for k in keys}})

def secret_data(obj, ns, user, c=None):
    need(ns in SCOPE, 'NAMESPACE_SCOPE')
    m = obj.get('metadata', {})
    need(obj.get('kind') == 'Secret' and obj.get('type') == 'kubernetes.io/dockerconfigjson' and
         m.get('name') == SECRET_NAME and m.get('namespace') == ns and m.get('uid') == SCOPE[ns]['secret_uid'] and
         isinstance(m.get('resourceVersion'),str) and not m.get('deletionTimestamp') and
         not obj.get('immutable', False), 'SECRET_IDENTITY')
    need(set(obj.get('data', {})) == {'.dockerconfigjson'}, 'SECRET_DATA_SCOPE')
    try: raw = base64.b64decode(obj['data']['.dockerconfigjson'], validate=True)
    except Exception: raise Stop('SECRET_ENCODING') from None
    d = decode_docker(raw);need(set(d['auths']) == {REGISTRY}, 'REGISTRY_SCOPE')
    verify_entry(d['auths'][REGISTRY], user, c['password'] if c else None)
    return raw

def secret_patch(before, ns, replacement):
    # Revalidate replacement shape, preserving the existing object identity and metadata.
    d = decode_docker(replacement);need(set(d['auths']) == {REGISTRY}, 'REGISTRY_SCOPE')
    m = before['metadata']; need(m.get('uid') == SCOPE[ns]['secret_uid'], 'SECRET_IDENTITY')
    return [{'op':'test','path':'/metadata/uid','value':m['uid']},
            {'op':'test','path':'/metadata/resourceVersion','value':m['resourceVersion']},
            {'op':'replace','path':'/data/.dockerconfigjson','value':base64.b64encode(replacement).decode()}]

def compare_secret_metadata(before, after):
    a, b = copy.deepcopy(before), copy.deepcopy(after)
    for x in (a,b):
        x.pop('data',None)
        for k in ('resourceVersion','managedFields'): x['metadata'].pop(k,None)
    need(a == b, 'SECRET_METADATA_CHANGED')

def pod_name(inv):return 'p1-hbr-'+nonce(inv)

def pod_nonce(inv, ns, node):
    need(ns in SCOPE and node in SCOPE[ns]['nodes'], 'POD_SCOPE')
    return hashlib.sha256((nonce(inv)+'/'+ns+'/'+node).encode()).hexdigest()[:32]

def deny_tag(inv, node):
    need(node in NODES, 'NODE_SCOPE');return REGISTRY+'/fds/test:worker-deny-'+nonce(inv)+'-'+node

def validate_sa(obj, ns):
    need(ns in SCOPE, 'NAMESPACE_SCOPE');m=obj.get('metadata',{})
    need(obj.get('kind')=='ServiceAccount' and m.get('namespace')==ns and m.get('name')==SCOPE[ns]['sa'] and
         m.get('uid')==SCOPE[ns]['sa_uid'] and not m.get('deletionTimestamp'), 'SA_IDENTITY')

def pod_manifest(inv, ns, node):
    need(ns in SCOPE and node in SCOPE[ns]['nodes'], 'POD_SCOPE')
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':pod_name(inv),'namespace':ns,
        'labels':{'harbor-rotation':nonce(inv)}},'spec':{
        'nodeName':node,'serviceAccountName':SCOPE[ns]['sa'],'automountServiceAccountToken':False,
        'imagePullSecrets':[{'name':SECRET_NAME}],'restartPolicy':'Never',
        'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,'seccompProfile':{'type':'RuntimeDefault'}},
        'containers':[{'name':'p1-hbr-verify','image':IMAGE,'imagePullPolicy':'Always','command':['sleep','300'],
                       'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']},'readOnlyRootFilesystem':True}}]}}

def owned_pod(obj, inv, ns, node, uid=None):
    expected=pod_manifest(inv,ns,node);m=obj.get('metadata',{});s=obj.get('spec',{})
    need(obj.get('kind')=='Pod' and m.get('name')==expected['metadata']['name'] and m.get('namespace')==ns and
         m.get('labels',{}).get('harbor-rotation')==inv and isinstance(m.get('uid'),str) and bool(m['uid']), 'POD_OWNERSHIP')
    if uid is not None: need(m['uid']==uid, 'POD_REPLACED')
    for k in ('nodeName','serviceAccountName','automountServiceAccountToken','imagePullSecrets','restartPolicy','securityContext'):
        need(s.get(k)==expected['spec'][k], 'POD_SPEC_CHANGED')
    need(not s.get('hostNetwork',False) and not s.get('hostPID',False) and not s.get('hostIPC',False) and
         not s.get('volumes') and not s.get('initContainers') and not s.get('ephemeralContainers'), 'POD_EXTRA_SCOPE')
    need(len(s.get('containers',[]))==1, 'POD_CONTAINER_SCOPE')
    for k,v in expected['spec']['containers'][0].items():need(s['containers'][0].get(k)==v,'POD_CONTAINER_CHANGED')
    need(not s['containers'][0].get('env') and not s['containers'][0].get('envFrom') and
         not s['containers'][0].get('volumeMounts') and not s['containers'][0].get('volumeDevices') and
         not s['containers'][0].get('lifecycle') and not s['containers'][0].get('args'), 'POD_EXTRA_SCOPE')
    return m['uid']

def ready_digest(obj, inv, ns, node, uid):
    owned_pod(obj,inv,ns,node,uid);need(not obj['metadata'].get('deletionTimestamp'),'POD_DELETING')
    status=obj.get('status',{});rows=status.get('containerStatuses',[])
    need(any(c.get('type')=='Ready' and c.get('status')=='True' for c in status.get('conditions',[])), 'POD_NOT_READY')
    need(len(rows)==1 and rows[0].get('name')=='p1-hbr-verify' and rows[0].get('ready') is True and
         isinstance(rows[0].get('state',{}).get('running'),dict), 'POD_STATUS_BINDING')
    need(rows[0].get('imageID','').split('@')[-1]==DIGEST and '@' in rows[0].get('imageID',''), 'POD_DIGEST_MISMATCH')

def push_denied(rc, output):
    low=output.lower()
    ambiguous=(b'authentication required',b'timeout',b'certificate',b'tls',b'connection refused',b'eof',b'temporary failure',b'dial tcp')
    need(rc != 0 and not any(x in low for x in ambiguous), 'PUSH_RESULT_UNCERTAIN')
    need(b'denied: requested access' in low or re.search(rb'unauthorized to access repository[^\n]*action: push',low), 'PUSH_NOT_PERMISSION_DENIED')

def tool_bytes(raw,pin):
    need(isinstance(raw,bytes) and raw.startswith(b'\x7fELF') and hashlib.sha256(raw).hexdigest()==pin['sha256'],'TOOL_SOURCE_PIN_MISMATCH')
    return raw

def receipt_binding(plan,key,r,now):
    """Public, same-round receipts only; host-to-host transfer is operator authenticated."""
    rows={'node-'+n:(n,None,n) for n in NODES}
    rows.update({'secret-'+ns:('k8s-control01',ns,None) for ns in SCOPE})
    rows.update({'pod-'+ns+'-'+n:('k8s-control01',ns,n) for ns in SCOPE for n in SCOPE[ns]['nodes']})
    need(key in rows,'RECEIPT_SCOPE');host,ns,node=rows[key]
    fields={'status','operation','observed_at_epoch','invocation','plan_sha256','robot_id','host','namespace','node','uid','rv','cleanup_complete'}
    need(isinstance(r,dict) and set(r)<=fields,'RECEIPT_PUBLIC_FIELDS')
    need(r.get('status')=='PASS' and r.get('operation')==key and r.get('host')==host and
         r.get('invocation')==plan['invocation'] and r.get('plan_sha256')==hashlib.sha256(encoded(plan)).hexdigest() and
         type(r.get('robot_id')) is int and r['robot_id']==plan['new_robot']['id'] and
         type(r.get('observed_at_epoch')) in (int,float) and
         timestamp(plan['not_before'])<=r['observed_at_epoch']<=now,'PREREQUISITE_MISSING')
    need(r.get('namespace')==ns and r.get('node')==node,'RECEIPT_TARGET_CHANGED')
    if key.startswith(('node-','pod-')):need(r.get('cleanup_complete') is True,'PREREQUISITE_CLEANUP_INCOMPLETE')
    if key.startswith('secret-'):
        need(r.get('uid')==SCOPE[ns]['secret_uid'] and isinstance(r.get('rv'),str) and r['rv'].isdigit(),'RECEIPT_SECRET_IDENTITY')
    else:need('uid' not in r and 'rv' not in r,'RECEIPT_PUBLIC_FIELDS')
    return r
