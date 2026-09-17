#!/usr/bin/env python3
"""Fault injection: all sudo/container/Kubernetes/Harbor commands are isolated mocks."""
import argparse, base64, hashlib, json, os, pathlib, shutil, subprocess, tempfile
P=argparse.ArgumentParser(); P.add_argument('--source',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[2]); P.add_argument('--out',type=pathlib.Path)
A=P.parse_args(); SRC=A.source.resolve()/'scripts/verify'; OUT=(A.out or pathlib.Path(tempfile.mkdtemp(prefix='hbr-proposal-tests-'))).resolve(); OUT.mkdir(exist_ok=True,parents=True)
MOCK=r'''#!/usr/bin/env python3
import base64,json,os,pathlib,shutil,signal,sys,tempfile
name=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]; root=pathlib.Path(os.environ['CASE_DIR']); mode=os.environ['MOCK_MODE']
with (root/'calls.jsonl').open('a') as f: f.write(json.dumps({'cmd':name,'args':a})+'\n')
if name=='sudo':
 if a[0]=='-E': a=a[1:]
 if a[0]=='mktemp': print(tempfile.mkdtemp(dir=root/'tmp')); sys.exit(0)
 if a[0]=='chmod': os.chmod(a[2],int(a[1],8)); sys.exit(0)
 if a[0]=='rm':
  p=pathlib.Path(a[-1]).resolve(); assert p.is_relative_to(root/'tmp')
  if mode=='auth_remove_fail': sys.exit(1)
  shutil.rmtree(p); sys.exit(0)
 if a[0]=='env':
  a=a[1:]
  while a and '=' in a[0]:
   k,v=a.pop(0).split('=',1); os.environ[k]=v
 assert a[0] in ('crictl','nerdctl'),a
 os.execv(str(pathlib.Path(sys.argv[0]).parent/a[0]),a)
if name=='crictl':
 if mode=='pull_fail': sys.exit(1)
 if mode=='worker_term': os.kill(os.getppid(),signal.SIGTERM)
 if mode=='worker_int': os.kill(os.getppid(),signal.SIGINT)
 print('mock pull succeeded'); sys.exit(0)
if name in ('nerdctl','docker'):
 if 'login' in a:
  sys.stdin.read()
  if mode=='login_fail': print('unauthorized: authentication required'); sys.exit(1)
  sys.exit(0)
 if 'push' in a:
  if mode=='push_success': sys.exit(0)
  if mode=='mixed_auth': print('denied: requested access\nunauthorized: authentication required'); sys.exit(1)
  if mode=='transport': print('connection refused'); sys.exit(1)
  print('denied: requested access'); sys.exit(1)
 if 'logout' in a and mode=='logout_fail': sys.exit(1)
 sys.exit(0)
if name=='kubectl':
 assert a[:2]==['--context','mock-context']; assert a[2]=='--request-timeout=10s'; a=a[3:]
 p=root/'pod.json'
 def read(): return json.loads(p.read_text()) if p.exists() else None
 def write(d): p.write_text(json.dumps(d))
 def foreign(d):
  d['metadata']['uid']='uid-foreign'; write(d); return d
 if a[0]=='get' and a[1] in ('namespace','node','serviceaccount'):
  if mode=='preflight_forbidden': sys.exit(1)
  print(a[1]+'/'+a[2]); sys.exit(0)
 if a[:2]==['get','secret']:
  if mode=='secret_missing': sys.exit(1)
  auth=base64.b64encode((os.environ['WORKER_ROBOT_USER']+':'+os.environ['WORKER_ROBOT_SECRET']).encode()).decode()
  if mode=='secret_wrong_robot': auth=base64.b64encode(b'other:wrong').decode()
  config={'auths':{'10.1.93.54':{'auth':auth}}}
  if mode=='secret_wrong_registry': config['auths']={'elsewhere':{'auth':auth}}
  print(json.dumps({'type':'kubernetes.io/dockerconfigjson','data':{'.dockerconfigjson':base64.b64encode(json.dumps(config).encode()).decode()}})); sys.exit(0)
 if a[0]=='create':
  d=json.load(sys.stdin); d['metadata']['uid']='uid-created'; d['status']={'conditions':[{'type':'Ready','status':'True'}], 'containerStatuses':[{'name':d['spec']['containers'][0]['name'],'ready':True,'state':{'running':{}},'imageID':'10.1.93.54/fds/test@sha256:'+'a'*64}]}
  if mode=='already_exists':
   d['metadata']['labels']['review-invocation']='foreign'; foreign(d); sys.exit(1)
  if mode=='create_not_observed': sys.exit(1)
  write(d)
  if mode=='create_response_lost': sys.exit(1)
  if mode=='malformed_create': print('{}'); sys.exit(0)
  print(json.dumps(d)); sys.exit(0)
 if a[0]=='wait':
  if mode=='ready_fail': sys.exit(1)
  if mode=='uid_replaced': foreign(read())
  sys.exit(0)
 if a[:2]==['get','pod']:
  cleanup='--ignore-not-found' in a
  if (cleanup and mode=='cleanup_get_error') or (not cleanup and mode=='observation_get_error'): sys.exit(1)
  if cleanup and mode=='already_absent': p.unlink(missing_ok=True)
  d=read()
  if d is None:
   if cleanup: sys.exit(0)
   sys.exit(1)
  if not cleanup:
   if mode=='wrong_node': d['spec']['nodeName']='k8s-worker03'
   if mode=='wrong_run': d['metadata']['labels']['review-run-id']='another-run'
   if mode=='wrong_nonce': d['metadata']['labels']['review-invocation']='another-invocation'
   if mode=='wrong_sa': d['spec']['serviceAccountName']='default'
   if mode=='wrong_pull_secret': d['spec']['imagePullSecrets']=[{'name':'other'}]
   if mode=='wrong_spec_image': d['spec']['containers'][0]['image']='other/image:latest'
   if mode=='wrong_image_policy': d['spec']['containers'][0]['imagePullPolicy']='IfNotPresent'
   if mode=='not_ready': d['status']['conditions'][0]['status']='False'
   if mode=='target_missing': d['status']['containerStatuses'][0]['name']='other'
   if mode=='empty_image': d['status']['containerStatuses'][0]['imageID']=''
   if mode=='invalid_image': d['status']['containerStatuses'][0]['imageID']='not-a-digest'
   if mode=='wrong_digest': d['status']['containerStatuses'][0]['imageID']='10.1.93.54/fds/test@sha256:'+'b'*64
   if mode in ('sidecar_first','sidecar_hides_bad_target'):
    side={'name':'other-sidecar','ready':True,'state':{'running':{}},'imageID':'sha256:'+'b'*64}
    if mode=='sidecar_hides_bad_target': side['imageID']='sha256:'+'a'*64; d['status']['containerStatuses'][0]['imageID']='sha256:'+'b'*64
    d['status']['containerStatuses'].insert(0,side)
  print(json.dumps(d)); sys.exit(0)
 if a[0]=='delete':
  assert '--raw' in a and a[-2:]==['-f','-']
  options=json.load(sys.stdin); (root/'delete-options.json').write_text(json.dumps(options)); d=read()
  assert a[a.index('--raw')+1]=='/api/v1/namespaces/'+d['metadata']['namespace']+'/pods/'+d['metadata']['name']
  if mode=='delete_race': d=foreign(d)
  if mode=='delete_fail' or options['preconditions']['uid']!=d['metadata']['uid']: sys.exit(1)
  (root/'deleted_uid').write_text(d['metadata']['uid'])
  if mode!='delete_pending': p.unlink()
  sys.exit(0)
 raise SystemExit('unhandled kubectl '+str(a))
if name=='curl':
 cfg=pathlib.Path(a[a.index('-K')+1]); (root/'curl-observed.json').write_text(json.dumps({'mode':cfg.stat().st_mode&0o777,'path':str(cfg)}))
 assert 'DUMMY_REVIEW_SECRET_ONLY' in cfg.read_text()
 if mode=='digest_term': os.kill(os.getppid(),signal.SIGTERM)
 if mode=='digest_int': os.kill(os.getppid(),signal.SIGINT)
 if mode=='manifest_401': sys.exit(22)
 typ='application/vnd.oci.image.index.v1+json' if mode=='manifest_index' else 'application/vnd.oci.image.manifest.v1+json'
 digest='b' if mode=='harbor_wrong_digest' else 'a'
 print('HTTP/1.1 200 OK\r\nContent-Type: '+typ+'\r\nDocker-Content-Digest: sha256:'+digest*64+'\r\n'); sys.exit(0)
if name=='rm':
 p=pathlib.Path(a[-1]).resolve(); assert p.is_relative_to(root/'tmp')
 if mode=='curl_remove_fail': sys.exit(1)

 if p.is_dir(): shutil.rmtree(p)
 else: p.unlink(missing_ok=True)
 sys.exit(0)
raise SystemExit('unhandled '+name)
'''
BIN=OUT/'bin'; BIN.mkdir(exist_ok=True)
for name in ['sudo','crictl','nerdctl','docker','kubectl','curl','rm']:
 p=BIN/name;p.write_text(MOCK);p.chmod(0o755)
RESULTS=[]
def run(cid,mode='normal',expected=1,overrides=None,meta=None,checksum='normal',script='worker-pull-pod-start-test.sh'):
 d=OUT/cid;d.mkdir();(d/'tmp').mkdir()
 raw=meta or 'TEST_TAG=review-1234\nREVIEW_RUN_ID=review-1234\n'
 (d/'review-run.env').write_text(raw)
 checksum_name='.review-run.env' if checksum=='dotfile' else 'review-run.env'
 (d/'review-run.env.sha256').write_text(hashlib.sha256(raw.encode()).hexdigest()+'  '+checksum_name+'\n')
 shutil.copy(SRC/'pod-restricted-psa-overrides.json',d); (d/'ca.pem').write_text('MOCK CA ONLY')
 env=dict(os.environ,PATH=str(BIN)+':'+os.environ['PATH'],CASE_DIR=str(d),MOCK_MODE=mode,TMPDIR=str(d/'tmp'),WORKER_ROBOT_USER='robot$dummy',WORKER_ROBOT_SECRET='DUMMY_REVIEW_SECRET_ONLY',KUBE_CONTEXT='mock-context',NAMESPACE='fds-app',NODE_NAME='k8s-worker01',SERVICE_ACCOUNT_NAME='review-sa',PULL_SECRET_NAME='worker-pull',EXPECTED_HARBOR_DIGEST='sha256:'+'a'*64,CA_FILE=str(d/'ca.pem'),CLEANUP_TIMEOUT_SECONDS='1')
 env.update(overrides or {})
 cp=subprocess.run(['bash',str(SRC/script)],cwd=d,env=env,text=True,capture_output=True,timeout=15)
 (d/'stdout.txt').write_text(cp.stdout);(d/'stderr.txt').write_text(cp.stderr)
 calls=[json.loads(s) for s in (d/'calls.jsonl').read_text().splitlines()] if (d/'calls.jsonl').exists() else []
 leaked='DUMMY_REVIEW_SECRET_ONLY' in (cp.stdout+cp.stderr+json.dumps(calls))
 auth=[p for p in (d/'tmp').iterdir() if p.is_dir()]
 obs=json.loads((d/'curl-observed.json').read_text()) if (d/'curl-observed.json').exists() else None
 remaining=json.loads((d/'pod.json').read_text()) if (d/'pod.json').exists() else None
 deleted=(d/'deleted_uid').read_text() if (d/'deleted_uid').exists() else None
 errors=[]
 if expected==1 and cp.returncode==0 or expected!=1 and cp.returncode!=expected: errors.append('unexpected exit')
 if leaked: errors.append('credential leaked')
 if deleted=='uid-foreign': errors.append('foreign UID deleted')
 if cp.returncode!=0 and 'PASS: local checks' in cp.stdout: errors.append('false aggregate PASS')
 if cp.returncode==0 and script.startswith('worker-pull') and (remaining or 'PASS: local checks' not in cp.stdout): errors.append('incomplete successful lifecycle')
 if obs and obs['mode']!=0o600: errors.append('config permissions')
 if obs and pathlib.Path(obs['path']).exists() and mode!='curl_remove_fail': errors.append('config leftover')
 if auth and mode!='auth_remove_fail': errors.append('auth directory leftover')
 if mode in ('digest_int','digest_term'):
  curl_i=next(i for i,c in enumerate(calls) if c['cmd']=='curl')
  if any(c['cmd']=='kubectl' and '--ignore-not-found' not in c['args'] and c['args'][3:5]==['get','pod'] for c in calls[curl_i+1:]): errors.append('digest continued after signal')
 if mode in ('create_response_lost','malformed_create') and deleted!='uid-created': errors.append('ownership recovery failed')
 if mode in ('already_exists','uid_replaced','delete_race') and (not remaining or remaining['metadata']['uid']!='uid-foreign'): errors.append('foreign Pod not preserved')
 if mode in ('secret_missing','secret_wrong_robot','secret_wrong_registry','preflight_forbidden') and any(c['cmd']=='crictl' or 'create' in c['args'] for c in calls): errors.append('preflight did not stop side effects')
 if mode in ('delete_fail','delete_pending','cleanup_get_error') and remaining is None: errors.append('fault fixture invalid')
 result={'id':cid,'mode':mode,'expected':expected,'rc':cp.returncode,'ok':not errors,'errors':errors,'deleted_uid':deleted,'remaining_uid':remaining['metadata']['uid'] if remaining else None,'credential_argv_log_leak':leaked}
 RESULTS.append(result);print(json.dumps(result))
run('normal',expected=0)
run('sidecar-first',mode='sidecar_first',expected=0)
run('already-absent',mode='already_absent',expected=0)
for mode in ['pull_fail','login_fail','mixed_auth','transport','push_success','secret_missing','secret_wrong_robot','secret_wrong_registry','preflight_forbidden','ready_fail','already_exists','create_response_lost','create_not_observed','malformed_create','uid_replaced','delete_race','delete_fail','delete_pending','cleanup_get_error','observation_get_error','wrong_node','wrong_run','wrong_nonce','wrong_sa','wrong_pull_secret','wrong_spec_image','wrong_image_policy','not_ready','target_missing','empty_image','invalid_image','wrong_digest','sidecar_hides_bad_target','manifest_401','manifest_index','harbor_wrong_digest','auth_remove_fail','logout_fail','curl_remove_fail']:
 run(mode,mode=mode)
for mode,rc in [('worker_term',143),('worker_int',130),('digest_term',143),('digest_int',130)]: run(mode,mode=mode,expected=rc)
for key in ['KUBE_CONTEXT','NAMESPACE','NODE_NAME','SERVICE_ACCOUNT_NAME','PULL_SECRET_NAME','EXPECTED_HARBOR_DIGEST']:
 run('missing-'+key,overrides={key:''})
run('checksum-wrong-target',checksum='dotfile')
run('duplicate-tag',meta='TEST_TAG=first\nTEST_TAG=second\nREVIEW_RUN_ID=review-1234\n')
run('missing-tag-stale-env',meta='REVIEW_RUN_ID=review-1234\n',overrides={'TEST_TAG':'stale'})
run('credential-newline',overrides={'WORKER_ROBOT_SECRET':'DUMMY_REVIEW_SECRET_ONLY\nother'})
for mode,expected in [('normal',0),('mixed_auth',1),('transport',1),('push_success',1),('login_fail',1)]: run('push-'+mode,mode=mode,expected=expected,script='worker-push-deny-test.sh')
(OUT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
failed=[r for r in RESULTS if not r['ok']]; print(f'{len(RESULTS)-len(failed)}/{len(RESULTS)} passed; evidence: {OUT}');raise SystemExit(bool(failed))
