"""Offline renderer: exact public sources/inputs only; never invokes SSH or a server."""
import argparse
import base64
import hashlib
import importlib
import json
from pathlib import Path
import sys
import time
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from public_deploy import *
A=HERE.parent/'rotation-adapter-r2'
O=HERE.parent/'rotation-orchestration'

def sources():
    result={}
    for k,path in (('adapter',A),('orchestrator',O)):
        manifest=(path/MFILE[k]).read_bytes()
        for name,row in bundle_rows(k,manifest).items():
            raw=(path/name).read_bytes()
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'LOCAL_SOURCE_PIN')
            result[k+'/'+name]=raw
    return result

def request_set(plan,now):
    need(isinstance(plan,dict) and set(plan)=={'version','state','phase','requests'} and plan['version']==1 and plan['state']=='BOUND' and plan['phase'] in PHASES,'DELIVERY_PLAN')
    rows=plan['requests'];need(isinstance(rows,list),'HOST_REQUESTS')
    wanted=set(HOSTS) if plan['phase'] in ('code','rotation-input') else {'k8s-control01'} if plan['phase']=='issue-input' else {'ansible01'}
    need(len(rows)==len(wanted) and {r.get('host') for r in rows}==wanted,'DELIVERY_HOST_SET')
    for r in rows:validate(r,now);need(r['phase']==plan['phase'],'PHASE_BINDING')
    need(len({r['invocation'] for r in rows})==1,'INVOCATION_SET')
    need(len({(r['not_before'],r['deadline'],r['authorization_reference']) for r in rows})==1,'WINDOW_OR_AUTH_SET')
    return rows

def validate_semantics(phase,values,now):
    # Verify both pinned source sets before loading any frozen contract.
    sources();sys.path[:0]=[str(O),str(A)]
    oc=importlib.import_module('orch_contract')
    if phase=='issue-input':oc.prep_request(next(iter(values.values())),now)
    elif phase=='rotation-input':
        rotation=next(v for k,v in values.items() if k.startswith('orchestration-request-'))
        oc.rotation_request(rotation,now)
        inv=rotation['plan']['invocation']
        need(values['rotation-request.json']==rotation and values['request-'+inv+'.json']==rotation['plan'],'CROSS_HOST_INPUT')
    # closeout requires the exact earlier rotation request, loaded by caller.

def make_script(engine,r,payload,action,receipt=None):
    need(action in ('supply','verify'),'ACTION')
    if action=='verify':need(isinstance(receipt,dict),'ACTUAL_RECEIPT_REQUIRED')
    packed={k:base64.b64encode(v).decode('ascii') for k,v in payload.items()}
    text=("# Public-only generated script; externally verify this entire script SHA before use.\n"
          "import base64,hashlib,json,sys\n"
          "engine=base64.b64decode("+repr(base64.b64encode(engine).decode('ascii'))+",validate=True)\n"
          "if hashlib.sha256(engine).hexdigest()!="+repr(sha(engine))+":raise SystemExit(2)\n"
          "namespace={'__name__':'public_delivery_engine'}\n"
          "exec(compile(engine,'reviewed-public-deploy','exec'),namespace)\n"
          "request=json.loads("+repr(encoded(r).decode())+")\n"
          "payload={k:base64.b64decode(v,validate=True) for k,v in json.loads("+repr(encoded(packed).decode())+").items()}\n"
          "receipt=json.loads("+repr(encoded(receipt).decode())+")\n"
          "raise SystemExit(namespace['entry']("+repr(action)+",request,payload,receipt))\n")
    return text.encode('utf-8')

def prepare(plan,input_dir,action,receipts,now):
    rows=request_set(plan,now);src=sources();values={};raws={}
    for r in rows:
        for n in input_names(r):
            if n not in raws:
                raw=(input_dir/n).read_bytes();values[n]=parse(raw);raws[n]=raw
    validate_semantics(plan['phase'],values,now)
    if plan['phase']=='closeout-input':
        r=rows[0];inv=r['invocation']
        earlier=parse((input_dir/('orchestration-request-'+inv+'.json')).read_bytes())
        sys.path[:0]=[str(O),str(A)]
        oc=importlib.import_module('orch_contract')
        oc.rotation_request(earlier,now);oc.closeout(earlier,values['closeout.json'],now)
        need(earlier['plan']['invocation']==inv and earlier['relay_uid']==r['uid'] and earlier['relay_boot_id']==r['boot_id'],'CLOSEOUT_BINDING')
    # Offline tool checks cross-host boot/uid rather than accepting one matching host at a time.
    if plan['phase']=='rotation-input':
        rotation=values['rotation-request.json']
        for r in rows:
            if r['host']=='ansible01':need(rotation['relay_uid']==r['uid'] and rotation['relay_boot_id']==r['boot_id'],'RELAY_BINDING')
            else:need(rotation['plan']['host_boot_ids'][r['host']]==r['boot_id'],'HOST_BOOT_SET')
    engine=(HERE/'public_deploy.py').read_bytes();out={}
    for r in rows:
        payload=src if r['phase']=='code' else {n:raws[n] for n in input_names(r)}
        payload_files(r,payload)
        receipt=None
        if action=='verify':
            receipt=parse((receipts/(r['host']+'.json')).read_bytes())
            supply_receipt(r,receipt)
        out[action+'-'+r['host']+'.py']=make_script(engine,r,payload,action,receipt)
    return out

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('action',choices=['supply','verify'])
    ap.add_argument('--input',required=True)
    ap.add_argument('--public-inputs',required=True)
    ap.add_argument('--receipts')
    ap.add_argument('--out',required=True)
    args=ap.parse_args()
    need(args.action!='verify' or args.receipts,'ACTUAL_RECEIPTS_REQUIRED')
    plan=parse(Path(args.input).read_bytes())
    files=prepare(plan,Path(args.public_inputs),args.action,Path(args.receipts) if args.receipts else None,time.time())
    destination=Path(args.out).resolve();destination.mkdir(parents=False,exist_ok=False)
    for name,raw in files.items():
        with (destination/name).open('xb') as f:f.write(raw)
    index={'kind':'PUBLIC_DELIVERY_RENDERED_NOT_EXECUTED','action':args.action,'phase':plan['phase'],
           'plan_sha256':sha(encoded(plan)),'engine_sha256':sha((HERE/'public_deploy.py').read_bytes()),
           'files':{n:{'bytes':len(b),'sha256':sha(b)} for n,b in files.items()},
           'remote_calls':0,'credential_actions':0}
    with (destination/'delivery-manifest.json').open('xb') as f:f.write(encoded(index))
    print(json.dumps(index,sort_keys=True))
if __name__=='__main__':main()

