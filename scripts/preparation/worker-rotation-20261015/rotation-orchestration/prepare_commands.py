"""Offline command rendering only. Never invokes shell, SSH or a server API."""
import argparse
import json
from pathlib import Path
import shlex
import sys
import time
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'rotation-adapter-r2')]
from orch_contract import prep_request,rotation_request,closeout,sha,ROOT
from rotation_contract import parse_json,encoded

def render(kind,value,manifest,now,co=None):
    if kind=='issue':
        prep_request(value,now)
        inv=value['invocation']
        argv=['sudo','/usr/bin/python3','-I','-S','-B',ROOT+'/orchestrator-'+inv+'/orch_launch.py',
              manifest,ROOT+'/code-'+inv,'endpoint','issue','--request',
              ROOT+'/prep-request-'+inv+'.json','--request-sha256',sha(encoded(value))]
        return {'execution_host':'k8s-control01','console_only':True,
                'command':' '.join(shlex.quote(v) for v in argv),'request_sha256':sha(encoded(value))}
    rotation_request(value,now);inv=value['plan']['invocation']
    base='/home/server01_ansible/hbr-rotation-'+inv
    args=['/usr/bin/python3','-I','-S','-B',base+'/orchestrator/orch_launch.py',
          manifest,base+'/adapter','relay']
    def cmd(action,extra=()):
        a=args+[action,'--request',base+'/rotation-request.json',
                '--request-sha256',sha(encoded(value)),*extra]
        return ' '.join(shlex.quote(x) for x in a)
    result={'execution_host':'ansible01','account':'server01_ansible',
            'request_sha256':sha(encoded(value)),'adapter_plan_sha256':sha(encoded(value['plan'])),
            'stage_command':cmd('stage-all'),'supply_command':cmd('supply-all')}
    if co is not None:
        closeout(value,co,now)
        result['retire_command']=cmd('retire-all',('--closeout',base+'/closeout.json',
                                                   '--closeout-sha256',sha(encoded(co))))
    return result

def main():
    a=argparse.ArgumentParser()
    a.add_argument('kind',choices=['issue','rotation'])
    a.add_argument('--input',required=True);a.add_argument('--closeout');a.add_argument('--out',required=True)
    args=a.parse_args()
    # This accepts only a real, explicitly bound input. Draft/null inputs fail.
    value=parse_json(Path(args.input).read_bytes())
    co=parse_json(Path(args.closeout).read_bytes()) if args.closeout else None
    manifest=sha((HERE/'orchestration-manifest.json').read_bytes())
    result=render(args.kind,value,manifest,time.time(),co)
    # Write only validated public inputs; argv/env never receive a credential.
    inv=value['invocation'] if args.kind=='issue' else value['plan']['invocation']
    out=Path(args.out).resolve();out.mkdir(parents=False,exist_ok=False)
    def save(name,obj):
        with (out/name).open('xb') as f:f.write(encoded(obj))
    if args.kind=='issue':save('prep-request-'+inv+'.json',value)
    else:
        save('orchestration-request-'+inv+'.json',value)
        save('rotation-request.json',value)
        save('request-'+inv+'.json',value['plan'])
        if co is not None:save('closeout.json',co)
    save('commands.json',result)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
