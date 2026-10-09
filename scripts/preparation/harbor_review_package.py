#!/usr/bin/env python3
"""Offline review package, never a guest installer or Runtime approval.

Run from a trusted checkout on an approved private workstation path. Complete
input/hash is mandatory: no live enrollment, sample target or default budget.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/recovery'))
from harbor_recovery_bundle import MODULES, parse_bundle, bound_host_digest
from harbor_recovery_docker import UnixEngine, execution_binding, parse_json, require
from harbor_recovery_host import absolute
from harbor_recovery_protected_store import label
from harbor_recovery_service import unit_text


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(obj): return (json.dumps(obj,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def prepare(raw, expected_input_sha256, sources, bootstrap):
    require(sha(raw)==expected_input_sha256,'PACKAGE_INPUT_HASH')
    request=parse_json(raw)
    require(isinstance(request,dict) and set(request)=={'version','bundle','runtime'} and
            type(request['version']) is int and request['version']==1,'PACKAGE_SCHEMA')
    obj=parse_bundle(encoded(request['bundle']))
    runtime=request['runtime']
    require(isinstance(runtime,dict) and set(runtime)=={'python','bootstrap_context','bundle_path',
            'bundle_context','launch_context','startup_seconds','shutdown_seconds'},'PACKAGE_RUNTIME')
    require(set(sources)==MODULES and all(isinstance(v,bytes) for v in sources.values()) and
            isinstance(bootstrap,bytes),'PACKAGE_SOURCES')
    for name, payload in sources.items():
        require(sha(payload)==obj['source']['files'][name],'PACKAGE_SOURCE_HASH')
        compile(payload.decode('utf-8'),name,'exec',dont_inherit=True)
    compile(bootstrap.decode('utf-8'),'harbor_recovery_bootstrap.py','exec',dont_inherit=True)
    for key in ('bootstrap_context','bundle_context','launch_context'): label(runtime[key])
    bundle_path=runtime['bundle_path']
    require(absolute(bundle_path) and bundle_path.startswith('/etc/fds-harbor-recovery/bundles/') and
            bundle_path.endswith('.json'),'PACKAGE_BUNDLE_PATH')
    bootstrap_path='/opt/fds-harbor-recovery/bootstrap/'+sha(bootstrap)+'/harbor_recovery_bootstrap.py'
    unit=unit_text(runtime['python'],bootstrap_path,runtime['launch_context'],
                   startup_seconds=runtime['startup_seconds'],shutdown_seconds=runtime['shutdown_seconds']).encode()
    manager=obj['manager']['fragment']
    require(manager=='/etc/systemd/system/fds-harbor-recovery.service' and obj['manager']['dropins']==[],
            'PACKAGE_MANAGER_SCOPE')
    require(sha(unit)==obj['host_policy']['files'][manager]['sha256'],'PACKAGE_UNIT_HASH')
    require(runtime['shutdown_seconds'] >= obj['plan']['start_seconds']+3*obj['plan']['max_age_seconds']+5,
            'PACKAGE_SHUTDOWN_BUDGET')
    p=obj['host_policy']; engine=UnixEngine(p['api_version'],socket_path=p['socket'])
    require(obj['plan']['execution_binding']==execution_binding(bound_host_digest(obj),p['project'],engine.binding),
            'PACKAGE_EXECUTION_BINDING')
    bundle=encoded(obj)
    launch=encoded({'version':1,'bundle':bundle_path,'sha256':sha(bundle),'context':runtime['bundle_context']})
    files=dict(sources,**{'harbor_recovery_bootstrap.py':bootstrap,'manager.service':unit,
                         'bundle.json':bundle,'launch.json':launch})
    entries=[]
    def entry(name,target,mode,context):
        entries.append({'file':name,'target':target,'sha256':sha(files[name]),'bytes':len(files[name]),
                        'uid':0,'gid':0,'mode':mode,'selinux':context,'existing_target':'STOP_NO_OVERWRITE'})
    for name in sorted(sources):
        target=obj['source']['directory']+'/'+name
        spec=p['files'][target]
        require(spec['gid']==0,'PACKAGE_SOURCE_GID')
        entry(name,target,spec['mode'],spec['selinux'])
    entry('harbor_recovery_bootstrap.py',bootstrap_path,0o444,runtime['bootstrap_context'])
    entry('manager.service',manager,p['files'][manager]['mode'],p['files'][manager]['selinux'])
    entry('bundle.json',bundle_path,0o600,runtime['bundle_context'])
    entry('launch.json','/etc/fds-harbor-recovery/launch.json',0o400,runtime['launch_context'])
    require(len({e['target'] for e in entries})==len(entries),'PACKAGE_TARGET_COLLISION')
    plan={'schema':'fds.harbor.review-package.v1','status':'PREPARED_NOT_APPROVED_NOT_INSTALLED',
          'input_sha256':expected_input_sha256,'source_revision':obj['source']['revision'],
          'files':entries,'store':deepcopy(obj['store']),
          'external_existing_inputs':{k:v for k,v in p['files'].items() if k not in {e['target'] for e in entries}},
          'prerequisites':['Exact HEAD independent review','Fresh clone identity/isolation and restore point',
                           'Trusted Python/stdlib/bootstrap provenance','Approved metadata/SELinux contexts',
                           'Complete external existing inputs','Exact package Runtime scope and recovery handoff'],
          'apply':'NOT_IMPLEMENTED_REQUIRES_TARGET_INPUT_REVIEW',
          'rollback':'Preserve state/claims/logs; never delete or overwrite changed/unowned paths',
          'automatic_deletion':False,'runtime_go':False}
    files['INSTALL_PLAN.json']=encoded(plan)
    return files,plan


def write_package(directory,files):
    directory=Path(directory)
    directory.mkdir(mode=0o700,parents=False,exist_ok=False)
    # Any failure leaves partial material for inspection. Never delete/reuse it.
    for name,raw in sorted(files.items()):
        require(Path(name).name==name and name not in ('.','..'),'PACKAGE_OUTPUT_NAME')
        with (directory/name).open('xb') as stream: stream.write(raw)
    return directory


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    p.add_argument('--input',required=True); p.add_argument('--input-sha256',required=True)
    p.add_argument('--output',required=True)
    args=p.parse_args(argv)
    try:
        source={name:(ROOT/'scripts/recovery'/name).read_bytes() for name in MODULES}
        boot=(ROOT/'scripts/bootstrap/harbor_recovery_bootstrap.py').read_bytes()
        files,plan=prepare(Path(args.input).read_bytes(),args.input_sha256,source,boot)
        write_package(args.output,files)
        print(json.dumps({'status':plan['status'],'files':len(files),'runtime_go':False}))
        return 0
    except Exception:
        print('{"status":"STOP","partial_output":"PRESERVE_IF_PRESENT","runtime_go":false}')
        return 2


if __name__=='__main__':raise SystemExit(main())
