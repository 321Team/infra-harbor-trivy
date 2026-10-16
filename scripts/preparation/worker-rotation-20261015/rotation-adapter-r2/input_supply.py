"""Explicit root-local supply only. No remote connection, credential creation or server API."""
import hashlib
import json
import os
from pathlib import Path
import time
from rotation_contract import *
from linux_host import LinuxHost,regular_bytes,write_new,fsync_parent

def import_credential(h,raw):
    validate_plan(h.plan,h.wall_time())
    need(h.wall_time()<timestamp(h.plan['mutation_until']),'DEADLINE_EXPIRED')
    ready=h.receipt('stage')
    need(ready=={'status':'PASS','invocation':h.inv,'host':h.name,'plan_sha256':hashlib.sha256(encoded(h.plan)).hexdigest(),'robot_id':h.plan['new_robot']['id']},'STAGE_NOT_VERIFIED')
    c=credential(raw)
    path=h.runroot/'credential.json'
    write_new(path,encoded(c))
    s=path.lstat()
    # No password/fingerprint in the ownership marker or public status.
    write_new(h.runroot/'credential-owner.json',encoded({'invocation':h.inv,'device':s.st_dev,'inode':s.st_ino,'username':NEW_USER}))

def console_credential(h):
    import getpass
    import sys
    import warnings
    need(sys.stdin.isatty(),'PRIVATE_CONSOLE_REQUIRED')
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        password=getpass.getpass('New worker Robot secret (not echoed): ')
    import_credential(h,encoded({'username':NEW_USER,'password':password}))

def retire_credential(h):
    """Explicit, one fixed owned file; keep existing authentication/backup/claim untouched."""
    validate_plan(h.plan,h.wall_time())
    path=h.runroot/'credential.json';marker=h.runroot/'credential-owner.json'
    owner=parse_json(regular_bytes(marker)[0]);raw,s=regular_bytes(path,32768);credential(raw)
    need(owner=={'invocation':h.inv,'device':s.st_dev,'inode':s.st_ino,'username':NEW_USER},'CREDENTIAL_OWNER_CHANGED')
    need(h.wall_time()<timestamp(h.plan['not_after']),'DEADLINE_EXPIRED')
    path.unlink();fsync_parent(path);marker.unlink();fsync_parent(marker)

def import_receipt(h,key,raw,expected_hash):
    validate_plan(h.plan,h.wall_time())
    need(hashlib.sha256(raw).hexdigest()==expected_hash,'RECEIPT_HASH_MISMATCH')
    r=receipt_binding(h.plan,key,parse_json(raw),h.wall_time())
    # Only the 3 Worker -> control and last MON Pod -> worker01 links cross hosts.
    allowed={'k8s-control01':{'node-'+n for n in NODES},
             'k8s-worker01':{'pod-monitoring-node-k8s-worker01'}}
    need(key in allowed.get(h.name,set()),'RECEIPT_DESTINATION_SCOPE')
    write_new(h.root/'incoming'/(key+'.json'),encoded(r))

def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['credential','credential-console','receipt','retire-credential'])
    parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--source');parser.add_argument('--operation');parser.add_argument('--receipt-sha256')
    args=parser.parse_args()
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        raw,_=regular_bytes(args.plan)
        need(hashlib.sha256(raw).hexdigest()==args.plan_sha256,'PLAN_HASH_MISMATCH')
        plan=parse_json(raw);validate_plan(plan,time.time());h=LinuxHost(plan)
        if args.action=='retire-credential':retire_credential(h)
        elif args.action=='credential-console':console_credential(h)
        else:
            need(args.source is not None,'SOURCE_REQUIRED');source,_=regular_bytes(args.source,32768)
            if args.action=='credential':import_credential(h,source)
            else:import_receipt(h,args.operation,source,args.receipt_sha256)
        print('{"status":"SUPPLY_RETURNED"}');return 0
    except Stop as exc:print(json.dumps({'status':'STOP','code':exc.code}));return 2
    except BaseException:print('{"status":"STOP","code":"UNEXPECTED_ERROR_PRESERVE_STATE"}');return 2

if __name__=='__main__':raise SystemExit(main())
