#!/usr/bin/env python3
"""Mock/fault verification for P1-HBR-01 AC-03 split runtime scripts."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts" / "verify"
WORKER = VERIFY / "worker-node-access-test.sh"
CONTROL = VERIFY / "control-plane-pod-start-test.sh"

MOCK = r'''#!/usr/bin/env python3
import base64, json, os, pathlib, shutil, sys, tempfile
name=pathlib.Path(sys.argv[0]).name
a=sys.argv[1:]
root=pathlib.Path(os.environ['CASE_DIR'])
mode=os.environ.get('MOCK_MODE','normal')
with (root/'calls.jsonl').open('a') as f:
    f.write(json.dumps({'cmd':name,'args':a})+'\n')

if name=='hostname':
    print(os.environ.get('MOCK_HOST','k8s-worker01'))
    sys.exit(0)

if name=='sudo':
    if a and a[0]=='-E': a=a[1:]
    if a and a[0]=='mktemp':
        print(tempfile.mkdtemp(dir=root/'tmp')); sys.exit(0)
    if a and a[0]=='chmod':
        os.chmod(a[2],int(a[1],8)); sys.exit(0)
    if a and a[0]=='rm':
        p=pathlib.Path(a[-1]).resolve()
        assert p.is_relative_to(root/'tmp')
        shutil.rmtree(p,ignore_errors=False); sys.exit(0)
    if a and a[0]=='env':
        a=a[1:]
        while a and '=' in a[0]:
            k,v=a.pop(0).split('=',1); os.environ[k]=v
    assert a and a[0] in ('crictl','nerdctl'),a
    os.execv(str(pathlib.Path(sys.argv[0]).parent/a[0]),a)

if name=='crictl':
    if a[0]=='pull':
        if mode=='pull_fail': sys.exit(1)
        print('pulled'); sys.exit(0)
    if a[0]=='inspecti':
        digest=os.environ['EXPECTED_IMAGE_DIGEST']
        if mode=='digest_mismatch':
            digest='10.1.93.54/fds/test@sha256:'+'b'*64
        print(json.dumps({'status':{'repoDigests':[digest]}})); sys.exit(0)

if name=='nerdctl':
    if 'login' in a:
        sys.stdin.read()
        if mode=='login_fail':
            print('unauthorized: authentication required'); sys.exit(1)
        sys.exit(0)
    if 'tag' in a: sys.exit(0)
    if 'push' in a:
        if mode=='push_success': sys.exit(0)
        if mode=='mixed_auth':
            print('denied: requested access\nunauthorized: authentication required'); sys.exit(1)
        print('denied: requested access'); sys.exit(1)
    if 'logout' in a: sys.exit(0)

if name=='kubectl':
    assert a[:2]==['--context','mock-context'],a
    assert a[2]=='--request-timeout=10s',a
    a=a[3:]
    pod=root/'pod.json'
    def read():
        return json.loads(pod.read_text()) if pod.exists() else None
    if a[0]=='get' and a[1] in ('namespace','node','serviceaccount'):
        if mode=='preflight_fail': sys.exit(1)
        print(a[1]+'/'+a[2]); sys.exit(0)
    if a[:2]==['get','secret']:
        if mode=='preflight_fail': sys.exit(1)
        auth=base64.b64encode((os.environ['WORKER_ROBOT_USER']+':'+os.environ['WORKER_ROBOT_SECRET']).encode()).decode()
        cfg={'auths':{'10.1.93.54':{'auth':auth}}}
        print(json.dumps({'type':'kubernetes.io/dockerconfigjson','data':{'.dockerconfigjson':base64.b64encode(json.dumps(cfg).encode()).decode()}}))
        sys.exit(0)
    if a[0]=='create':
        d=json.load(sys.stdin)
        d['metadata']['uid']='uid-created'
        digest=os.environ['EXPECTED_DIGEST']
        if mode=='pod_wrong_digest':
            digest='sha256:'+'b'*64
        d['status']={
          'conditions':[{'type':'Ready','status':'True'}],
          'containerStatuses':[{
            'name':d['spec']['containers'][0]['name'],
            'ready':True,
            'state':{'running':{}},
            'imageID':'10.1.93.54/fds/test@'+digest
          }]
        }
        pod.write_text(json.dumps(d))
        print(json.dumps(d)); sys.exit(0)
    if a[0]=='wait':
        if mode=='ready_fail': sys.exit(1)
        sys.exit(0)
    if a[:2]==['get','pod']:
        d=read()
        if d is None:
            if '--ignore-not-found' in a: sys.exit(0)
            sys.exit(1)
        print(json.dumps(d)); sys.exit(0)
    if a[0]=='delete':
        opts=json.load(sys.stdin)
        d=read()
        assert d and opts['preconditions']['uid']==d['metadata']['uid']
        pod.unlink()
        sys.exit(0)
    raise SystemExit('unhandled kubectl '+repr(a))

if name=='curl':
    digest=os.environ['EXPECTED_DIGEST']
    if mode=='harbor_wrong_digest': digest='sha256:'+'b'*64
    print('HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\nDocker-Content-Digest: '+digest+'\r\n')
    sys.exit(0)

raise SystemExit('unhandled '+name+' '+repr(a))
'''

def prepare_case(name):
    d = Path(tempfile.mkdtemp(prefix=f"hbr-ac03-{name}-"))
    (d / "tmp").mkdir()
    raw = "TEST_TAG=ifup-20261002T071118Z\nREVIEW_RUN_ID=hbr-20261002-161052-d57ab5dc\n"
    (d / "review-run.env").write_text(raw)
    (d / "review-run.env.sha256").write_text(
        hashlib.sha256(raw.encode()).hexdigest() + "  review-run.env\n"
    )
    digest = "sha256:" + "a"*64
    summary = (
        "RUN_ID=hbr-20261002-161052-d57ab5dc\n"
        "TEST_TAG=ifup-20261002T071118Z\n"
        f"EXPECTED_HARBOR_DIGEST={digest}\n"
        "IMAGE=10.1.93.54/fds/test:ifup-20261002T071118Z\n"
        "BASE_IMAGE_REF=docker.io/library/alpine@sha256:" + "c"*64 + "\n"
        "WRAPPER_SHA256=" + "d"*64 + "\n"
        "CHILD_RC=0\n"
        "EVIDENCE_SEAL=OK\n"
    )
    (d / "summary.txt").write_text(summary)
    seal = []
    for name in ("review-run.env", "review-run.env.sha256", "summary.txt"):
        data = (d / name).read_bytes()
        seal.append(hashlib.sha256(data).hexdigest() + "  " + name)
    (d / "SHA256SUMS").write_text("\n".join(seal) + "\n")
    (d / "ca.pem").write_text("MOCK CA\n")
    b = d / "bin"; b.mkdir()
    for cmd in ("hostname","sudo","crictl","nerdctl","kubectl","curl"):
        p=b/cmd; p.write_text(MOCK); p.chmod(0o755)
    return d,b

def run_worker(case, mode="normal", host="k8s-worker01", expected=0, supplied_digest=None, tamper=None):
    d,b=prepare_case(case)
    digest="sha256:"+"a"*64
    if tamper == "summary":
        (d/"summary.txt").write_text((d/"summary.txt").read_text()+"TAMPER=1\n")
    elif tamper == "seal":
        text=(d/"SHA256SUMS").read_text()
        (d/"SHA256SUMS").write_text(text.replace(text.split()[0], "0"*64, 1))
    env=dict(os.environ,
        PATH=str(b)+":"+os.environ["PATH"],
        CASE_DIR=str(d), MOCK_MODE=mode, MOCK_HOST=host, TMPDIR=str(d/"tmp"),
        WORKER_ROBOT_USER="robot$worker",
        WORKER_ROBOT_SECRET="DUMMY_SECRET_ONLY",
        NODE_NAME="k8s-worker01",
        EXPECTED_IMAGE_DIGEST="10.1.93.54/fds/test@"+digest,
    )
    if supplied_digest is not None:
        env["EXPECTED_HARBOR_DIGEST"]=supplied_digest
    cp=subprocess.run(["bash",str(WORKER)],cwd=d,env=env,text=True,capture_output=True,timeout=15)
    text=cp.stdout+cp.stderr
    ok=(cp.returncode==expected and "DUMMY_SECRET_ONLY" not in text)
    if expected==0:
        ok=ok and "AC03_NODE_RESULT=PASS" in cp.stdout
    shutil.rmtree(d)
    return ok,cp.returncode,text

def run_control(case, mode="normal", expected=0, host="k8s-control01"):
    d,b=prepare_case(case)
    digest="sha256:"+"a"*64
    env=dict(os.environ,
        PATH=str(b)+":"+os.environ["PATH"],
        CASE_DIR=str(d), MOCK_MODE=mode, MOCK_HOST=host, TMPDIR=str(d/"tmp"),
        EXPECTED_DIGEST=digest,
        WORKER_ROBOT_USER="robot$worker",
        WORKER_ROBOT_SECRET="DUMMY_SECRET_ONLY",
        KUBE_CONTEXT="mock-context",
        NAMESPACE="fds-app",
        NODE_NAME="k8s-worker01",
        SERVICE_ACCOUNT_NAME="default",
        PULL_SECRET_NAME="harbor-pull-secret",
        CA_FILE=str(d/"ca.pem"),
        CLEANUP_TIMEOUT_SECONDS="1",
    )
    cp=subprocess.run(["bash",str(CONTROL)],cwd=d,env=env,text=True,capture_output=True,timeout=15)
    text=cp.stdout+cp.stderr
    pod_left=(d/"pod.json").exists()
    ok=(cp.returncode==expected and "DUMMY_SECRET_ONLY" not in text)
    if expected==0:
        ok=ok and "AC03_CONTROL_RESULT=PASS" in cp.stdout and not pod_left
    shutil.rmtree(d)
    return ok,cp.returncode,text

cases=[
    ("worker-normal", run_worker("worker-normal", expected=0)),
    ("worker-host-mismatch", run_worker("worker-host-mismatch", host="k8s-worker02", expected=1)),
    ("worker-digest-mismatch", run_worker("worker-digest-mismatch", mode="digest_mismatch", expected=1)),
    ("worker-mixed-auth", run_worker("worker-mixed-auth", mode="mixed_auth", expected=1)),
    ("worker-push-success", run_worker("worker-push-success", mode="push_success", expected=1)),
    ("worker-summary-tamper", run_worker("worker-summary-tamper", tamper="summary", expected=1)),
    ("worker-stale-seal", run_worker("worker-stale-seal", tamper="seal", expected=1)),
    ("worker-supplied-digest-mismatch", run_worker("worker-supplied-digest-mismatch", supplied_digest="sha256:"+"b"*64, expected=1)),
    ("control-normal", run_control("control-normal", expected=0)),
    ("control-host-mismatch", run_control("control-host-mismatch", host="k8s-control02", expected=1)),
    ("control-preflight-fail", run_control("control-preflight-fail", mode="preflight_fail", expected=1)),
    ("control-ready-fail", run_control("control-ready-fail", mode="ready_fail", expected=1)),
    ("control-pod-wrong-digest", run_control("control-pod-wrong-digest", mode="pod_wrong_digest", expected=1)),
    ("control-harbor-wrong-digest", run_control("control-harbor-wrong-digest", mode="harbor_wrong_digest", expected=1)),
]

failed=[]
for name,(ok,rc,text) in cases:
    print(json.dumps({"case":name,"ok":ok,"rc":rc}))
    if not ok:
        failed.append((name,rc,text[-2000:]))

if failed:
    for name,rc,text in failed:
        print(f"FAIL_DETAIL {name} rc={rc}\n{text}")
    raise SystemExit(1)

print(f"P1_HBR_AC03_SPLIT_MOCK=PASS cases={len(cases)}")
