# P1-HBR-01 AC-03 Split Runtime Runbook

## Purpose

Validate the same approved IF-09 Review Run across three Workers without copying an
admin kubeconfig or creating temporary Worker-side Kubernetes credentials.

The verification is split into two planes that must use the same:

- `REVIEW_RUN_ID`
- `TEST_TAG`
- `EXPECTED_HARBOR_DIGEST`
- target `NODE_NAME`

The split is intentional and preserves the current operating model:

- Worker: node-local CRI/container-runtime verification only.
- control01: Kubernetes API / Pod lifecycle / Harbor↔Pod digest binding only.

The legacy combined `worker-pull-pod-start-test.sh` remains in the repository for
history/backward compatibility but is not the preferred path for the current lab
because Workers do not hold an approved kubeconfig.

## Security boundary

Do not:

- copy `admin.conf` or any admin kubeconfig to Workers;
- create a temporary ServiceAccount/Role/Binding solely to satisfy the old combined script;
- place bearer tokens, Worker Robot passwords, or private keys in evidence;
- use `--insecure-skip-tls-verify`, `-k`, or disable certificate verification;
- change Harbor/Worker firewall or Kubernetes security controls as part of this test.

Use the existing approved context on control01 only.

## Authoritative Review Run

Use the HBR Lead-declared official AC-02 Review Run. Do not replace it with a later
supplemental revalidation unless the Lead explicitly changes the handoff.

Before runtime, the Lead provides these sealed files from the official Run:

- `review-run.env`
- `review-run.env.sha256`
- `summary.txt`
- `SHA256SUMS`

Each split script verifies the official handoff itself before any runtime action:
- `review-run.env` against `review-run.env.sha256`;
- `review-run.env`, `review-run.env.sha256`, and `summary.txt` against the official `SHA256SUMS`;
- `RUN_ID` / `TEST_TAG` equality between env and summary;
- `CHILD_RC=0` and `EVIDENCE_SEAL=OK`;
- the exact `EXPECTED_HARBOR_DIGEST` from the sealed `summary.txt`.

Do not infer or manually choose a digest from a tag. If an operator pre-supplies
`EXPECTED_HARBOR_DIGEST`, the script treats it only as a cross-check and stops
unless it exactly matches the sealed summary.

## Current lab inputs

Current environment identified in baseline #13:

- namespace: `fds-app`
- approved workload service account: `transaction-api-sa` or `fds-engine-sa`
- pull secret: `harbor-pull-secret`
- Workers:
  - `k8s-worker01`
  - `k8s-worker02`
  - `k8s-worker03`
- Harbor: `10.1.93.54`

Use the manifest digest from the official AC-02 `summary.txt`; do not infer it
from a tag.

## Phase A — Worker-local plane

Run on each Worker separately.

Required files in the working directory:

- `review-run.env`
- `review-run.env.sha256`
- `summary.txt`
- `SHA256SUMS`

Required environment:

- `NODE_NAME` = actual Worker hostname
- `WORKER_ROBOT_USER`
- `WORKER_ROBOT_SECRET`

`EXPECTED_HARBOR_DIGEST` is derived from the sealed official `summary.txt`; it
is not a normal operator input.

Inject the secret interactively in the shell; do not place the value in command
history or a file.

Example shell preparation:

```bash
set +x
read -rsp 'robot$worker password: ' WORKER_ROBOT_SECRET
echo
export WORKER_ROBOT_SECRET
export WORKER_ROBOT_USER='robot$worker'
export NODE_NAME="$(hostname -s)"

bash ./worker-node-access-test.sh
RC=$?
echo "AC03_NODE_RC=$RC"
unset WORKER_ROBOT_SECRET
```

PASS requires all of:

- execution host == `NODE_NAME`;
- `crictl pull` succeeds with Worker Robot;
- `crictl inspecti` reports exact
  `10.1.93.54/fds/test@<EXPECTED_HARBOR_DIGEST>`;
- Worker Robot login succeeds;
- unique-tag push is denied specifically by authorization;
- ambiguous auth/TLS/transport failures are ERROR, not PASS;
- local temporary auth directory is removed.

Capture host/user/KST/source commit/command/rc/raw output and SHA256.

## Phase B — control01 Kubernetes plane

Run on control01 only. Do not distribute its kubeconfig.

Required files:

- the same `review-run.env`
- the same `review-run.env.sha256`
- the same `summary.txt`
- the same official `SHA256SUMS`
- `pod-restricted-psa-overrides.json`
- approved Root CA file

Required environment:

- actual execution host = **`k8s-control01`**; the script checks `hostname -s`
  and stops before Kubernetes mutation on any mismatch
- `KUBE_CONTEXT` = current approved control01 context
- `NAMESPACE=fds-app`
- `NODE_NAME` = one of the three Workers
- `SERVICE_ACCOUNT_NAME` = `transaction-api-sa` or `fds-engine-sa` only; `default` is not accepted
- `PULL_SECRET_NAME=harbor-pull-secret`
- `CA_FILE` = approved Root CA
- Worker Robot credentials, supplied interactively

The exact digest is again derived from the sealed official `summary.txt`.

Before the first run:

```bash
kubectl config current-context
kubectl --context "$KUBE_CONTEXT" get namespace fds-app
```

For each Worker:

```bash
set +x
read -rsp 'robot$worker password: ' WORKER_ROBOT_SECRET
echo
export WORKER_ROBOT_SECRET
export WORKER_ROBOT_USER='robot$worker'

export NAMESPACE='fds-app'
export SERVICE_ACCOUNT_NAME='transaction-api-sa'
export PULL_SECRET_NAME='harbor-pull-secret'
export NODE_NAME='k8s-worker01'   # change for worker02/03
export CA_FILE='<approved-root-ca-path>'
export KUBE_CONTEXT='<approved-control01-context>'

bash ./control-plane-pod-start-test.sh
RC=$?
echo "AC03_CONTROL_RC=$RC"
unset WORKER_ROBOT_SECRET
```

PASS requires:

- namespace/node/approved workload service account/pull secret preflight passes;
- existing pull secret matches the supplied Worker Robot without logging its bytes;
- a unique Pod is created with:
  - exact immutable Harbor digest;
  - target `NODE_NAME`;
  - `automountServiceAccountToken=false`;
  - explicit `harbor-pull-secret`;
  - restricted PSA-compatible security context;
- Pod reaches Ready;
- one bound Pod snapshot matches UID/run/invocation/node/container;
- Harbor manifest digest == Pod imageID digest;
- UID-preconditioned cleanup completes and absence is confirmed.

## AC-03 aggregation

For every Worker, require both planes to PASS with the same:

- official `REVIEW_RUN_ID`
- `TEST_TAG`
- `EXPECTED_HARBOR_DIGEST`
- `NODE_NAME`

Expected matrix:

| Worker | Node-local Pull/Digest | Push DENY | Pod Ready | Harbor↔Pod Digest | Cleanup |
|---|---|---|---|---|---|
| worker01 | PASS | PASS | PASS | PASS | PASS |
| worker02 | PASS | PASS | PASS | PASS | PASS |
| worker03 | PASS | PASS | PASS | PASS | PASS |

A partial matrix is not AC-03 PASS.

## Evidence

Create one collection for the official Review Run with separate raw logs:

- `worker01-node.log`
- `worker02-node.log`
- `worker03-node.log`
- `worker01-control.log`
- `worker02-control.log`
- `worker03-control.log`
- the official sealed `review-run.env` + `review-run.env.sha256`
- the official sealed `summary.txt`
- the official Formal Run `SHA256SUMS`
- a separate collection `SHA256SUMS` for the AC-03 logs
- source commit / script hashes

Never include Robot password/token bytes.

Evidence import and AC acceptance remain separate. The evidence PR needs an
independent reviewer who did not execute the runtime.

## Stop conditions

Stop and preserve raw output if:

- official Review Run env/summary/seal do not match;
- an operator-supplied digest (if any) differs from the sealed official digest;
- exact Harbor digest differs;
- Worker hostname differs from `NODE_NAME`;
- pull/login fails;
- push result is ambiguous or succeeds;
- existing pull secret does not match the Worker Robot;
- Pod create/wait/digest binding fails;
- cleanup is incomplete;
- any unexpected cluster/security mutation is required.

Do not change RBAC, PSA, NetworkPolicy, firewall, Harbor project policy, or
certificate verification to make the test pass.
