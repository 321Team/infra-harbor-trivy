#!/usr/bin/env python3
"""Static contract for P1-HBR-01 AC-03 split runtime tools."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts" / "verify"
WORKER = (VERIFY / "worker-node-access-test.sh").read_text(encoding="utf-8")
CONTROL = (VERIFY / "control-plane-pod-start-test.sh").read_text(encoding="utf-8")
HANDOFF = (VERIFY / "lib" / "load-review-run-handoff.sh").read_text(encoding="utf-8")


def require(cond, msg):
    if not cond:
        raise SystemExit(f"FAIL: {msg}")


for name, text in (("worker", WORKER), ("control", CONTROL)):
    require('load-review-run-handoff.sh' in text, f"{name}: sealed handoff loader missing")
    require('EXPECTED_HARBOR_DIGEST' in text, f"{name}: approved digest binding missing")
    require('REVIEW_RUN_ID' in text and 'TEST_TAG' in text,
            f"{name}: review-run identity binding missing")

# Worker plane must remain node-local and must not acquire/use Kubernetes API credentials.
for token in ('crictl pull', 'crictl inspecti', 'nerdctl -n k8s.io login',
              'worker-push-denytest-', 'AC03_NODE_RESULT=PASS'):
    require(token in WORKER, f"worker: required node-local contract missing: {token}")
require('kubectl ' not in WORKER and 'KUBE_CONTEXT' not in WORKER and 'KUBECONFIG' not in WORKER,
        "worker: Kubernetes API credential/use must not be introduced")
require('hostname -s' in WORKER and 'execution host mismatch' in WORKER,
        "worker: target node identity check missing")

# Control plane must remain Kubernetes/Harbor API only; no node-local sudo/CRI mutation path.
for token in ('pod-review-binding.sh', 'pod-review-lifecycle.sh',
              'preflight_pod_review', ' create -f - -o json',
              'wait --for=condition=Ready', 'digest-traceability-check.sh',
              'AC03_CONTROL_RESULT=PASS'):
    require(token in CONTROL, f"control: required pod contract missing: {token}")
for forbidden in ('sudo ', 'crictl ', 'nerdctl '):
    require(forbidden not in CONTROL, f"control: node-local command leaked into control plane: {forbidden}")

# Both planes must use the same exact target-node naming contract.
require('^k8s-worker0[123]$' in WORKER, "worker: node allowlist regex drift")
require('require_pod_review_inputs' in CONTROL, "control: shared pod input validator missing")
require('APPROVED_CONTROL_HOST="k8s-control01"' in CONTROL
        and 'control execution host mismatch' in CONTROL,
        "control: exact control01 execution host binding missing")
for token in ('summary.txt', 'SHA256SUMS', 'EXPECTED_HARBOR_DIGEST',
              'CHILD_RC', 'EVIDENCE_SEAL', 'load_review_run_env'):
    require(token in HANDOFF, f"handoff: missing official seal contract: {token}")

print("P1_HBR_AC03_SPLIT_CONTRACT=PASS")
