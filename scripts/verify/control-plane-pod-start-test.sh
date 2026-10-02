#!/usr/bin/env bash
# P1-HBR-01 AC-03 split runtime — Control-plane plane only.
# Performs Pod create/Ready/digest binding/cleanup using an approved Kubernetes context.
# Node-local container-runtime operations are intentionally NOT performed here.
set -euo pipefail
set +x
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/load-review-run-env.sh"
source "${SCRIPT_DIR}/lib/pod-review-binding.sh"
source "${SCRIPT_DIR}/lib/pod-review-lifecycle.sh"

HARBOR_REGISTRY="10.1.93.54"

require_pod_review_inputs || {
  echo "ERROR: invalid Kubernetes review inputs" >&2
  exit 1
}

POD_OVERRIDES_FILE="${POD_OVERRIDES_FILE:-${SCRIPT_DIR}/pod-restricted-psa-overrides.json}"
CLEANUP_TIMEOUT_SECONDS="${CLEANUP_TIMEOUT_SECONDS:-60}"
[[ "${CLEANUP_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]] || exit 1

: "${CA_FILE:?Harbor CA file required}"
[ -f "${CA_FILE}" ] || exit 1

if [ -z "${WORKER_ROBOT_USER:-}" ] || [ -z "${WORKER_ROBOT_SECRET:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER / WORKER_ROBOT_SECRET required" >&2
  exit 1
fi

[[ "${WORKER_ROBOT_USER}" != *:* &&
   "${WORKER_ROBOT_USER}" != *$'\n'* &&
   "${WORKER_ROBOT_USER}" != *$'\r'* ]] || exit 1
[[ "${WORKER_ROBOT_SECRET}" != *$'\n'* &&
   "${WORKER_ROBOT_SECRET}" != *$'\r'* ]] || exit 1

load_review_run_env "./review-run.env" "./review-run.env.sha256" || exit 1

POD_IMAGE="${HARBOR_REGISTRY}/fds/test@${EXPECTED_HARBOR_DIGEST}"
RUN_NONCE="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ "${RUN_NONCE}" =~ ^[0-9a-f]{32}$ ]] || exit 1
POD_NAME="p1-hbr-${RUN_NONCE}"

[ -f "${POD_OVERRIDES_FILE}" ] || {
  echo "ERROR: POD_OVERRIDES_FILE missing: ${POD_OVERRIDES_FILE}" >&2
  exit 1
}
jq -e '(.spec.containers | length) == 1' "${POD_OVERRIDES_FILE}" >/dev/null || exit 1
POD_CONTAINER_NAME="$(jq -er '.spec.containers[0].name | select(type == "string" and length > 0)' "${POD_OVERRIDES_FILE}")"

export WORKER_ROBOT_USER WORKER_ROBOT_SECRET
preflight_pod_review || exit 1

POD_MANIFEST="$(jq   --arg name "${POD_NAME}"   --arg ns "${NAMESPACE}"   --arg run "${REVIEW_RUN_ID}"   --arg nonce "${RUN_NONCE}"   --arg img "${POD_IMAGE}"   --arg node "${NODE_NAME}"   --arg sa "${SERVICE_ACCOUNT_NAME}"   --arg secret "${PULL_SECRET_NAME}" '
    .apiVersion = "v1" | .kind = "Pod"
    | .metadata = {name:$name, namespace:$ns, labels:{"review-run-id":$run,"review-invocation":$nonce}}
    | .spec.containers[0].image = $img
    | .spec.containers[0].imagePullPolicy = "Always"
    | .spec.nodeName = $node
    | .spec.serviceAccountName = $sa
    | .spec.automountServiceAccountToken = false
    | .spec.imagePullSecrets = [{name:$secret}]
    | .spec.restartPolicy = "Never"
  ' "${POD_OVERRIDES_FILE}")"

TEST_AUTH_DIR=""
POD_UID=""
CREATE_ATTEMPTED=0
LOGIN_ATTEMPTED=0
REVIEW_CHECKS_PASSED=0

trap 'cleanup_review 130' INT
trap 'cleanup_review 143' TERM
trap cleanup_review EXIT

CREATE_ATTEMPTED=1
CREATE_RESPONSE=""
if ! CREATE_RESPONSE=$(printf '%s' "${POD_MANIFEST}" | "${KUBECTL[@]}" create -f - -o json); then
  echo "ERROR: create failed/response lost; cleanup will attempt invocation-bound recovery" >&2
  exit 1
fi

if ! POD_UID=$(printf '%s' "${CREATE_RESPONSE}" | owned_pod_uid); then
  echo "ERROR: invalid create response; cleanup will attempt invocation-bound recovery" >&2
  exit 1
fi

echo "CREATED: context=${KUBE_CONTEXT} namespace=${NAMESPACE} pod=${POD_NAME} uid=${POD_UID} run=${REVIEW_RUN_ID} invocation=${RUN_NONCE} node=${NODE_NAME}"

"${KUBECTL[@]}" wait --for=condition=Ready "pod/${POD_NAME}" -n "${NAMESPACE}" --timeout=60s

export KUBE_CONTEXT NAMESPACE NODE_NAME SERVICE_ACCOUNT_NAME PULL_SECRET_NAME EXPECTED_HARBOR_DIGEST
export POD_UID REVIEW_RUN_ID RUN_NONCE CA_FILE

bash "${SCRIPT_DIR}/digest-traceability-check.sh"   "${NAMESPACE}" "${POD_NAME}" "${POD_CONTAINER_NAME}" "${POD_IMAGE}"

echo "AC03_CONTROL_RESULT=PASS REVIEW_RUN_ID=${REVIEW_RUN_ID} TEST_TAG=${TEST_TAG} NODE_NAME=${NODE_NAME} EXPECTED_HARBOR_DIGEST=${EXPECTED_HARBOR_DIGEST}"
REVIEW_CHECKS_PASSED=1
