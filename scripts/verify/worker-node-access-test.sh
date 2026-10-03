#!/usr/bin/env bash
# P1-HBR-01 AC-03 split runtime — Worker-local plane only.
# Performs node-local pull + exact RepoDigest binding + Worker Robot push DENY.
# Kubernetes API operations are intentionally NOT performed on Worker nodes.
set -euo pipefail
set +x
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/load-review-run-handoff.sh"

HARBOR_REGISTRY="10.1.93.54"

: "${NODE_NAME:?target Worker required}"
[[ "${NODE_NAME}" =~ ^k8s-worker0[123]$ ]] || {
  echo "ERROR: invalid NODE_NAME=${NODE_NAME}" >&2
  exit 1
}

ACTUAL_NODE="$(hostname -s)"
[ "${ACTUAL_NODE}" = "${NODE_NAME}" ] || {
  echo "ERROR: execution host mismatch expected=${NODE_NAME} actual=${ACTUAL_NODE}" >&2
  exit 1
}

if [ -z "${WORKER_ROBOT_USER:-}" ] || [ -z "${WORKER_ROBOT_SECRET:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER / WORKER_ROBOT_SECRET required" >&2
  exit 1
fi

[[ "${WORKER_ROBOT_USER}" != *:* &&
   "${WORKER_ROBOT_USER}" != *$'\n'* &&
   "${WORKER_ROBOT_USER}" != *$'\r'* ]] || {
  echo "ERROR: unsafe Worker Robot username syntax" >&2
  exit 1
}
[[ "${WORKER_ROBOT_SECRET}" != *$'\n'* &&
   "${WORKER_ROBOT_SECRET}" != *$'\r'* ]] || {
  echo "ERROR: unsafe Worker Robot secret syntax" >&2
  exit 1
}

load_review_run_handoff "." || exit 1

TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"
EXPECTED_IMAGE_DIGEST="${HARBOR_REGISTRY}/fds/test@${EXPECTED_HARBOR_DIGEST}"
DENY_TEST_TAG="worker-push-denytest-${REVIEW_RUN_ID}-${NODE_NAME}"
DENY_TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${DENY_TEST_TAG}"

TEST_AUTH_DIR=""
LOGIN_ATTEMPTED=0
LOCAL_DENY_TAG_CREATED=0

cleanup_node_review() {
  local rc="${1:-$?}" failed=0
  trap - EXIT INT TERM

  if [ -n "${TEST_AUTH_DIR}" ]; then
    if [ "${LOCAL_DENY_TAG_CREATED}" -eq 1 ]; then
      sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io image rm "${DENY_TEST_IMAGE}" >/dev/null 2>&1 || failed=1
    fi
    if [ "${LOGIN_ATTEMPTED}" -eq 1 ]; then
      sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io logout "${HARBOR_REGISTRY}" >/dev/null 2>&1 || failed=1
    fi
    sudo rm -rf -- "${TEST_AUTH_DIR}" || failed=1
  fi

  unset WORKER_ROBOT_SECRET

  if [ "${failed}" -ne 0 ]; then
    echo "ERROR: Worker-local cleanup incomplete node=${NODE_NAME} run=${REVIEW_RUN_ID}" >&2
    [ "${rc}" -ne 0 ] || rc=1
  fi
  exit "${rc}"
}
trap 'cleanup_node_review 130' INT
trap 'cleanup_node_review 143' TERM
trap cleanup_node_review EXIT

TEST_AUTH_DIR="$(sudo mktemp -d)"
sudo chmod 0700 "${TEST_AUTH_DIR}"

# 1. Authenticate explicitly with the Worker Robot. The secret is read on stdin,
# never placed in argv. DOCKER_CONFIG is scoped to the temporary directory only.
LOGIN_ATTEMPTED=1
LOGIN_OUTPUT=""
LOGIN_EXIT_CODE=0
LOGIN_OUTPUT=$(printf '%s' "${WORKER_ROBOT_SECRET}" |
  sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io login "${HARBOR_REGISTRY}" \
    --username "${WORKER_ROBOT_USER}" \
    --password-stdin 2>&1) || LOGIN_EXIT_CODE=$?

if [ "${LOGIN_EXIT_CODE}" -ne 0 ]; then
  echo "ERROR: Worker Robot login failed; Pull/Push authorization tests invalid node=${NODE_NAME}" >&2
  echo "Login Output: ${LOGIN_OUTPUT}" >&2
  exit 1
fi

# 2. Worker-local Pull positive through the authenticated containerd client.
# Do not use an undocumented credential environment variable. crictl is used
# only to observe the resulting CRI image inventory and exact RepoDigest.
PULL_EXIT_CODE=0
sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io \
  --hosts-dir /etc/containerd/certs.d pull "${TEST_IMAGE}" || PULL_EXIT_CODE=$?

if [ "${PULL_EXIT_CODE}" -ne 0 ]; then
  echo "FAIL: authenticated Worker Robot pull failed node=${NODE_NAME} rc=${PULL_EXIT_CODE}" >&2
  exit 1
fi

INSPECT_JSON="$(sudo crictl inspecti "${TEST_IMAGE}")" || {
  echo "ERROR: crictl inspecti failed after authenticated pull node=${NODE_NAME}" >&2
  exit 1
}

if ! printf '%s' "${INSPECT_JSON}" |
  jq -e --arg expected "${EXPECTED_IMAGE_DIGEST}" '
    (.status.repoDigests // []) | index($expected) != null
  ' >/dev/null; then
  echo "ERROR: Worker pulled image is not bound to approved digest node=${NODE_NAME} expected=${EXPECTED_IMAGE_DIGEST}" >&2
  exit 1
fi
echo "PASS: Worker Robot authenticated Pull + exact CRI RepoDigest node=${NODE_NAME} image=${EXPECTED_IMAGE_DIGEST}"

# 3. Login is already proven. Re-tag only for the authorization-negative push.
sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io tag "${TEST_IMAGE}" "${DENY_TEST_IMAGE}"
LOCAL_DENY_TAG_CREATED=1

PUSH_OUTPUT=""
PUSH_EXIT_CODE=0
PUSH_OUTPUT=$(sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io   --hosts-dir /etc/containerd/certs.d push "${DENY_TEST_IMAGE}" 2>&1) || PUSH_EXIT_CODE=$?

AMBIGUOUS_PUSH_MARKERS='unauthorized: authentication required|timeout|TLS|certificate|connection refused|EOF|temporary failure|dial tcp'
if [ "${PUSH_EXIT_CODE}" -ne 0 ] &&
   echo "${PUSH_OUTPUT}" | grep -iqE "${AMBIGUOUS_PUSH_MARKERS}"; then
  echo "ERROR: Push output contains authentication/transport ambiguity node=${NODE_NAME}" >&2
  echo "Push Output: ${PUSH_OUTPUT}" >&2
  exit 1
elif [ "${PUSH_EXIT_CODE}" -ne 0 ] &&
     echo "${PUSH_OUTPUT}" | grep -iqE 'denied: requested access|unauthorized to access repository.*action: push'; then
  echo "PASS: Worker Push DENY authorization check node=${NODE_NAME}"
else
  echo "FAIL: Worker Push was not a verified authorization denial node=${NODE_NAME}" >&2
  echo "Push Output: ${PUSH_OUTPUT}" >&2
  exit 1
fi

echo "AC03_NODE_RESULT=PASS REVIEW_RUN_ID=${REVIEW_RUN_ID} TEST_TAG=${TEST_TAG} NODE_NAME=${NODE_NAME} EXPECTED_HARBOR_DIGEST=${EXPECTED_HARBOR_DIGEST}"
