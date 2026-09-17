#!/usr/bin/env bash
# P1-HBR-01 / AC-03, AC-05 — Worker Pull + Pod Start 검증 (containerd/CRI 기반)
# 관련 리뷰: fds-project-baseline#13 (HBR-01, HBR-02, HBR-03, HBR-05)
# 8차 리뷰 후속: https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615
# 실행 대상: k8s-worker01(.105), k8s-worker02(.107), k8s-worker03(.108) 각각 개별 실행
# Usage and required approved inputs: docs/runbooks/p1-hbr-01-worker-verify.md
set -euo pipefail

# HBR-01: Secret을 참조하는 어떤 줄보다도 먼저 xtrace를 끈다.
# (이전 버전은 아래 WORKER_ROBOT_SECRET 조건문 뒤에 위치해, 그 조건문 자체가
#  호출자의 bash -x 트레이스에 찍혀 Secret 값이 노출될 수 있었다.)
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# HBR-02: review-run.env를 source(실행)하지 않고 허용된 키만 값으로만 읽는
# 검증 로직은 worker-push-deny-test.sh와 동일해야 재발을 막을 수 있어
# 공통 함수로 뽑아 둘 다 같은 함수를 사용한다.
source "${SCRIPT_DIR}/lib/load-review-run-env.sh"

HARBOR_REGISTRY="10.1.93.54"
source "${SCRIPT_DIR}/lib/pod-review-binding.sh"
source "${SCRIPT_DIR}/lib/pod-review-lifecycle.sh"
require_pod_review_inputs || { echo "ERROR: invalid review inputs" >&2; exit 1; }
POD_OVERRIDES_FILE="${POD_OVERRIDES_FILE:-./pod-restricted-psa-overrides.json}"

if [ -z "${WORKER_ROBOT_SECRET:-}" ] || [ -z "${WORKER_ROBOT_USER:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi

load_review_run_env "./review-run.env" "./review-run.env.sha256" || exit 1

TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"
POD_IMAGE="${HARBOR_REGISTRY}/fds/test@${EXPECTED_HARBOR_DIGEST}"
RUN_NONCE="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$RUN_NONCE" =~ ^[0-9a-f]{32}$ ]] || exit 1
POD_NAME="p1-hbr-${RUN_NONCE}"
CLEANUP_TIMEOUT_SECONDS="${CLEANUP_TIMEOUT_SECONDS:-60}"
[[ "$CLEANUP_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || exit 1
: "${CA_FILE:?Harbor CA file required}"
[ -f "$CA_FILE" ] || exit 1
# Reject credential syntax that cannot be represented safely as Basic auth/config.
[[ "$WORKER_ROBOT_USER" != *:* && "$WORKER_ROBOT_USER" != *$'\n'* && "$WORKER_ROBOT_USER" != *$'\r'* ]] || exit 1
[[ "$WORKER_ROBOT_SECRET" != *$'\n'* && "$WORKER_ROBOT_SECRET" != *$'\r'* ]] || exit 1
export WORKER_ROBOT_USER WORKER_ROBOT_SECRET
preflight_pod_review || exit 1
[ -f "$POD_OVERRIDES_FILE" ] || exit 1
jq -e '(.spec.containers | length) == 1' "$POD_OVERRIDES_FILE" >/dev/null || exit 1
POD_CONTAINER_NAME=$(jq -er '.spec.containers[0].name | select(type == "string" and length > 0)' "$POD_OVERRIDES_FILE")
POD_MANIFEST=$(jq --arg name "$POD_NAME" --arg ns "$NAMESPACE" --arg run "$REVIEW_RUN_ID" \
  --arg nonce "$RUN_NONCE" --arg img "$POD_IMAGE" --arg node "$NODE_NAME" \
  --arg sa "$SERVICE_ACCOUNT_NAME" --arg secret "$PULL_SECRET_NAME" '
  .apiVersion = "v1" | .kind = "Pod"
  | .metadata = {name:$name, namespace:$ns, labels:{"review-run-id":$run,"review-invocation":$nonce}}
  | .spec.containers[0].image = $img | .spec.containers[0].imagePullPolicy = "Always"
  | .spec.nodeName = $node | .spec.serviceAccountName = $sa
  | .spec.automountServiceAccountToken = false | .spec.imagePullSecrets = [{name:$secret}]
  | .spec.restartPolicy = "Never"' "$POD_OVERRIDES_FILE")
TEST_AUTH_DIR="" POD_UID="" CREATE_ATTEMPTED=0 LOGIN_ATTEMPTED=0 REVIEW_CHECKS_PASSED=0
trap 'cleanup_review 130' INT
trap 'cleanup_review 143' TERM
trap cleanup_review EXIT
TEST_AUTH_DIR="$(sudo mktemp -d)"
sudo chmod 0700 "$TEST_AUTH_DIR"

# 1. crictl pull — argv 대신 환경변수로 Credential 전달
export CRICTL_AUTH
CRICTL_AUTH=$(printf '%s:%s' "${WORKER_ROBOT_USER}" "${WORKER_ROBOT_SECRET}" | base64)
PULL_EXIT_CODE=0
sudo -E crictl pull "${TEST_IMAGE}" || PULL_EXIT_CODE=$?
unset CRICTL_AUTH

if [ ${PULL_EXIT_CODE} -ne 0 ]; then
  echo "FAIL: crictl pull 실패 (Exit Code: ${PULL_EXIT_CODE})"
  exit 1
fi

# 2a. HBR-03: 로그인 단계를 push와 분리한다.
# 이전 버전은 `login && push`를 하나의 커맨드 substitution 안에서 실행해,
# 로그인 자체가 "unauthorized: authentication required"로 실패해도(=push
# 시도조차 안 함) 아래 grep 패턴과 우연히 일치해 "Push DENY PASS"로 오판했다.
LOGIN_ATTEMPTED=1
LOGIN_OUTPUT=""
LOGIN_EXIT_CODE=0
LOGIN_OUTPUT=$(printf '%s' "${WORKER_ROBOT_SECRET}" | \
  sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io login "${HARBOR_REGISTRY}" \
    --username "${WORKER_ROBOT_USER}" \
    --password-stdin 2>&1) || LOGIN_EXIT_CODE=$?

if [ ${LOGIN_EXIT_CODE} -ne 0 ]; then
  echo "ERROR: 로그인 자체가 실패해 Push DENY 시험이 무효함 (Credential/네트워크를 먼저 확인)"
  echo "Login Output: ${LOGIN_OUTPUT}"
  exit 1
fi

# 2b. 로그인 성공을 확인한 뒤에만 push를 시도한다.
PUSH_OUTPUT=""
PUSH_EXIT_CODE=0
PUSH_OUTPUT=$(sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io \
  --hosts-dir /etc/containerd/certs.d push "${TEST_IMAGE}" 2>&1) || PUSH_EXIT_CODE=$?

# R10 HBR-03: 이전에는 "denied" 분기를 먼저 검사해서, 재시도/여러 요청의
# 출력이 합쳐져 "denied: requested access"와 인증/전송 오류 문구가 한 출력
# 안에 함께 있으면 denied 분기가 먼저 매치돼 PASS로 오판정했다(재현됨).
# 인증 실패뿐 아니라 원인을 알 수 없게 만드는 전송/TLS 오류 신호가 섞여
# 있어도 먼저 ERROR로 분류하고, 그런 신호가 전혀 없을 때만 권한 거부로
# 인정한다.
AMBIGUOUS_PUSH_MARKERS='unauthorized: authentication required|timeout|TLS|certificate|connection refused|EOF|temporary failure|dial tcp'
if [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
   echo "${PUSH_OUTPUT}" | grep -iqE "${AMBIGUOUS_PUSH_MARKERS}"; then
  echo "ERROR: push 출력에 인증/전송 오류로 해석될 수 있는 신호가 포함됨 — denied 문구와 섞여 있어도 권한 거부로 확정할 수 없어 시험 무효"
  echo "Push Output: ${PUSH_OUTPUT}"
  exit 1
elif [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
     echo "${PUSH_OUTPUT}" | grep -iq "denied: requested access"; then
  echo "PASS: 로그인 성공 후 Push DENY(권한 거부) 확인 완료"
else
  echo "FAIL: 로그인 실패, 또는 Push 차단/성공 원인이 검증된 권한 거부가 아님"
  echo "Push Output: ${PUSH_OUTPUT}"
  exit 1
fi

# Capture the create response UID, not an unrelated subsequent GET UID.
CREATE_ATTEMPTED=1
CREATE_RESPONSE=""
if ! CREATE_RESPONSE=$(printf '%s' "$POD_MANIFEST" | "${KUBECTL[@]}" create -f - -o json); then
  echo "ERROR: create failed/response lost; cleanup will attempt invocation-bound recovery" >&2
  exit 1
fi
if ! POD_UID=$(printf '%s' "$CREATE_RESPONSE" | owned_pod_uid); then
  echo "ERROR: invalid create response; cleanup will attempt invocation-bound recovery" >&2
  exit 1
fi
echo "CREATED: context=$KUBE_CONTEXT namespace=$NAMESPACE pod=$POD_NAME uid=$POD_UID run=$REVIEW_RUN_ID invocation=$RUN_NONCE node=$NODE_NAME"
"${KUBECTL[@]}" wait --for=condition=Ready "pod/$POD_NAME" -n "$NAMESPACE" --timeout=60s
# The checker independently observes Harbor and one complete Pod snapshot, and its
# nonzero status propagates to this script. Cleanup runs on success/failure/signal.
export KUBE_CONTEXT NAMESPACE NODE_NAME SERVICE_ACCOUNT_NAME PULL_SECRET_NAME EXPECTED_HARBOR_DIGEST
export POD_UID REVIEW_RUN_ID RUN_NONCE CA_FILE
bash "${SCRIPT_DIR}/digest-traceability-check.sh" "$NAMESPACE" "$POD_NAME" "$POD_CONTAINER_NAME" "$POD_IMAGE"
REVIEW_CHECKS_PASSED=1
