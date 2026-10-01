#!/usr/bin/env bash
# P1-HBR-01 / IF-09 — Runner Push/Pull Positive & Negative Test
#
# 종료 코드: 0=PASS, 1=FAIL(기대와 다른 결과), 2=ERROR(원인을 확정할 수 없음 — PASS도 FAIL도 아님)
# 필수 입력(환경변수, 값은 출력하지 않는다):
#   RUNNER_ROBOT_USER / RUNNER_ROBOT_SECRET  Runner 정상 credential
#   WRONG_ROBOT_SECRET                       음성시험용 잘못된 secret
#   BASE_IMAGE_REF                           digest로 고정된 시험 입력 이미지 (예: alpine@sha256:<64 hex>)
set -euo pipefail

HARBOR_REGISTRY="10.1.93.54"
DIGEST_RE='^sha256:[0-9a-f]{64}$'
BASE_REF_RE='^[^@[:space:]]+@sha256:[0-9a-f]{64}$'
AUTH_REJECT_MARKERS='unauthorized|401|authentication required|incorrect username or password|invalid username'
AMBIGUOUS_MARKERS='timeout|TLS|certificate|connection refused|EOF|temporary failure|dial tcp|no such host|network is unreachable'

TEST_DOCKER_CONFIG="$(mktemp -d)"
WORK_DIR="$(mktemp -d)"
export DOCKER_CONFIG="${TEST_DOCKER_CONFIG}"
set +x

TEST_TAG="ifup-$(date -u +%Y%m%dT%H%M%SZ)"
TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"

cleanup() {
  podman logout "${HARBOR_REGISTRY}" >/dev/null 2>&1 || true
  podman rmi -f "${TEST_IMAGE}" >/dev/null 2>&1 || true
  rm -rf "${TEST_DOCKER_CONFIG}" "${WORK_DIR}"
  unset DOCKER_CONFIG RUNNER_ROBOT_SECRET WRONG_ROBOT_SECRET
}
trap cleanup EXIT

if [ -z "${RUNNER_ROBOT_USER:-}" ] || [ -z "${RUNNER_ROBOT_SECRET:-}" ]; then
  echo "ERROR: RUNNER_ROBOT_USER 또는 RUNNER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 2
fi
if [ -z "${WRONG_ROBOT_SECRET:-}" ]; then
  echo "ERROR: WRONG_ROBOT_SECRET 환경변수(음성시험용, 임의 문자열)가 필요합니다."
  exit 2
fi
if [ -z "${BASE_IMAGE_REF:-}" ] || ! printf '%s' "${BASE_IMAGE_REF}" | grep -qE "${BASE_REF_RE}"; then
  echo "ERROR: BASE_IMAGE_REF는 digest 고정 참조(name@sha256:<64 hex>)여야 합니다. moving tag는 허용하지 않습니다."
  exit 2
fi
echo "INFO: base_image=${BASE_IMAGE_REF}"

echo "### 1. Positive: Runner Credential 로그인"
LOGIN_EXIT_CODE=0
printf '%s' "${RUNNER_ROBOT_SECRET}" | \
  podman login "${HARBOR_REGISTRY}" \
    --username "${RUNNER_ROBOT_USER}" \
    --password-stdin || LOGIN_EXIT_CODE=$?
if [ ${LOGIN_EXIT_CODE} -ne 0 ]; then
  echo "FAIL: 정상 credential로도 로그인 실패 — IF-09 Positive 시험 무의미"
  exit 1
fi
echo "OK: 로그인 성공"

echo "### 2. Positive: 이미지 push (manifest digest는 push가 기록한 digestfile에서 읽는다)"
PULL_BASE_EXIT_CODE=0
podman pull "${BASE_IMAGE_REF}" >/dev/null || PULL_BASE_EXIT_CODE=$?
if [ ${PULL_BASE_EXIT_CODE} -ne 0 ]; then
  echo "ERROR: 시험 입력 이미지를 받지 못했습니다 (Exit Code: ${PULL_BASE_EXIT_CODE}) — Harbor 시험 이전 단계 실패"
  exit 2
fi
podman tag "${BASE_IMAGE_REF}" "${TEST_IMAGE}"
DIGEST_FILE="${WORK_DIR}/push.digest"
PUSH_EXIT_CODE=0
PUSH_OUTPUT=$(podman push --digestfile "${DIGEST_FILE}" "${TEST_IMAGE}" 2>&1) || PUSH_EXIT_CODE=$?
if [ ${PUSH_EXIT_CODE} -ne 0 ]; then
  echo "FAIL: Runner Push 실패 (Exit Code: ${PUSH_EXIT_CODE})"
  echo "Output: ${PUSH_OUTPUT}"
  exit 1
fi
PUSHED_DIGEST=""
if [ -s "${DIGEST_FILE}" ]; then
  PUSHED_DIGEST="$(tr -d '[:space:]' < "${DIGEST_FILE}")"
fi
if ! printf '%s' "${PUSHED_DIGEST}" | grep -qE "${DIGEST_RE}"; then
  echo "ERROR: push가 manifest digest를 기록하지 않았거나 형식이 올바르지 않습니다 (DIGEST_UNVERIFIED)"
  exit 2
fi
echo "PASS: Runner Push 성공 image=${TEST_IMAGE} manifest_digest=${PUSHED_DIGEST}"

echo "### 3. Positive: 같은 Runner credential로 Harbor에서 exact digest Pull"
# 로컬에 같은 내용이 남아 있으면 Harbor Pull이 아니므로 입력/시험 이미지를 모두 지운 뒤 받는다.
podman rmi -f "${TEST_IMAGE}" "${BASE_IMAGE_REF}" >/dev/null 2>&1 || true
PULL_REF="${HARBOR_REGISTRY}/fds/test@${PUSHED_DIGEST}"
PULL_EXIT_CODE=0
PULL_OUTPUT=$(podman pull "${PULL_REF}" 2>&1) || PULL_EXIT_CODE=$?
if [ ${PULL_EXIT_CODE} -ne 0 ]; then
  echo "FAIL: Harbor에서 digest Pull 실패 (Exit Code: ${PULL_EXIT_CODE})"
  echo "Output: ${PULL_OUTPUT}"
  exit 1
fi
PULLED_DIGEST="$(podman image inspect --format '{{.Digest}}' "${PULL_REF}" 2>/dev/null | tr -d '[:space:]' || true)"
if [ "${PULLED_DIGEST}" != "${PUSHED_DIGEST}" ]; then
  echo "FAIL: Pull한 이미지 digest(${PULLED_DIGEST:-없음})가 push digest(${PUSHED_DIGEST})와 다름"
  exit 1
fi
echo "PASS: Harbor digest Pull 성공 및 digest 일치 pulled=${PULLED_DIGEST}"
podman rmi -f "${PULL_REF}" >/dev/null 2>&1 || true
podman logout "${HARBOR_REGISTRY}" >/dev/null 2>&1 || true

echo "### 4. Negative: 잘못된 credential 로그인 시도 (인증 거부가 관측돼야 PASS)"
WRONG_DOCKER_CONFIG="$(mktemp -d)"
WRONG_LOGIN_EXIT_CODE=0
WRONG_LOGIN_OUTPUT=$(
  export DOCKER_CONFIG="${WRONG_DOCKER_CONFIG}"
  printf '%s' "${WRONG_ROBOT_SECRET}" | podman login "${HARBOR_REGISTRY}" --username "${RUNNER_ROBOT_USER}" --password-stdin 2>&1
) || WRONG_LOGIN_EXIT_CODE=$?
rm -rf "${WRONG_DOCKER_CONFIG}"

if [ ${WRONG_LOGIN_EXIT_CODE} -eq 0 ]; then
  echo "FAIL: 잘못된 credential로 로그인 성공함 (거부돼야 하는데 안 됨)"
  exit 1
elif printf '%s' "${WRONG_LOGIN_OUTPUT}" | grep -iqE "${AMBIGUOUS_MARKERS}"; then
  echo "ERROR: 로그인 실패 원인에 인증 외 오류(네트워크/TLS) 신호가 섞여 있어 권한 거부로 확정할 수 없음"
  echo "Output: ${WRONG_LOGIN_OUTPUT}"
  exit 2
elif printf '%s' "${WRONG_LOGIN_OUTPUT}" | grep -iqE "${AUTH_REJECT_MARKERS}"; then
  echo "PASS: 잘못된 credential 로그인이 인증 거부로 확인됨"
else
  echo "ERROR: 로그인은 실패했지만 인증 거부 신호(401/unauthorized 등)가 없어 원인을 확정할 수 없음 (UNRESOLVED)"
  echo "Output: ${WRONG_LOGIN_OUTPUT}"
  exit 2
fi

echo "### 완료 — TEST_TAG=${TEST_TAG} MANIFEST_DIGEST=${PUSHED_DIGEST} BASE_IMAGE_REF=${BASE_IMAGE_REF}"
