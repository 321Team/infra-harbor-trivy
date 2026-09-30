#!/usr/bin/env bash
# P1-HBR-01 / IF-09 — Runner Push/Pull Positive & Negative Test
set -euo pipefail

HARBOR_REGISTRY="10.1.93.54"
TEST_DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG="${TEST_DOCKER_CONFIG}"
set +x

trap 'rm -rf "${TEST_DOCKER_CONFIG}"; unset DOCKER_CONFIG RUNNER_ROBOT_SECRET WRONG_ROBOT_SECRET' EXIT

if [ -z "${RUNNER_ROBOT_USER:-}" ] || [ -z "${RUNNER_ROBOT_SECRET:-}" ]; then
  echo "ERROR: RUNNER_ROBOT_USER 또는 RUNNER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi
if [ -z "${WRONG_ROBOT_SECRET:-}" ]; then
  echo "ERROR: WRONG_ROBOT_SECRET 환경변수(음성시험용, 임의 문자열)가 필요합니다."
  exit 1
fi

TEST_TAG="ifup-$(date -u +%Y%m%dT%H%M%SZ)"
TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"

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

echo "### 2. Positive: 이미지 push"
podman pull alpine:3.20 >/dev/null
podman tag alpine:3.20 "${TEST_IMAGE}"
PUSH_EXIT_CODE=0
PUSH_OUTPUT=$(podman push "${TEST_IMAGE}" 2>&1) || PUSH_EXIT_CODE=$?
if [ ${PUSH_EXIT_CODE} -ne 0 ]; then
  echo "FAIL: Runner Push 실패 (Exit Code: ${PUSH_EXIT_CODE})"
  echo "Output: ${PUSH_OUTPUT}"
  exit 1
fi
PUSHED_DIGEST=$(echo "${PUSH_OUTPUT}" | grep -oE 'sha256:[0-9a-f]{64}' | tail -1 || true)
echo "PASS: Runner Push 성공 image=${TEST_IMAGE} digest=${PUSHED_DIGEST}"
podman logout "${HARBOR_REGISTRY}" >/dev/null 2>&1 || true

echo "### 3. Negative: 잘못된 credential 로그인 시도 (거부돼야 함)"
WRONG_DOCKER_CONFIG="$(mktemp -d)"
WRONG_LOGIN_EXIT_CODE=0
WRONG_LOGIN_OUTPUT=$(
  export DOCKER_CONFIG="${WRONG_DOCKER_CONFIG}"
  printf '%s' "${WRONG_ROBOT_SECRET}" | podman login "${HARBOR_REGISTRY}" --username "${RUNNER_ROBOT_USER}" --password-stdin 2>&1
) || WRONG_LOGIN_EXIT_CODE=$?
rm -rf "${WRONG_DOCKER_CONFIG}"

AMBIGUOUS_MARKERS='timeout|TLS|certificate|connection refused|EOF|temporary failure|dial tcp'
if [ ${WRONG_LOGIN_EXIT_CODE} -eq 0 ]; then
  echo "FAIL: 잘못된 credential로 로그인 성공함 (거부돼야 하는데 안 됨)"
  exit 1
elif echo "${WRONG_LOGIN_OUTPUT}" | grep -iqE "${AMBIGUOUS_MARKERS}"; then
  echo "ERROR: 로그인 실패 원인에 인증 외 오류(네트워크/TLS) 신호가 섞여 있어 권한 거부로 확정할 수 없음"
  echo "Output: ${WRONG_LOGIN_OUTPUT}"
  exit 1
else
  echo "PASS: 잘못된 credential 로그인 거부 확인"
fi

echo "### 완료 — TEST_TAG=${TEST_TAG} PUSHED_DIGEST=${PUSHED_DIGEST}"
