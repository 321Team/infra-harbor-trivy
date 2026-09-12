#!/usr/bin/env bash
# P1-HBR-01 / AC-03, AC-06 — Worker Robot Account 최소권한 검증 (Push DENY)
# 관련 리뷰: fds-project-baseline#13 (HBR-01, HBR-03)
set -euo pipefail

HARBOR_REGISTRY="10.1.93.54"
TEST_DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG="${TEST_DOCKER_CONFIG}"

# HBR-01: Secret을 참조하는 어떤 줄보다도 먼저 xtrace를 끈다.
set +x

trap 'rm -rf "${TEST_DOCKER_CONFIG}"; unset DOCKER_CONFIG WORKER_ROBOT_SECRET' EXIT

if [ -z "${WORKER_ROBOT_SECRET:-}" ] || [ -z "${WORKER_ROBOT_USER:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi

# 1. Worker Credential 로그인
printf '%s' "${WORKER_ROBOT_SECRET}" | \
  docker login "${HARBOR_REGISTRY}" \
    --username "${WORKER_ROBOT_USER}" \
    --password-stdin

# 2. Push DENY 시도
# HBR-03: 태그 이름에 판정 키워드를 넣지 않는다 (에러 메시지에 이미지 참조가 그대로
#         포함되므로 "forbidden" 같은 단어를 태그에 쓰면 원인과 무관하게 오탐 PASS 가능).
DENY_TEST_TAG="worker-push-denytest-$(date +%s)"
DENY_TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${DENY_TEST_TAG}"
docker tag "${TEST_IMAGE}" "${DENY_TEST_IMAGE}"

PUSH_OUTPUT=$(docker push "${DENY_TEST_IMAGE}" 2>&1) && PUSH_EXIT_CODE=0 || PUSH_EXIT_CODE=$?

# 3. Registry가 실제로 반환하는 정형 거부 문구만 매치한다 (이미지 이름과 겹칠 수 있는
#    범용 단어는 사용하지 않는다).
if [ ${PUSH_EXIT_CODE} -ne 0 ] && echo "${PUSH_OUTPUT}" | grep -iqE "denied: requested access|unauthorized: authentication required"; then
  echo "PASS: Worker Push가 권한 거부로 정상 차단됨"
else
  echo "FAIL: Worker Push 차단 실패 또는 실패 원인이 권한 거부가 아님."
  echo "Output: ${PUSH_OUTPUT}"
  exit 1
fi

docker logout "${HARBOR_REGISTRY}"
