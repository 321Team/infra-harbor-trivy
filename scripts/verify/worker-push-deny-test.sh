#!/usr/bin/env bash
# P1-HBR-01 / AC-03, AC-06 — Worker Robot Account 최소권한 검증 (Push DENY)
# 관련 리뷰: fds-project-baseline#13 (HBR-01, HBR-02, HBR-03)
# 8차 리뷰 후속: https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615
set -euo pipefail

HARBOR_REGISTRY="10.1.93.54"
TEST_DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG="${TEST_DOCKER_CONFIG}"

# HBR-01: Secret을 참조하는 어떤 줄보다도 먼저 xtrace를 끈다. (기존 위치 유지 — 7차 리뷰에서 CLOSED)
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# HBR-02: review-run.env 검증 로직은 worker-pull-pod-start-test.sh와 동일해야
# 재발을 막을 수 있어 공통 함수로 뽑아 둘 다 같은 함수를 사용한다.
source "${SCRIPT_DIR}/lib/load-review-run-env.sh"

trap 'rm -rf "${TEST_DOCKER_CONFIG}"; unset DOCKER_CONFIG WORKER_ROBOT_SECRET' EXIT

if [ -z "${WORKER_ROBOT_SECRET:-}" ] || [ -z "${WORKER_ROBOT_USER:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi

load_review_run_env "./review-run.env" "./review-run.env.sha256" || exit 1

TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"

# 1. Worker Credential 로그인 (push 시도와 분리된 별도 단계 — 실패 시 즉시 중단)
LOGIN_EXIT_CODE=0
printf '%s' "${WORKER_ROBOT_SECRET}" | \
  docker login "${HARBOR_REGISTRY}" \
    --username "${WORKER_ROBOT_USER}" \
    --password-stdin || LOGIN_EXIT_CODE=$?

if [ ${LOGIN_EXIT_CODE} -ne 0 ]; then
  echo "ERROR: 로그인 자체가 실패해 Push DENY 시험이 무효함 (Credential/네트워크를 먼저 확인)"
  exit 1
fi

# R10 HBR-05: 로그인 성공만으로는 이 robot 계정이 "실제로 쓸 수 있는" 계정인지
# 증명되지 않는다. 로그인 후 곧장 Push DENY만 시도하면, Push 실패가 "권한
# 거부"인지 "애초에 이 계정 자체가 무효"인지 구분할 근거가 없다. 같은 계정으로
# 허용된 image를 먼저 pull해 identity가 유효함을 먼저 증명한다(worker-pull
# 스크립트의 crictl pull과 동일한 목적).
PULL_EXIT_CODE=0
docker pull "${TEST_IMAGE}" >/dev/null || PULL_EXIT_CODE=$?
if [ ${PULL_EXIT_CODE} -ne 0 ]; then
  echo "ERROR: Push DENY 시험 전 Pull 근거 확보 실패 (Exit Code: ${PULL_EXIT_CODE}) — 이 identity가 유효한지부터 확인 필요"
  exit 1
fi
echo "OK: 동일 identity Pull 성공 확인 (image=${TEST_IMAGE}) — Push DENY 시험 진행"

# 2. Push DENY 시도
# HBR-03: 태그 이름에 판정 키워드를 넣지 않는다 (에러 메시지에 이미지 참조가 그대로
#         포함되므로 "forbidden" 같은 단어를 태그에 쓰면 원인과 무관하게 오탐 PASS 가능).
DENY_TEST_TAG="worker-push-denytest-${REVIEW_RUN_ID}"
DENY_TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${DENY_TEST_TAG}"
docker tag "${TEST_IMAGE}" "${DENY_TEST_IMAGE}"

PUSH_EXIT_CODE=0
PUSH_OUTPUT=$(docker push "${DENY_TEST_IMAGE}" 2>&1) || PUSH_EXIT_CODE=$?

# 3. R10 HBR-03: 이전에는 "denied" 분기를 먼저 검사해서, 재시도/여러 요청의
#    출력이 합쳐져 "denied: requested access"와 인증/전송 오류 문구가 한
#    출력 안에 함께 있으면 denied 분기가 먼저 매치돼 PASS로 오판정했다
#    (재현됨). 인증 실패뿐 아니라 원인을 알 수 없게 만드는 전송/TLS 오류
#    신호가 섞여 있어도 먼저 ERROR로 분류하고, 그런 신호가 전혀 없을 때만
#    권한 거부로 인정한다.
AMBIGUOUS_PUSH_MARKERS='unauthorized: authentication required|timeout|TLS|certificate|connection refused|EOF|temporary failure|dial tcp'
if [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
   echo "${PUSH_OUTPUT}" | grep -iqE "${AMBIGUOUS_PUSH_MARKERS}"; then
  echo "ERROR: push 출력에 인증/전송 오류로 해석될 수 있는 신호가 포함됨 — denied 문구와 섞여 있어도 권한 거부로 확정할 수 없어 시험 무효"
  echo "Output: ${PUSH_OUTPUT}"
  exit 1
elif [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
     echo "${PUSH_OUTPUT}" | grep -iq "denied: requested access"; then
  echo "PASS: 로그인 성공 후 Worker Push가 권한 거부로 정상 차단됨"
else
  echo "FAIL: 로그인 실패, 또는 Worker Push 차단/성공 원인이 검증된 권한 거부가 아님."
  echo "Output: ${PUSH_OUTPUT}"
  exit 1
fi

docker logout "${HARBOR_REGISTRY}"
