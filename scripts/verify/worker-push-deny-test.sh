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

trap 'rm -rf "${TEST_DOCKER_CONFIG}"; unset DOCKER_CONFIG WORKER_ROBOT_SECRET' EXIT

if [ -z "${WORKER_ROBOT_SECRET:-}" ] || [ -z "${WORKER_ROBOT_USER:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi

# HBR-02: review-run.env를 source하지 않고 허용 키만 파싱한다.
# (이전 버전은 TEST_IMAGE를 정의하는 이 로드 과정 자체가 빠져 있어
#  아래 docker tag 단계에서 TEST_IMAGE가 unbound variable로 실패하던 결함도 함께 해소한다.)
if [ ! -f "./review-run.env" ] || [ ! -f "./review-run.env.sha256" ]; then
  echo "ERROR: review-run.env 또는 review-run.env.sha256 파일이 없습니다. Runner에서 전달받았는지 확인하세요."
  exit 1
fi

if ! sha256sum --check "./review-run.env.sha256" >/dev/null 2>&1; then
  echo "ERROR: review-run.env 무결성 검증 실패. 파일이 전송 중 변조/손상되었을 수 있습니다."
  exit 1
fi

unset TEST_TAG REVIEW_RUN_ID
ALLOWED_ENV_KEYS="TEST_TAG REVIEW_RUN_ID"

while IFS='=' read -r env_key env_value; do
  [[ -z "${env_key}" || "${env_key}" =~ ^[[:space:]]*# ]] && continue
  case " ${ALLOWED_ENV_KEYS} " in
    *" ${env_key} "*)
      if [[ ! "${env_value}" =~ ^[A-Za-z0-9._:-]*$ ]]; then
        echo "ERROR: review-run.env의 ${env_key} 값 형식이 허용 범위를 벗어남"
        exit 1
      fi
      printf -v "${env_key}" '%s' "${env_value}"
      ;;
    *)
      echo "ERROR: review-run.env에 허용되지 않은 키(${env_key})가 존재함"
      exit 1
      ;;
  esac
done < "./review-run.env"

if [ -z "${TEST_TAG:-}" ] || [ -z "${REVIEW_RUN_ID:-}" ]; then
  echo "ERROR: TEST_TAG 또는 REVIEW_RUN_ID가 review-run.env에 비어 있습니다."
  exit 1
fi

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

# 2. Push DENY 시도
# HBR-03: 태그 이름에 판정 키워드를 넣지 않는다 (에러 메시지에 이미지 참조가 그대로
#         포함되므로 "forbidden" 같은 단어를 태그에 쓰면 원인과 무관하게 오탐 PASS 가능).
DENY_TEST_TAG="worker-push-denytest-${REVIEW_RUN_ID}"
DENY_TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${DENY_TEST_TAG}"
docker tag "${TEST_IMAGE}" "${DENY_TEST_IMAGE}"

PUSH_EXIT_CODE=0
PUSH_OUTPUT=$(docker push "${DENY_TEST_IMAGE}" 2>&1) || PUSH_EXIT_CODE=$?

# 3. Registry가 실제로 반환하는 정형 거부 문구만 매치한다 (이미지 이름과 겹칠 수 있는
#    범용 단어는 사용하지 않는다).
if [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
   echo "${PUSH_OUTPUT}" | grep -iqE "denied: requested access|unauthorized: authentication required"; then
  echo "PASS: 로그인 성공 후 Worker Push가 권한 거부로 정상 차단됨"
else
  echo "FAIL: 로그인 실패 또는 Worker Push 차단 원인이 권한 거부가 아님."
  echo "Output: ${PUSH_OUTPUT}"
  exit 1
fi

docker logout "${HARBOR_REGISTRY}"
