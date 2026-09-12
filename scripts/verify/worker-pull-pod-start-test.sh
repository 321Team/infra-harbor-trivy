#!/usr/bin/env bash
# P1-HBR-01 / AC-03, AC-05 — Worker Pull + Pod Start 검증 (containerd/CRI 기반)
# 관련 리뷰: fds-project-baseline#13 (HBR-01, HBR-02, HBR-03, HBR-05)
# 8차 리뷰 후속: https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615
# 실행 대상: k8s-worker01(.105), k8s-worker02(.107), k8s-worker03(.108) 각각 개별 실행
# 사용: NAMESPACE=fds-verify NODE_NAME=k8s-worker01 worker-pull-pod-start-test.sh
set -euo pipefail

# HBR-01: Secret을 참조하는 어떤 줄보다도 먼저 xtrace를 끈다.
# (이전 버전은 아래 WORKER_ROBOT_SECRET 조건문 뒤에 위치해, 그 조건문 자체가
#  호출자의 bash -x 트레이스에 찍혀 Secret 값이 노출될 수 있었다.)
set +x

HARBOR_REGISTRY="10.1.93.54"
NAMESPACE="${NAMESPACE:-fds-verify}"
POD_OVERRIDES_FILE="${POD_OVERRIDES_FILE:-./pod-restricted-psa-overrides.json}"

if [ -z "${WORKER_ROBOT_SECRET:-}" ] || [ -z "${WORKER_ROBOT_USER:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi

# review-run.env 무결성 확인
if [ ! -f "./review-run.env" ] || [ ! -f "./review-run.env.sha256" ]; then
  echo "ERROR: review-run.env 또는 review-run.env.sha256 파일이 없습니다. Runner에서 전달받았는지 확인하세요."
  exit 1
fi

if ! sha256sum --check "./review-run.env.sha256" >/dev/null 2>&1; then
  echo "ERROR: review-run.env 무결성 검증 실패. 파일이 전송 중 변조/손상되었을 수 있습니다."
  exit 1
fi

# HBR-02: review-run.env를 source(실행)하지 않고, 허용된 키만 값으로만 읽는다.
# - source는 파일 내용이 임의 shell 코드로 실행되는 것을 허용해 메타데이터
#   명령 실행 등 오남용이 가능했다.
# - 로드 전 대상 변수를 명시적으로 unset해, 파일에 값이 없을 때 이전 세션의
#   값을 상속해 통과하던 문제(TEST_TAG 누락 시 구 값 재사용)를 차단한다.
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
echo "OK: review-run.env 무결성 확인 및 안전 로드 완료 (Run ID: ${REVIEW_RUN_ID})"

TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"
POD_NAME="p1-hbr-verify-${REVIEW_RUN_ID}"

# HBR-01: nerdctl 인증 저장소를 공유 root config(/root/.docker/config.json)가
# 아니라 격리된 임시 경로로 분리하고, 종료/오류/중단 시 항상 정리한다.
TEST_AUTH_DIR="$(sudo mktemp -d)"
sudo chmod 0700 "${TEST_AUTH_DIR}"

cleanup() {
  sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io logout "${HARBOR_REGISTRY}" >/dev/null 2>&1 || true
  sudo rm -rf "${TEST_AUTH_DIR}"
  kubectl delete pod "${POD_NAME}" -n "${NAMESPACE}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  unset CRICTL_AUTH WORKER_ROBOT_SECRET
}
trap cleanup EXIT INT TERM

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

# 정형 거부 문구만 매치 (이미지 참조 문자열과 겹치는 범용 단어 배제)
if [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
   echo "${PUSH_OUTPUT}" | grep -iqE "denied: requested access|unauthorized: authentication required"; then
  echo "PASS: 로그인 성공 후 Push DENY(권한 거부) 확인 완료"
else
  echo "FAIL: 로그인 실패 또는 Push 차단 원인이 권한 거부가 아님"
  echo "Push Output: ${PUSH_OUTPUT}"
  exit 1
fi

# 3. HBR-05: 파일명이 "pod-start-test"인데 실제 Pod 생성/Ready/imageID 검증이
#    없던 문제를 해소한다. 실제 Pod apply → Ready 대기 → imageID 확인 → cleanup.
if [ ! -f "${POD_OVERRIDES_FILE}" ]; then
  echo "ERROR: Restricted PSA overrides 파일(${POD_OVERRIDES_FILE})이 없습니다."
  exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq가 필요합니다."; exit 1; }
# NODE_NAME을 지정하면 해당 Worker에 강제 스케줄해, Worker 3대 각각의
# 개별 실행 증적을 남길 수 있다 (대표 Host 결과로 대체 금지 원칙 준수).
POD_OVERRIDES_JSON=$(jq --arg img "${TEST_IMAGE}" --arg node "${NODE_NAME:-}" \
  '.spec.containers[0].image = $img
   | if $node != "" then .spec.nodeName = $node else . end' \
  "${POD_OVERRIDES_FILE}")

kubectl run "${POD_NAME}" -n "${NAMESPACE}" --image="${TEST_IMAGE}" \
  --restart=Never \
  --overrides="${POD_OVERRIDES_JSON}"

if ! kubectl wait --for=condition=Ready "pod/${POD_NAME}" -n "${NAMESPACE}" --timeout=60s; then
  echo "FAIL: Pod Ready 대기 실패"
  kubectl describe pod "${POD_NAME}" -n "${NAMESPACE}" || true
  kubectl get events -n "${NAMESPACE}" --field-selector "involvedObject.name=${POD_NAME}" || true
  exit 1
fi

ACTUAL_IMAGE_ID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" \
  -o jsonpath='{.status.containerStatuses[0].imageID}')
ACTUAL_NODE=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.nodeName}')

if [ -z "${ACTUAL_IMAGE_ID}" ]; then
  echo "FAIL: Pod imageID를 확인할 수 없음"
  exit 1
fi

echo "PASS: Pod Ready 확인 완료 (Node: ${ACTUAL_NODE}, imageID: ${ACTUAL_IMAGE_ID})"
