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

# R9: sha256sum --check는 파일에 나열된 항목이 "모두" 일치하면 성공하므로,
# review-run.env.sha256에 review-run.env가 아닌 다른 파일(unrelated.txt 등)만
# 들어있어도 통과할 수 있었다. review-run.env 항목이 실제로 존재하고 그 줄
# 자체가 검증에 성공하는지를 명시적으로 확인한다.
REVIEW_ENV_HASH_LINES=$(grep -cE '(^|[[:space:]])\*?\.?/?review-run\.env$' "./review-run.env.sha256" || true)
if [ "${REVIEW_ENV_HASH_LINES}" -ne 1 ]; then
  echo "ERROR: review-run.env.sha256에 review-run.env 항목이 정확히 1개 있어야 합니다 (실제: ${REVIEW_ENV_HASH_LINES}개)."
  exit 1
fi

if ! grep -E '(^|[[:space:]])\*?\.?/?review-run\.env$' "./review-run.env.sha256" | sha256sum --check --strict - >/dev/null 2>&1; then
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

# R9 HBR-01/05: 이 실행이 실제로 만든 Pod의 UID를 기록해두고, cleanup에서
# "이름이 같다"는 이유만으로 남의 Pod(다른 실행/이전 잔여 Pod)를 지우지
# 않는다. Pod 생성에 도달하기 전(예: crictl pull 실패)에는 POD_UID가 비어
# 있으므로 삭제를 아예 시도하지 않는다.
POD_UID=""

cleanup() {
  local rc=$?
  # R9: INT/TERM에 대해 trap이 걸려 있으면 bash는 handler 종료 후 스크립트를
  # 자동 종료하지 않고 중단된 지점부터 재개한다. 재진입/재개를 막기 위해
  # trap을 먼저 해제하고, 마지막에 명시적으로 exit한다.
  trap - EXIT INT TERM

  sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io logout "${HARBOR_REGISTRY}" >/dev/null 2>&1 || true
  sudo rm -rf "${TEST_AUTH_DIR}"

  if [ -n "${POD_UID}" ]; then
    CURRENT_UID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
    if [ "${CURRENT_UID}" = "${POD_UID}" ]; then
      if ! kubectl delete pod "${POD_NAME}" -n "${NAMESPACE}" --wait=false >/dev/null 2>&1; then
        echo "WARN: Pod ${POD_NAME}(uid=${POD_UID}) 삭제 요청 실패 — 수동 정리 필요" >&2
      fi
    elif [ -n "${CURRENT_UID}" ]; then
      echo "WARN: Pod ${POD_NAME}의 현재 uid(${CURRENT_UID})가 본 실행이 생성한 uid(${POD_UID})와 달라 삭제를 건너뜀 (다른 실행 소유 가능성)" >&2
    fi
  fi

  unset CRICTL_AUTH WORKER_ROBOT_SECRET
  exit "${rc}"
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

# R9 HBR-03: "unauthorized: authentication required"는 로그인 세션이 push
# 시점에 이미 무효화됐다는 뜻이라 역할 기반 권한 거부와 다르다(인증 실패를
# 권한 거부 PASS로 오판정할 수 있었음). Harbor가 검증된 RBAC 거부에서 실제로
# 반환하는 "denied: requested access"만 PASS 근거로 인정한다.
if [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
   echo "${PUSH_OUTPUT}" | grep -iq "denied: requested access"; then
  echo "PASS: 로그인 성공 후 Push DENY(권한 거부) 확인 완료"
elif [ ${LOGIN_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && \
     echo "${PUSH_OUTPUT}" | grep -iq "unauthorized: authentication required"; then
  echo "ERROR: push 시점에 인증이 무효화됨(authentication required) — 권한 거부와 별개 원인이라 시험 무효"
  echo "Push Output: ${PUSH_OUTPUT}"
  exit 1
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

# R9 HBR-01/05: kubectl run이 성공해 실제로 이 실행이 Pod를 만든 뒤부터만
# uid를 기록한다 — 이 시점 이전에 스크립트가 중단되면(pull 실패 등) 위
# cleanup은 POD_UID가 비어 있어 어떤 Pod도 삭제하지 않는다.
POD_UID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}')

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
