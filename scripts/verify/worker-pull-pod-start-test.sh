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

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# HBR-02: review-run.env를 source(실행)하지 않고 허용된 키만 값으로만 읽는
# 검증 로직은 worker-push-deny-test.sh와 동일해야 재발을 막을 수 있어
# 공통 함수로 뽑아 둘 다 같은 함수를 사용한다.
source "${SCRIPT_DIR}/lib/load-review-run-env.sh"

HARBOR_REGISTRY="10.1.93.54"
NAMESPACE="${NAMESPACE:-fds-verify}"
POD_OVERRIDES_FILE="${POD_OVERRIDES_FILE:-./pod-restricted-psa-overrides.json}"

if [ -z "${WORKER_ROBOT_SECRET:-}" ] || [ -z "${WORKER_ROBOT_USER:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi

load_review_run_env "./review-run.env" "./review-run.env.sha256" || exit 1

TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"
POD_NAME="p1-hbr-verify-${REVIEW_RUN_ID}"

# HBR-01: nerdctl 인증 저장소를 공유 root config(/root/.docker/config.json)가
# 아니라 격리된 임시 경로로 분리하고, 종료/오류/중단 시 항상 정리한다.
TEST_AUTH_DIR="$(sudo mktemp -d)"
sudo chmod 0700 "${TEST_AUTH_DIR}"

# R10: 자동 Pod 삭제는 하지 않는다. "삭제 요청은 보냈지만 실제로는 실패/오삭제"
# 상태를 rc=0으로 숨길 위험(HBR-01/05 재현 A/B/C/D) 자체를 없애기 위해, 이 실행이
# 만든 Pod의 name/uid만 정확히 기록해뒀다가 사람이 직접 확인 후 지우도록 안내만
# 한다. Pod 생성에 도달하기 전(예: crictl pull 실패)에는 POD_UID가 비어 있으므로
# 안내 대상도 없다.
POD_UID=""
CLEANUP_LOCAL_FAILED=0

cleanup() {
  local rc="${1:-$?}"
  # R9/R10: INT/TERM에 대해 trap이 걸려 있으면 bash는 handler 종료 후 스크립트를
  # 자동 종료하지 않고 중단된 지점부터 재개한다. 재진입/재개를 막기 위해 trap을
  # 먼저 해제하고, 마지막에 명시적으로 exit한다. INT/TERM은 직전 명령의 우연한
  # $?(예: mock이 0을 반환)를 신뢰하지 않고 130/143을 강제한다(재현 B 대응).
  trap - EXIT INT TERM

  # R10: set -e가 cleanup 도중 실패에서 나머지 정리 단계를 건너뛰지 않도록
  # (인증 디렉터리 삭제 실패 → Pod 안내 누락) 각 단계를 개별적으로 시도한다.
  if ! sudo env DOCKER_CONFIG="${TEST_AUTH_DIR}" nerdctl -n k8s.io logout "${HARBOR_REGISTRY}" >/dev/null 2>&1; then
    echo "WARN: nerdctl logout 실패 (registry=${HARBOR_REGISTRY})" >&2
    CLEANUP_LOCAL_FAILED=1
  fi

  if ! sudo rm -rf "${TEST_AUTH_DIR}"; then
    echo "WARN: 임시 인증 디렉터리 삭제 실패 (${TEST_AUTH_DIR}) — 수동 삭제 필요" >&2
    CLEANUP_LOCAL_FAILED=1
  fi

  if [ -n "${POD_UID}" ]; then
    CURRENT_UID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
    if [ -z "${CURRENT_UID}" ]; then
      echo "INFO: Pod ${POD_NAME}이(가) 이미 존재하지 않음 — 별도 정리 불필요" >&2
    elif [ "${CURRENT_UID}" = "${POD_UID}" ]; then
      echo "정리 필요: 이 실행이 만든 Pod가 아직 남아 있습니다. 아래로 UID를 다시 확인한 뒤 직접 삭제하세요." >&2
      echo "  kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.metadata.uid}'   # ${POD_UID} 와 일치하는지 확인" >&2
      echo "  kubectl delete pod ${POD_NAME} -n ${NAMESPACE}" >&2
    else
      echo "WARN: Pod ${POD_NAME}의 현재 uid(${CURRENT_UID})가 본 실행이 생성한 uid(${POD_UID})와 다릅니다 — 다른 실행/다른 프로세스 소유일 수 있으니 자동/수동 삭제 모두 하지 마세요." >&2
    fi
  fi

  unset CRICTL_AUTH WORKER_ROBOT_SECRET

  if [ "${rc}" -eq 0 ] && [ "${CLEANUP_LOCAL_FAILED}" -eq 1 ]; then
    echo "ERROR: 시험 자체는 성공했으나 로컬 정리(logout/임시 디렉터리)가 실패해 잔여 상태가 있습니다." >&2
    exit 1
  fi
  exit "${rc}"
}
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
trap cleanup EXIT

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

# R10 HBR-05: 템플릿의 container name을 POD_NAME과 같다고 가정하지 않는다
# (pod-restricted-psa-overrides.json은 "p1-hbr-verify"로 고정돼 있어 실제로는
# 다르다). 템플릿에서 직접 읽어, 이후 안내 출력이 존재하지 않는 컨테이너를
# 가리키지 않게 한다.
POD_CONTAINER_NAME=$(jq -r '.spec.containers[0].name // empty' "${POD_OVERRIDES_FILE}")
if [ -z "${POD_CONTAINER_NAME}" ]; then
  echo "ERROR: ${POD_OVERRIDES_FILE}에서 container name을 확인할 수 없습니다."
  exit 1
fi

# R10 HBR-01/05: 생성 요청에 이 run 전용 라벨을 남겨, 아래 UID 조회 응답을
# 못 받는 경우(네트워크 유실 등)에도 라벨로 다시 찾아 소유권을 회복할 수
# 있게 한다 ("생성 응답 유실은 잔여 자원을 미확인 상태로 두지 말라"는 지적 대응).
kubectl run "${POD_NAME}" -n "${NAMESPACE}" --image="${TEST_IMAGE}" \
  --restart=Never \
  --labels="review-run-id=${REVIEW_RUN_ID}" \
  --overrides="${POD_OVERRIDES_JSON}"

# R9 HBR-01/05: kubectl run이 성공해 실제로 이 실행이 Pod를 만든 뒤부터만
# uid를 기록한다 — 이 시점 이전에 스크립트가 중단되면(pull 실패 등) 위
# cleanup은 POD_UID가 비어 있어 어떤 Pod도 삭제하지 않는다.
POD_UID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)

if [ -z "${POD_UID}" ]; then
  # R10: kubectl run은 성공했는데(이미 Pod가 만들어졌을 가능성이 높음) 뒤이은
  # UID 조회만 실패한 경우, 이전에는 POD_UID가 빈 채로 넘어가 cleanup이
  # 아무 안내도 하지 못하고 Pod 존재 자체를 조용히 놓쳤다. run 전용 라벨로
  # 재조회를 시도해 소유권을 회복하거나, 그래도 못 찾으면 불확실 상태를
  # 명시적으로 보고한다.
  echo "WARN: Pod 생성 직후 UID 조회에 실패함 — review-run-id 라벨로 재조회 시도" >&2
  LABEL_MATCH_JSON=$(kubectl get pods -n "${NAMESPACE}" -l "review-run-id=${REVIEW_RUN_ID}" -o json 2>/dev/null || true)
  LABEL_MATCH_COUNT=$(printf '%s' "${LABEL_MATCH_JSON}" | jq '.items | length' 2>/dev/null || echo 0)
  if [ "${LABEL_MATCH_COUNT}" = "1" ]; then
    POD_UID=$(printf '%s' "${LABEL_MATCH_JSON}" | jq -r '.items[0].metadata.uid')
    echo "OK: review-run-id 라벨로 소유권 회복함 (uid=${POD_UID})" >&2
  else
    echo "ERROR: Pod가 생성됐을 수 있으나 UID/소유권을 확인하지 못함 (라벨 매치: ${LABEL_MATCH_COUNT}개) — 잔여 자원 여부를 수동으로 확인하세요: kubectl get pods -n ${NAMESPACE} -l review-run-id=${REVIEW_RUN_ID}" >&2
    exit 1
  fi
fi

if ! kubectl wait --for=condition=Ready "pod/${POD_NAME}" -n "${NAMESPACE}" --timeout=60s; then
  echo "FAIL: Pod Ready 대기 실패"
  kubectl describe pod "${POD_NAME}" -n "${NAMESPACE}" || true
  kubectl get events -n "${NAMESPACE}" --field-selector "involvedObject.name=${POD_NAME}" || true
  exit 1
fi

ACTUAL_IMAGE_ID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" \
  -o jsonpath='{.status.containerStatuses[0].imageID}')
ACTUAL_NODE=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.nodeName}')

# R10 HBR-05: NODE_NAME을 지정했는데 실제로는 다른 Node에서 뜬 경우(재현:
# worker01 요청/worker03 관측)를 지금까지는 출력만 하고 그냥 PASS 처리했다.
# 요청한 대상과 실제 대상이 다르면 명시적으로 FAIL한다.
if [ -n "${NODE_NAME:-}" ] && [ "${ACTUAL_NODE}" != "${NODE_NAME}" ]; then
  echo "FAIL: 요청한 Node(${NODE_NAME})와 실제 스케줄된 Node(${ACTUAL_NODE})가 다릅니다"
  exit 1
fi

# R10 HBR-05: imageID가 "비어있지 않기만" 하면 통과했었다(재현: imageID가
# "not-a-digest"인데도 PASS). digest-traceability-check.sh와 동일한 형식
# 검증을 적용해 실제로 유효한 sha256 Digest를 포함하는지 확인한다.
ACTUAL_POD_DIGEST="${ACTUAL_IMAGE_ID##*@}"
if [[ ! "${ACTUAL_POD_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "FAIL: Pod imageID에서 유효한 sha256 Digest를 추출하지 못함: ${ACTUAL_IMAGE_ID}"
  exit 1
fi

echo "PASS: Pod Ready 확인 완료 (Node: ${ACTUAL_NODE}, imageID: ${ACTUAL_IMAGE_ID})"

# R10 HBR-05: 이 Pod 검증과 별도 Digest 검증기(digest-traceability-check.sh)의
# 결과가 서로 연결되지 않는다는 지적에 대한 조치 — 같은 실행에서 그대로 이어
# 쓸 수 있는 정확한 namespace/pod/container/image를 출력한다. container name은
# POD_NAME이 아니라 위에서 템플릿으로부터 읽은 POD_CONTAINER_NAME이다.
echo "다음 명령으로 이 실행의 Pod Digest를 Harbor manifest Digest와 독립 재검증할 수 있습니다:"
echo "  CA_FILE=\"\${CA_FILE}\" WORKER_ROBOT_USER=\"\${WORKER_ROBOT_USER}\" WORKER_ROBOT_SECRET=\"\${WORKER_ROBOT_SECRET}\" \\"
echo "    ${SCRIPT_DIR}/digest-traceability-check.sh \"${NAMESPACE}\" \"${POD_NAME}\" \"${POD_CONTAINER_NAME}\" \"${TEST_IMAGE}\""
