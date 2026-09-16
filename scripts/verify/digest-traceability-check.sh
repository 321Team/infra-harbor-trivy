#!/usr/bin/env bash
# P1-HBR-01 / AC-05 — Pod Digest와 Harbor Digest 완전 일치 검증
# 관련 리뷰: fds-project-baseline#13 (HBR-05)
# 8차 리뷰 후속: https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615
# R9 후속: https://github.com/321Team/infra-harbor-trivy/pull/2#issuecomment-5647308804
# R10 딥리뷰: https://github.com/321Team/infra-harbor-trivy/pull/2#pullrequestreview-5217513542
# 사용: CA_FILE=<ca.pem> digest-traceability-check.sh <namespace> <pod-name> <container-name> <harbor-image-ref>
#   harbor-image-ref 예: 10.1.93.54/fds/test:review-1234 (registry/project/repo:tag 형식, tag 필수)
#   registry는 아래 HARBOR_REGISTRY로 고정되며, 다른 값이 오면 거부한다.
set -euo pipefail

# HBR-01: Secret을 참조하는 어떤 줄보다도 먼저 xtrace를 끈다.
set +x

HARBOR_REGISTRY="10.1.93.54"

NAMESPACE="${1:?namespace를 지정하세요}"
POD_NAME="${2:?pod name을 지정하세요}"
CONTAINER_NAME="${3:?대상 container name을 명시하세요 (첫 번째 컨테이너를 임의로 선택하지 않음)}"
HARBOR_IMAGE_REF="${4:?검증 대상 Harbor image reference(registry/project/repo:tag)를 지정하세요}"
CA_FILE="${CA_FILE:?CA_FILE 환경변수를 지정하세요 (Harbor manifest 조회용 TLS 검증)}"

if [ -z "${WORKER_ROBOT_USER:-}" ] || [ -z "${WORKER_ROBOT_SECRET:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다 (Harbor manifest 조회용)."
  exit 1
fi

# R10: 개행 문자는 curl config의 "user = ..." 한 줄 형식을 깨뜨려 값이 잘리거나
# 다음 줄이 별도의 config 지시어로 잘못 해석될 수 있다(config injection). 값
# 자체를 이스케이프로 보존하려 하지 않고, 개행이 섞인 자격증명은 거부한다.
if [[ "${WORKER_ROBOT_USER}" == *$'\n'* || "${WORKER_ROBOT_USER}" == *$'\r'* ]] || \
   [[ "${WORKER_ROBOT_SECRET}" == *$'\n'* || "${WORKER_ROBOT_SECRET}" == *$'\r'* ]]; then
  echo "ERROR: WORKER_ROBOT_USER/WORKER_ROBOT_SECRET에 개행 문자가 포함되어 있어 안전하게 전달할 수 없습니다."
  exit 1
fi

if [ ! -f "${CA_FILE}" ]; then
  echo "ERROR: CA_FILE(${CA_FILE})이 존재하지 않습니다."
  exit 1
fi

HARBOR_HOST="${HARBOR_IMAGE_REF%%/*}"
HARBOR_REPO_TAG="${HARBOR_IMAGE_REF#*/}"
HARBOR_TAG="${HARBOR_REPO_TAG##*:}"
HARBOR_REPO="${HARBOR_REPO_TAG%:${HARBOR_TAG}}"

if [ "${HARBOR_REPO_TAG}" = "${HARBOR_TAG}" ] || [ -z "${HARBOR_TAG}" ] || [ -z "${HARBOR_REPO}" ]; then
  echo "ERROR: harbor-image-ref 형식이 올바르지 않음 (registry/project/repo:tag): ${HARBOR_IMAGE_REF}"
  exit 1
fi

# R10: harbor-image-ref의 host를 검증 없이 그대로 curl 대상으로 쓰면, 호출자가
# (실수로든 악의적으로든) 다른 host를 넣었을 때 그 host로 Robot 자격증명이
# 그대로 전송될 수 있다. 고정된 Harbor endpoint로만 조회를 허용한다.
if [ "${HARBOR_HOST}" != "${HARBOR_REGISTRY}" ]; then
  echo "ERROR: harbor-image-ref의 registry host가 허용된 Harbor(${HARBOR_REGISTRY})와 다릅니다: ${HARBOR_HOST}"
  exit 1
fi

# R10 HBR-01/AC-06: `curl -u user:secret`은 비밀번호를 프로세스 인자(argv)로
# 그대로 남긴다 — 더미 Secret으로 재현됨. set +x는 화면 출력만 막을 뿐 argv
# 노출 경로 자체를 막지 못한다. curl config 파일(-K)로 옮겨 argv에는 파일
# 경로만 남기고, 파일은 umask 077 + chmod 600으로 생성 즉시 보호하며, 정상
# 종료/오류/중단(EXIT/INT/TERM) 모두에서 삭제한다.
umask 077
CURL_CONFIG_FILE="$(mktemp)"
chmod 600 "${CURL_CONFIG_FILE}"
trap 'rm -f "${CURL_CONFIG_FILE}"' EXIT INT TERM

# curl config 문법(`user = "id:secret"`)에서 백슬래시와 큰따옴표는 각각
# `\\`, `\"`로 이스케이프해야 값이 깨지지 않는다 (백슬래시를 먼저 치환).
_curl_cfg_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}
printf 'user = "%s:%s"\n' \
  "$(_curl_cfg_escape "${WORKER_ROBOT_USER}")" \
  "$(_curl_cfg_escape "${WORKER_ROBOT_SECRET}")" \
  > "${CURL_CONFIG_FILE}"

# R9 HBR-05: 호출자가 넘긴 Digest를 그대로 신뢰하지 않는다. sha256 정규식
# 형식만으로는 그 값이 image index/manifest 자체의 Digest인지, 내부 config나
# layer의 Digest인지 구분할 수 없기 때문이다. 대신 Harbor Registry v2 API로
# 해당 tag의 manifest를 직접 조회해 응답 헤더 Docker-Content-Digest를 사용한다
# — 이 헤더는 정의상 "조회한 manifest/index 자체"의 Digest이므로 config/layer
# Digest와 혼동될 여지가 없다.
MANIFEST_HEADERS=$(curl -K "${CURL_CONFIG_FILE}" \
  --fail --silent --show-error --cacert "${CA_FILE}" \
  -o /dev/null -D - \
  -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
  "https://${HARBOR_HOST}/v2/${HARBOR_REPO}/manifests/${HARBOR_TAG}")

HARBOR_DIGEST=$(printf '%s' "${MANIFEST_HEADERS}" | tr -d '\r' \
  | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2; exit}')

if [[ ! "${HARBOR_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: Harbor manifest 조회에서 유효한 Docker-Content-Digest를 얻지 못함 (image=${HARBOR_IMAGE_REF})"
  exit 1
fi
echo "OK: Harbor manifest에서 직접 조회한 Digest 확인 (image=${HARBOR_IMAGE_REF}): ${HARBOR_DIGEST}"

# HBR-05: 첫 번째 containerStatuses 항목을 임의로 사용하지 않고, 명시된
# container name으로 정확히 지정해 실제 대상 container를 특정한다.
POD_IMAGE_ID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" \
  -o jsonpath="{.status.containerStatuses[?(@.name==\"${CONTAINER_NAME}\")].imageID}")

if [ -z "${POD_IMAGE_ID}" ]; then
  echo "ERROR: container '${CONTAINER_NAME}'을(를) Pod '${POD_NAME}'에서 찾을 수 없음"
  exit 1
fi
echo "Pod ImageID (container=${CONTAINER_NAME}): ${POD_IMAGE_ID}"

# HBR-05: substring 포함 여부(`*"${HARBOR_DIGEST}"*`)가 아니라, imageID에서
# "...@sha256:xxxx" 형태의 Digest 부분만 정확히 추출해 완전 일치로 비교한다.
POD_DIGEST="${POD_IMAGE_ID##*@}"

if [[ ! "${POD_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: Pod imageID에서 유효한 sha256 Digest를 추출하지 못함: ${POD_IMAGE_ID}"
  exit 1
fi

if [ "${POD_DIGEST}" = "${HARBOR_DIGEST}" ]; then
  echo "PASS: ${POD_NAME} Pod Digest가 Harbor manifest Digest와 정확히 일치함"
else
  echo "FAIL: ${POD_NAME} Digest 불일치 (Pod: ${POD_DIGEST}, Harbor manifest: ${HARBOR_DIGEST})"
  exit 1
fi
