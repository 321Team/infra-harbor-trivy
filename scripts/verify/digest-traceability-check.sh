#!/usr/bin/env bash
# P1-HBR-01 / AC-05 — Pod Digest와 Harbor Digest 완전 일치 검증
# 관련 리뷰: fds-project-baseline#13 (HBR-05)
# 8차 리뷰 후속: https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615
# R9 후속: https://github.com/321Team/infra-harbor-trivy/pull/2#issuecomment-5647308804
# 사용: CA_FILE=<ca.pem> digest-traceability-check.sh <namespace> <pod-name> <container-name> <harbor-image-ref>
#   harbor-image-ref 예: 10.1.93.54/fds/test:review-1234 (registry/project/repo:tag 형식, tag 필수)
set -euo pipefail

# HBR-01: Secret을 참조하는 어떤 줄보다도 먼저 xtrace를 끈다.
set +x

NAMESPACE="${1:?namespace를 지정하세요}"
POD_NAME="${2:?pod name을 지정하세요}"
CONTAINER_NAME="${3:?대상 container name을 명시하세요 (첫 번째 컨테이너를 임의로 선택하지 않음)}"
HARBOR_IMAGE_REF="${4:?검증 대상 Harbor image reference(registry/project/repo:tag)를 지정하세요}"
CA_FILE="${CA_FILE:?CA_FILE 환경변수를 지정하세요 (Harbor manifest 조회용 TLS 검증)}"

if [ -z "${WORKER_ROBOT_USER:-}" ] || [ -z "${WORKER_ROBOT_SECRET:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다 (Harbor manifest 조회용)."
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

# R9 HBR-05: 호출자가 넘긴 Digest를 그대로 신뢰하지 않는다. sha256 정규식
# 형식만으로는 그 값이 image index/manifest 자체의 Digest인지, 내부 config나
# layer의 Digest인지 구분할 수 없기 때문이다. 대신 Harbor Registry v2 API로
# 해당 tag의 manifest를 직접 조회해 응답 헤더 Docker-Content-Digest를 사용한다
# — 이 헤더는 정의상 "조회한 manifest/index 자체"의 Digest이므로 config/layer
# Digest와 혼동될 여지가 없다.
MANIFEST_HEADERS=$(curl --fail --silent --show-error --cacert "${CA_FILE}" \
  -u "${WORKER_ROBOT_USER}:${WORKER_ROBOT_SECRET}" \
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
