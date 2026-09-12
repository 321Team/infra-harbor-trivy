#!/usr/bin/env bash
# P1-HBR-01 / AC-05 — Pod Digest와 Harbor Digest 완전 일치 검증
# 관련 리뷰: fds-project-baseline#13 (HBR-05)
# 8차 리뷰 후속: https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615
# 사용: digest-traceability-check.sh <namespace> <pod-name> <container-name> <expected-harbor-digest>
set -euo pipefail

NAMESPACE="${1:?namespace를 지정하세요}"
POD_NAME="${2:?pod name을 지정하세요}"
CONTAINER_NAME="${3:?대상 container name을 명시하세요 (첫 번째 컨테이너를 임의로 선택하지 않음)}"
HARBOR_DIGEST="${4:?기대하는 Harbor Digest(sha256:...)를 지정하세요}"

if [[ ! "${HARBOR_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: HARBOR_DIGEST 형식이 올바르지 않음 (manifest/config digest와 혼동되지 않았는지 확인): ${HARBOR_DIGEST}"
  exit 1
fi

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
  echo "PASS: ${POD_NAME} Pod Digest가 Harbor Digest와 정확히 일치함"
else
  echo "FAIL: ${POD_NAME} Digest 불일치 (Pod: ${POD_DIGEST}, Expected: ${HARBOR_DIGEST})"
  exit 1
fi
