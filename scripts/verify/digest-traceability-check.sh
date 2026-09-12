#!/usr/bin/env bash
# P1-HBR-01 / AC-05 — Pod Digest와 Harbor Digest 완전 일치 검증
# 관련 리뷰: fds-project-baseline#13 (HBR-05)
# 사용: digest-traceability-check.sh <namespace> <pod-name> <expected-harbor-digest>
set -euo pipefail

NAMESPACE="${1:?namespace를 지정하세요}"
POD_NAME="${2:?pod name을 지정하세요}"
HARBOR_DIGEST="${3:?기대하는 Harbor Digest(sha256:...)를 지정하세요}"

POD_IMAGE_ID=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].imageID}')
echo "Pod ImageID: ${POD_IMAGE_ID}"

# HBR-05: substring 포함 여부(`*"${HARBOR_DIGEST}"*`)가 아니라, imageID에서
# "...@sha256:xxxx" 형태의 Digest 부분만 정확히 추출해 완전 일치로 비교한다.
POD_DIGEST="${POD_IMAGE_ID##*@}"

if [ "${POD_DIGEST}" = "${HARBOR_DIGEST}" ]; then
  echo "PASS: ${POD_NAME} Pod Digest가 Harbor Digest와 정확히 일치함"
else
  echo "FAIL: ${POD_NAME} Digest 불일치 (Pod: ${POD_DIGEST}, Expected: ${HARBOR_DIGEST})"
  exit 1
fi
