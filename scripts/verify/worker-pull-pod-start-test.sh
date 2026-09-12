#!/usr/bin/env bash
# P1-HBR-01 / AC-03, AC-05 — Worker Pull + Pod Start 검증 (containerd/CRI 기반)
# 관련 리뷰: fds-project-baseline#13 (HBR-01, HBR-02, HBR-03)
# 실행 대상: k8s-worker01(.105), k8s-worker02(.107), k8s-worker03(.108) 각각 개별 실행
set -euo pipefail

HARBOR_REGISTRY="10.1.93.54"

if [ -z "${WORKER_ROBOT_SECRET:-}" ] || [ -z "${WORKER_ROBOT_USER:-}" ]; then
  echo "ERROR: WORKER_ROBOT_USER 또는 WORKER_ROBOT_SECRET 환경변수가 주입되지 않았습니다."
  exit 1
fi

# HBR-01: Secret을 참조하는 위 조건문보다 뒤가 아니라, 여기서 바로 xtrace를 끈다.
set +x

# review-run.env 무결성 확인 및 로드
if [ ! -f "./review-run.env" ] || [ ! -f "./review-run.env.sha256" ]; then
  echo "ERROR: review-run.env 또는 review-run.env.sha256 파일이 없습니다. Runner에서 전달받았는지 확인하세요."
  exit 1
fi

if ! sha256sum --check "./review-run.env.sha256" >/dev/null 2>&1; then
  echo "ERROR: review-run.env 무결성 검증 실패. 파일이 전송 중 변조/손상되었을 수 있습니다."
  exit 1
fi

source "./review-run.env"

if [ -z "${TEST_TAG:-}" ] || [ -z "${REVIEW_RUN_ID:-}" ]; then
  echo "ERROR: TEST_TAG 또는 REVIEW_RUN_ID가 review-run.env에 비어 있습니다."
  exit 1
fi
echo "OK: review-run.env 무결성 확인 및 로드 완료 (Run ID: ${REVIEW_RUN_ID})"

# HBR-02: TEST_IMAGE는 review-run.env 로드/검증 이후에 조합한다.
# (로드 전에 조합하면 TEST_TAG가 비어 있어 빈 태그로 판정될 수 있었음)
TEST_IMAGE="${HARBOR_REGISTRY}/fds/test:${TEST_TAG}"

# 1. crictl pull — argv 대신 환경변수로 Credential 전달
export CRICTL_AUTH=$(echo -n "${WORKER_ROBOT_USER}:${WORKER_ROBOT_SECRET}" | base64)
sudo -E crictl pull "${TEST_IMAGE}"
PULL_EXIT_CODE=$?
unset CRICTL_AUTH

# 2. nerdctl push 시도 — --password-stdin으로 argv 노출 없이 Credential 전달
PUSH_OUTPUT=$(printf '%s' "${WORKER_ROBOT_SECRET}" | \
  sudo nerdctl -n k8s.io login "${HARBOR_REGISTRY}" \
    --username "${WORKER_ROBOT_USER}" \
    --password-stdin 2>&1 && \
  sudo nerdctl -n k8s.io --hosts-dir /etc/containerd/certs.d \
    push "${TEST_IMAGE}" 2>&1) && PUSH_EXIT_CODE=0 || PUSH_EXIT_CODE=$?

sudo nerdctl -n k8s.io logout "${HARBOR_REGISTRY}" >/dev/null 2>&1

# HBR-03: 정형 거부 문구만 매치 (이미지 참조 문자열과 겹치는 범용 단어 배제)
if [ ${PULL_EXIT_CODE} -eq 0 ] && [ ${PUSH_EXIT_CODE} -ne 0 ] && echo "${PUSH_OUTPUT}" | grep -iqE "denied: requested access|unauthorized: authentication required"; then
  echo "PASS: Worker Pull ALLOW 및 Push DENY(권한 거부) 확인 완료"
else
  echo "FAIL: Pull 실패 또는 Push 차단 원인이 권한 거부가 아님"
  echo "Push Output: ${PUSH_OUTPUT}"
  exit 1
fi
