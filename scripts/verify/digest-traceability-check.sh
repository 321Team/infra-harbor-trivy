#!/usr/bin/env bash
# P1-HBR-01 / AC-05 — Pod Digest와 Harbor Digest 완전 일치 검증
# 관련 리뷰: fds-project-baseline#13 (HBR-05)
# 8차 리뷰 후속: https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-5644892615
# R9 후속: https://github.com/321Team/infra-harbor-trivy/pull/2#issuecomment-5647308804
# R10 딥리뷰: https://github.com/321Team/infra-harbor-trivy/pull/2#pullrequestreview-5217513542
# 사용: CA_FILE=<ca.pem> digest-traceability-check.sh <namespace> <pod-name> <container-name> <harbor-image-ref>
#   image reference: 10.1.93.54/fds/test@sha256:<approved single-platform manifest digest>
#   registry는 아래 HARBOR_REGISTRY로 고정되며, 다른 값이 오면 거부한다.
set -euo pipefail

# HBR-01: Secret을 참조하는 어떤 줄보다도 먼저 xtrace를 끈다.
set +x

HARBOR_REGISTRY="10.1.93.54"

NAMESPACE="${1:?namespace를 지정하세요}"
POD_NAME="${2:?pod name을 지정하세요}"
CONTAINER_NAME="${3:?대상 container name을 명시하세요 (첫 번째 컨테이너를 임의로 선택하지 않음)}"
HARBOR_IMAGE_REF="${4:?immutable Harbor image reference required}"
POD_CONTAINER_NAME="$CONTAINER_NAME"
POD_IMAGE="$HARBOR_IMAGE_REF"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/pod-review-binding.sh"
require_pod_review_inputs || exit 1
: "${POD_UID:?create-response Pod UID required}"
: "${REVIEW_RUN_ID:?review run required}"
: "${RUN_NONCE:?invocation nonce required}"
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
HARBOR_REPO_DIGEST="${HARBOR_IMAGE_REF#*/}"
HARBOR_DIGEST_REF="${HARBOR_REPO_DIGEST##*@}"
HARBOR_REPO="${HARBOR_REPO_DIGEST%@*}"
if [[ ! "$HARBOR_REPO" =~ ^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$ ]] ||
   [ "$HARBOR_DIGEST_REF" != "$EXPECTED_HARBOR_DIGEST" ]; then
  echo "ERROR: expected an approved immutable registry/repository@sha256 reference" >&2
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
cleanup_curl_config() {
  local rc=$?
  trap - EXIT INT TERM
  if [ -n "$CURL_CONFIG_FILE" ] && ! rm -f -- "$CURL_CONFIG_FILE"; then
    echo "ERROR: curl credential config cleanup failed" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup_curl_config EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 600 "${CURL_CONFIG_FILE}"

# curl config 문법(`user = "id:secret"`)에서 백슬래시와 큰따옴표는 각각
# `\\`, `\"`로 이스케이프해야 값이 깨지지 않는다 (백슬래시를 먼저 치환).
_curl_cfg_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}
printf 'user = "%s:%s"\n' \
  "$(_curl_cfg_escape "${WORKER_ROBOT_USER}")" \
  "$(_curl_cfg_escape "${WORKER_ROBOT_SECRET}")" \
  > "${CURL_CONFIG_FILE}"

# Single-platform scope: compare an immutable Harbor manifest and a bound Pod.
# Index/list references require child-manifest resolution and are not accepted here.
MANIFEST_HEADERS=$(curl -q -K "${CURL_CONFIG_FILE}" \
  --fail --silent --show-error --cacert "${CA_FILE}" \
  --proto "=https" --connect-timeout 10 --max-time 30 \
  -o /dev/null -D - \
  -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
  "https://${HARBOR_HOST}/v2/${HARBOR_REPO}/manifests/${HARBOR_DIGEST_REF}")

HARBOR_DIGEST=$(printf '%s' "${MANIFEST_HEADERS}" | tr -d '\r' \
  | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2; exit}')

if [[ ! "${HARBOR_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: Harbor manifest 조회에서 유효한 Docker-Content-Digest를 얻지 못함 (image=${HARBOR_IMAGE_REF})"
  exit 1
fi
echo "OK: Harbor manifest에서 직접 조회한 Digest 확인 (image=${HARBOR_IMAGE_REF}): ${HARBOR_DIGEST}"

MANIFEST_TYPE=$(printf '%s' "$MANIFEST_HEADERS" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-type"{print $2; exit}')
case "${MANIFEST_TYPE%%;*}" in
  application/vnd.oci.image.manifest.v1+json|application/vnd.docker.distribution.manifest.v2+json) ;;
  *) echo "ERROR: manifest type is not a verified single-platform manifest" >&2; exit 1 ;;
esac
[ "$HARBOR_DIGEST" = "$EXPECTED_HARBOR_DIGEST" ] || { echo 'ERROR: Harbor digest differs from approved digest' >&2; exit 1; }
POD_SNAPSHOT=$("${KUBECTL[@]}" get pod "$POD_NAME" -n "$NAMESPACE" -o json)
if ! POD_IMAGE_ID=$(printf '%s' "$POD_SNAPSHOT" | bound_pod_image_id); then
  echo 'ERROR: Pod UID/run/node/container/credential binding or Ready state mismatch' >&2
  exit 1
fi
POD_DIGEST="${POD_IMAGE_ID##*@}"
[[ "$POD_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'ERROR: invalid Pod imageID digest' >&2; exit 1; }
[ "$POD_DIGEST" = "$HARBOR_DIGEST" ] || { echo 'ERROR: Pod/Harbor manifest digest mismatch' >&2; exit 1; }
# Do not print a successful result while the credential config still exists.
rm -f -- "$CURL_CONFIG_FILE"
CURL_CONFIG_FILE=""
echo "PASS: Pod/Harbor manifest digest binding uid=$POD_UID node=$NODE_NAME container=$POD_CONTAINER_NAME digest=$POD_DIGEST"
