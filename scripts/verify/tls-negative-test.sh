#!/usr/bin/env bash
# P1-HBR-01 / AC-01 — TLS Negative Test (DEC-P1-TLS-01/D19)
# 관련 리뷰: fds-project-baseline#13 (HBR-04)
set -euo pipefail

HARBOR_IP="10.1.93.54"
CA_FILE="${CA_FILE:?CA_FILE 환경변수를 지정하세요}"
WRONG_CA_FILE="${WRONG_CA_FILE:?WRONG_CA_FILE 환경변수를 지정하세요}"

if [ ! -f "${WRONG_CA_FILE}" ]; then
  echo "ERROR: Wrong CA 파일이 존재하지 않음 (${WRONG_CA_FILE})"
  exit 1
fi
openssl x509 -in "${WRONG_CA_FILE}" -noout -subject >/dev/null 2>&1 || {
  echo "ERROR: Wrong CA 파일이 유효한 인증서 형식이 아님"
  exit 1
}

# 1. 정상 CA로 Positive 선행 확인 (네트워크/TLS 자체는 정상임을 먼저 증명)
if ! curl --fail --silent --cacert "${CA_FILE}" "https://${HARBOR_IP}:443/api/v2.0/health" >/dev/null; then
  echo "ERROR: 정상 CA로도 접속 실패 — 네트워크/서비스 장애로 판단, TLS Negative 시험 무의미"
  exit 1
fi
echo "OK: 정상 CA Positive 확인 완료"

# 2. Wrong CA로 시도
TLS_ERR=$(curl --fail --silent --cacert "${WRONG_CA_FILE}" "https://${HARBOR_IP}:443/api/v2.0/health" 2>&1 >/dev/null) && TLS_EXIT_CODE=0 || TLS_EXIT_CODE=$?

# HBR-04: curl Exit Code 60(SSL certificate problem)만으로 판정한다.
# 이전 버전은 `-eq 60 OR grep "certificate"`로 판정해, 60이 아닌 다른 원인도
# 문자열만 맞으면 PASS 처리될 수 있었다. curl 공식 오류 정의(60=SSL cert verify
# failed)를 기준으로 다른 실패(네트워크/타임아웃 등)와 명확히 구분한다.
if [ ${TLS_EXIT_CODE} -eq 60 ]; then
  echo "PASS: Wrong CA로 인증서 검증 실패 확인 (Exit Code: 60)"
else
  echo "FAIL: 접속 실패했으나 원인이 인증서 검증 실패(60)가 아님 (실제 Exit Code: ${TLS_EXIT_CODE})"
  echo "Error: ${TLS_ERR}"
  exit 1
fi

# 3. 올바른 CA로는 정상 접속돼야 함 (반대쪽 증거도 함께 저장)
curl --fail --cacert "${CA_FILE}" "https://${HARBOR_IP}:443/api/v2.0/health"
