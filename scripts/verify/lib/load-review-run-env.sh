#!/usr/bin/env bash
# R10 HBR-02 공통 라이브러리 — review-run.env를 안전하게 검증·파싱한다.
# worker-pull-pod-start-test.sh, worker-push-deny-test.sh가 함께 source해
# 동일한 결함이 두 곳에 따로 재발하지 않게 한다.
#
# 사용:
#   source "<이 파일 경로>"
#   load_review_run_env "./review-run.env" "./review-run.env.sha256"
# 성공(return 0) 시 TEST_TAG, REVIEW_RUN_ID 전역 변수가 채워진다.

load_review_run_env() {
  local env_file="$1"
  local sha_file="$2"

  if [ ! -f "${env_file}" ] || [ ! -f "${sha_file}" ]; then
    echo "ERROR: ${env_file} 또는 ${sha_file} 파일이 없습니다. Runner에서 전달받았는지 확인하세요." >&2
    return 1
  fi

  # R10: 이전 정규식(`\.?/?review-run\.env`)은 `.`과 `/`를 각각 독립적으로
  # optional 처리해서 review-run.env가 아닌 "다른 파일"인 .review-run.env도
  # 매치되는 결함이 있었다(재현됨). "./" 는 함께 오거나 아예 없어야 하므로
  # 그룹으로 묶고, 줄 전체를 앵커해 sha256sum이 특수문자 파일명에 쓰는 선행
  # `\` 이스케이프 표기도 차단한다.
  local base_name
  base_name="$(basename -- "${env_file}")"
  local escaped_name="${base_name//./\\.}"
  local line_pattern="^[0-9a-fA-F]{64}[[:space:]][ *](\\./)?${escaped_name}\$"

  local matches
  matches="$(grep -cE "${line_pattern}" "${sha_file}" || true)"
  if [ "${matches}" -ne 1 ]; then
    echo "ERROR: ${sha_file}에 ${base_name} 항목이 정확히 1개 있어야 합니다 (실제: ${matches}개)." >&2
    return 1
  fi

  # R10: 체크섬 검증과 파싱을 각각 원본 경로에서 따로 열면 그 사이에 파일이
  # 바뀔 수 있다(TOCTOU). 한 번만 스냅샷으로 복사해 그 바이트만 해시·파싱에
  # 함께 사용한다.
  local snapshot
  snapshot="$(mktemp)"
  # RETURN trap은 함수 반환 뒤에도 남을 수 있다. 지역변수가 유효한
  # 첫 반환에서 스냅샷을 정리하고 trap을 해제해 상위 함수로 누출하지 않는다.
  trap 'rm -f -- "${snapshot}"; trap - RETURN' RETURN

  cp -- "${env_file}" "${snapshot}"

  local expected_hash actual_hash
  expected_hash="$(grep -E "${line_pattern}" "${sha_file}" | head -n1 | awk '{print tolower($1)}')"
  actual_hash="$(sha256sum "${snapshot}" | awk '{print $1}')"

  if [ "${expected_hash}" != "${actual_hash}" ]; then
    echo "ERROR: ${env_file} 무결성 검증 실패. 파일이 전송 중 변조/손상되었을 수 있습니다." >&2
    return 1
  fi

  unset TEST_TAG REVIEW_RUN_ID
  local -A seen_keys=()
  local allowed_keys="TEST_TAG REVIEW_RUN_ID"
  local env_key env_value

  while IFS='=' read -r env_key env_value; do
    [[ -z "${env_key}" || "${env_key}" =~ ^[[:space:]]*# ]] && continue
    case " ${allowed_keys} " in
      *" ${env_key} "*)
        if [ -n "${seen_keys[${env_key}]:-}" ]; then
          echo "ERROR: ${env_file}에 ${env_key} 키가 중복됨 (마지막 값을 조용히 채택하지 않음)" >&2
          return 1
        fi
        seen_keys[${env_key}]=1

        # R10: 이전에는 모든 키에 동일한 느슨한 문자셋(`[A-Za-z0-9._:-]*`)만
        # 적용해 "bad:tag", "Bad_Run:001" 같은 값도 사전 검증을 통과했다.
        # TEST_TAG는 Docker tag 문법, REVIEW_RUN_ID는 최종적으로 Pod 이름
        # (`p1-hbr-verify-<id>`)에 들어가므로 k8s 리소스 이름(RFC1123) 문법을
        # 각각 명시적으로 적용한다.
        case "${env_key}" in
          TEST_TAG)
            if [[ ! "${env_value}" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]]; then
              echo "ERROR: TEST_TAG 형식이 Docker tag 규칙에 맞지 않음: '${env_value}'" >&2
              return 1
            fi
            ;;
          REVIEW_RUN_ID)
            if [[ ! "${env_value}" =~ ^[a-z0-9]([a-z0-9-]{0,47}[a-z0-9])?$ ]]; then
              echo "ERROR: REVIEW_RUN_ID 형식이 k8s 리소스 이름 규칙(소문자/숫자/-)에 맞지 않음: '${env_value}'" >&2
              return 1
            fi
            ;;
        esac

        printf -v "${env_key}" '%s' "${env_value}"
        ;;
      *)
        echo "ERROR: ${env_file}에 허용되지 않은 키(${env_key})가 존재함" >&2
        return 1
        ;;
    esac
  done < "${snapshot}"

  if [ -z "${TEST_TAG:-}" ] || [ -z "${REVIEW_RUN_ID:-}" ]; then
    echo "ERROR: TEST_TAG 또는 REVIEW_RUN_ID가 ${env_file}에 비어 있습니다." >&2
    return 1
  fi

  echo "OK: ${env_file} 무결성 확인 및 안전 로드 완료 (Run ID: ${REVIEW_RUN_ID})" >&2
  return 0
}
