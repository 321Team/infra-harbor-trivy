#!/usr/bin/env bash
# runner-push-test.sh 격리 시험: podman은 모의 명령이며 Harbor/네트워크에 접속하지 않는다.
# 사용: bash tests/review/test_runner_push_mock.sh   (Linux 또는 Git Bash)
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/verify/runner-push-test.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT
mkdir -p "${ROOT}/bin"
GOOD_DIGEST="sha256:$(printf 'a%.0s' $(seq 1 64))"
OTHER_DIGEST="sha256:$(printf 'b%.0s' $(seq 1 64))"
BASE_REF="alpine@sha256:$(printf 'c%.0s' $(seq 1 64))"

cat > "${ROOT}/bin/podman" <<'MOCK'
#!/usr/bin/env bash
# 모의 podman. 동작은 MOCK_* 환경변수로 제어한다.
echo "$*" >> "${MOCK_CALLS}"
sub="$1"; shift
case "${sub}" in
  login)
    pw="$(cat)"
    if [ "${pw}" = "WRONGPW" ]; then
      case "${MOCK_WRONG_LOGIN:-unauthorized}" in
        unauthorized) echo "Error: logging into \"10.1.93.54\": invalid username/password: unauthorized: authentication required"; exit 125 ;;
        status401)     echo "Error: unexpected status: 401 Unauthorized"; exit 125 ;;
        transport)     echo "Error: dial tcp 10.1.93.54:443: connect: connection refused"; exit 125 ;;
        tls)           echo "Error: x509: certificate signed by unknown authority"; exit 125 ;;
        silent)        exit 125 ;;
        mixed)         echo "unauthorized: authentication required; TLS handshake timeout"; exit 125 ;;
        success)       exit 0 ;;
      esac
    fi
    [ "${MOCK_GOOD_LOGIN:-ok}" = "ok" ] && exit 0
    echo "unauthorized"; exit 125 ;;
  pull)
    ref="${!#}"
    case "${ref}" in
      10.1.93.54/*) [ "${MOCK_HARBOR_PULL:-ok}" = "ok" ] && exit 0; echo "manifest unknown"; exit 125 ;;
      *) [ "${MOCK_BASE_PULL:-ok}" = "ok" ] && exit 0; echo "base pull failed"; exit 125 ;;
    esac ;;
  tag|rmi|logout) exit 0 ;;
  push)
    [ "${MOCK_PUSH:-ok}" = "ok" ] || { echo "push failed"; exit 125; }
    df=""
    while [ $# -gt 0 ]; do [ "$1" = "--digestfile" ] && df="$2"; shift; done
    case "${MOCK_DIGESTFILE:-good}" in
      good)  [ -n "${df}" ] && printf '%s' "${MOCK_PUSH_DIGEST}" > "${df}" ;;
      empty) [ -n "${df}" ] && : > "${df}" ;;
      bad)   [ -n "${df}" ] && printf 'not-a-digest' > "${df}" ;;
      none)  : ;;
    esac
    echo "Writing manifest to image destination"
    exit 0 ;;
  image)
    # image inspect --format ... <ref>
    echo "${MOCK_PULLED_DIGEST}"; exit 0 ;;
esac
exit 0
MOCK
chmod +x "${ROOT}/bin/podman"

PASS=0; FAIL=0
# run <이름> <기대 종료코드> <기대 출력 패턴|-> [ENV=VAL ...]
run() {
  local name="$1" want="$2" pat="$3"; shift 3
  : > "${ROOT}/calls.log"
  local out rc
  out="$(env PATH="${ROOT}/bin:${PATH}" MOCK_CALLS="${ROOT}/calls.log" \
         MOCK_PUSH_DIGEST="${GOOD_DIGEST}" MOCK_PULLED_DIGEST="${GOOD_DIGEST}" \
         RUNNER_ROBOT_USER="robot\$push" RUNNER_ROBOT_SECRET="GOODPW" WRONG_ROBOT_SECRET="WRONGPW" \
         BASE_IMAGE_REF="${BASE_REF}" "$@" bash "${SCRIPT}" 2>&1)"; rc=$?
  local ok=1
  [ "${rc}" -eq "${want}" ] || ok=0
  if [ "${pat}" != "-" ] && ! printf '%s' "${out}" | grep -qE "${pat}"; then ok=0; fi
  # credential 값이 출력에 나오면 실패
  if printf '%s' "${out}" | grep -qE 'GOODPW|WRONGPW'; then ok=0; echo "  !! secret 값이 출력됨"; fi
  if [ "${ok}" -eq 1 ]; then PASS=$((PASS+1)); echo "PASS  ${name} (rc=${rc})"
  else FAIL=$((FAIL+1)); echo "FAIL  ${name} (rc=${rc}, want=${want}, pat=${pat})"; printf '%s\n' "${out}" | sed 's/^/      | /' | tail -12; fi
}

run "정상: push→digest Pull→인증거부 PASS"              0 "MANIFEST_DIGEST=${GOOD_DIGEST}"
run "Negative: 401 문구도 인증 거부로 인정"            0 "인증 거부로 확인" MOCK_WRONG_LOGIN=status401
run "Negative: 네트워크 오류는 PASS 아님(ERROR)"       2 "인증 외 오류"      MOCK_WRONG_LOGIN=transport
run "Negative: TLS 오류는 PASS 아님(ERROR)"           2 "인증 외 오류"      MOCK_WRONG_LOGIN=tls
run "Negative: 문구 없는 실패는 UNRESOLVED(ERROR)"    2 "UNRESOLVED"        MOCK_WRONG_LOGIN=silent
run "Negative: 인증+전송 혼합은 ERROR"                2 "인증 외 오류"      MOCK_WRONG_LOGIN=mixed
run "Negative: 틀린 secret으로 로그인 성공이면 FAIL"   1 "로그인 성공함"     MOCK_WRONG_LOGIN=success
run "정상 credential 로그인 실패는 FAIL"               1 "로그인 실패"       MOCK_GOOD_LOGIN=bad
run "base 이미지 Pull 실패는 ERROR"                   2 "시험 입력 이미지"  MOCK_BASE_PULL=fail
run "Push 실패는 FAIL"                                1 "Push 실패"         MOCK_PUSH=fail
run "digestfile 비어 있으면 ERROR(DIGEST_UNVERIFIED)" 2 "DIGEST_UNVERIFIED" MOCK_DIGESTFILE=empty
run "digestfile 형식 오류는 ERROR"                    2 "DIGEST_UNVERIFIED" MOCK_DIGESTFILE=bad
run "digestfile 미생성은 ERROR"                       2 "DIGEST_UNVERIFIED" MOCK_DIGESTFILE=none
run "Harbor digest Pull 실패는 FAIL"                  1 "Pull 실패"         MOCK_HARBOR_PULL=fail
run "Pull digest 불일치는 FAIL"                       1 "digest.*다름"      MOCK_PULLED_DIGEST="${OTHER_DIGEST}"
run "BASE_IMAGE_REF 없음은 ERROR"                     2 "BASE_IMAGE_REF"    BASE_IMAGE_REF=
run "moving tag(alpine:3.20)는 거부"                  2 "moving tag"        BASE_IMAGE_REF=alpine:3.20
run "digest 길이 오류는 거부"                         2 "moving tag"        BASE_IMAGE_REF="alpine@sha256:abc"
run "WRONG_ROBOT_SECRET 없음은 ERROR"                 2 "WRONG_ROBOT_SECRET" WRONG_ROBOT_SECRET=
run "RUNNER_ROBOT_SECRET 없음은 ERROR"                2 "RUNNER_ROBOT_USER" RUNNER_ROBOT_SECRET=

# 호출 순서 검증: Harbor Pull 이전에 로컬 이미지를 지워야 한다(로컬 캐시로 PASS 방지).
: > "${ROOT}/calls.log"
env PATH="${ROOT}/bin:${PATH}" MOCK_CALLS="${ROOT}/calls.log" MOCK_PUSH_DIGEST="${GOOD_DIGEST}" MOCK_PULLED_DIGEST="${GOOD_DIGEST}" \
    RUNNER_ROBOT_USER="robot\$push" RUNNER_ROBOT_SECRET="GOODPW" WRONG_ROBOT_SECRET="WRONGPW" BASE_IMAGE_REF="${BASE_REF}" \
    bash "${SCRIPT}" >/dev/null 2>&1
rmi_line="$(grep -n '^rmi -f .*alpine@' "${ROOT}/calls.log" | head -1 | cut -d: -f1)"
pull_line="$(grep -n '^pull 10.1.93.54/fds/test@' "${ROOT}/calls.log" | head -1 | cut -d: -f1)"
if [ -n "${rmi_line}" ] && [ -n "${pull_line}" ] && [ "${rmi_line}" -lt "${pull_line}" ]; then
  PASS=$((PASS+1)); echo "PASS  Harbor Pull 이전에 로컬 이미지 제거(rmi ${rmi_line} < pull ${pull_line})"
else
  FAIL=$((FAIL+1)); echo "FAIL  로컬 이미지 제거가 Harbor Pull 이전이 아님 (rmi=${rmi_line:-없음} pull=${pull_line:-없음})"
fi
# 모든 base pull/push 인자가 digest 고정인지(moving tag 호출 없음)
if grep -E '^pull alpine:' "${ROOT}/calls.log" >/dev/null; then
  FAIL=$((FAIL+1)); echo "FAIL  moving tag로 pull 호출됨"
else
  PASS=$((PASS+1)); echo "PASS  moving tag pull 호출 없음"
fi

echo "---- 결과: PASS=${PASS} FAIL=${FAIL}"
[ "${FAIL}" -eq 0 ]
