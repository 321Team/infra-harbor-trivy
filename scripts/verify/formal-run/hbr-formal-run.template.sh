#!/usr/bin/env bash
# P1-HBR-01 IF-09 Runner 정식 시험 (AC-02) wrapper v2 — 병합된 runner-push-test.sh(infra-harbor-trivy main 6edf816, tree 25b8195fe1c1)
# 모의/우회 없음. 자격증명은 /dev/tty에서만 입력받고 어디에도 기록하지 않는다. fail-closed: PASS는 모든 조건이 참일 때만.
# 사용: bash ~/hbr-formal-run.sh <기대 wrapper sha256>   (종료코드: 0=PASS, 1=FAIL, 2=ERROR — 본체 rc를 그대로 전달)
set -u
set -o pipefail
umask 077

EXPECT_WRAPPER_SHA="${1:-}"
EXPECT_SCRIPT_SHA=1305e9affe70132bcc570a646369834dd1ce237570a4c7537bbead6da6b6fe1e
PINNED_BASE_IMAGE_REF=docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
CA_SHA=20ddfa5e92c346aaf46fc30179fbc0b069e256effd2615a9f4308a8fe719053f
HARBOR_REGISTRY=10.1.93.54

stop() { echo "ABORT: $*" >&2; exit 2; }

# --- 0. 사전 확인 (child 실행 전 STOP) ---
for c in podman sha256sum base64 tee grep head tr cut mktemp date hostname whoami; do
  command -v "$c" >/dev/null 2>&1 || stop "필수 명령 없음: $c"
done
[[ "$EXPECT_WRAPPER_SHA" =~ ^[0-9a-f]{64}$ ]] || stop "사용법: bash $0 <기대 wrapper sha256(64 hex)>"
WRAPPER_SHA="$(sha256sum "$0" | cut -d' ' -f1)"
[ "$WRAPPER_SHA" = "$EXPECT_WRAPPER_SHA" ] || stop "wrapper sha256 불일치(실제 $WRAPPER_SHA) — 검토된 바이트와 다름"
echo "OK: wrapper sha256 일치 ($WRAPPER_SHA)"
[ -z "${RUNNER_ROBOT_SECRET+x}" ] || stop "RUNNER_ROBOT_SECRET이 이미 설정됨 — Formal Run은 터미널 입력만 허용 (unset 후 새 shell에서 실행)"
[ -z "${WRONG_ROBOT_SECRET+x}" ] || stop "WRONG_ROBOT_SECRET이 이미 설정됨 — wrapper가 생성함 (unset 후 재실행)"
if [ -n "${BASE_IMAGE_REF+x}" ] && [ "$BASE_IMAGE_REF" != "$PINNED_BASE_IMAGE_REF" ]; then
  stop "BASE_IMAGE_REF override 거부 — 승인된 digest 고정값만 사용"
fi
unset BASE_IMAGE_REF
[ -r /dev/tty ] || stop "/dev/tty 없음 — 터미널에서 실행해야 함"

# --- 1. Run 격리: 항상 새 디렉터리, 재사용 금지 ---
STAMP="$(date +%Y%m%d-%H%M%S%z)"
DIR="$(mktemp -d "$HOME/hbr-review-run-$STAMP.XXXXXX")" || stop "결과 폴더 생성 실패"
chmod 700 "$DIR" || stop "결과 폴더 chmod 실패"
RUN_ID="hbr-${DIR##*/hbr-review-run-}"
[ -z "$(ls -A "$DIR")" ] || stop "결과 폴더가 비어 있지 않음"

# --- 2. 본체 포함 + sha256 검증 ---
cat > "$DIR/runner-push-test.sh" <<'SCRIPT_EOF'
@@BODY@@
SCRIPT_EOF
[ $? -eq 0 ] || stop "본체 기록 실패"
ACT_SHA="$(sha256sum "$DIR/runner-push-test.sh" | cut -d' ' -f1)"
[ "$ACT_SHA" = "$EXPECT_SCRIPT_SHA" ] || stop "시험 스크립트 sha256 불일치($ACT_SHA) — 붙여넣기 손상"
echo "OK: 시험 스크립트 sha256 일치 (리뷰·병합된 코드와 동일)"
CA_FILE="$HOME/.config/containers/certs.d/$HARBOR_REGISTRY/ca.crt"
[ "$(sha256sum "$CA_FILE" 2>/dev/null | cut -d' ' -f1)" = "$CA_SHA" ] || stop "Podman CA trust 파일이 없거나 승인 Root와 다릅니다"
echo "OK: Podman CA trust(승인 Root) 확인"

# --- 3. 비밀 입력: 항상 /dev/tty 1회, 비export ---
SECRET=""
read -rsp 'robot$push 비밀번호(화면에 표시되지 않음): ' SECRET < /dev/tty || { echo; stop "비밀번호 입력 실패"; }
echo
[ -n "$SECRET" ] || stop "비밀번호 미입력"
WRONG="$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')x"
[ -n "$WRONG" ] && [ "$WRONG" != "$SECRET" ] || stop "WRONG_ROBOT_SECRET 생성 실패/정상 secret과 동일"

# --- 4. child 실행: child rc와 tee rc를 각각 보존 ---
LOG="$DIR/run.log"
SEAL_OK=1
{
  echo "# host=$(hostname) user=$(whoami) time=$(date -Is)"
  echo "RUN_ID=$RUN_ID  SCRIPT_SHA256=$ACT_SHA  WRAPPER_SHA256=$WRAPPER_SHA  SOURCE=infra-harbor-trivy main 6edf816 (tree 25b8195fe1c1)"
  echo "BASE_IMAGE_REF=$PINNED_BASE_IMAGE_REF"
  echo "CA_FILE_SHA256=$CA_SHA  tls_verify=on(default, --tls-verify=false 미사용)"
  echo "podman: $(podman --version 2>&1)"
} 2>&1 | tee "$LOG"
HDR_RC=("${PIPESTATUS[@]}")
[ "${HDR_RC[0]}" = 0 ] && [ "${HDR_RC[1]}" = 0 ] || SEAL_OK=0

RUNNER_ROBOT_USER='robot$push' RUNNER_ROBOT_SECRET="$SECRET" WRONG_ROBOT_SECRET="$WRONG" BASE_IMAGE_REF="$PINNED_BASE_IMAGE_REF" \
  bash "$DIR/runner-push-test.sh" 2>&1 | tee -a "$LOG"
PIPE_RC=("${PIPESTATUS[@]}")
CHILD_RC="${PIPE_RC[0]}"; TEE_RC="${PIPE_RC[1]}"
[ "$TEE_RC" = 0 ] || SEAL_OK=0
echo "RUN_RC=$CHILD_RC" >> "$LOG" || SEAL_OK=0

# --- 5. rc 정규화 (0/1/2 외 → ERROR 2, 원 rc는 별도 기록) ---
case "$CHILD_RC" in 0|1|2) RUN_RC="$CHILD_RC" ;; *) RUN_RC=2 ;; esac

TEST_TAG="$(grep -oE 'TEST_TAG=ifup-[0-9]{8}T[0-9]{6}Z' "$LOG" | tail -1 | cut -d= -f2)"
DIGEST="$(grep -oE 'MANIFEST_DIGEST=sha256:[0-9a-f]{64}' "$LOG" | tail -1 | cut -d= -f2)"
echo "--- 판정 입력: CHILD_RC=$CHILD_RC TEST_TAG=$TEST_TAG MANIFEST_DIGEST=$DIGEST TEE_RC=$TEE_RC"

# --- 6. 비밀 비노출 점검 (결과 폴더 전체) ---
if grep -rlFf <(printf '%s\n%s\n' "$SECRET" "$WRONG") "$DIR" >/dev/null 2>&1; then
  echo "ERROR: 결과 폴더에 secret 문자열이 기록됨" >&2; SEAL_OK=0
fi
SECRET=""; WRONG=""; unset SECRET WRONG

# --- 7. handoff + seal (PASS는 RUN_RC=0 + TAG/DIGEST valid + handoff + seal 모두 참) ---
RESULT=NOT_PASS
if [ "$RUN_RC" = 0 ] && [ "$CHILD_RC" = 0 ] && [ -n "$TEST_TAG" ] && [ -n "$DIGEST" ] && [ "$SEAL_OK" = 1 ]; then
  printf 'TEST_TAG=%s\nREVIEW_RUN_ID=%s\n' "$TEST_TAG" "$RUN_ID" > "$DIR/review-run.env" || SEAL_OK=0
  ( cd "$DIR" && sha256sum review-run.env > review-run.env.sha256 ) || SEAL_OK=0
  { echo "RUN_ID=$RUN_ID"; echo "TEST_TAG=$TEST_TAG"; echo "EXPECTED_HARBOR_DIGEST=$DIGEST"; echo "IMAGE=$HARBOR_REGISTRY/fds/test:$TEST_TAG"; echo "BASE_IMAGE_REF=$PINNED_BASE_IMAGE_REF"; echo "WRAPPER_SHA256=$WRAPPER_SHA"; echo "CHILD_RC=$CHILD_RC"; } > "$DIR/summary.txt" || SEAL_OK=0
  [ "$SEAL_OK" = 1 ] && RESULT=PASS
fi
if [ "$RESULT" != PASS ]; then
  # 실패/ERROR 경로에는 handoff 산출물을 남기지 않는다
  rm -f "$DIR/review-run.env" "$DIR/review-run.env.sha256" "$DIR/summary.txt"
  if [ "$RUN_RC" = 0 ]; then RUN_RC=2; fi   # 본체는 PASS였으나 wrapper 검증/seal 실패 → ERROR
fi
[ "$RESULT" = PASS ] || { [ "$RUN_RC" = 1 ] || RUN_RC=2; }

FILES=(run.log runner-push-test.sh)
{
  echo "RESULT=$RESULT"; echo "WRAPPER_SHA256=$WRAPPER_SHA"; echo "CHILD_RC_RAW=$CHILD_RC"; echo "WRAPPER_RC=$([ "$RESULT" = PASS ] && echo 0 || echo "$RUN_RC")"
  echo "SEAL_OK=$SEAL_OK"
} > "$DIR/wrapper-result.txt" || SEAL_OK=0
FILES+=(wrapper-result.txt)
[ -f "$DIR/review-run.env" ] && FILES+=(review-run.env review-run.env.sha256 summary.txt)
( cd "$DIR" && sha256sum "${FILES[@]}" > SHA256SUMS && cat SHA256SUMS ) || SEAL_OK=0

if [ "$SEAL_OK" != 1 ] && [ "$RESULT" = PASS ]; then
  RESULT=ERROR; RUN_RC=2
  rm -f "$DIR/review-run.env" "$DIR/review-run.env.sha256" "$DIR/summary.txt" "$DIR/SHA256SUMS"
  echo "RESULT=ERROR (seal 실패 — 이전 판정 PASS 무효)" >> "$DIR/wrapper-result.txt"
fi

if [ "$RESULT" = PASS ]; then
  echo "RESULT=PASS (AC-02 Runner Push/Pull/Negative). Worker 시험용 review-run.env 생성됨"
  echo "결과 폴더: $DIR"; exit 0
fi
echo "RESULT=$RESULT — review-run.env 생성하지 않음. run.log 확인 (WRAPPER_RC=$RUN_RC; FAIL=1, ERROR=2)"
echo "결과 폴더: $DIR"
exit "$RUN_RC"
