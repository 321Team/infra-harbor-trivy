#!/usr/bin/env bash
# wrapper-v2.sh 격리 시험 (Review Owner 재검증 조건 1~9). podman/tee/sha256sum/date 등은 모의 또는 shim이며 Harbor/네트워크에 접속하지 않는다.
# 시험용 사본만 만든다: 입력원(/dev/tty→파일)과 CA 해시를 치환한다. 운영 파일은 건드리지 않는다.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; W="$REPO/scripts/verify/formal-run/hbr-formal-run.sh"
ROOT="$(mktemp -d)"; trap 'rm -rf "$ROOT"' EXIT
SECRET='S3cr3t-TEST-VALUE-XYZ'
mkdir -p "$ROOT/bin"
cat > "$ROOT/bin/podman" <<'MOCK'
#!/usr/bin/env bash
echo "$*" >> "${MOCK_CALLS:-/dev/null}"
sub="$1"; shift
case "$sub" in
  --version) echo "podman version 6.1.0 (mock)";;
  login) pw="$(cat)"; if [ "$pw" = "S3cr3t-TEST-VALUE-XYZ" ]; then echo "Login Succeeded!"; exit 0; fi
         case "${MOCK_WRONG_LOGIN:-unauthorized}" in
           unauthorized) echo "Error: logging into \"10.1.93.54\": invalid username/password: unauthorized: authentication required"; exit 125;;
           transport) echo "Error: dial tcp 10.1.93.54:443: connect: connection refused"; exit 125;;
         esac;;
  pull) exit 0;; tag|rmi|logout) exit 0;;
  push) [ "${MOCK_PUSH:-ok}" = "ok" ] || { echo "push failed"; exit 125; }
        df=""; while [ $# -gt 0 ]; do [ "$1" = "--digestfile" ] && df="$2"; shift; done
        printf 'sha256:%064d' 7 > "$df"; echo "Writing manifest to image destination";;
  image) echo "sha256:$(printf '%064d' 7)";;
esac
MOCK
chmod +x "$ROOT/bin/podman"
# 시험용 사본 생성(입력원·CA 해시 치환)
mkdir -p "$ROOT/home0/.config/containers/certs.d/10.1.93.54"; echo dummy-ca > "$ROOT/home0/.config/containers/certs.d/10.1.93.54/ca.crt"
MYCA="$(sha256sum "$ROOT/home0/.config/containers/certs.d/10.1.93.54/ca.crt" | cut -d' ' -f1)"
printf '%s\n' "$SECRET" > "$ROOT/secret.txt"
sed -e "s|^SECRET_SRC=.*|SECRET_SRC=$ROOT/secret.txt|" -e "s|^CA_SHA=.*|CA_SHA=$MYCA|" "$W" > "$ROOT/wrapper-test.sh"
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "PASS  $1"; }
no() { FAIL=$((FAIL+1)); echo "FAIL  $1  ($2)"; }
newhome() { H="$ROOT/h$1"; rm -rf "$H"; mkdir -p "$H/.config/containers/certs.d/10.1.93.54"; cp "$ROOT/home0/.config/containers/certs.d/10.1.93.54/ca.crt" "$H/.config/containers/certs.d/10.1.93.54/"; : > "$ROOT/calls$1"; }
run() { # run <n> [ENV=VAL ...] -> RC, OUT
  local n="$1"; shift
  OUT="$(env HOME="$ROOT/h$n" PATH="$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls$n" "$@" bash "$ROOT/wrapper-test.sh" 2>&1)"; RC=$?
}
dirs() { ls -d "$ROOT/h$1"/hbr-review-run-* 2>/dev/null; }

# 1. child rc=0 -> wrapper rc=0 + review-run.env
newhome 1; run 1
D="$(dirs 1 | head -1)"
if [ "$RC" = 0 ] && [ -f "$D/review-run.env" ] && [ -f "$D/review-run.env.sha256" ] && grep -q "WRAPPER_SHA256=" "$D/summary.txt" && grep -q "EVIDENCE_SEAL=OK" "$D/summary.txt" && (cd "$D" && sha256sum -c SHA256SUMS >/dev/null) && echo "$OUT" | grep -q "^RESULT=PASS"; then ok "1 child rc=0 → wrapper rc=0, handoff 생성, seal 검증 OK"; else no "1 child rc=0" "rc=$RC"; fi
# 9. secret 문자열이 stdout/stderr/파일 어디에도 없어야 함
LEAK=$(grep -rl "$SECRET" "$ROOT/h1" 2>/dev/null | wc -l); echo "$OUT" | grep -q "$SECRET" && LEAK=$((LEAK+1))
[ "$LEAK" = 0 ] && ok "9 secret 문자열 stdout/stderr/run.log/SHA/handoff 0건" || no "9 secret 노출" "leak=$LEAK"

# 2. child rc=1 -> wrapper rc=1, handoff 미생성
newhome 2; run 2 MOCK_PUSH=fail
D="$(dirs 2 | head -1)"
if [ "$RC" = 1 ] && [ ! -e "$D/review-run.env" ] && [ ! -e "$D/summary.txt" ] && echo "$OUT" | grep -q "^RESULT=NOT_PASS"; then ok "2 child rc=1 → wrapper rc=1, review-run.env/summary 미생성"; else no "2 child rc=1" "rc=$RC"; fi
# 3. child rc=2 -> wrapper rc=2, handoff 미생성
newhome 3; run 3 MOCK_WRONG_LOGIN=transport
D="$(dirs 3 | head -1)"
if [ "$RC" = 2 ] && [ ! -e "$D/review-run.env" ] && [ ! -e "$D/summary.txt" ]; then ok "3 child rc=2 → wrapper rc=2, handoff 미생성"; else no "3 child rc=2" "rc=$RC"; fi

# 4. 동일 시각(+동일 nonce) 재실행 -> 기존 디렉터리 재사용 불가, 본체 미실행
newhome 4
mkdir -p "$ROOT/shim4"; cat > "$ROOT/shim4/date" <<'SH'
#!/usr/bin/env bash
case "$*" in *-Is*) exec /usr/bin/date "$@";; *) echo "20261002-000000";; esac
SH
cat > "$ROOT/shim4/od" <<'SH'
#!/usr/bin/env bash
echo " 0a 0b 0c 0d"
SH
chmod +x "$ROOT/shim4/date" "$ROOT/shim4/od"
mkdir -p "$ROOT/h4/hbr-review-run-hbr-20261002-000000-0a0b0c0d"; echo "OLD_PASS" > "$ROOT/h4/hbr-review-run-hbr-20261002-000000-0a0b0c0d/review-run.env"
OUT="$(env HOME="$ROOT/h4" PATH="$ROOT/shim4:$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls4" bash "$ROOT/wrapper-test.sh" 2>&1)"; RC=$?
if [ "$RC" = 2 ] && echo "$OUT" | grep -q "재사용 금지" && ! grep -q "^login" "$ROOT/calls4" && [ "$(cat "$ROOT/h4/hbr-review-run-hbr-20261002-000000-0a0b0c0d/review-run.env")" = "OLD_PASS" ]; then ok "4 동일 run 디렉터리 재사용 불가(rc=2), 본체 미실행, 기존 파일 보존"; else no "4 재사용 방지" "rc=$RC"; fi

# 5. 기존 PASS 폴더가 있어도 FAIL run에 stale handoff 유입 0
newhome 5; run 5; PASSDIR="$(dirs 5 | head -1)"; run 5 MOCK_PUSH=fail
ALL="$(dirs 5)"; N=$(echo "$ALL" | wc -l); FAILDIR="$(echo "$ALL" | grep -v "^$PASSDIR$" | head -1)"
if [ "$N" = 2 ] && [ "$FAILDIR" != "$PASSDIR" ] && [ ! -e "$FAILDIR/review-run.env" ] && [ ! -e "$FAILDIR/summary.txt" ] && [ -f "$PASSDIR/review-run.env" ]; then ok "5 PASS 후 FAIL 재실행 → 별도 디렉터리, FAIL run에 stale handoff 0, 기존 PASS 보존"; else no "5 stale handoff" "dirs=$N"; fi

# 6a. tee 실패 -> rc=2, PASS 출력 없음
newhome 6; mkdir -p "$ROOT/shim6"; printf '#!/usr/bin/env bash\ncat >/dev/null; exit 1\n' > "$ROOT/shim6/tee"; chmod +x "$ROOT/shim6/tee"
OUT="$(env HOME="$ROOT/h6" PATH="$ROOT/shim6:$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls6" bash "$ROOT/wrapper-test.sh" 2>&1)"; RC=$?
if [ "$RC" = 2 ] && ! echo "$OUT" | grep -q "^RESULT=PASS"; then ok "6a tee 실패 → rc=2, PASS 출력 없음"; else no "6a tee 실패" "rc=$RC"; fi
# 6b. 최종 해시 seal 실패 -> rc=2, handoff 폐기, PASS 출력 없음
newhome 7; mkdir -p "$ROOT/shim7"; cat > "$ROOT/shim7/sha256sum" <<'SH'
#!/usr/bin/env bash
case "$*" in *run.log*summary.txt*) exit 1;; esac
exec /usr/bin/sha256sum "$@"
SH
chmod +x "$ROOT/shim7/sha256sum"
OUT="$(env HOME="$ROOT/h7" PATH="$ROOT/shim7:$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls7" bash "$ROOT/wrapper-test.sh" 2>&1)"; RC=$?
D="$(dirs 7 | head -1)"
if [ "$RC" = 2 ] && ! echo "$OUT" | grep -q "^RESULT=PASS" && [ ! -e "$D/review-run.env" ] && [ ! -e "$D/summary.txt" ]; then ok "6b 최종 seal 실패 → rc=2, handoff 폐기, PASS 출력 없음"; else no "6b seal 실패" "rc=$RC"; fi
# 6c. handoff 파일 쓰기(hash 생성) 실패 -> rc=2
newhome 8; mkdir -p "$ROOT/shim8"; cat > "$ROOT/shim8/sha256sum" <<'SH'
#!/usr/bin/env bash
case "$*" in *review-run.env*) case "$*" in *run.log*) ;; *) exit 1;; esac;; esac
exec /usr/bin/sha256sum "$@"
SH
chmod +x "$ROOT/shim8/sha256sum"
OUT="$(env HOME="$ROOT/h8" PATH="$ROOT/shim8:$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls8" bash "$ROOT/wrapper-test.sh" 2>&1)"; RC=$?
D="$(dirs 8 | head -1)"
if [ "$RC" = 2 ] && ! echo "$OUT" | grep -q "^RESULT=PASS" && [ ! -e "$D/review-run.env" ]; then ok "6c review-run.env.sha256 생성 실패 → rc=2, handoff 폐기"; else no "6c handoff hash 실패" "rc=$RC"; fi

# 7. wrapper SHA 불일치 -> 본체 실행 전 STOP (oneshot의 외부 sha256sum -c 단계)
newhome 9
{ echo "cat > ~/hbr-formal-run.sh <<'WRAP_EOF'"; cat "$ROOT/wrapper-test.sh"; echo "WRAP_EOF"; } > "$ROOT/oneshot-ok.txt"
EXP="$(sha256sum "$ROOT/wrapper-test.sh" | cut -d' ' -f1)"
printf 'echo "%s  $HOME/hbr-formal-run.sh" | sha256sum -c - && bash ~/hbr-formal-run.sh\n' "$EXP" >> "$ROOT/oneshot-ok.txt"
sed 's/^umask 077$/umask 022/' "$ROOT/oneshot-ok.txt" > "$ROOT/oneshot-tamper.txt"
OUT="$(env HOME="$ROOT/h9" PATH="$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls9" bash "$ROOT/oneshot-tamper.txt" 2>&1)"; RC=$?
if [ "$RC" != 0 ] && echo "$OUT" | grep -qiE "FAILED|실패|일치하지" && [ ! -s "$ROOT/calls9" ] && [ -z "$(dirs 9)" ]; then ok "7 wrapper 변조 → 외부 sha256sum 검증 실패, 본체·wrapper 미실행"; else no "7 wrapper SHA" "rc=$RC calls=$(wc -c < "$ROOT/calls9")"; fi
# 7b. 변조 없는 oneshot은 검증 통과 후 실행(PASS)
newhome 10
OUT="$(env HOME="$ROOT/h10" PATH="$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls10" bash "$ROOT/oneshot-ok.txt" 2>&1)"; RC=$?
[ "$RC" = 0 ] && echo "$OUT" | grep -q "^RESULT=PASS" && ok "7b 변조 없는 wrapper는 SHA 검증 통과 후 정상 실행" || no "7b 정상 oneshot" "rc=$RC"

# 8. 사전 설정 비밀 -> 본체 실행 전 STOP
newhome 11
OUT="$(env HOME="$ROOT/h11" PATH="$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls11" RUNNER_ROBOT_SECRET=preset bash "$ROOT/wrapper-test.sh" 2>&1)"; RC=$?
if [ "$RC" = 2 ] && echo "$OUT" | grep -q "사전 주입" && [ ! -s "$ROOT/calls11" ] && [ -z "$(dirs 11)" ]; then ok "8 RUNNER_ROBOT_SECRET 사전 설정 → rc=2, podman 미호출, run 디렉터리 미생성"; else no "8 pre-set secret" "rc=$RC"; fi
# 8b. 빈 입력 -> rc=2
newhome 12; : > "$ROOT/empty.txt"; sed "s|^SECRET_SRC=.*|SECRET_SRC=$ROOT/empty.txt|" "$ROOT/wrapper-test.sh" > "$ROOT/wrapper-empty.sh"
OUT="$(env HOME="$ROOT/h12" PATH="$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls12" bash "$ROOT/wrapper-empty.sh" 2>&1)"; RC=$?
[ "$RC" = 2 ] && ! grep -q "^push" "$ROOT/calls12" && ok "8b 빈 비밀번호/입력 실패 → rc=2, 본체 미실행" || no "8b 빈 입력" "rc=$RC"

# 10. AC-02→AC-03 인계 contract: 생성된 review-run.env를 실제 병합된 Worker 공통 로더로 읽어 본다
LOADER="${LOADER:-$REPO/scripts/verify/lib/load-review-run-env.sh}"
if [ -f "$LOADER" ]; then
  D1="$(dirs 1 | head -1)"
  RID_EXPECT="$(basename "$D1" | sed 's/^hbr-review-run-//')"
  R="$( cd "$D1" && bash -c 'source "$1"; load_review_run_env ./review-run.env ./review-run.env.sha256 >/dev/null 2>&1 && echo "OK:$REVIEW_RUN_ID:$TEST_TAG"' _ "$LOADER" )"
  if [ "${R%%:*}" = "OK" ] && [ "$(echo "$R" | cut -d: -f2)" = "$RID_EXPECT" ]; then ok "10 생성된 review-run.env를 실제 AC-03 로더(load-review-run-env.sh)가 수용 (REVIEW_RUN_ID=$RID_EXPECT)"; else no "10 AC-03 로더 계약" "R='$R' expect=$RID_EXPECT"; fi
  # 10b. 로더 규칙 위반 ID(대문자/+/.)였다면 거부됨을 확인(시험이 실제로 규칙을 검사하는지)
  T="$(mktemp -d)"; printf 'TEST_TAG=ifup-x\nREVIEW_RUN_ID=hbr-20261002-104500+0900.Ab12Cd\n' > "$T/review-run.env"; ( cd "$T" && sha256sum review-run.env > review-run.env.sha256 )
  if ( cd "$T" && bash -c 'source "$1"; load_review_run_env ./review-run.env ./review-run.env.sha256' _ "$LOADER" >/dev/null 2>&1 ); then no "10b 규칙 위반 ID가 로더를 통과함" "시험 무효"; else ok "10b 규칙 위반 ID(+,.,대문자)는 로더가 거부 — 계약 시험이 유효함"; fi
else
  no "10 AC-03 로더 계약" "로더 파일 없음($LOADER) — SKIP 불허, LOADER=<path>로 지정"
fi

# 11. wrapper에 내장된 본체가 저장소의 병합된 runner-push-test.sh와 바이트 동일한지(내장본 드리프트 방지)
BODY="$REPO/scripts/verify/runner-push-test.sh"
EXP_IN_WRAPPER="$(grep -m1 "^EXPECT_SCRIPT_SHA=" "$W" | cut -d= -f2)"
ACT_BODY="$(sha256sum "$BODY" | cut -d" " -f1)"
EMB="$ROOT/embedded-body.sh"
awk 'index($0, "<<'"'"'SCRIPT_EOF'"'"'") && index($0, "runner-push-test.sh") {on=1; next} on && $0=="SCRIPT_EOF" {exit} on {print}' "$W" > "$EMB"
if [ "$EXP_IN_WRAPPER" = "$ACT_BODY" ] && [ "$(sha256sum "$EMB" | cut -d" " -f1)" = "$ACT_BODY" ]; then ok "11 wrapper 내장 본체 == 저장소 runner-push-test.sh (sha256 $ACT_BODY)"; else no "11 내장 본체 드리프트" "expected=$EXP_IN_WRAPPER repo=$ACT_BODY"; fi

# 12. RUN_ID fail-closed: timestamp/nonce 생성 실패·빈 값이면 run 디렉터리·비밀 입력·podman 호출 전에 rc=2
t12() { # t12 <n> <date-shim-out> <od-shim-out> <label>
  newhome "$1"; mkdir -p "$ROOT/shim$1"
  printf '#!/usr/bin/env bash\ncase "$*" in *-Is*) PATH=/usr/bin:/bin exec date "$@";; *) printf "%%s\\n" "%s";; esac\n' "$2" > "$ROOT/shim$1/date"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s"\n' "$3" > "$ROOT/shim$1/od"
  chmod +x "$ROOT/shim$1/date" "$ROOT/shim$1/od"
  OUT="$(env HOME="$ROOT/h$1" PATH="$ROOT/shim$1:$ROOT/bin:$PATH" MOCK_CALLS="$ROOT/calls$1" bash "$ROOT/wrapper-test.sh" 2>&1)"; RC=$?
  if [ "$RC" = 2 ] && echo "$OUT" | grep -q "RUN_ID" && [ ! -s "$ROOT/calls$1" ] && [ -z "$(dirs "$1")" ]; then ok "12 $4 → rc=2, podman 호출 0건, run 디렉터리 미생성"; else no "12 $4" "rc=$RC calls=$(wc -c < "$ROOT/calls$1")"; fi
}
t12 13 "20261002-000000" "" "nonce 빈 값"
t12 14 "" " 0a 0b 0c 0d" "timestamp 빈 값"
t12 15 "BAD TIME" " 0a 0b 0c 0d" "timestamp 형식 오류"
t12 16 "20261002-000000" " 0A 0B 0C 0D" "nonce 대문자(로더 규칙 위반)"

# 13. 저장소의 oneshot 파일이 wrapper에서 파생된 값과 바이트 동일한지(체크섬 줄 포함)
ONESHOT="$REPO/scripts/verify/formal-run/runner-formal-run-oneshot.txt"
WSHA="$(sha256sum "$W" | cut -d' ' -f1)"
{ echo "cat > ~/hbr-formal-run.sh <<'WRAP_EOF'"; cat "$W"; echo "WRAP_EOF"; echo 'sha256sum ~/hbr-formal-run.sh'; echo "echo \"$WSHA  \$HOME/hbr-formal-run.sh\" | sha256sum -c - && bash ~/hbr-formal-run.sh"; } > "$ROOT/oneshot-expected.txt"
if cmp -s "$ROOT/oneshot-expected.txt" "$ONESHOT"; then ok "13 runner-formal-run-oneshot.txt == wrapper 파생본 (sha256 $WSHA)"; else no "13 oneshot 드리프트" "wrapper sha=$WSHA"; fi
if grep -q "$WSHA" "$REPO/scripts/verify/formal-run/README.md"; then ok "13b README의 wrapper sha256이 실제와 일치"; else no "13b README sha 불일치" "wrapper sha=$WSHA"; fi

# 14. 승인된 IF-09 공통 Test Artifact digest를 정확히 유지하는지 검증
APPROVED_BASE_IMAGE_REF='docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e'
ACTUAL_BASE_IMAGE_REF="$(grep -m1 "^BASE_IMAGE_REF=" "$W" | cut -d"'" -f2)"
if [ "$ACTUAL_BASE_IMAGE_REF" = "$APPROVED_BASE_IMAGE_REF" ]; then
  ok "14 승인된 IF-09 base artifact digest 유지 ($ACTUAL_BASE_IMAGE_REF)"
else
  no "14 IF-09 base artifact identity drift" "expected=$APPROVED_BASE_IMAGE_REF actual=$ACTUAL_BASE_IMAGE_REF"
fi

echo "---- 결과: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
