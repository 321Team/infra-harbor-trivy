#!/usr/bin/env bash
# wrapper v2 mock/fault 시험 — stub 본체/가짜 podman/가짜 tty 사용 (실제 Harbor 접촉 없음)
# 시험용 변형: 본체=stub, EXPECT_SCRIPT_SHA/CA_SHA 치환, /dev/tty → 파일. 나머지 wrapper 로직은 동일.
set -u
HERE="$(cd "$(dirname "$0")/../../scripts/verify/formal-run" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME/.config/containers/certs.d/10.1.93.54" "$T/bin"
echo fake-ca > "$HOME/.config/containers/certs.d/10.1.93.54/ca.crt"
CA="$(sha256sum "$HOME/.config/containers/certs.d/10.1.93.54/ca.crt" | cut -d' ' -f1)"
printf '#!/bin/sh\necho "podman version 0.0-mock"\n' > "$T/bin/podman"; chmod +x "$T/bin/podman"
cat > "$T/stub.sh" <<'S'
#!/usr/bin/env bash
case "${STUB_MODE:-pass}" in
  pass) echo "### 완료 — TEST_TAG=ifup-20261002T010203Z MANIFEST_DIGEST=sha256:$(printf 'a%.0s' $(seq 64)) BASE=x"; exit 0;;
  fail) echo "FAIL case"; exit 1;;
  err)  echo "ERROR case"; exit 2;;
  weird) echo "weird"; exit 7;;
  leak) echo "secret=$RUNNER_ROBOT_SECRET"; echo "### TEST_TAG=ifup-20261002T010203Z MANIFEST_DIGEST=sha256:$(printf 'a%.0s' $(seq 64))"; exit 0;;
esac
S
STUB_SHA="$(sha256sum "$T/stub.sh" | cut -d' ' -f1)"
echo "mock-secret-VALUE-123" > "$T/tty"
mkvariant() { # $1=out
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = "@@BODY@@" ]; then cat "$T/stub.sh"; else printf '%s\n' "$line"; fi
  done < "$HERE/hbr-formal-run.template.sh" | sed -e "s/^EXPECT_SCRIPT_SHA=.*/EXPECT_SCRIPT_SHA=$STUB_SHA/" -e "s/^CA_SHA=.*/CA_SHA=$CA/" -e "s#/dev/tty#$T/tty#g" > "$1"
}
mkvariant "$T/w.sh"; WSHA="$(sha256sum "$T/w.sh" | cut -d' ' -f1)"
PASSN=0; FAILN=0
ok() { if [ "$2" = 1 ]; then echo "PASS  $1"; PASSN=$((PASSN+1)); else echo "FAIL  $1"; FAILN=$((FAILN+1)); fi; }
run() { # $1=mode, rest=extra env assignments; sets RC OUT LAST
  local mode="$1"; shift
  OUT="$(env PATH="$T/bin:$PATH" STUB_MODE="$mode" "$@" bash "$T/w.sh" "$WSHA" 2>&1)"; RC=$?
  LAST="$(ls -dt "$HOME"/hbr-review-run-* 2>/dev/null | head -1)"
}
has() { [ -e "$LAST/$1" ]; }

run pass;  [ $RC = 0 ] && has review-run.env && has review-run.env.sha256 && has summary.txt && has SHA256SUMS; ok "1 child rc=0 -> wrapper rc=0 + review-run.env" $([ $? = 0 ] && echo 1 || echo 0)
PASSDIR="$LAST"
run fail;  [ $RC = 1 ] && ! has review-run.env && ! has summary.txt; ok "2 child rc=1 -> wrapper rc=1, handoff 없음" $([ $? = 0 ] && echo 1 || echo 0)
run err;   [ $RC = 2 ] && ! has review-run.env && ! has summary.txt; ok "3 child rc=2 -> wrapper rc=2, handoff 없음" $([ $? = 0 ] && echo 1 || echo 0)
run weird; [ $RC = 2 ] && ! has review-run.env && grep -q 'CHILD_RC_RAW=7' "$LAST/wrapper-result.txt"; ok "3b child rc=7 -> ERROR 2, 원 rc 기록" $([ $? = 0 ] && echo 1 || echo 0)
FAILDIR="$LAST"
[ "$PASSDIR" != "$FAILDIR" ] && [ -f "$PASSDIR/review-run.env" ] && [ ! -e "$FAILDIR/review-run.env" ] && ! grep -q "ifup-" "$FAILDIR/SHA256SUMS" 2>/dev/null; ok "4/5 재실행 시 별도 폴더, FAIL run에 stale handoff 0" $([ $? = 0 ] && echo 1 || echo 0)

# 6 seal 실패: sha256sum이 review-run.env에서 실패하도록 shim
cat > "$T/bin/sha256sum" <<S
#!/bin/sh
for a in "\$@"; do [ "\$a" = review-run.env ] && exit 1; done
exec $(command -v sha256sum) "\$@"
S
chmod +x "$T/bin/sha256sum"
run pass; [ $RC = 2 ] && ! has review-run.env && ! echo "$OUT" | grep -q '^RESULT=PASS'; ok "6 hash seal 실패 -> rc=2, PASS 미출력, handoff 제거" $([ $? = 0 ] && echo 1 || echo 0)
rm "$T/bin/sha256sum"
# 6b tee 실패: 로그를 디렉터리로 막을 수 없으므로 읽기전용 DIR 대신 tee shim
printf '#!/bin/sh\ncat >/dev/null; exit 1\n' > "$T/bin/tee"; chmod +x "$T/bin/tee"
run pass; [ $RC = 2 ] && ! has review-run.env; ok "6b tee 실패 -> rc=2, handoff 없음" $([ $? = 0 ] && echo 1 || echo 0)
rm "$T/bin/tee"

# 7 wrapper sha 불일치
OUT="$(env PATH="$T/bin:$PATH" bash "$T/w.sh" "$(printf '0%.0s' $(seq 64))" 2>&1)"; RC=$?
[ $RC = 2 ] && echo "$OUT" | grep -q 'wrapper sha256 불일치' && ! echo "$OUT" | grep -q 'OK: 시험 스크립트'; ok "7 wrapper SHA mismatch -> 본체 실행 전 STOP" $([ $? = 0 ] && echo 1 || echo 0)
# 8 pre-set secret
run pass RUNNER_ROBOT_SECRET=preset; [ $RC = 2 ] && echo "$OUT" | grep -q '이미 설정됨' && ! echo "$OUT" | grep -q 'OK: 시험 스크립트'; ok "8 pre-set RUNNER_ROBOT_SECRET -> STOP" $([ $? = 0 ] && echo 1 || echo 0)
run pass BASE_IMAGE_REF=docker.io/library/alpine@sha256:$(printf 'b%.0s' $(seq 64)); [ $RC = 2 ] && echo "$OUT" | grep -q 'override 거부'; ok "8b BASE_IMAGE_REF override -> STOP" $([ $? = 0 ] && echo 1 || echo 0)
# 9 secret 0건 (정상 run + leak 유발 run)
run pass; ! grep -rqF "mock-secret-VALUE-123" "$LAST" && ! echo "$OUT" | grep -qF "mock-secret-VALUE-123"; ok "9 정상 run: secret 문자열 0건 (stdout/log/SHA)" $([ $? = 0 ] && echo 1 || echo 0)
run leak; [ $RC = 2 ] && ! has review-run.env && ! echo "$OUT" | grep -q '^RESULT=PASS'; ok "9b 본체가 secret 노출 시 -> ERROR 2, PASS 불가" $([ $? = 0 ] && echo 1 || echo 0)
echo "== PASS=$PASSN FAIL=$FAILN"; [ $FAILN = 0 ]
