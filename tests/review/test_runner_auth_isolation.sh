#!/usr/bin/env bash
# Offline contract tests: no registry access, no real credential reads.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf -- "$ROOT"' EXIT
mkdir -p "$ROOT/bin" "$ROOT/runtime/containers" "$ROOT/docker" "$ROOT/tmp"
printf 'runtime sentinel\n' > "$ROOT/runtime/containers/auth.json"
printf 'inherited sentinel\n' > "$ROOT/inherited.json"
printf 'docker sentinel\n' > "$ROOT/docker/config.json"
sha256sum "$ROOT/runtime/containers/auth.json" "$ROOT/inherited.json" "$ROOT/docker/config.json" > "$ROOT/before"
# Reuse the functional Podman mock, wrapping it with authfile assertions.
awk '/^cat > .*MOCK/{keep=1;next} /^MOCK$/{keep=0} keep{print}' \
  "$REPO/tests/review/test_runner_push_mock.sh" > "$ROOT/bin/podman-functional"
cat > "$ROOT/bin/podman" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
sub="$1"; shift
case "$sub" in
  logout) echo 'unexpected logout' >&2; exit 98 ;;
  login|pull|push)
    args=("$@")
    [ "${1:-}" = --authfile ] || exit 97
    auth="$2"
    [ "$auth" = "$REGISTRY_AUTH_FILE" ] || exit 96
    case "$auth" in "$TMPDIR"/*/positive-auth.json|"$TMPDIR"/*/negative-auth.json) ;; *) exit 95 ;; esac
    [ -f "$auth" ] || exit 94
    printf '%s\n' "$auth" >> "$AUTH_PATHS"
    # Model login writes. Only the selected isolated file may be modified.
    if [ "$sub" = login ]; then
      if [[ "$auth" == */negative-auth.json ]]; then
        [ "$(cat "$auth")" = '{"auths":{}}' ] || exit 93
      fi
      printf '{"auths":{"mock":"fixture"}}\n' > "$auth"
      if [ -n "${TEST_SIGNAL:-}" ]; then
        kill -s "$TEST_SIGNAL" "$PPID"
        exit 125
      fi
    fi
    exec podman-functional "$sub" "${args[@]}" ;;
  *) exec podman-functional "$sub" "$@" ;;
esac
MOCK
chmod +x "$ROOT/bin/podman" "$ROOT/bin/podman-functional"
count=0
for scenario in normal loginfail pushfail negative-success INT TERM HUP; do
  extra=(); want=0
  case "$scenario" in
    loginfail) extra=(MOCK_GOOD_LOGIN=bad); want=1 ;;
    pushfail) extra=(MOCK_PUSH=fail); want=1 ;;
    negative-success) extra=(MOCK_WRONG_LOGIN=success); want=1 ;;
    INT) extra=(TEST_SIGNAL=INT); want=130 ;;
    TERM) extra=(TEST_SIGNAL=TERM); want=143 ;;
    HUP) extra=(TEST_SIGNAL=HUP); want=129 ;;
  esac
  : > "$ROOT/auth-paths"
  rc=0
  env PATH="$ROOT/bin:$PATH" TMPDIR="$ROOT/tmp" \
    XDG_RUNTIME_DIR="$ROOT/runtime" REGISTRY_AUTH_FILE="$ROOT/inherited.json" DOCKER_CONFIG="$ROOT/docker" \
    AUTH_PATHS="$ROOT/auth-paths" MOCK_CALLS="$ROOT/calls" \
    MOCK_PUSH_DIGEST="sha256:$(printf 'a%.0s' {1..64})" MOCK_PULLED_DIGEST="sha256:$(printf 'a%.0s' {1..64})" \
    RUNNER_ROBOT_USER='robot$push' RUNNER_ROBOT_SECRET=GOODPW WRONG_ROBOT_SECRET=WRONGPW \
    BASE_IMAGE_REF="alpine@sha256:$(printf 'c%.0s' {1..64})" "${extra[@]}" \
    bash "$REPO/scripts/verify/runner-push-test.sh" > "$ROOT/output" 2>&1 || rc=$?
  [ "$rc" -eq "$want" ] || { printf 'FAIL %s rc=%s expected=%s\n' "$scenario" "$rc" "$want"; exit 1; }
  sha256sum -c "$ROOT/before" >/dev/null
  [ -s "$ROOT/auth-paths" ]
  while IFS= read -r auth; do [ ! -e "$auth" ]; done < "$ROOT/auth-paths"
  [ -z "$(find "$ROOT/tmp" -mindepth 1 -print -quit)" ]
  if grep -Eq 'GOODPW|WRONGPW' "$ROOT/output"; then exit 1; fi
  if [ "$scenario" = normal ]; then
    [ "$(sort -u "$ROOT/auth-paths" | wc -l)" -eq 2 ]
  fi
  count=$((count+1)); printf 'PASS auth isolation %s\n' "$scenario"
done
printf 'PASS=%s FAIL=0 (mock only)\n' "$count"
