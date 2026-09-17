#!/usr/bin/env bash
# Source after pod-review-binding.sh. No cluster objects are created here.
preflight_pod_review() {
  "${KUBECTL[@]}" get namespace "$NAMESPACE" -o name >/dev/null || return 1
  "${KUBECTL[@]}" get node "$NODE_NAME" -o name >/dev/null || return 1
  "${KUBECTL[@]}" get serviceaccount "$SERVICE_ACCOUNT_NAME" -n "$NAMESPACE" -o name >/dev/null || return 1
  # Keep Secret bytes out of argv/files/logs. jq reads expected credentials from env.
  # A configured matching Secret is not proof of the kubelet's actual credential source.
  if ! "${KUBECTL[@]}" get secret "$PULL_SECRET_NAME" -n "$NAMESPACE" -o json |
    jq -e --arg host "$HARBOR_REGISTRY" '
      select(.type == "kubernetes.io/dockerconfigjson")
      | .data[".dockerconfigjson"] | @base64d | fromjson | .auths[$host]
      | select(type == "object")
      | (env.WORKER_ROBOT_USER + ":" + env.WORKER_ROBOT_SECRET | @base64) as $expected
      | ((.auth == $expected) or
         (.username == env.WORKER_ROBOT_USER and .password == env.WORKER_ROBOT_SECRET))
        and ((has("auth") | not) or .auth == $expected)
        and ((has("username") | not) or .username == env.WORKER_ROBOT_USER)
        and ((has("password") | not) or .password == env.WORKER_ROBOT_SECRET)
        and ((has("identitytoken") | not) and (has("registrytoken") | not))
    ' >/dev/null 2>&1; then
    echo 'ERROR: existing imagePullSecret does not verify as the supplied Worker Robot' >&2
    return 1
  fi
}

cleanup_review_pod() {
  [ "$CREATE_ATTEMPTED" -eq 1 ] || return 0
  local current current_uid options deadline
  if ! current=$("${KUBECTL[@]}" get pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found -o json); then
    echo "ERROR: Pod cleanup state UNKNOWN (GET failed): $POD_NAME" >&2
    return 1
  fi
  if [ -z "$current" ]; then
    if [ -z "$POD_UID" ]; then
      echo "ERROR: create response was not confirmed; a later create cannot be ruled out: $POD_NAME" >&2
      return 1
    fi
    echo "CLEANUP: confirmed absent uid=$POD_UID"
    return 0
  fi
  if ! current_uid=$(printf '%s' "$current" | owned_pod_uid); then
    echo "ERROR: different Pod owner; preserved $POD_NAME" >&2
    return 1
  fi
  if [ -n "$POD_UID" ] && [ "$current_uid" != "$POD_UID" ]; then
    echo "ERROR: replacement Pod UID; preserved $POD_NAME" >&2
    return 1
  fi
  # Response-loss recovery is allowed only for the unique name + invocation + run.
  POD_UID="$current_uid"
  options=$(jq -cn --arg uid "$POD_UID" \
    '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}') || return 1
  if ! printf '%s' "$options" | "${KUBECTL[@]}" delete \
    --raw "/api/v1/namespaces/$NAMESPACE/pods/$POD_NAME" -f - >/dev/null; then
    echo "ERROR: UID-preconditioned Pod DELETE failed: $POD_NAME uid=$POD_UID" >&2
    return 1
  fi
  deadline=$((SECONDS + CLEANUP_TIMEOUT_SECONDS))
  while :; do
    current=$("${KUBECTL[@]}" get pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found -o json) || return 1
    if [ -z "$current" ]; then
      echo "CLEANUP: confirmed deleted uid=$POD_UID"
      return 0
    fi
    current_uid=$(printf '%s' "$current" | jq -er '.metadata.uid | select(type == "string" and length > 0)') || return 1
    if [ "$current_uid" != "$POD_UID" ]; then
      echo "ERROR: replacement Pod observed after DELETE; preserved $POD_NAME" >&2
      return 1
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "ERROR: Pod deletion still pending: $POD_NAME uid=$POD_UID" >&2
      return 1
    fi
    sleep 1
  done
}

cleanup_review() {
  local rc="${1:-$?}" failed=0
  trap - EXIT INT TERM
  if [ -n "$TEST_AUTH_DIR" ]; then
    if [ "$LOGIN_ATTEMPTED" -eq 1 ]; then
      sudo env DOCKER_CONFIG="$TEST_AUTH_DIR" nerdctl -n k8s.io logout "$HARBOR_REGISTRY" >/dev/null 2>&1 || failed=1
    fi
    sudo rm -rf -- "$TEST_AUTH_DIR" || failed=1
  fi
  cleanup_review_pod || failed=1
  unset CRICTL_AUTH WORKER_ROBOT_SECRET
  if [ "$failed" -ne 0 ]; then
    echo "ERROR: cleanup incomplete; context=$KUBE_CONTEXT namespace=$NAMESPACE pod=$POD_NAME invocation=$RUN_NONCE" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  if [ "$rc" -eq 0 ] && [ "$REVIEW_CHECKS_PASSED" -eq 1 ]; then
    echo 'PASS: local checks + bound Pod/Harbor digest + cleanup (not full AC-03/AC-05 Runtime acceptance)'
  fi
  exit "$rc"
}
