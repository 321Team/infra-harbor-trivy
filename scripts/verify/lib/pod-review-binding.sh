#!/usr/bin/env bash
# Shared checks for one explicitly selected review Pod/container.
# Callers enable errexit/nounset/pipefail and disable xtrace before sourcing.
require_pod_review_inputs() {
  : "${KUBE_CONTEXT:?approved Kubernetes context required}"
  : "${NAMESPACE:?approved namespace required}"
  : "${NODE_NAME:?target Worker required}"
  : "${SERVICE_ACCOUNT_NAME:?approved service account required}"
  : "${PULL_SECRET_NAME:?existing Worker Robot pull secret required}"
  : "${EXPECTED_HARBOR_DIGEST:?approved single-platform Harbor manifest digest required}"
  local value
  for value in "$NAMESPACE" "$SERVICE_ACCOUNT_NAME" "$PULL_SECRET_NAME"; do
    [[ "$value" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#value} -le 63 ]] || return 1
  done
  [[ "$NODE_NAME" =~ ^k8s-worker0[123]$ ]] || return 1
  [[ "$EXPECTED_HARBOR_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  command -v jq >/dev/null || return 1
  KUBECTL=(kubectl --context "$KUBE_CONTEXT" --request-timeout=10s)
}

owned_pod_uid() {
  # A label alone is insufficient: name, namespace and both run labels must match.
  jq -er --arg name "$POD_NAME" --arg ns "$NAMESPACE" \
    --arg run "$REVIEW_RUN_ID" --arg nonce "$RUN_NONCE" '
    select(.metadata.name == $name and .metadata.namespace == $ns
      and .metadata.labels["review-run-id"] == $run
      and .metadata.labels["review-invocation"] == $nonce)
    | .metadata.uid | select(type == "string" and length > 0)'
}

bound_pod_image_id() {
  # Read all identity and status fields from one API response; never statuses[0].
  jq -er --arg uid "$POD_UID" --arg name "$POD_NAME" --arg ns "$NAMESPACE" \
    --arg run "$REVIEW_RUN_ID" --arg nonce "$RUN_NONCE" --arg node "$NODE_NAME" \
    --arg sa "$SERVICE_ACCOUNT_NAME" --arg secret "$PULL_SECRET_NAME" \
    --arg container "$POD_CONTAINER_NAME" --arg image "$POD_IMAGE" '
    select(.metadata.uid == $uid and .metadata.name == $name
      and .metadata.namespace == $ns and .metadata.deletionTimestamp == null
      and .metadata.labels["review-run-id"] == $run
      and .metadata.labels["review-invocation"] == $nonce
      and .spec.nodeName == $node and .spec.serviceAccountName == $sa
      and .spec.automountServiceAccountToken == false
      and .spec.imagePullSecrets == [{name: $secret}]
      and any(.status.conditions[]?; .type == "Ready" and .status == "True"))
    | ([.spec.containers[]? | select(.name == $container)]) as $spec
    | ([.status.containerStatuses[]? | select(.name == $container)]) as $status
    | select(($spec | length) == 1 and $spec[0].image == $image
      and $spec[0].imagePullPolicy == "Always"
      and ($status | length) == 1 and $status[0].ready == true
      and $status[0].state.running != null)
    | $status[0].imageID | select(type == "string" and length > 0)'
}
