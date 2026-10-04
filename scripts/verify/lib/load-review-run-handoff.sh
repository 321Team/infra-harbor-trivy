#!/usr/bin/env bash
# P1-HBR-01 AC-03 — consume the official AC-02 sealed handoff fail-closed.
# The formal run seals review-run.env, review-run.env.sha256 and summary.txt in
# SHA256SUMS. Runtime digest identity must come from that sealed summary.
set +x

HANDOFF_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${HANDOFF_LIB_DIR}/load-review-run-env.sh"

_verify_formal_seal_entry() {
  local dir="$1" target="$2" seal="$3"
  local count expected actual
  [ -f "${dir}/${target}" ] || {
    echo "ERROR: official handoff file missing: ${target}" >&2
    return 1
  }
  [ -f "${seal}" ] || {
    echo "ERROR: official SHA256SUMS missing" >&2
    return 1
  }
  count="$(awk -v t="${target}" '$2 == t || $2 == "./" t {c++} END {print c+0}' "${seal}")"
  [ "${count}" -eq 1 ] || {
    echo "ERROR: SHA256SUMS must contain exactly one ${target} entry (actual=${count})" >&2
    return 1
  }
  expected="$(awk -v t="${target}" '$2 == t || $2 == "./" t {print tolower($1); exit}' "${seal}")"
  [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "ERROR: invalid SHA256SUMS digest for ${target}" >&2
    return 1
  }
  actual="$(sha256sum "${dir}/${target}" | awk '{print $1}')"
  [ "${actual}" = "${expected}" ] || {
    echo "ERROR: official handoff seal mismatch: ${target}" >&2
    return 1
  }
}

load_review_run_handoff() {
  local dir="${1:-.}"
  local seal="${dir}/SHA256SUMS"
  local supplied_digest="${EXPECTED_HARBOR_DIGEST:-}"
  local summary_snapshot="" key value
  local summary_count summary_expected summary_actual
  local -A seen=()
  local -A values=()
  local allowed="RUN_ID TEST_TAG EXPECTED_HARBOR_DIGEST IMAGE BASE_IMAGE_REF WRAPPER_SHA256 CHILD_RC EVIDENCE_SEAL"

  load_review_run_env "${dir}/review-run.env" "${dir}/review-run.env.sha256" || return 1
  _verify_formal_seal_entry "${dir}" "review-run.env" "${seal}" || return 1
  _verify_formal_seal_entry "${dir}" "review-run.env.sha256" "${seal}" || return 1

  # Snapshot summary.txt first, then verify and parse that exact immutable copy.
  # This prevents a verified-source / later-consumed-source TOCTOU gap.
  [ -f "${dir}/summary.txt" ] || {
    echo "ERROR: official handoff file missing: summary.txt" >&2
    return 1
  }
  [ -f "${seal}" ] || {
    echo "ERROR: official SHA256SUMS missing" >&2
    return 1
  }
  summary_count="$(awk '$2 == "summary.txt" || $2 == "./summary.txt" {c++} END {print c+0}' "${seal}")"
  [ "${summary_count}" -eq 1 ] || {
    echo "ERROR: SHA256SUMS must contain exactly one summary.txt entry (actual=${summary_count})" >&2
    return 1
  }
  summary_expected="$(awk '$2 == "summary.txt" || $2 == "./summary.txt" {print tolower($1); exit}' "${seal}")"
  [[ "${summary_expected}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "ERROR: invalid SHA256SUMS digest for summary.txt" >&2
    return 1
  }

  summary_snapshot="$(mktemp)" || return 1
  cp -- "${dir}/summary.txt" "${summary_snapshot}" || {
    rm -f "${summary_snapshot}"
    return 1
  }
  summary_actual="$(sha256sum "${summary_snapshot}" | awk '{print $1}')"
  [ "${summary_actual}" = "${summary_expected}" ] || {
    echo "ERROR: official handoff seal mismatch: summary.txt" >&2
    rm -f "${summary_snapshot}"
    return 1
  }
  OFFICIAL_REVIEW_SUMMARY_SHA256="${summary_actual}"

  while IFS='=' read -r key value; do
    [ -n "${key}" ] || continue
    case " ${allowed} " in
      *" ${key} "*) ;;
      *)
        echo "ERROR: summary.txt contains unapproved key: ${key}" >&2
        rm -f "${summary_snapshot}"
        return 1
        ;;
    esac
    [ -z "${seen[${key}]:-}" ] || {
      echo "ERROR: summary.txt contains duplicate key: ${key}" >&2
      rm -f "${summary_snapshot}"
      return 1
    }
    seen[${key}]=1
    values[${key}]="${value}"
  done < "${summary_snapshot}"

  for key in RUN_ID TEST_TAG EXPECTED_HARBOR_DIGEST IMAGE BASE_IMAGE_REF WRAPPER_SHA256 CHILD_RC EVIDENCE_SEAL; do
    [ -n "${seen[${key}]:-}" ] || {
      echo "ERROR: summary.txt missing key: ${key}" >&2
      rm -f "${summary_snapshot}"
      return 1
    }
  done

  if [ "${values[RUN_ID]}" != "${REVIEW_RUN_ID}" ]; then
    echo "ERROR: official run mismatch env=${REVIEW_RUN_ID} summary=${values[RUN_ID]}" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if [ "${values[TEST_TAG]}" != "${TEST_TAG}" ]; then
    echo "ERROR: official tag mismatch env=${TEST_TAG} summary=${values[TEST_TAG]}" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if ! [[ "${values[EXPECTED_HARBOR_DIGEST]}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: invalid official Harbor digest in summary.txt" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if [ "${values[IMAGE]}" != "10.1.93.54/fds/test:${TEST_TAG}" ]; then
    echo "ERROR: official IMAGE does not bind to TEST_TAG" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if ! [[ "${values[BASE_IMAGE_REF]}" =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: invalid BASE_IMAGE_REF in summary.txt" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if ! [[ "${values[WRAPPER_SHA256]}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: invalid WRAPPER_SHA256 in summary.txt" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if [ "${values[CHILD_RC]}" != "0" ]; then
    echo "ERROR: official AC-02 child result is not PASS" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if [ "${values[EVIDENCE_SEAL]}" != "OK" ]; then
    echo "ERROR: official AC-02 evidence seal is not OK" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi
  if [ -n "${supplied_digest}" ] && [ "${supplied_digest}" != "${values[EXPECTED_HARBOR_DIGEST]}" ]; then
    echo "ERROR: supplied EXPECTED_HARBOR_DIGEST differs from sealed official digest" >&2
    rm -f "${summary_snapshot}"
    return 1
  fi

  EXPECTED_HARBOR_DIGEST="${values[EXPECTED_HARBOR_DIGEST]}"
  rm -f "${summary_snapshot}"
  export EXPECTED_HARBOR_DIGEST OFFICIAL_REVIEW_SUMMARY_SHA256
  echo "OK: official AC-02 handoff sealed and bound run=${REVIEW_RUN_ID} tag=${TEST_TAG} digest=${EXPECTED_HARBOR_DIGEST}" >&2
}
