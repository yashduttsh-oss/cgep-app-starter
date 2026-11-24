#!/usr/bin/env bash
# scripts/verify-evidence.sh
# Verifies one run's evidence the way a grader or auditor would:
#   1. Integrity     - SHA-256 of the bundle matches the stored hash
#   2. Authenticity  - Cosign signature from THIS repo's grc-gate workflow,
#                      checked against the public Sigstore (Rekor) log
#   3. Preservation  - Object Lock retention is still in force
#
# Usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]
#        (vault defaults to $EVIDENCE_VAULT)
set -euo pipefail
RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG=(--profile "$2"); shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$VAULT" ]] || { echo "Set --vault or EVIDENCE_VAULT" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHASUM=(sha256sum); else SHASUM=(shasum -a 256); fi

# Only signatures made by this repo's workflow count, not any GitHub workflow.
IDENTITY='^https://github\.com/yashduttsh-oss/cgep-app-starter/\.github/workflows/grc-gate\.yml@refs/'
ISSUER='https://token.actions.githubusercontent.com'

WORK=$(mktemp -d); trap 'cd /; rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"
aws "${PROFILE_ARG[@]}" s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive --no-progress \
  --exclude "*" --include "evidence-*.tar.gz*"
BUNDLE=$(ls evidence-*.tar.gz | head -1)

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$("${SHASUM[@]}" "$BUNDLE" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA-256 mismatch"; exit 1; }
echo "1. Integrity: SHA-256 matches ($ACTUAL)"

# 2. Authenticity + timestamp
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' cosign verify-blob --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  "$BUNDLE"
echo "2. Authenticity: signed by grc-gate.yml in yashduttsh-oss/cgep-app-starter"

# 3. Preservation
read -r MODE UNTIL < <(aws "${PROFILE_ARG[@]}" s3api get-object-retention \
  --bucket "$VAULT" --key "${PREFIX}/${BUNDLE}" \
  --query '[Retention.Mode, Retention.RetainUntilDate]' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired ($UNTIL)"; exit 1; }
echo "3. Preservation: Object Lock ${MODE} until ${UNTIL}"

echo "CHAIN INTACT for run ${RUN_ID}"
