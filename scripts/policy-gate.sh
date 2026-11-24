#!/usr/bin/env bash
# scripts/policy-gate.sh
# Layer 2 policy gate: runs the five CMMC L2 Rego policies against the
# Terraform plan and fails closed. Adapted from the Lab 3.4 gate.
#
# Usage: scripts/policy-gate.sh [--workspace terraform] [--policy policies]
# Needs a saved plan in the workspace: terraform plan -out=tfplan
set -euo pipefail

WORKSPACE="terraform"
POLICY_DIR="policies"
EVIDENCE_DIR="evidence"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$WORKSPACE/tfplan" ]] || { echo "policy-gate: FAIL (no $WORKSPACE/tfplan; run terraform plan -out=tfplan)" >&2; exit 1; }
mkdir -p "$EVIDENCE_DIR"

# -chdir keeps a relative WORKSPACE path from being doubled.
terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"

# Prove the policies themselves work before trusting their verdict.
opa test "$POLICY_DIR" > /dev/null || { echo "policy-gate: FAIL (opa test failed)" >&2; exit 1; }

# Explicit list, one namespace per material gap. A missing or misnamed
# namespace would "pass" with zero rules run (the Lab 3 empty-pass lesson),
# so each one is named here on purpose.
NAMESPACES=(
  compliance.gap01_s3_encryption
  compliance.gap02_dynamodb_encryption
  compliance.gap03_s3_tls_only
  compliance.gap05_lambda_in_vpc
  compliance.gap07_iam_least_privilege
)

EXIT=0
{
  echo "["
  FIRST=1
  for ns in "${NAMESPACES[@]}"; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    # Keep the JSON even when conftest fails; its exit code decides the gate.
    # Any non-zero code (violations, or an error) fails closed.
    set +e
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json")
    STATUS=$?
    set -e
    [[ $STATUS -eq 0 ]] || EXIT=1
    printf '%s' "$OUT"
  done
  echo
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

# Show every deny and warning in the log, so the PR author sees which
# control failed and how to fix it. Messages hold addresses and control
# IDs only, no ARNs or values.
jq -r '.[][] | ((.failures // [])[] | "DENY: " + .msg), ((.warnings // [])[] | "WARN: " + .msg)' \
  "$EVIDENCE_DIR/conftest-results.json" || true

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL (full results: $EVIDENCE_DIR/conftest-results.json)"
fi
exit $EXIT
