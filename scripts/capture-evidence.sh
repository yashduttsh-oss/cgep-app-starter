#!/usr/bin/env bash
# scripts/capture-evidence.sh
# Bundles one pipeline run's evidence into a .tar.gz plus its SHA-256.
# Called by the Sign step of grc-gate.yml; prints the bundle path.
#
# Usage: capture-evidence.sh --evidence-dir <dir> --out-dir <dir>
set -euo pipefail

EVIDENCE_DIR=""
OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
    --out-dir)      OUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -d "$EVIDENCE_DIR" && -n "$OUT_DIR" ]] || { echo "Usage: $0 --evidence-dir <dir> --out-dir <dir>" >&2; exit 2; }
mkdir -p "$OUT_DIR"

RUN_ID="${GITHUB_RUN_ID:-local}"
SHA="${GITHUB_SHA:-$(git rev-parse HEAD)}"
CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# What happened in this run, so the bundle explains itself.
jq -n --arg run "$RUN_ID" --arg sha "$SHA" --arg at "$CAPTURED_AT" \
      --arg event "${GITHUB_EVENT_NAME:-local}" --arg ref "${GITHUB_REF:-}" \
      --arg actor "${GITHUB_ACTOR:-}" --arg repo "${GITHUB_REPOSITORY:-}" \
      --arg gate "${GATE_RESULT:-unknown}" --arg apply "${APPLY_RESULT:-skipped}" \
  '{run_id:$run, commit:$sha, captured_at_utc:$at, event:$event, ref:$ref,
    actor:$actor, repository:$repo, policy_gate:$gate, apply:$apply,
    framework:"CMMC 2.0 Level 2 (NIST SP 800-171)"}' > "$EVIDENCE_DIR/run.json"
git log -1 --pretty=fuller > "$EVIDENCE_DIR/commit.txt"
terraform version > "$EVIDENCE_DIR/versions.txt"
{ opa version | sed -n 1p; conftest --version; } >> "$EVIDENCE_DIR/versions.txt"

# manifest.json: name, SHA-256 and size of every file in the bundle.
( cd "$EVIDENCE_DIR"
  for f in *; do
    [[ "$f" == manifest.json ]] && continue
    jq -n --arg f "$f" --arg h "$(sha256sum "$f" | awk '{print $1}')" --argjson s "$(wc -c < "$f")" \
      '{filename:$f, sha256:$h, size:$s}'
  done | jq -s '.' > manifest.json )

BUNDLE="$OUT_DIR/evidence-${RUN_ID}-${SHA}.tar.gz"
tar -czf "$BUNDLE" -C "$EVIDENCE_DIR" .
sha256sum "$BUNDLE" | awk '{print $1}' > "${BUNDLE}.sha256"
echo "$BUNDLE"
