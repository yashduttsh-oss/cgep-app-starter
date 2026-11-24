#!/usr/bin/env bash
# scripts/validate-oscal.sh
# Validates the OSCAL component definition and profile with compliance-trestle,
# then resolves the profile against the NIST SP 800-171 Rev 3 catalog to prove
# every selected control ID exists.
#
# Usage: scripts/validate-oscal.sh      (needs: pip install compliance-trestle)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
COMPONENT="$ROOT/oscal/components/acme-health-intake.json"
PROFILE="$ROOT/oscal/profiles/cge-p-minimum.json"

# Trestle validates inside a workspace; use a throwaway one so the repo keeps
# its own layout.
WORK=$(mktemp -d); trap 'cd /; rm -rf "$WORK"' EXIT; cd "$WORK"
trestle init > /dev/null
trestle import -f "$COMPONENT" -o acme-health-intake > /dev/null
trestle import -f "$PROFILE" -o cge-p-minimum > /dev/null
trestle validate -a
trestle author profile-resolve -n cge-p-minimum -o resolved > /dev/null
echo "Profile resolves to $(python -c "import json;print(sum(len(g.get('controls',[])) for g in json.load(open('catalogs/resolved/catalog.json'))['catalog'].get('groups',[])))") controls from the 800-171 Rev 3 catalog"