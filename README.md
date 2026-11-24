# Acme Health Patient Intake API: CGE-P capstone

The `cgep-app-starter` workload (API Gateway → Lambda → DynamoDB / S3), made audit-defensible against **CMMC 2.0 Level 2** (NIST SP 800-171) with four layers:

| Layer | Where | What it does |
|---|---|---|
| 1. Terraform baseline | `terraform/` | Customer-managed KMS keys, Object Lock evidence vault, multi-region CloudTrail, and fixes for all 8 gaps in `GAPS.md` |
| 2. Policy suite | `policies/`, `scripts/policy-gate.sh` | Five Rego policies (GAP-01, 02, 03, 05, 07) with tests; Conftest gate that fails closed |
| 3. Pipeline | `.github/workflows/grc-gate.yml` | Plan → policy check → apply on merge to `main` → Cosign keyless sign → upload to the vault |
| 4. OSCAL | `oscal/` | Component definition citing the NIST SP 800-171 Rev 3 catalog, plus a profile selecting the 8 implemented controls |

Design reasoning, control coverage and known gaps: **[WRITEUP.md](WRITEUP.md)**.

## Verify it

**Policies** (needs [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) 1.x):
```bash
opa test policies -v        # 23/23 pass
```

**OSCAL** (needs `pip install compliance-trestle`):
```bash
bash scripts/validate-oscal.sh
# VALID: component-definition ... VALID: profile ... Profile resolves to 8 controls
```

**Gate behaviour:** see PR #3 (passed, merged, applied) and PR #5 (GAP-02 re-introduced, blocked by the required `grc-gate` check).

**Evidence chain** (needs the AWS CLI, `cosign`, and read access to the vault through the evidence key's admin principals):
```bash
export EVIDENCE_VAULT=acme-health-intake-evidence-63f7bc54
bash scripts/verify-evidence.sh 45456179365   # green run on main
bash scripts/verify-evidence.sh 45461398718   # red PR run (blocked at the gate)
```
Each prints three checks, then `CHAIN INTACT`:
1. **Integrity:** the SHA-256 of the bundle matches the stored hash.
2. **Authenticity:** the Cosign signature verifies against the public Sigstore (Rekor) log, signed by this repo's `grc-gate.yml` workflow.
3. **Preservation:** S3 Object Lock retention is in force.

## Run the workload

```bash
make creds AWS_PROFILE=<profile>   # confirm the account
make test  AWS_PROFILE=<profile>   # POST to the API, expect "status": "received"
```
Changes to the infrastructure go through a PR: the pipeline plans and gates them, and applies on merge to `main`. What the API does is described in [WORKLOAD.md](WORKLOAD.md); the original gaps are in [GAPS.md](GAPS.md).
