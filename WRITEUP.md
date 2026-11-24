# Acme Health: GRC Engineering Capstone Write-up

## Primary framework
**CMMC 2.0 Level 2** (NIST SP 800-171). Acme's federal pilot puts CUI (Controlled Unclassified Information) in scope, and CMMC Level 2 is the contractual bar for handling it. Its 800-171 control families (AC / AU / SC / SI / MP) map almost 1:1 onto the access-control, audit, encryption and boundary work this system needs, more precisely than HIPAA's addressable-safeguard language or SOC 2's broad criteria. Every Rego policy cites a CMMC practice ID, and the OSCAL component cites the NIST SP 800-171 Rev 3 OSCAL catalog, the catalog CMMC Level 2 is derived from.

## Control coverage
Every gap is fixed in Terraform. The five most material are also guarded by a Rego policy, so CI fails closed if one is re-introduced. All are described in the OSCAL component (`oscal/components/acme-health-intake.json`).

| Gap | Control (CMMC L2 / 800-171) | Terraform | Policy | OSCAL | How closed |
|---|---|:--:|:--:|:--:|---|
| GAP-01 | SC.L2-3.13.11 (CUI cryptography) | ✅ | ✅ | ✅ | **Terraform + policy.** SSE-KMS under a customer-managed key via the `secure-bucket` module. Rego denies a bucket with no encryption config, a non-`aws:kms` algorithm, or `aws:kms` with no key (silent fallback to `aws/s3`). |
| GAP-02 | SC.L2-3.13.11 (CUI cryptography) | ✅ | ✅ | ✅ | **Terraform + policy.** DynamoDB `server_side_encryption` with the CMK. Rego denies a table with no encryption block, or with no `kms_key_arn` (fallback to `aws/dynamodb`). |
| GAP-03 | SC.L2-3.13.8 (encryption in transit) | ✅ | ✅ | ✅ | **Terraform + policy.** Every bucket policy denies `aws:SecureTransport = false` on the bucket and its objects. Rego requires the statement. |
| GAP-04 | MP.L2-3.8.9 (protect backups) | ✅ | — | ✅ | **Terraform + OSCAL.** Bucket versioning; every prior version is encrypted under the CMK. Lower materiality, so no policy slot spent. |
| GAP-05 | SC.L2-3.13.1 (boundary protection) | ✅ | ✅ | ✅ | **Terraform + policy.** Lambda moved into the starter's VPC: private subnets with no internet route, gateway endpoints (S3, DynamoDB), interface endpoints (Logs, X-Ray), HTTPS-only egress. Rego requires `vpc_config` with subnets and security groups. |
| GAP-06 | SI.L2-3.14.6 (monitor for attacks) | ◑ | — | ✅ | **Terraform (partial) + OSCAL.** X-Ray active tracing and an encrypted DLQ. Reserved concurrency is configurable but not set in this account (see trade-offs). |
| GAP-07 | AC.L2-3.1.5 (least privilege) | ✅ | ✅ | ✅ | **Terraform + policy.** Lambda role scoped to `dynamodb:PutItem` on the table and `s3:PutObject` under `uploads/`. Rego denies `*` and `service:*` in any Allow. |
| GAP-08 | AU.L2-3.3.1 (audit records) | ◑ | — | ✅ | **Terraform (partial) + OSCAL.** JSON access logging to a KMS-encrypted log group (365 days) and stage throttling. WAF can't attach to an HTTP API; documented as a known limitation with a remediation path. |

**Legend:** ✅ closed/enforced · ◑ partially closed · — not used for this gap.

The OSCAL component also claims **AU.L2-3.3.8 (protection of audit information)**, which is what the evidence vault and CloudTrail log-file validation implement. The profile `oscal/profiles/cge-p-minimum.json` selects those 8 controls, and `scripts/validate-oscal.sh` validates both files with trestle and resolves the profile against NIST's catalog.

## Design decisions

### Region: `us-east-1`
- **Choice:** One region for the whole footprint.
- **Why:** Simpler audit scope and blast radius for a small team; every required service is available; no residency requirement yet.
- **Trade-off:** Real CUI belongs in GovCloud eventually. Deferred until the pilot proves out.

### Object Lock: GOVERNANCE
- **Choice:** GOVERNANCE mode, 365-day default retention.
- **Why:** Evidence is tamper-evident from day one, while retention rules are still settling. A narrow, audited path remains to fix mistakes, and the pipeline role is explicitly denied `s3:BypassGovernanceRetention`.
- **Trade-off:** COMPLIANCE is stronger but would lock us out of our own storage. Planned once the program stabilizes.

### Apply: on merge to `main`
- **Choice:** Auto-apply on merge, gated by the policy check, with a branch ruleset that requires the `grc-gate` check and a PR for every change to `main`.
- **Why:** Governance can't slow delivery; a gate of seconds enforces the controls on every change instead of in a meeting. Apply uses the exact plan the gate approved, never a fresh one.
- **Trade-off:** The pipeline holds deploy authority. Acceptable at this blast radius; add a manual approval step as PHI volume and headcount grow.

### Accounts: single account
- **Choice:** One AWS account, evidence vault included.
- **Why:** Multi-account overhead outweighs its benefit for a two-person function, and is itself a misconfiguration risk.
- **Trade-off:** A workload compromise could reach the evidence. Mitigated by Object Lock, a separate evidence KMS key the workload can't use, and validated CloudTrail; move the vault to its own account as we scale.

### Terraform vs policy: fix every gap in code, guard the material five
- **Choice:** Remediate every gap in Terraform; add Rego gates for GAP-01, 02, 03, 05 and 07.
- **Why:** IaC is the durable fix. Policy guards the controls where a silent regression hurts most (encryption, transit, boundary, least privilege), and each one is a clean signal in the plan.
- **Trade-off:** GAP-04, GAP-06 and GAP-08's WAF are code + OSCAL only, caught in review rather than CI: a deliberate call to avoid alert fatigue. WAF can't bind to an HTTP API, so it's documented with a remediation path rather than faked.

### Key design: two customer-managed keys, no `kms:*`
- **Choice:** A data key (PHI) and an evidence key (vault, CloudTrail), rotation on. Key policies name administrators who can manage but not use the keys; workload use is limited per service with `kms:ViaService`.
- **Why:** Separation of duties. The workload can't read evidence, and administrators can't decrypt PHI. Key admins can decrypt evidence only through S3, so they can act as verifiers.
- **Trade-off:** More key-policy statements to maintain, and every new service that touches PHI needs its own grant.

### Policies read the code where the plan can't know the value
- **Choice:** GAP-02 and GAP-05 decide from the plan's `configuration` (what the code declares); GAP-01, 03 and 07 read planned values, and `warn` when a policy's content is only known after apply.
- **Why:** `kms_key_arn` on DynamoDB is Optional + Computed, so a table with *no* key in code still shows the key as "known after apply". A values-only rule would let the AWS-managed key through. Subnet and security-group IDs are also unknown on a first deploy.
- **Trade-off:** Configuration checks cover root-module resources; a table or function moved into a module would need the rule extended.

### No generic IaC scanner in the gate
- **Choice:** The gate is the five CMMC-mapped Rego policies only.
- **Why:** Each guard maps to a declared control and a real gap, so every failure is actionable and cites the control to fix. Generic scanners report vendor check IDs, not framework controls, and would block on risks already accepted here (no WAF on the HTTP API): the alert fatigue this design avoids.
- **Trade-off:** Misconfigurations outside the five material gaps aren't caught in CI. Next sprint: add `trivy config` as a non-blocking, evidence-only scan.

### Pipeline configuration and public logs
- **Choice:** No AWS keys anywhere. GitHub OIDC assumes a role trusted only for this repo's `main` and PRs, by immutable repo and owner IDs, with 1-hour sessions. Non-secret settings (role ARN, admin ARN, OIDC subject) are repository variables. Because Actions logs on a public repo are public, the workflow masks the account ID and vault name, prints only resource addresses from the plan, keeps the full plan in the encrypted vault, and doesn't upload workflow artifacts.
- **Why:** A role ARN is not a credential; the trust policy is the control. Plan output contains ARNs and configuration that don't belong in a public log.
- **Trade-off:** Repository variables aren't masked automatically, and the admin user name is visible in step headers. Moving those values to Secrets would hide them.

## How the pipeline produces evidence
One workflow, `.github/workflows/grc-gate.yml`, five ordered steps. Every run that produces a plan leaves a signed bundle in the vault, including runs the gate blocks.

**Green path: PR #3 (Layer 3 pipeline), merged.**
1. **PR Open.** The PR run planned `0 to add, 2 to change, 0 to destroy` (the evidence key policy and a one-time Lambda redeploy), listing each changed resource address in the log.
2. **Policy Check (Gate).** `policy-gate.sh` ran `opa test`, then Conftest on the plan for all five namespaces: `policy-gate: PASS`.
3. **Apply.** Skipped on the PR. After merge, the push to `main` (run **45456179365**, merge commit `5d3a6ba`) applied the approved plan: `Apply complete! Resources: 0 added, 2 changed, 0 destroyed.`
4. **Sign.** The run's evidence (plan, Conftest results, run metadata, tool versions, per-file SHA-256 manifest) was bundled and signed with Cosign keyless, using the workflow's GitHub OIDC identity and recorded in the public Rekor log.
5. **Upload.** Bundle, hash, signature and receipt went to `runs/45456179365/` in the vault, locked in GOVERNANCE mode.

`scripts/verify-evidence.sh 45456179365` → SHA-256 matches, Cosign verifies (signer pinned to this repo's `grc-gate.yml`), Object Lock retention active: **`CHAIN INTACT`**.

**Red path: PR #5, blocked.** The PR removed the DynamoDB table's `kms_key_arn`. The policy check failed with `DENY: [SC.L2-3.13.11] aws_dynamodb_table.intake: encryption uses the AWS-managed aws/dynamodb key, not a customer-managed key (GAP-02)`, Apply was skipped, and the required `grc-gate` check blocked the merge. The blocked run (**45461398718**) was still signed and uploaded, and verifies `CHAIN INTACT`. The PR was closed without merging.

## Trade-offs and what I'd do with another sprint
- **Reserved concurrency (GAP-06).** The account's total Lambda concurrency quota is 10, so reserving any would starve the rest of the account; `lambda_reserved_concurrency` is set to `-1`. API Gateway throttling (50 req/s, burst 100) is the compensating control. Next: raise the quota and reserve capacity for the intake function.
- **DLQ coverage.** The dead-letter queue only receives asynchronous invocations, and API Gateway invokes the function synchronously, so failed API requests surface as errors to the caller rather than in the DLQ.
- **Evidence access for assessors.** The vault is private. Today, verification needs the evidence key's admin principals (decrypt through S3 only). Next: a dedicated read-only auditor role, so an external assessor can run `verify-evidence.sh` without admin rights.
- **Signing resilience.** One run failed at signing because GitHub's OIDC endpoint returned a transient error; a re-run passed. Next: retry the signing step.
- **Cross-platform fixes found in CI.** The Lambda zip hashed differently on Windows and Linux (fixed with `output_file_mode`), and Windows shells mangled the Cosign identity argument (fixed in `verify-evidence.sh`). Both now behave the same on both platforms.

## What I didn't get to
- **WAF for the API (GAP-08).** WAF can't be associated with an API Gateway HTTP API. Remediation: put CloudFront with AWS WAF in front of the API, or migrate to a REST API.
- **COMPLIANCE-mode Object Lock, a separate evidence account, and a manual approval gate.** All deliberately deferred (see design decisions).
- **GovCloud.** Real CUI should run in AWS GovCloud (US).
- **FIPS validation citation.** SC.L2-3.13.11 requires FIPS-validated cryptography. AWS KMS uses FIPS-validated HSMs, but the CMVP certificate I checked showed a sunset date of 2026-11-17; the current certificate number needs confirming before citing it.
- **Policy coverage for GAP-04, GAP-06 and GAP-08,** and policy checks for resources inside modules beyond the S3 buckets.
