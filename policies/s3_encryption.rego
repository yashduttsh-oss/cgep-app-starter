
# METADATA
# title: SC.L2-3.13.11 - Encryption at rest with a customer-managed key (S3)
# description: >-
#   PHI in S3 must be encrypted under a key Acme controls. AWS's default
#   (SSE-S3) and SSE-KMS with the AWS-managed aws/s3 key both fail.
# scope: package
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc-l2
#   gap: GAP-01
#   severity: high
#   remediation: >-
#     Use the secure-bucket module for every bucket, or add an
#     aws_s3_bucket_server_side_encryption_configuration with
#     sse_algorithm = "aws:kms" and kms_master_key_id = <your CMK ARN>.
package compliance.gap01_s3_encryption 

import data.lib.plan
import rego.v1

# 1. Every bucket the code declares must have a default-encryption configuration. 
# Read from 'configuration', so it works even on a first deploy. 
deny contains msg if {
    some bucket in plan.root_buckets
    not bucket in 
    plan.covered_buckets("aws_s3_bucket_server_side_encryption_configuration")
    msg := sprintf("[SC.L2-3.13.11] %s: no default encryption configuration (GAP-01). Remediation: use the secure-bucket module, or add SSE-KMS with a customer-managed key.", [bucket])
}  

# 2. The algorithm must be aws:kms (not AES256 / SSE-S3).
deny contains msg if {
    some rc in 
plan.resources("aws_s3_bucket_server_side_encryption_configuration")
    some rule in rc.change.after.rule
    some d in rule.apply_server_side_encryption_by_default
    d.sse_algorithm != "aws:kms"
    msg := sprintf("[SC.L2-3.13.11] %s: sse_algorithm is %q, not aws:kms (GAP-01). Remediation: set sse_algorithm = \"aws:kms\" with a customer-managed key.", [rc.address, d.sse_algorithm])   
}

# 3. A customer key must be named. aws:kms with no key falls back to the
#    AWS-managed aws/s3 key. A key that is "known after apply" is fine:
#    it references a key being created in the same plan.
deny contains msg if {
    some rc in 
plan.resources("aws_s3_bucket_server_side_encryption_configuration")
    some i, rule in rc.change.after.rule
    some j, d in rule.apply_server_side_encryption_by_default
    d.sse_algorithm == "aws:kms"
    plan.missing(object.get(d, "kms_master_key_id", null))
    not plan.unknown(rc, ["rule", i, "apply_server_side_encryption_by_default", j, "kms_master_key_id"])
    msg := sprintf("[SC.L2-3.13.11] %s: no no kms_master_key_id, so S3 uses the AWS-managed aws/s3 key (GAP-01). Remediation: set kms_master_key_id to your customer-managed key ARN.", [rc.address])
}

