# METADATA
# title: SC.L2-3.13.11 - Encryption at rest with a customer-managed key (DynamoDB)
# description: >-
#   PHI in DynamoDB must be encrypted under a key Acme controls. A table with
#   no server_side_encryption block uses an AWS-owned key; enabled = true
#   with no kms_key_arn uses the AWS-managed aws/dynamodb key. Both fail.
# scope: package
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc-l2
#   gap: GAP-02
#   severity: high
#   remediation: >-
#     Add server_side_encryption { enabled = true, kms_key_arn = <your CMK ARN> }
#     to the aws_dynamodb_table.
package compliance.gap02_dynamodb_encryption

import data.lib.plan
import rego.v1

# Decided from `configuration`, not from planned values: kms_key_arn is
# Optional + Computed, so a table with NO key in code still shows the key
# as "known after apply". Only the code tells us whether a key was named.

# 1. Encryption block missing, or not enabled with a literal true.
deny contains msg if {
	some r in plan.config_resources("aws_dynamodb_table")
	not sse_enabled(r)
	msg := sprintf("[SC.L2-3.13.11] %s: server-side encryption with a customer-managed key is not configured (GAP-02). Remediation: add server_side_encryption { enabled = true, kms_key_arn = <CMK ARN> }.", [r.address])
}

# 2. Enabled, but no customer key named: AWS falls back to aws/dynamodb.
deny contains msg if {
	some r in plan.config_resources("aws_dynamodb_table")
	sse_enabled(r)
	some sse in r.expressions.server_side_encryption
	not plan.has_value(object.get(sse, "kms_key_arn", {}))
	msg := sprintf("[SC.L2-3.13.11] %s: encryption uses the AWS-managed aws/dynamodb key, not a customer-managed key (GAP-02). Remediation: set kms_key_arn = <CMK ARN> in server_side_encryption.", [r.address])
}

sse_enabled(r) if {
	some sse in object.get(r, ["expressions", "server_side_encryption"], [])
	object.get(sse, ["enabled", "constant_value"], false) == true
}
