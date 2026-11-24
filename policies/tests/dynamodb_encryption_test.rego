package compliance.gap02_dynamodb_encryption_test

import data.compliance.gap02_dynamodb_encryption as policy
import rego.v1

# One root-module table whose `expressions` are given by each test.
table(expressions) := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"mode": "managed",
	"type": "aws_dynamodb_table",
	"expressions": expressions,
}]}}}

key_ref := {"references": ["aws_kms_key.data.arn", "aws_kms_key.data"]}

test_customer_key_passes if {
	count(policy.deny) == 0 with input as table({"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": key_ref,
	}]})
}

test_no_encryption_block_fails if {
	some msg in policy.deny with input as table({"name": {"constant_value": "intake"}})
	contains(msg, "[SC.L2-3.13.11]")
	contains(msg, "aws_dynamodb_table.intake")
}

test_enabled_false_fails if {
	some msg in policy.deny with input as table({"server_side_encryption": [{
		"enabled": {"constant_value": false},
		"kms_key_arn": key_ref,
	}]})
	contains(msg, "not configured")
}

# The case after_unknown would miss: no key in code, AWS picks aws/dynamodb.
test_aws_managed_key_fails if {
	some msg in policy.deny with input as table({"server_side_encryption": [{"enabled": {"constant_value": true}}]})
	contains(msg, "aws/dynamodb")
}
