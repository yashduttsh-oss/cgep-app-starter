package compliance.gap07_iam_least_privilege_test

import data.compliance.gap07_iam_least_privilege as policy
import rego.v1

role_policy(statements) := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"mode": "managed",
	"type": "aws_iam_role_policy",
	"change": {
		"actions": ["update"],
		"after": {"policy": json.marshal({"Version": "2012-10-17", "Statement": statements})},
		"after_unknown": {},
	},
}]}

table_arn := "arn:aws:dynamodb:us-east-1:111122223333:table/acme-health-intake-1a2b3c4d"

test_scoped_actions_pass if {
	count(policy.deny) == 0 with input as role_policy([
		{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn},
		{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"},
	])
}

# Wildcards inside a Deny only take access away.
test_wildcard_in_deny_passes if {
	count(policy.deny) == 0 with input as role_policy([{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}])
}

test_service_wildcard_fails if {
	some msg in policy.deny with input as role_policy([{"Effect": "Allow", "Action": "dynamodb:*", "Resource": table_arn}])
	contains(msg, "[AC.L2-3.1.5]")
	contains(msg, "\"dynamodb:*\"")
}

test_full_wildcard_in_list_fails if {
	some msg in policy.deny with input as role_policy([{"Effect": "Allow", "Action": ["s3:PutObject", "*"], "Resource": "*"}])
	contains(msg, "aws_iam_role_policy.lambda_inline")
}

test_unknown_policy_warns_not_denies if {
	inp := {"resource_changes": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"mode": "managed",
		"type": "aws_iam_role_policy",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {"policy": true}},
	}]}
	count(policy.deny) == 0 with input as inp
	count(policy.warn) == 1 with input as inp
}
