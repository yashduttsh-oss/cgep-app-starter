package compliance.gap05_lambda_in_vpc_test

import data.compliance.gap05_lambda_in_vpc as policy
import rego.v1

function(expressions) := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"mode": "managed",
	"type": "aws_lambda_function",
	"expressions": expressions,
}]}}}

subnets := {"references": ["aws_subnet.private"]}

sgs := {"references": ["aws_security_group.lambda.id", "aws_security_group.lambda"]}

test_in_vpc_passes if {
	count(policy.deny) == 0 with input as function({"vpc_config": [{"subnet_ids": subnets, "security_group_ids": sgs}]})
}

test_no_vpc_config_fails if {
	some msg in policy.deny with input as function({"function_name": {"constant_value": "intake"}})
	contains(msg, "[SC.L2-3.13.1]")
	contains(msg, "aws_lambda_function.intake")
}

test_missing_security_groups_fails if {
	some msg in policy.deny with input as function({"vpc_config": [{"subnet_ids": subnets}]})
	contains(msg, "security_group_ids")
}

test_empty_subnet_list_fails if {
	some msg in policy.deny with input as function({"vpc_config": [{
		"subnet_ids": {"constant_value": []},
		"security_group_ids": sgs,
	}]})
	contains(msg, "subnet_ids")
}
