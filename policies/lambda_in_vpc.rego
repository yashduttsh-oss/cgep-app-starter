# METADATA
# title: SC.L2-3.13.1 - Boundary protection (Lambda inside the VPC)
# description: >-
#   The intake Lambda handles PHI, so it must run in the VPC's private
#   subnets behind a security group, not on AWS's shared Lambda network.
# scope: package
# custom:
#   control_id: SC.L2-3.13.1
#   framework: cmmc-l2
#   gap: GAP-05
#   severity: high
#   remediation: >-
#     Add vpc_config { subnet_ids = aws_subnet.private[*].id,
#     security_group_ids = [aws_security_group.lambda.id] } to the function.
package compliance.gap05_lambda_in_vpc

import data.lib.plan
import rego.v1

# Read from `configuration`: subnet and security group IDs are unknown on a
# first deploy, but the code's references to them are always there.

# 1. No vpc_config block at all.
deny contains msg if {
	some r in plan.config_resources("aws_lambda_function")
	count(object.get(r, ["expressions", "vpc_config"], [])) == 0
	msg := sprintf("[SC.L2-3.13.1] %s: function runs outside the VPC (no vpc_config) (GAP-05). Remediation: add vpc_config with the private subnets and the Lambda security group.", [r.address])
}

# 2. A vpc_config block missing its subnets or security groups.
deny contains msg if {
	some r in plan.config_resources("aws_lambda_function")
	some vpc in object.get(r, ["expressions", "vpc_config"], [])
	some field in ["subnet_ids", "security_group_ids"]
	not plan.has_value(object.get(vpc, field, {}))
	msg := sprintf("[SC.L2-3.13.1] %s: vpc_config has no %s (GAP-05). Remediation: set both subnet_ids and security_group_ids.", [r.address, field])
}
