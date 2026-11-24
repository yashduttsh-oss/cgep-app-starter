# METADATA
# title: AC.L2-3.1.5 - Least privilege (no wildcard IAM actions)
# description: >-
#   IAM policies may not Allow every action ("*") or every action of a
#   service ("s3:*", "dynamodb:*"). Scoped patterns such as "s3:Get*" are
#   allowed: they are read-only families, not a whole service.
# scope: package
# custom:
#   control_id: AC.L2-3.1.5
#   framework: cmmc-l2
#   gap: GAP-07
#   severity: high
#   remediation: >-
#     List only the actions the code calls (e.g. dynamodb:PutItem,
#     s3:PutObject), scoped to specific resource ARNs.
package compliance.gap07_iam_least_privilege

import data.lib.plan
import rego.v1

policy_types := {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

# 1. An Allow statement grants "*" or "<service>:*".
deny contains msg if {
	some type in policy_types
	some rc in plan.resources(type)
	not plan.unknown(rc, ["policy"])
	doc := json.unmarshal(rc.change.after.policy)
	some s in plan.statements(doc)
	object.get(s, "Effect", "Allow") == "Allow"
	some action in plan.as_list(object.get(s, "Action", []))
	wildcard(action)
	msg := sprintf("[AC.L2-3.1.5] %s: Allow grants wildcard action %q (GAP-07). Remediation: list only the specific actions the workload calls.", [rc.address, action])
}

# Policies built from ARNs that don't exist yet can't be read until apply.
warn contains msg if {
	some type in policy_types
	some rc in plan.resources(type)
	plan.unknown(rc, ["policy"])
	msg := sprintf("[AC.L2-3.1.5] %s: policy content is known only after apply; actions are verified on the next plan (GAP-07).", [rc.address])
}

wildcard(action) if action == "*"

wildcard(action) if endswith(action, ":*")
