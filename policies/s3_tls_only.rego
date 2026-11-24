# METADATA
# title: SC.L2-3.13.8 - Encryption in transit (S3 TLS-only bucket policy)
# description: >-
#   Every S3 bucket must refuse requests that don't use TLS. The bucket
#   policy needs a Deny for all principals and all S3 actions, on the bucket
#   and its objects, when aws:SecureTransport is false.
# scope: package
# custom:
#   control_id: SC.L2-3.13.8
#   framework: cmmc-l2
#   gap: GAP-03
#   severity: high
#   remediation: >-
#     Use the secure-bucket module, or add a bucket policy statement:
#     Effect Deny, Principal "*", Action "s3:*", Resource [bucket, bucket/*],
#     Condition Bool aws:SecureTransport = "false".
package compliance.gap03_s3_tls_only

import data.lib.plan
import rego.v1

# 1. Every bucket the code declares must have a bucket policy.
deny contains msg if {
	some bucket in plan.root_buckets
	not bucket in plan.covered_buckets("aws_s3_bucket_policy")
	msg := sprintf("[SC.L2-3.13.8] %s: no bucket policy, so plain-HTTP requests are allowed (GAP-03). Remediation: use the secure-bucket module, or add a bucket policy that denies aws:SecureTransport = false.", [bucket])
}

# 2. A bucket policy whose content is known must contain the TLS deny.
deny contains msg if {
	some rc in plan.resources("aws_s3_bucket_policy")
	not plan.unknown(rc, ["policy"])
	doc := json.unmarshal(rc.change.after.policy)
	not has_tls_deny(doc)
	msg := sprintf("[SC.L2-3.13.8] %s: bucket policy has no Deny for aws:SecureTransport = false (GAP-03). Remediation: add the TLS-only Deny statement (see the secure-bucket module).", [rc.address])
}

# The policy is built from ARNs that don't exist yet on a first deploy, so
# its content can't be read until after apply. Rule 1 still proves a policy
# is attached; the next plan (after apply) checks its content.
warn contains msg if {
	some rc in plan.resources("aws_s3_bucket_policy")
	plan.unknown(rc, ["policy"])
	msg := sprintf("[SC.L2-3.13.8] %s: policy content is known only after apply; the TLS deny is verified on the next plan (GAP-03).", [rc.address])
}

has_tls_deny(doc) if {
	some s in plan.statements(doc)
	s.Effect == "Deny"
	secure_transport_false(s)
	all_principals(s.Principal)
	some action in plan.as_list(s.Action)
	action in {"s3:*", "*"}
	some resource in plan.as_list(s.Resource)
	endswith(resource, "/*")
}

# IAM accepts the condition value as a string, a boolean, or a list.
secure_transport_false(s) if {
	v := s.Condition.Bool["aws:SecureTransport"]
	some x in plan.as_list(v)
	x in {"false", false}
}

all_principals(p) if p == "*"

all_principals(p) if {
	some x in plan.as_list(p.AWS)
	x == "*"
}
