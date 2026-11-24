package compliance.gap03_s3_tls_only_test

import data.compliance.gap03_s3_tls_only as policy
import rego.v1

bucket_arn := "arn:aws:s3:::acme-health-intake-uploads-1a2b3c4d"

# The uploads bucket, attached to the secure-bucket module (which contains
# an aws_s3_bucket_policy), or not attached at all.
config_with_module := {"root_module": {
	"resources": [{"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket"}],
	"module_calls": {"uploads_bucket": {
		"expressions": {"bucket_id": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
		"module": {"resources": [{"address": "aws_s3_bucket_policy.this", "mode": "managed", "type": "aws_s3_bucket_policy"}]},
	}},
}}

config_without_module := {"root_module": {"resources": [{"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket"}]}}

tls_deny := {
	"Sid": "DenyNonTLSRequests",
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:*",
	"Resource": [bucket_arn, sprintf("%s/*", [bucket_arn])],
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}

policy_change(statements, unknown) := {
	"address": "module.uploads_bucket.aws_s3_bucket_policy.this",
	"mode": "managed",
	"type": "aws_s3_bucket_policy",
	"change": {
		"actions": ["update"],
		"after": {"policy": json.marshal({"Version": "2012-10-17", "Statement": statements})},
		"after_unknown": {"policy": unknown},
	},
}

test_tls_deny_passes if {
	count(policy.deny) == 0 with input as {
		"configuration": config_with_module,
		"resource_changes": [policy_change([tls_deny], false)],
	}
}

test_policy_unknown_warns_not_denies if {
	inp := {"configuration": config_with_module, "resource_changes": [policy_change([], true)]}
	count(policy.deny) == 0 with input as inp
	count(policy.warn) == 1 with input as inp
}

test_bucket_without_policy_fails if {
	some msg in policy.deny with input as {"configuration": config_without_module, "resource_changes": []}
	contains(msg, "[SC.L2-3.13.8]")
	contains(msg, "aws_s3_bucket.uploads")
}

test_policy_without_tls_deny_fails if {
	allow_read := {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": bucket_arn}
	some msg in policy.deny with input as {
		"configuration": config_with_module,
		"resource_changes": [policy_change([allow_read], false)],
	}
	contains(msg, "aws:SecureTransport")
}

# A deny that only covers the bucket ARN leaves objects reachable over HTTP.
test_tls_deny_without_objects_fails if {
	bucket_only := object.union(tls_deny, {"Resource": bucket_arn})
	some msg in policy.deny with input as {
		"configuration": config_with_module,
		"resource_changes": [policy_change([bucket_only], false)],
	}
	contains(msg, "GAP-03")
}
