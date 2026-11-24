package compliance.gap01_s3_encryption_test

import data.compliance.gap01_s3_encryption as policy
import rego.v1

# --- Fixture builders (shaped like real `terraform show -json` output) ---

# Configuration where the uploads bucket is hardened by the secure-bucket
# module (its inputs reference the bucket).
config_with_module := {"root_module": {
	"resources": [{"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket"}],
	"module_calls": {"uploads_bucket": {
		"expressions": {"bucket_id": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
		"module": {"resources": [{"type": "aws_s3_bucket_server_side_encryption_configuration"}]},
	}},
}}

# Configuration where the module call was removed: GAP-01 re-introduced.
config_without_module := {"root_module": {
	"resources": [{"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket"}],
	"module_calls": {},
}}

sse_change(algorithm, key, key_unknown) := {
	"address": "module.uploads_bucket.aws_s3_bucket_server_side_encryption_configuration.this",
	"mode": "managed",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {
		"actions": ["create"],
		"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": algorithm, "kms_master_key_id": key}]}]},
		"after_unknown": {"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": key_unknown}]}]},
	},
}

key_arn := "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"

# --- Passing ---

test_compliant_cmk_passes if {
	count(policy.deny) == 0 with input as {
		"configuration": config_with_module,
		"resource_changes": [sse_change("aws:kms", key_arn, false)],
	}
}

# First deploy: the key ARN isn't known until the key is created.
test_key_known_after_apply_passes if {
	count(policy.deny) == 0 with input as {
		"configuration": config_with_module,
		"resource_changes": [sse_change("aws:kms", null, true)],
	}
}

# --- Failing ---

test_bucket_without_encryption_config_fails if {
	some msg in policy.deny with input as {"configuration": config_without_module, "resource_changes": []}
	contains(msg, "aws_s3_bucket.uploads: no default encryption")
	contains(msg, "SC.L2-3.13.11")
}

test_sse_s3_aes256_fails if {
	some msg in policy.deny with input as {
		"configuration": config_with_module,
		"resource_changes": [sse_change("AES256", null, false)],
	}
	contains(msg, "AES256")
}

test_aws_managed_key_fails if {
	some msg in policy.deny with input as {
		"configuration": config_with_module,
		"resource_changes": [sse_change("aws:kms", null, false)],
	}
	contains(msg, "aws/s3")
}