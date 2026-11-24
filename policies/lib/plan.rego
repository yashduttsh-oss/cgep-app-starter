# METADATA
# title: Plan JSON helpers
# description: >-
#   Shared helpers for reading `terraform show -json` output. Used by every
#   GAP policy so they read the plan the same way.
# scope: package
package lib.plan

import rego.v1

# Resources that will exist after apply (created, updated, or unchanged),
# by type. Skips pure deletes, whose `after` is null.
resources(type) := [rc |
	some rc in input.resource_changes
	rc.type == type
	rc.mode == "managed"
	rc.change.after != null
]

# True when a value is "known after apply" (it depends on a resource that
# doesn't exist yet, e.g. a KMS key ARN on a first deploy). The plan marks
# these in change.after_unknown, mirroring the shape of change.after.
unknown(rc, path) if object.get(rc.change.after_unknown, path, false) == true

# A value that is missing: null, empty string, or empty list.
missing(v) if v == null
missing(v) if v == ""
missing(v) if v == []

# Addresses of the root-module S3 buckets the code declares
# (e.g. "aws_s3_bucket.uploads"). Read from `configuration`, which is
# present even when values are unknown.
root_buckets contains r.address if {
	some r in input.configuration.root_module.resources
	r.mode == "managed"
	r.type == "aws_s3_bucket"
}

# Buckets covered by a resource of `type` (e.g. a bucket policy), either
# declared at the root and referencing the bucket, or inside a module call
# (like secure-bucket) whose inputs reference the bucket.
covered_buckets(type) := {b |
	some r in input.configuration.root_module.resources
	r.type == type
	some b in object.get(r, ["expressions", "bucket", "references"], [])
	bucket_address(b)
} | {b |
	some mc in input.configuration.root_module.module_calls
	some r in object.get(mc, ["module", "resources"], [])
	r.type == type
	some e in mc.expressions
	some b in object.get(e, "references", [])
	bucket_address(b)
}

# A bare bucket address like "aws_s3_bucket.uploads". Terraform lists both
# that and attribute forms ("aws_s3_bucket.uploads.id") in references.
bucket_address(ref) if {
	startswith(ref, "aws_s3_bucket.")
	count(split(ref, ".")) == 2
}

# Root-module resources of `type` as the code declares them. Use this when
# a provider fills a value in at apply time ("Optional + Computed"), so the
# plan's after_unknown can't tell "set in code" from "AWS will pick one".
config_resources(type) := [r |
	some r in input.configuration.root_module.resources
	r.mode == "managed"
	r.type == type
]

# True when a configuration expression sets a value: it references
# something (e.g. aws_kms_key.data.arn) or holds a non-empty constant.
has_value(expr) if count(object.get(expr, "references", [])) > 0

has_value(expr) if {
	v := object.get(expr, "constant_value", null)
	not missing(v)
}

# A policy field that may be a string or a list, always as a list.
as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

# The statements of a JSON policy document (Statement may be one object
# or a list of them).
statements(doc) := as_list(doc.Statement)
