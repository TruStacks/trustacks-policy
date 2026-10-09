# practice.ecs_task_image_is_pinned — every ECS container image names a digest
# or a non-floating tag.
#
# ADR-0062. A missing tag means `latest`, and `latest` (or `main`, `stable`, …)
# means the revision that runs is whatever was pushed last — unknowable after
# the fact, which a product selling auditability cannot ship (ADR-0040).
#
# Honest about strength: a digest (`@sha256:…`) is immutable and verified. A
# tag is only checked for not being a known floating name — whether the
# registry makes tags immutable is a registry setting we do not read. The
# emitted tag is the service commit SHA; digest pinning is a recorded gap
# (ADR-0062 decision 7).

package proposal

import rego.v1

rule_metadata["practice.ecs_task_image_is_pinned"] := {
	"description": "Every ECS container image is pinned by digest or by a tag that is not latest or another floating name.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["ecs-fargate"],
}

_floating_tags := {
	"latest", "main", "master", "stable", "edge", "nightly", "dev", "develop",
	"staging", "prod", "production", "release", "current",
}

deny contains msg if {
	some f in input.proposal.files
	_is_ecs_task_definition(f.path)
	some c in _ecs_containers(f.content)
	not _image_is_pinned(object.get(c, "image", ""))
	msg := {
		"rule_id": "practice.ecs_task_image_is_pinned",
		"message": sprintf(
			"file %v: container %v image %v must be pinned by digest or by a non-floating tag (not latest, and not untagged)",
			[f.path, object.get(c, "name", "<unnamed>"), object.get(c, "image", "")],
		),
	}
}

_image_is_pinned(image) if {
	is_string(image)
	regex.match(`@sha256:[0-9a-f]{64}$`, image)
}

_image_is_pinned(image) if {
	is_string(image)
	not contains(image, "@")
	tag := _image_tag(image)
	tag != ""
	not lower(tag) in _floating_tags
}

# The tag is what follows the last ':' after the last '/'. A registry port
# (`registry:5000/app`) is a colon too, and is not a tag.
_image_tag(image) := tag if {
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	contains(last, ":")
	segs := split(last, ":")
	tag := segs[count(segs) - 1]
} else := ""
