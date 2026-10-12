# practice.ecs_task_runs_as_nonroot — every container in an ECS task
# definition names a non-root `user`.
#
# ADR-0062. The ECS implementation of `non_root_containers`, the same intent as
# `practice.dockerfile_runs_as_nonroot`. ECS runs the container as `user`, so
# this is enforcement in the artifact, and its verdict is honest evidence.
# AWS Security Hub ECS.20 checks the same thing after deploy.
#
# Root is `root`, `0`, or either of those as the user half of `user:group`.
# An absent or empty `user` falls back to the image's USER, which we cannot
# see — so it is refused rather than assumed.

package proposal

import rego.v1

rule_metadata["practice.ecs_task_runs_as_nonroot"] := {
	"description": "Every container in an ECS task definition sets a non-root `user` (not root / 0).",
	"required_tooling_categories": [],
	"practice_dimensions": ["non_root_containers"],
	"tier_scope": ["any"],
	"target_kinds": ["ecs-fargate"],
}

deny contains msg if {
	some f in input.proposal.files
	_is_ecs_task_definition(f.path)
	some c in _ecs_containers(f.content)
	not _ecs_user_is_nonroot(c)
	msg := {
		"rule_id": "practice.ecs_task_runs_as_nonroot",
		"message": sprintf(
			"file %v: container %v must set `user` to a non-root UID (it is absent, empty, root or 0)",
			[f.path, object.get(c, "name", "<unnamed>")],
		),
	}
}

_ecs_user_is_nonroot(c) if {
	user := c.user
	is_string(user)
	identity := trim_space(split(user, ":")[0])
	identity != ""
	not identity in {"root", "0"}
}
