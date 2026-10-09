# practice.ecs_task_readonly_root_filesystem — every container in an ECS task
# definition mounts its root filesystem read-only.
#
# ADR-0062. AWS Security Hub ECS.5. Reads the exact key
# `readonlyRootFilesystem`: AWS's SDK silently drops a mis-cased key, so
# `readOnlyRootFilesystem: true` deploys a WRITABLE root and must fail here,
# which it does, because the correctly-cased key is then absent.
#
# No practice dimension yet (ADR-0062 decision 5): a new dimension is a new
# row in every customer's score, and Kubernetes customers have no
# implementation of it until per-kind scoring lands (ADR-0060 §2).

package proposal

import rego.v1

rule_metadata["practice.ecs_task_readonly_root_filesystem"] := {
	"description": "Every container in an ECS task definition sets readonlyRootFilesystem: true.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["ecs-fargate"],
}

deny contains msg if {
	some f in input.proposal.files
	_is_ecs_task_definition(f.path)
	some c in _ecs_containers(f.content)
	not c.readonlyRootFilesystem == true
	msg := {
		"rule_id": "practice.ecs_task_readonly_root_filesystem",
		"message": sprintf(
			"file %v: container %v must set `readonlyRootFilesystem: true` (exactly that casing — AWS silently ignores any other)",
			[f.path, object.get(c, "name", "<unnamed>")],
		),
	}
}
