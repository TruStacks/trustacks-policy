# proposal.has_ecs_task_definition — an ECS Fargate proposal ships a task
# definition.
#
# ADR-0062. The ECS Fargate counterpart of `has_helm_chart` /
# `has_kustomization`: the deploy artifact for the target's kind must be
# present. Fires only when the target's kind is `ecs-fargate`.

package proposal

import rego.v1

rule_metadata["proposal.has_ecs_task_definition"] := {
	"description": "An ECS Fargate proposal includes a task-definition.json under the gitops/ service root.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["ecs-fargate"],
}

deny contains msg if {
	target_kind == "ecs-fargate"
	count([f | some f in input.proposal.files; _is_ecs_task_definition(f.path)]) == 0
	msg := {
		"rule_id": "proposal.has_ecs_task_definition",
		"message": "an ECS Fargate proposal must include gitops/<application>/<target>/<service>/task-definition.json",
	}
}
