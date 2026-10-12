# proposal.has_ecs_deploy_workflow — an ECS Fargate proposal ships the
# workflow that deploys its task definition.
#
# ADR-0062. ArgoCD is what applies a Kubernetes proposal; on ECS nothing
# applies a merged task definition unless a workflow does. Without one the
# task definition merges, passes review, and never runs. A deploy workflow is
# one with a job that uses `aws-actions/amazon-ecs-deploy-task-definition`.

package proposal

import rego.v1

rule_metadata["proposal.has_ecs_deploy_workflow"] := {
	"description": "An ECS Fargate proposal includes a workflow that deploys the task definition (uses aws-actions/amazon-ecs-deploy-task-definition).",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["ecs-fargate"],
}

deny contains msg if {
	target_kind == "ecs-fargate"
	count([f |
		some f in input.proposal.files
		_is_workflow(f.path)
		_is_deploy_workflow(yaml.unmarshal(f.content))
	]) == 0
	msg := {
		"rule_id": "proposal.has_ecs_deploy_workflow",
		"message": "an ECS Fargate proposal must include a .github/workflows/ file that deploys the task definition with aws-actions/amazon-ecs-deploy-task-definition",
	}
}
