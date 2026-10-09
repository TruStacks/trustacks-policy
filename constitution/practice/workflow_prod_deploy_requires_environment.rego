# practice.workflow_prod_deploy_requires_environment — on a prod-tier target,
# every job that deploys declares a GitHub `environment:`.
#
# ADR-0062 decision 4. The GitHub Actions implementation of the intent behind
# `manual_promotion_to_prod` (ADR-0060 §2): a human approves promotion to prod.
#
# This is PRESENCE OF A REFERENCE, not enforcement. It proves the deploy job
# names an environment. Whether that environment has required reviewers is a
# repository setting we do not read — and for private repositories below
# GitHub Enterprise, required reviewers are not available at all. So this rule
# deliberately declares NO practice dimension: its silence must never read as
# "a human approves promotion to prod: verified" (the ADR-0038 presence-not-
# validity defect inside the score). `manual_promotion_to_prod` for such a
# target stays claimed-only until the environment's protection rules are read
# through the API.
#
# Kind-agnostic by construction (any workflow that runs the ECS deploy action),
# declared for `ecs-fargate` because that is the only kind deployed that way.

package proposal

import rego.v1

rule_metadata["practice.workflow_prod_deploy_requires_environment"] := {
	"description": "On a prod-tier target, every job that deploys (aws-actions/amazon-ecs-deploy-task-definition) declares a GitHub environment. Presence only: the environment's reviewers are not verified.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["prod"],
	"target_kinds": ["ecs-fargate"],
}

deny contains msg if {
	target_tier == "prod"
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	some job_id, job in wf.jobs
	_job_deploys_to_ecs(job)
	not _job_has_environment(job)
	msg := {
		"rule_id": "practice.workflow_prod_deploy_requires_environment",
		"message": sprintf(
			"workflow %v: job %v deploys to a prod-tier target without an `environment:`; name one so the deploy can be held for approval",
			[f.path, job_id],
		),
	}
}

_job_has_environment(job) if {
	is_string(job.environment)
	trim_space(job.environment) != ""
}

_job_has_environment(job) if {
	is_string(job.environment.name)
	trim_space(job.environment.name) != ""
}
