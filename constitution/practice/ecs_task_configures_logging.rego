# practice.ecs_task_configures_logging — every container in an ECS task
# definition ships its logs somewhere.
#
# ADR-0062. AWS Security Hub ECS.9. A Fargate task with no log driver runs,
# and its output is gone: nothing to read when it fails. Any driver satisfies
# the rule (awslogs, FireLens, splunk, …); the pack emits awslogs.

package proposal

import rego.v1

rule_metadata["practice.ecs_task_configures_logging"] := {
	"description": "Every container in an ECS task definition sets logConfiguration.logDriver.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["ecs-fargate"],
}

deny contains msg if {
	some f in input.proposal.files
	_is_ecs_task_definition(f.path)
	some c in _ecs_containers(f.content)
	not _has_log_driver(c)
	msg := {
		"rule_id": "practice.ecs_task_configures_logging",
		"message": sprintf(
			"file %v: container %v has no logConfiguration.logDriver, so its output is lost",
			[f.path, object.get(c, "name", "<unnamed>")],
		),
	}
}

_has_log_driver(c) if {
	driver := c.logConfiguration.logDriver
	is_string(driver)
	driver != ""
}
