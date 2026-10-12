# practice.ecs_task_secrets_not_in_environment — secrets reach an ECS
# container through `secrets` (by ARN), never as plaintext `environment`.
#
# ADR-0062. AWS Security Hub ECS.8, made stricter: ECS.8 checks three variable
# names; this checks the common credential-name suffixes, values that are
# credentials on their face, and that every `secrets[].valueFrom` is a full
# Secrets Manager or SSM Parameter Store ARN.
#
# Names are matched as SUFFIXES (`DB_PASSWORD`, `AUTH_TOKEN`), so configuration
# such as `TOKEN_URL` or `AUTH_SERVER` is not flagged — a false positive blocks
# a correct proposal, which ADR-0038 calls worse than no check.

package proposal

import rego.v1

rule_metadata["practice.ecs_task_secrets_not_in_environment"] := {
	"description": "No credential-like value in an ECS container's `environment`; every `secrets[].valueFrom` is a full Secrets Manager or SSM ARN.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["ecs-fargate"],
}

_secret_name_pattern := `(?i)(^|_)(PASSWORD|PASSWD|SECRET|SECRET_KEY|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY(_ID)?|SECRET_ACCESS_KEY|CREDENTIALS?|AUTH_DATA)$`

# Values that are credentials whatever the variable is called: an AWS access
# key id, a PEM block, or a URL with a password in its authority.
_secret_value_patterns := [
	`^(AKIA|ASIA)[0-9A-Z]{16}$`,
	`-----BEGIN [A-Z ]*PRIVATE KEY-----`,
	`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`,
]

_secret_arn_pattern := `^arn:aws[a-z-]*:(secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:|ssm:[a-z0-9-]+:[0-9]{12}:parameter/).+`

deny contains msg if {
	some f in input.proposal.files
	_is_ecs_task_definition(f.path)
	some c in _ecs_containers(f.content)
	some e in object.get(c, "environment", [])
	_env_entry_is_secret(e)
	msg := {
		"rule_id": "practice.ecs_task_secrets_not_in_environment",
		"message": sprintf(
			"file %v: container %v has %v in plaintext `environment`; move it to `secrets` with a Secrets Manager or SSM ARN",
			[f.path, object.get(c, "name", "<unnamed>"), object.get(e, "name", "<unnamed>")],
		),
	}
}

deny contains msg if {
	some f in input.proposal.files
	_is_ecs_task_definition(f.path)
	some c in _ecs_containers(f.content)
	some s in object.get(c, "secrets", [])
	not _is_secret_arn(object.get(s, "valueFrom", ""))
	msg := {
		"rule_id": "practice.ecs_task_secrets_not_in_environment",
		"message": sprintf(
			"file %v: container %v secret %v must reference a full Secrets Manager or SSM Parameter Store ARN in `valueFrom`",
			[f.path, object.get(c, "name", "<unnamed>"), object.get(s, "name", "<unnamed>")],
		),
	}
}

_env_entry_is_secret(e) if {
	is_string(e.value)
	e.value != ""
	regex.match(_secret_name_pattern, e.name)
}

_env_entry_is_secret(e) if {
	is_string(e.value)
	some pattern in _secret_value_patterns
	regex.match(pattern, e.value)
}

_is_secret_arn(value) if {
	is_string(value)
	regex.match(_secret_arn_pattern, value)
}
