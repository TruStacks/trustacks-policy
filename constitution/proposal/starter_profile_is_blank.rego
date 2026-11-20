# proposal.starter_profile_is_blank — a ci-only first run's starter
# `environment-profile.yaml` asserts nothing (ADR-0077 §10).
#
# When a ci-only repo has no Stack file, the runner proposes one instead of a
# pipeline (`starter_profile_run`). The file is something the customer will
# copy and keep, so every claim in it must be theirs to make: no tool category
# with an entry, no practice set, no other key carrying a value. Configuration
# (`schema_version`, `name`) is the only thing it may say. This is the CLAUDE.md
# rule "never pre-fill an attestation", held by the gate rather than by the
# runner's good behaviour, because a starter that pre-attests is scored as
# covered the moment it merges (#458).
#
# The starter proposal is that one file: a pipeline arrives on the next run,
# once the customer has filled the file in.

package proposal

import rego.v1

rule_metadata["proposal.starter_profile_is_blank"] := {
	"description": "A ci-only first run's starter environment-profile.yaml is the only file in its proposal and asserts nothing: no tool category entries, no practices, nothing but schema_version and name.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["ci-only"],
}

# Keys that configure the file rather than claim anything about the customer.
_starter_config_keys := {"schema_version", "name"}

_starter_files := [f | some f in input.proposal.files; f.path == stack_file]

deny contains msg if {
	starter_profile_run
	count(_starter_files) == 0
	msg := {
		"rule_id": "proposal.starter_profile_is_blank",
		"message": sprintf("a starter proposal must add %v", [stack_file]),
	}
}

deny contains msg if {
	starter_profile_run
	some f in input.proposal.files
	f.path != stack_file
	msg := {
		"rule_id": "proposal.starter_profile_is_blank",
		"message": sprintf("a starter proposal adds %v only; %v must wait for the next run", [stack_file, f.path]),
	}
}

deny contains msg if {
	starter_profile_run
	some f in _starter_files
	not _yaml_object(f.content)
	msg := {
		"rule_id": "proposal.starter_profile_is_blank",
		"message": sprintf("the starter %v must be a YAML mapping", [stack_file]),
	}
}

deny contains msg if {
	starter_profile_run
	some f in _starter_files
	_yaml_object(f.content)
	some key, value in yaml.unmarshal(f.content)
	not key in _starter_config_keys
	_asserts(value)
	msg := {
		"rule_id": "proposal.starter_profile_is_blank",
		"message": sprintf("the starter %v must leave %v blank: it is the customer's to fill in", [stack_file, key]),
	}
}

_yaml_object(content) if {
	yaml.is_valid(content)
	is_object(yaml.unmarshal(content))
}

# A value says something unless it is empty. `false` counts: "we do not do X"
# is as much the customer's statement as "we do".
_asserts(value) if {
	is_array(value)
	count(value) > 0
}

_asserts(value) if {
	is_object(value)
	count(value) > 0
}

_asserts(value) if is_boolean(value)

_asserts(value) if is_number(value)

_asserts(value) if {
	is_string(value)
	value != ""
}
