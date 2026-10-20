# practice.dockerfile_runs_as_nonroot — every Dockerfile declares a non-root
# USER. Reject any Dockerfile with no USER, or USER root / USER 0.

package proposal

import rego.v1

rule_metadata["practice.dockerfile_runs_as_nonroot"] := {
	"description": "Every Dockerfile in the proposal declares a USER directive other than root/0.",
	"required_tooling_categories": [],
	"practice_dimensions": ["non_root_containers"],
	"tier_scope": ["any"],
}

deny contains msg if {
	some f in input.proposal.files
	_is_dockerfile(f.path)
	not _dockerfile_runs_as_nonroot(f.content)
	msg := {
		"rule_id": "practice.dockerfile_runs_as_nonroot",
		"message": sprintf(
			"file %v: missing a non-root USER directive (declares no USER, or USER root / USER 0)",
			[f.path],
		),
	}
}

# A Dockerfile passes when the user its final image runs as is not root.
# That is the LAST `USER` in the FINAL stage, the lines after the last
# `FROM`: earlier stages only build, and a later `USER` overrides an earlier
# one. The user part (before any `:group`) must not be `root` or `0`.
#
# #696: this used to pass if *any* USER line anywhere was non-root, so
# `USER 1001` then `USER root`, `USER 0:0` and `USER root:root` all passed
# while the container ran as root. A final stage with no USER fails, because
# it runs as whatever the base image defaults to, which is usually root.
_dockerfile_runs_as_nonroot(content) if {
	user := _final_user(content)
	user != ""
	user != "root"
	user != "0"
}

_lines(content) := [trim_space(l) | some l in split(content, "\n")]

_final_stage_start(lines) := max(froms) if {
	froms := {i | some i; regex.match(`^(?i)from\s`, lines[i])}
	count(froms) > 0
} else := -1

_final_user(content) := user if {
	lines := _lines(content)
	start := _final_stage_start(lines)
	users := {i | some i; i > start; regex.match(`^(?i)user\s+\S`, lines[i])}
	count(users) > 0
	value := trim_space(regex.replace(lines[max(users)], `^(?i)user\s+`, ""))
	user := trim_space(split(value, ":")[0])
}
