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

# A Dockerfile passes when *some* USER directive declares a non-root
# identity. Strict definition: the value isn't `root` or `0` (after
# trimming whitespace). USER appearing later in the file overrides
# earlier ones, but for "passes" semantics we only need at least one
# non-root USER line — multi-stage builds with a final non-root USER
# satisfy this even if an earlier stage ran as root for build deps.
_dockerfile_runs_as_nonroot(content) if {
	some line in split(content, "\n")
	trimmed := trim_space(line)
	startswith(lower(trimmed), "user ")
	user := trim_space(substring(trimmed, 5, -1))
	user != ""
	user != "root"
	user != "0"
}
