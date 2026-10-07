# Practice rules (slice 14.5) — shared helpers.
#
# These answer "are you using your tools correctly?" rather than "do you have
# the tools?" Each rule fires deny on a proposal when the emitted artifact
# violates the practice; each is also linked to a `practice_dimensions` key
# the customer self-attests to in EnvironmentProfile.practices, so the
# maturity scorer can blend practice posture into coverage_pct.
#
# One rule per file in this directory, every rule_id in the `practice.`
# namespace. This file holds no rule — only the matchers more than one of them
# use.

package proposal

import rego.v1

_is_workflow(path) if {
	startswith(path, ".github/workflows/")
	endswith(path, ".yaml")
}

_is_workflow(path) if {
	startswith(path, ".github/workflows/")
	endswith(path, ".yml")
}

_is_dockerfile(path) if endswith(path, "/Dockerfile")

_is_dockerfile(path) if path == "Dockerfile"

# Needles are matched against a LOWERCASED command, so they must be lowercase
# themselves. `mvn -B verify -Dlint` used to live in the lint list and could
# never match anything — the command was lowercased and the needle was not, so
# Java could not satisfy the rule no matter what the agent emitted (#551). The
# comparison lowercases both sides now, which makes that class of bug
# impossible rather than fixed once.
_workflow_has_step_matching(wf, needles) if {
	some _, job in wf.jobs
	some _, step in job.steps
	cmd := lower(step.run)
	some needle in needles
	contains(cmd, lower(needle))
}

_workflow_has_step_matching_re(wf, pattern) if {
	some _, job in wf.jobs
	some _, step in job.steps
	regex.match(pattern, lower(step.run))
}
