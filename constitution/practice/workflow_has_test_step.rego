# practice.workflow_has_test_step — every CI workflow includes at least one
# job step whose `run:` command invokes a recognised test runner.

package proposal

import rego.v1

rule_metadata["practice.workflow_has_test_step"] := {
	"description": "Every CI workflow declares a step that runs the test suite (pytest / npm / yarn / pnpm / dotnet test / go test, or a Maven or Gradle test, verify or check).",
	"required_tooling_categories": [],
	"practice_dimensions": ["tests_in_ci"],
	"tier_scope": ["any"],
}

deny contains msg if {
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	# A deploy workflow (ADR-0062) applies an artifact; it has no suite to
	# run. The CI workflow beside it is still judged.
	not _is_deploy_workflow(wf)
	not _workflow_has_step_matching(wf, _test_runner_substrings)
	not _workflow_has_step_matching_re(wf, _jvm_test_pattern)
	msg := {
		"rule_id": "practice.workflow_has_test_step",
		"message": sprintf(
			"workflow %v has no step running the test suite (looked for pytest / npm test / yarn test / pnpm test / dotnet test / go test, or a Maven or Gradle invocation of `test`, `verify` or `check`, in `run:` commands)",
			[f.path],
		),
	}
}

# Lowercase, like every needle — see `_workflow_has_step_matching` in lib.rego.
_test_runner_substrings := ["pytest", "npm test", "yarn test", "pnpm test", "dotnet test", "go test"]

# JVM builds name a lifecycle phase or a task rather than a test runner, and
# flags sit between the tool and the goal — `mvn -B test`, `./gradlew test`,
# `mvn -B verify`. A substring list cannot express that without encoding one
# flag order, which is exactly how the dead needle (#551) came to exist.
#
# `\btest\b` deliberately does not match `-DskipTests`: that flag turns the
# test phase OFF, and counting it would be worse than missing it.
# Maven and Gradle are listed separately because their vocabularies differ:
# `verify` runs tests in Maven and `check` does in Gradle, while Maven's
# `check` is a plugin goal (`mvn checkstyle:check`) that runs no tests at all.
# One combined alternation accepted that as a test step — a false pass, which
# is the direction that matters most here.
#
# The goal must be a whole word at the end or followed by a space, so
# `-DskipTests` (which turns tests off) and `test-compile` (which does not run
# them) are both excluded.
_jvm_test_pattern := `(^|[\s;&|(])(mvn\s+([^;&|]*\s+)?(test|verify)|(\./)?gradlew?\s+([^;&|]*\s+)?(test|check|build))(\s|$)`
