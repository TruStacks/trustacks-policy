# practice.workflow_has_lint_step — every CI workflow includes a lint or
# static-analysis step. Same shape as `workflow_has_test_step`, lint runners.

package proposal

import rego.v1

rule_metadata["practice.workflow_has_lint_step"] := {
	"description": "Every CI workflow declares a lint/static-analysis step (ruff / eslint / biome / golangci-lint / go vet / staticcheck / dotnet format / checkstyle / spotless / spotbugs / pmd / -Dlint).",
	"required_tooling_categories": [],
	"practice_dimensions": ["linting_in_ci"],
	"tier_scope": ["any"],
}

deny contains msg if {
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	not _workflow_has_step_matching(wf, _lint_runner_substrings)
	msg := {
		"rule_id": "practice.workflow_has_lint_step",
		"message": sprintf(
			"workflow %v has no lint/static-analysis step (looked for any of: ruff, eslint, biome, golangci-lint, go vet, staticcheck, dotnet format, checkstyle, spotless, spotbugs, pmd, -Dlint in `run:` commands)",
			[f.path],
		),
	}
}

# Industry-standard analysers, named rather than inferred from an invocation:
# spotless/spotbugs/pmd/checkstyle are the JVM equivalents of ruff and eslint,
# and `-dlint` catches the pack's `-Dlint=true` convention for a pom that gates
# its plugins on that property. Lowercase, like every needle — see
# `_workflow_has_step_matching` in lib.rego for the #551 history.
_lint_runner_substrings := [
	"ruff",
	"eslint",
	"biome",
	"golangci-lint",
	"go vet",
	"staticcheck",
	"dotnet format",
	"checkstyle",
	"spotless",
	"spotbugs",
	"pmd",
	"-dlint",
]
