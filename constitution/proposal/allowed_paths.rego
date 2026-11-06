# proposal.allowed_paths — every artifact path must live under the whitelist.
#
# Rule 1 of the original five (Phase 3a).
#
# ADR-0071: the pipeline location follows the proposal's CI runtime
# (`ci_runtime`): `.github/workflows/` for GitHub Actions, `azure-pipelines.yml`
# and `azure-pipelines/` for Azure Pipelines, `.gitlab/ci/` for GitLab CI (never
# the platform repo's own root `.gitlab-ci.yml`). A proposal for one runtime may
# not write another's pipeline files.

package proposal

import rego.v1

rule_metadata["proposal.allowed_paths"] := {
	"description": "Every artifact path lives under gitops/, argo-apps/, or the CI runtime's pipeline location (.github/workflows/, azure-pipelines.yml / azure-pipelines/, or .gitlab/ci/). environment-profile.yaml only for a scoped fix declaring the tool the customer chose.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

_runtime_pipeline_prefixes := {
	"github_actions": [".github/workflows/"],
	"azure_pipelines": ["azure-pipelines/"],
	"gitlab_ci": [".gitlab/ci/"],
}

_runtime_pipeline_files := {"azure_pipelines": ["azure-pipelines.yml", "azure-pipelines.yaml"]}

allowed_prefixes := array.concat(
	["gitops/", "argo-apps/"],
	object.get(_runtime_pipeline_prefixes, ci_runtime, []),
)

is_allowed_path(path) if {
	some prefix in allowed_prefixes
	startswith(path, prefix)
}

is_allowed_path(path) if {
	some file in object.get(_runtime_pipeline_files, ci_runtime, [])
	path == file
}

# The Stack file, for one kind of proposal only: a scoped fix whose tool the
# customer chose in TruStacks, which declares that tool in the same PR that
# adds its step (2026-11-05). The runner authors that edit itself — never the
# agent — and refuses anything but the one addition; it says so here with
# `input.context.remediation.declares_profile`. Every other proposal is still
# denied for touching it: declaring a tool is the customer's statement, and only
# their explicit choice makes it one.
stack_file := "environment-profile.yaml"

is_allowed_path(path) if {
	path == stack_file
	input.context.remediation.declares_profile == true
}

# Fail closed on a CI runtime the constitution doesn't know: deny, naming it,
# rather than judge the proposal's pipeline paths as if it were GitHub Actions.
deny contains msg if {
	r := unsupported_ci_runtime
	msg := {
		"rule_id": "proposal.allowed_paths",
		"message": sprintf(
			"unsupported CI runtime %v; this policy judges %v",
			[r, sort([x | some x in supported_ci_runtimes])],
		),
	}
}

deny contains msg if {
	some f in input.proposal.files
	not is_allowed_path(f.path)
	msg := {
		"rule_id": "proposal.allowed_paths",
		"message": sprintf(
			"file %v is outside the allowed path whitelist (%v)",
			[f.path, allowed_prefixes],
		),
	}
}
