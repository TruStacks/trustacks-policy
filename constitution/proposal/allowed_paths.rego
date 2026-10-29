# proposal.allowed_paths — every artifact path must live under the whitelist.
#
# Rule 1 of the original five (Phase 3a).
#
# ADR-0071: the pipeline location follows the proposal's CI runtime
# (`ci_runtime`): `.github/workflows/` for GitHub Actions, `azure-pipelines.yml`
# and `azure-pipelines/` for Azure Pipelines. A proposal for one runtime may not
# write the other's pipeline files.

package proposal

import rego.v1

rule_metadata["proposal.allowed_paths"] := {
	"description": "Every artifact path lives under gitops/, argo-apps/, or the CI runtime's pipeline location (.github/workflows/, or azure-pipelines.yml / azure-pipelines/).",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

_runtime_pipeline_prefixes := {
	"github_actions": [".github/workflows/"],
	"azure_pipelines": ["azure-pipelines/"],
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
