# proposal.has_workflow — at least one CI workflow.
#
# Rule 2 of the original five (Phase 3a).
#
# ADR-0071: "a CI workflow" means the runtime the proposal is for
# (`ci_runtime`, GitHub Actions unless the runner says otherwise): a file under
# `.github/workflows/`, or for Azure Pipelines `azure-pipelines.yml` or a file
# under `azure-pipelines/`.

package proposal

import rego.v1

rule_metadata["proposal.has_workflow"] := {
	"description": "Proposal includes at least one CI pipeline file for its CI runtime (.github/workflows/*.yaml, or azure-pipelines.yml / azure-pipelines/*.yml).",
	"required_tooling_categories": ["ci_cd_platform"],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

deny contains msg if {
	ci_runtime == "github_actions"
	count([f | some f in input.proposal.files; startswith(f.path, ".github/workflows/")]) == 0
	msg := {
		"rule_id": "proposal.has_workflow",
		"message": "proposal must include at least one .github/workflows/*.yaml file",
	}
}

deny contains msg if {
	ci_runtime == "azure_pipelines"
	count([f | some f in input.proposal.files; _is_azure_pipeline_path(f.path)]) == 0
	msg := {
		"rule_id": "proposal.has_workflow",
		"message": "proposal must include at least one Azure Pipelines file (azure-pipelines.yml, or a file under azure-pipelines/)",
	}
}
