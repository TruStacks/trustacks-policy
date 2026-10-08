# proposal.has_workflow — at least one CI workflow.
#
# Rule 2 of the original five (Phase 3a).

package proposal

import rego.v1

rule_metadata["proposal.has_workflow"] := {
	"description": "Proposal includes at least one .github/workflows/*.yaml file.",
	"required_tooling_categories": ["ci_cd_platform"],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

deny contains msg if {
	count([f | some f in input.proposal.files; startswith(f.path, ".github/workflows/")]) == 0
	msg := {
		"rule_id": "proposal.has_workflow",
		"message": "proposal must include at least one .github/workflows/*.yaml file",
	}
}
