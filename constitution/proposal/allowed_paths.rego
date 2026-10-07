# proposal.allowed_paths — every artifact path must live under the whitelist.
#
# Rule 1 of the original five (Phase 3a).

package proposal

import rego.v1

rule_metadata["proposal.allowed_paths"] := {
	"description": "Every artifact path lives under gitops/, argo-apps/, or .github/workflows/.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

allowed_prefixes := ["gitops/", "argo-apps/", ".github/workflows/"]

is_allowed_path(path) if {
	some prefix in allowed_prefixes
	startswith(path, prefix)
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
