# proposal.has_kustomization — a kustomize Application ships a kustomization.
#
# Rule 3, kustomize half (ADR-0052). See `has_helm_chart.rego` for why the
# deploy-artifact rule is split by renderer.

package proposal

import rego.v1

rule_metadata["proposal.has_kustomization"] := {
	"description": "Proposal includes at least one kustomization.yaml under the gitops/ service root (kustomize renderer).",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["kubernetes"],
}

deny contains msg if {
	target_kind == "kubernetes"
	renderer == "kustomize"
	count([
	f |
		some f in input.proposal.files
		startswith(f.path, "gitops/")
		endswith(f.path, "/kustomization.yaml")
	]) == 0
	msg := {
		"rule_id": "proposal.has_kustomization",
		"message": "proposal must include at least one kustomization.yaml under gitops/",
	}
}
