# proposal.has_helm_chart — a helm Application ships a chart.
#
# Rule 3, helm half. ADR-0052: until then this rule asked one question — "is
# there a Chart.yaml?" — and a correct Kustomize proposal has none. So the gate
# would have DENIED the right artifact and ALLOWED the wrong one, which is the
# worst direction for a rule to be wrong in: the customer picks kustomize,
# receives a chart, and the constitution confirms it.
#
# Now the rule reads the Application's renderer (see `renderer` in lib.rego)
# and fires only for helm; `has_kustomization` is the kustomize half.

package proposal

import rego.v1

rule_metadata["proposal.has_helm_chart"] := {
	"description": "Proposal includes at least one Chart.yaml under the gitops/ service root (helm renderer).",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"target_kinds": ["kubernetes"],
}

# Kubernetes only (ADR-0062): a non-Kubernetes target has no renderer, whatever
# the Application's stored `renderer` field says.
deny contains msg if {
	target_kind == "kubernetes"
	renderer == "helm"
	count([
	f |
		some f in input.proposal.files
		startswith(f.path, "gitops/")
		endswith(f.path, "/Chart.yaml")
	]) == 0
	msg := {
		"rule_id": "proposal.has_helm_chart",
		"message": "proposal must include at least one Chart.yaml under gitops/",
	}
}
