# practice.argocd_prod_requires_manual_sync — ArgoCD Applications under
# argo-apps/argo-apps-prod/ must NOT have automated sync.
#
# The rule inspects an ArgoCD artifact but lives in `practice/`: its rule_id
# is `practice.*`, and the namespace — not the technology — names the
# directory.

package proposal

import rego.v1

rule_metadata["practice.argocd_prod_requires_manual_sync"] := {
	"description": "ArgoCD Applications targeting prod must opt out of automated sync (spec.syncPolicy.automated absent).",
	"required_tooling_categories": [],
	"practice_dimensions": ["manual_promotion_to_prod"],
	"tier_scope": ["prod"],
}

deny contains msg if {
	some f in input.proposal.files
	startswith(f.path, "argo-apps/argo-apps-prod/")
	endswith(f.path, "-application.yaml")
	doc := yaml.unmarshal(f.content)
	doc.spec.syncPolicy.automated
	msg := {
		"rule_id": "practice.argocd_prod_requires_manual_sync",
		"message": sprintf(
			"file %v: prod ArgoCD Application has spec.syncPolicy.automated set; remove it so a human approves the sync",
			[f.path],
		),
	}
}
