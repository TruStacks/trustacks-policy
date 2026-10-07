# proposal.has_argocd_application — at least one ArgoCD Application under
# argo-apps/argo-apps-<cluster>/.
#
# Rule 4 of the original five (Phase 3a).

package proposal

import rego.v1

rule_metadata["proposal.has_argocd_application"] := {
	"description": "Proposal includes at least one argo-apps/argo-apps-<cluster>/<svc>-application.yaml.",
	"required_tooling_categories": ["gitops_controller"],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

deny contains msg if {
	count([
	f |
		some f in input.proposal.files
		startswith(f.path, "argo-apps/argo-apps-")
		endswith(f.path, "-application.yaml")
	]) == 0
	msg := {
		"rule_id": "proposal.has_argocd_application",
		"message": "proposal must include at least one argo-apps/argo-apps-<cluster>/<svc>-application.yaml",
	}
}
