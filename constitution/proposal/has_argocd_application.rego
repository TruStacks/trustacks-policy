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
	"target_kinds": ["kubernetes"],
	"deliveries": ["gitops"],
}

# Kubernetes only (ADR-0062): an ECS Fargate target has no ArgoCD. Nor does a
# Kubernetes target whose CI applies the manifests (ADR-0069, delivery: push).
deny contains msg if {
	target_kind == "kubernetes"
	target_delivery == "gitops"
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
