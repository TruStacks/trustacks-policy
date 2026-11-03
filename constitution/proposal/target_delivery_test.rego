# Tests for the target_delivery helper and the ArgoCD rules' delivery gate
# (ADR-0069). Run with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

test_target_delivery_defaults_to_gitops_without_context if {
	proposal.target_delivery == "gitops" with input as {"proposal": {"files": []}}
}

test_target_delivery_defaults_to_gitops_when_target_has_none if {
	proposal.target_delivery == "gitops" with input as {
		"proposal": {"files": []},
		"context": {"target": {"name": "gke", "tier": "prod", "kind": "kubernetes"}},
	}
}

test_target_delivery_reads_push if {
	proposal.target_delivery == "push" with input as {
		"proposal": {"files": []},
		"context": {"target": {"name": "gke", "kind": "kubernetes", "delivery": "push"}},
	}
}

test_target_delivery_ignores_an_empty_value if {
	proposal.target_delivery == "gitops" with input as {
		"proposal": {"files": []},
		"context": {"target": {"delivery": ""}},
	}
}

test_has_argocd_application_still_required_for_gitops if {
	denies := {d |
		some d in proposal.deny
		d.rule_id == "proposal.has_argocd_application"
	}
		with input as {
			"proposal": {"files": []},
			"context": {"target": {"name": "gke", "kind": "kubernetes", "delivery": "gitops"}},
		}
	count(denies) == 1
}

test_has_argocd_application_still_required_without_delivery if {
	denies := {d |
		some d in proposal.deny
		d.rule_id == "proposal.has_argocd_application"
	}
		with input as {
			"proposal": {"files": []},
			"context": {"target": {"name": "gke", "kind": "kubernetes"}},
		}
	count(denies) == 1
}

test_has_argocd_application_off_for_push if {
	denies := {d |
		some d in proposal.deny
		d.rule_id == "proposal.has_argocd_application"
	}
		with input as {
			"proposal": {"files": []},
			"context": {"target": {"name": "gke", "kind": "kubernetes", "delivery": "push"}},
		}
	count(denies) == 0
}

test_argocd_rules_declare_gitops_delivery if {
	proposal.rule_metadata["proposal.has_argocd_application"].deliveries == ["gitops"]
	proposal.rule_metadata["practice.argocd_prod_requires_manual_sync"].deliveries == ["gitops"]
}

# The manual-sync rule's body is not delivery-gated: an automated prod
# Application in a push proposal is still refused.
test_manual_sync_still_fires_on_a_push_target if {
	app := "apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  syncPolicy:\n    automated: {}\n"
	denies := {d |
		some d in proposal.deny
		d.rule_id == "practice.argocd_prod_requires_manual_sync"
	}
		with input as {
			"proposal": {"files": [{"path": "argo-apps/argo-apps-gke/web-application.yaml", "content": app}]},
			"context": {"target": {"name": "gke", "tier": "prod", "kind": "kubernetes", "delivery": "push"}},
		}
	count(denies) == 1
}
