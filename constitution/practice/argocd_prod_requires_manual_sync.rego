# practice.argocd_prod_requires_manual_sync — an ArgoCD Application that
# deploys to a prod-TIER cluster must NOT have automated sync.
#
# Prod is a tier, not a name. Applications declare
# `target_clusters: [{name, tier: dev|uat|prod}]` (slice 14.6), and the
# runner passes the cluster this proposal targets as
# `input.context.target_cluster` + `input.context.target_tier`. An
# Application file for that cluster lives at
# `argo-apps/argo-apps-<target_cluster>/<service>-application.yaml`, so a
# prod-tier cluster named `gke-us-east` is protected exactly like one named
# `prod`. Before this, the rule matched only the literal path
# `argo-apps/argo-apps-prod/` and a prod cluster with any other name got no
# manual-sync gate at all.
#
# The name-based check stays, unconditionally. It covers evaluations that
# carry no tier context — a Control Plane older than the field, the CLI,
# tests — and a cluster literally named `prod` is treated as prod whatever
# tier it was given: when name and tier disagree, the rule takes the
# stricter reading rather than letting automated sync through.
#
# The rule inspects an ArgoCD artifact but lives in `practice/`: its rule_id
# is `practice.*`, and the namespace — not the technology — names the
# directory.

package proposal

import rego.v1

rule_metadata["practice.argocd_prod_requires_manual_sync"] := {
	"description": "ArgoCD Applications deploying to a prod-tier cluster must opt out of automated sync (spec.syncPolicy.automated absent).",
	"required_tooling_categories": [],
	"practice_dimensions": ["manual_promotion_to_prod"],
	"tier_scope": ["prod"],
	"target_kinds": ["kubernetes"],
}

deny contains msg if {
	some f in input.proposal.files
	_targets_prod_cluster(f.path)
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

# Tier-keyed: the file sits under the directory of the cluster this proposal
# targets, and that cluster's tier is prod. Read through the `target_*` helpers
# (proposal/lib.rego), which prefer `input.context.target` and fall back to the
# flat keys a runner before ADR-0060 sends.
_targets_prod_cluster(path) if {
	target_kind == "kubernetes"
	target_tier == "prod"
	cluster := target_name
	is_string(cluster)
	cluster != ""
	startswith(path, sprintf("argo-apps/argo-apps-%v/", [cluster]))
}

# Name-keyed fallback: a cluster literally named `prod`. The only signal an
# evaluation without tier context has.
_targets_prod_cluster(path) if startswith(path, "argo-apps/argo-apps-prod/")
