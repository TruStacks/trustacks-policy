# Tests for the overlay aggregator's scope filter in proposal/lib.rego
# (ADR-0065 §1): an overlay rule's denies count only when the proposal's
# target is inside the `tier_scope` and `target_kinds` the rule declares.
#
# Every fixture overlay here denies unconditionally, so whether its deny
# reaches `data.proposal.deny` is decided by the scope filter alone.

package proposal_test

import data.proposal
import rego.v1

# An overlay with one rule `acme.scoped` whose metadata is `meta` and whose
# deny always fires.
_scoped_overlay(meta) := {"acme_scoped": {
	"rule_metadata": {"acme.scoped": meta},
	"deny": [{"rule_id": "acme.scoped", "message": "acme.scoped fired"}],
}}

_with_target(target) := object.union(good_input, {"context": object.union(
	good_input.context,
	{"target": target},
)})

_repo_audit_input := object.union(good_input, {"context": object.union(
	good_input.context,
	{"subject": "repo"},
)})

_fires(overlay, inp) if {
	some v in proposal.deny with data.overlay as overlay with input as inp
	v.rule_id == "acme.scoped"
}

_prod_only := _scoped_overlay({
	"description": "prod only",
	"tier_scope": ["prod"],
	"target_kinds": ["any"],
})

_k8s_only := _scoped_overlay({
	"description": "kubernetes only",
	"tier_scope": ["any"],
	"target_kinds": ["kubernetes"],
})

_anywhere := _scoped_overlay({
	"description": "anywhere",
	"tier_scope": ["any"],
	"target_kinds": ["any"],
})

_legacy := _scoped_overlay({"description": "declares neither field"})

# ---- tier_scope ----------------------------------------------------------

test_prod_only_rule_denies_prod_proposal if {
	_fires(_prod_only, _with_target({"name": "prod-east", "tier": "prod", "kind": "kubernetes"}))
}

test_prod_only_rule_skips_dev_proposal if {
	not _fires(_prod_only, _with_target({"name": "dev-east", "tier": "dev", "kind": "kubernetes"}))
}

test_prod_only_rule_reads_deprecated_flat_tier if {
	inp := object.union(good_input, {"context": object.union(
		good_input.context,
		{"target_cluster": "prod-east", "target_tier": "prod"},
	)})
	_fires(_prod_only, inp)
}

test_tier_scoped_rule_skipped_without_a_tier if {
	# Nothing says this proposal deploys to prod, so a prod rule can't be
	# shown to apply.
	not _fires(_prod_only, good_input)
}

test_multi_tier_scope_matches_any_listed_tier if {
	o := _scoped_overlay({"description": "x", "tier_scope": ["uat", "prod"], "target_kinds": ["any"]})
	_fires(o, _with_target({"name": "u", "tier": "uat"}))
	not _fires(o, _with_target({"name": "d", "tier": "dev"}))
}

# ---- target_kinds --------------------------------------------------------

test_kubernetes_only_rule_skipped_on_ecs if {
	not _fires(_k8s_only, _with_target({"name": "svc", "tier": "prod", "kind": "ecs-fargate"}))
}

test_kubernetes_only_rule_denies_kubernetes if {
	_fires(_k8s_only, _with_target({"name": "c", "tier": "dev", "kind": "kubernetes"}))
}

test_kubernetes_only_rule_applies_when_kind_absent if {
	# Absent kind means kubernetes, as it does for every constitution rule.
	_fires(_k8s_only, good_input)
}

test_ecs_kind_spelled_with_underscore_matches if {
	o := _scoped_overlay({"description": "x", "tier_scope": ["any"], "target_kinds": ["ecs_fargate"]})
	_fires(o, _with_target({"name": "svc", "kind": "ecs-fargate"}))
	not _fires(o, _with_target({"name": "c", "kind": "kubernetes"}))
}

test_both_axes_must_match if {
	o := _scoped_overlay({"description": "x", "tier_scope": ["prod"], "target_kinds": ["kubernetes"]})
	_fires(o, _with_target({"name": "p", "tier": "prod", "kind": "kubernetes"}))
	not _fires(o, _with_target({"name": "p", "tier": "prod", "kind": "ecs-fargate"}))
	not _fires(o, _with_target({"name": "d", "tier": "dev", "kind": "kubernetes"}))
}

# ---- never silently narrowed ---------------------------------------------

test_legacy_rule_without_scope_fields_denies_everywhere if {
	_fires(_legacy, good_input)
	_fires(_legacy, _with_target({"name": "d", "tier": "dev", "kind": "kubernetes"}))
	_fires(_legacy, _with_target({"name": "s", "tier": "prod", "kind": "ecs-fargate"}))
	_fires(_legacy, _repo_audit_input)
}

test_rule_without_metadata_denies_everywhere if {
	o := {"acme_bare": {"deny": [{"rule_id": "acme.scoped", "message": "fired"}]}}
	_fires(o, _with_target({"name": "d", "tier": "dev", "kind": "ecs-fargate"}))
}

test_deny_naming_another_rule_id_is_not_narrowed if {
	# The deny's rule_id has no metadata in its package, so no scope applies.
	o := {"acme_scoped": {
		"rule_metadata": {"acme.other": {"description": "x", "tier_scope": ["prod"], "target_kinds": ["any"]}},
		"deny": [{"rule_id": "acme.scoped", "message": "fired"}],
	}}
	_fires(o, _with_target({"name": "d", "tier": "dev"}))
}

test_any_scope_denies_everywhere if {
	_fires(_anywhere, good_input)
	_fires(_anywhere, _with_target({"name": "d", "tier": "dev", "kind": "ecs-fargate"}))
}

test_invalid_tier_scope_is_treated_as_any if {
	every scope in [["staging"], [], "prod", ["any", "prod"], ["prod", "staging"], [1]] {
		o := _scoped_overlay({"description": "x", "tier_scope": scope, "target_kinds": ["any"]})
		_fires(o, _with_target({"name": "d", "tier": "dev"}))
	}
}

test_invalid_target_kinds_is_treated_as_any if {
	every kinds in [["kubernets"], [], "kubernetes", ["any", "kubernetes"], [""], [7]] {
		o := _scoped_overlay({"description": "x", "tier_scope": ["any"], "target_kinds": kinds})
		_fires(o, _with_target({"name": "s", "tier": "dev", "kind": "ecs-fargate"}))
	}
}

# ---- repo audit (ADR-0067) -----------------------------------------------

test_repo_audit_applies_any_scoped_rule if {
	_fires(_anywhere, _repo_audit_input)
}

test_repo_audit_skips_tier_scoped_rule if {
	not _fires(_prod_only, _repo_audit_input)
}

test_repo_audit_skips_kind_scoped_rule if {
	# Without the repo-audit check this would fire: absent kind reads as
	# kubernetes. A repo is not a deployment target.
	not _fires(_k8s_only, _repo_audit_input)
}

# ---- scoped fixes (#844) -------------------------------------------------

_remediation_input(tier) := object.union(good_input, {"context": object.union(
	good_input.context,
	{
		"target": {"name": "c", "tier": tier, "kind": "kubernetes"},
		"remediation": {"declares_profile": true, "category": "sast", "tool": "semgrep"},
	},
)})

test_remediation_context_neither_widens_nor_narrows_scope if {
	# The Stack-file exception is for allowed_paths only: a scoped fix is
	# judged by an overlay rule's scope exactly like any other proposal.
	_fires(_prod_only, _remediation_input("prod"))
	not _fires(_prod_only, _remediation_input("dev"))
	_fires(_anywhere, _remediation_input("dev"))
}

# ---- scope filters overlays only -----------------------------------------

test_scope_filter_leaves_other_overlay_rules_alone if {
	o := object.union(_prod_only, {"acme_any": {
		"rule_metadata": {"acme.any": {"description": "x", "tier_scope": ["any"], "target_kinds": ["any"]}},
		"deny": [{"rule_id": "acme.any", "message": "acme.any fired"}],
	}})
	violations := proposal.deny with data.overlay as o with input as _with_target({"name": "d", "tier": "dev"})
	ids := {v.rule_id | some v in violations}
	ids == {"acme.any"}
}
