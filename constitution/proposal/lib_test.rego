# Tests for the shared machinery in proposal/lib.rego: rule index, gap
# analysis and the customer-overlay aggregator.
#
# Every test file in the constitution shares `package proposal_test`, so the
# fixtures in proposal/fixtures_test.rego are visible here. Run the whole
# tree with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

# ---- rule_index ---------------------------------------------------------
# rule_index re-publishes rule_metadata so external consumers (the agent
# prompt, gap analysis) can enumerate rules without invoking deny.

test_rule_index_lists_all_constitution_rules if {
	idx := proposal.rule_index with input as good_input
	expected := {
		"proposal.allowed_paths",
		"proposal.no_path_traversal",
		"proposal.has_workflow",
		"proposal.has_helm_chart",
		"proposal.has_kustomization",
		"proposal.has_argocd_application",
		"argocd.repoURL_is_canonical",
		# Slice 14.5 practice rules.
		"practice.workflow_has_test_step",
		"practice.workflow_has_lint_step",
		"practice.argocd_prod_requires_manual_sync",
		"practice.dockerfile_runs_as_nonroot",
		"practice.workflow_pins_action_versions",
		# ADR-0050 decision 3 — posture rules. These score a tooling
		# category and carry no deny block; see `enforcement` below.
		"posture.image_scanning_declared",
		"posture.sast_sca_declared",
		"posture.secret_scanning_declared",
		"posture.sbom_signing_declared",
	}
	{rid | some rid, _ in idx} == expected
}

test_rule_index_carries_required_tooling_categories if {
	idx := proposal.rule_index with input as good_input
	# has_workflow → ci_cd_platform; has_argocd_application → gitops_controller.
	idx["proposal.has_workflow"].required_tooling_categories == ["ci_cd_platform"]
	idx["proposal.has_argocd_application"].required_tooling_categories == ["gitops_controller"]
	# rules with no tooling requirement carry an empty list.
	idx["proposal.allowed_paths"].required_tooling_categories == []
}

test_rule_index_carries_descriptions if {
	idx := proposal.rule_index with input as good_input
	some _, meta in idx
	count(meta.description) > 0
}

# ---- gap query ----------------------------------------------------------
# `gap` joins each rule's required_tooling_categories against the customer's
# data.env.tooling_categories and returns the unsatisfied (rule, category)
# pairs. Advisory only in 3b — does not block.

test_gap_empty_when_env_satisfies_all_required_categories if {
	count(proposal.gap) == 0 with data.env as complete_env
}

test_gap_lists_unsatisfied_categories if {
	missing_ci := object.union(complete_env, {"tooling_categories": object.union(
		complete_env.tooling_categories,
		{"ci_cd_platform": []},
	)})
	gaps := proposal.gap with data.env as missing_ci
	categories := {item.category | some item in gaps}
	# only ci_cd_platform should surface — gitops_controller is still satisfied.
	categories == {"ci_cd_platform"}
}

test_gap_attributes_each_unsatisfied_category_to_its_rule if {
	missing_gitops := object.union(complete_env, {"tooling_categories": object.union(
		complete_env.tooling_categories,
		{"gitops_controller": []},
	)})
	gaps := proposal.gap with data.env as missing_gitops
	some item in gaps
	item.rule_id == "proposal.has_argocd_application"
	item.category == "gitops_controller"
}

test_gap_returns_all_required_categories_when_env_is_absent if {
	# No `with data.env` → data.env undefined → every required category
	# counts as unsatisfied.
	#
	# This was two categories until ADR-0050 decision 3: ten of the twelve
	# were named by no rule at all, so a customer could declare eight
	# categories of real work and move their score by zero.
	gaps := proposal.gap
	categories := {item.category | some item in gaps}
	categories == {
		"ci_cd_platform",
		"gitops_controller",
		"image_scanning",
		"sast_sca",
		"secret_scanning",
		"sbom_signing",
	}
}

# ---- Overlay aggregator (Phase 4 slice 9a) -------------------------------

test_overlay_deny_merges_into_proposal_deny if {
	# Simulate a loaded overlay that fires a deny on the canonical
	# good_input. The aggregator should surface it under data.proposal.deny.
	fake_overlay := {"acme_demo": {"deny": [{
		"rule_id": "acme.demo",
		"message": "demo overlay rule fired",
	}]}}
	violations := proposal.deny with data.overlay as fake_overlay with input as good_input
	some v in violations
	v.rule_id == "acme.demo"
	v.message == "demo overlay rule fired"
}

test_overlay_no_deny_when_overlay_empty if {
	# Empty overlay set → aggregator contributes nothing; the canonical
	# good input should remain clean.
	violations := proposal.deny with data.overlay as {} with input as good_input
	count(violations) == 0
}

test_overlay_gap_merges_into_proposal_gap if {
	# An overlay rule that requires a category the customer hasn't
	# declared should appear in proposal.gap.
	fake_overlay := {"acme_demo": {"rule_metadata": {"acme.demo": {
		"description": "fake",
		"required_tooling_categories": ["image_scanning"],
	}}}}
	missing_scanner := object.union(complete_env, {"tooling_categories": object.union(
		complete_env.tooling_categories,
		{"image_scanning": []},
	)})
	gaps := proposal.gap with data.overlay as fake_overlay with data.env as missing_scanner
	some item in gaps
	item.rule_id == "acme.demo"
	item.category == "image_scanning"
}
