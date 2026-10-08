# Table-driven tests for the `proposal.*` rules.
#
# Every test file in the constitution shares `package proposal_test`, so the
# fixtures in proposal/fixtures_test.rego are visible here. Run the whole
# tree with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

# ---- allow path ----------------------------------------------------------

test_allow_when_canonical_proposal if {
	count(proposal.deny) == 0 with input as good_input
}

# ---- rule 1: allowed_paths -----------------------------------------------

test_deny_when_artifact_path_outside_whitelist if {
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		good_input.proposal.files[2],
		{"path": "scripts/evil.sh", "content": "rm -rf /\n"},
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "proposal.allowed_paths"
}

# ---- rule 2: has_workflow ------------------------------------------------

test_deny_when_no_workflow if {
	without_workflow := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as without_workflow
	some v in violations
	v.rule_id == "proposal.has_workflow"
}

# ---- rule 3: has_helm_chart ----------------------------------------------

test_deny_when_no_chart if {
	without_chart := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as without_chart
	some v in violations
	v.rule_id == "proposal.has_helm_chart"
}

# ---- rule 3b: has_kustomization, and the pair that selects between them ---
#
# ADR-0052. The important property is not that each rule fires — it is that
# picking a renderer cannot pick a weaker gate, and that the gate never demands
# the artifact the Application did not ask for.

test_kustomize_proposal_is_not_denied_for_lacking_a_chart if {
	kustomize_files := [
		good_input.proposal.files[0],
		{"path": "gitops/checkout/api/base/kustomization.yaml", "content": "resources: []"},
		good_input.proposal.files[2],
	]
	kustomize_input := object.union(good_input, {
		"proposal": object.union(good_input.proposal, {"files": kustomize_files}),
		"context": {"platform_repo_url": PLATFORM_URL, "renderer": "kustomize"},
	})
	violations := proposal.deny with input as kustomize_input
	rule_ids := {v.rule_id | some v in violations}
	not "proposal.has_helm_chart" in rule_ids
	not "proposal.has_kustomization" in rule_ids
}

test_deny_when_kustomize_proposal_has_no_kustomization if {
	no_kustomization := object.union(good_input, {
		"context": {"platform_repo_url": PLATFORM_URL, "renderer": "kustomize"},
	})
	violations := proposal.deny with input as no_kustomization
	some v in violations
	v.rule_id == "proposal.has_kustomization"
}

test_a_chart_does_not_satisfy_a_kustomize_application if {
	# The bug this whole slice exists to close: a customer picks kustomize and
	# receives a Helm chart. The chart must not buy its way past the gate.
	chart_under_kustomize := object.union(good_input, {
		"context": {"platform_repo_url": PLATFORM_URL, "renderer": "kustomize"},
	})
	violations := proposal.deny with input as chart_under_kustomize
	rule_ids := {v.rule_id | some v in violations}
	"proposal.has_kustomization" in rule_ids
}

test_helm_is_assumed_when_no_renderer_is_supplied if {
	# An older runner sends no renderer, and must be judged exactly as before.
	without_chart := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as without_chart
	some v in violations
	v.rule_id == "proposal.has_helm_chart"
}

test_a_kustomization_does_not_satisfy_a_helm_application if {
	# The mirror image, and the reason both rules exist rather than one relaxed
	# rule accepting either artifact: a renderer must not be a way to pick a
	# weaker gate.
	kustomize_files := [
		good_input.proposal.files[0],
		{"path": "gitops/checkout/api/base/kustomization.yaml", "content": "resources: []"},
		good_input.proposal.files[2],
	]
	helm_app := object.union(good_input, {
		"proposal": object.union(good_input.proposal, {"files": kustomize_files}),
		"context": {"platform_repo_url": PLATFORM_URL, "renderer": "helm"},
	})
	violations := proposal.deny with input as helm_app
	some v in violations
	v.rule_id == "proposal.has_helm_chart"
}

# ---- rule 4: has_argocd_application --------------------------------------

test_deny_when_no_argocd_application if {
	without_app := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
	]})})
	violations := proposal.deny with input as without_app
	some v in violations
	v.rule_id == "proposal.has_argocd_application"
}

# ---- rule 1b: no_path_traversal -----------------------------------------

test_deny_when_artifact_path_is_absolute if {
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		good_input.proposal.files[2],
		{"path": "/etc/passwd", "content": "x\n"},
	]})})
	violations := proposal.deny with input as bad
	rule_ids := {v.rule_id | some v in violations}
	# Both rules fire: allowed_paths AND no_path_traversal.
	"proposal.no_path_traversal" in rule_ids
}

test_deny_when_artifact_path_has_parent_segment if {
	# `gitops/../../../etc/passwd` PASSES allowed_paths (starts with gitops/)
	# but MUST be caught by no_path_traversal.
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		good_input.proposal.files[2],
		{"path": "gitops/../../../etc/passwd", "content": "x\n"},
	]})})
	violations := proposal.deny with input as bad
	rule_ids := {v.rule_id | some v in violations}
	"proposal.no_path_traversal" in rule_ids
}

test_no_path_traversal_does_not_fire_for_clean_paths if {
	# Sanity: the canonical good_input must NOT trigger no_path_traversal.
	violations := proposal.deny with input as good_input
	rule_ids := {v.rule_id | some v in violations}
	not "proposal.no_path_traversal" in rule_ids
}

# ---- combined: a maximally bad proposal triggers multiple rules ---------

test_multiple_rules_can_fire_at_once if {
	really_bad := {
		"proposal": {"files": [
			{"path": "Makefile", "content": "all:\n"},
			{"path": "argo-apps/argo-apps-local-k3d/demo-application.yaml", "content": "spec:\n  source:\n    repoURL: not-the-canonical-one\n"},
		]},
		"context": {"platform_repo_url": PLATFORM_URL},
	}
	violations := proposal.deny with input as really_bad
	rule_ids := {v.rule_id | some v in violations}
	# allowed_paths (Makefile), has_workflow, has_helm_chart, repoURL_is_canonical
	count(rule_ids) >= 4
}
