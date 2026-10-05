# Table-driven tests for proposal.rego.
#
# Run with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

PLATFORM_URL := "https://example.invalid/acme/platform.git"

# A canonical "good" proposal — passes all five rules. Phase 4 layout:
# gitops/<app>/<cluster>/<svc>/Chart.yaml + argo-apps/argo-apps-<cluster>/<svc>-application.yaml.
# Slice 14.5 — the workflow now includes practice-satisfying steps
# (test + lint) and pinned action versions so the canonical proposal
# also passes the new practice rules. The cluster suffix stays
# `local-k3d` (non-prod) so the prod-manual-sync practice rule
# doesn't fire either.
good_workflow_content := concat("\n", [
	"name: ci",
	"on: [push]",
	"jobs:",
	"  test:",
	"    runs-on: ubuntu-latest",
	"    steps:",
	"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
	"      - run: ruff check .",
	"      - run: pytest -q",
	"",
])

good_input := {
	"proposal": {
		"files": [
			{
				"path": ".github/workflows/ci.yaml",
				"content": good_workflow_content,
			},
			{
				"path": "gitops/checkout/local-k3d/demo/Chart.yaml",
				"content": "name: demo\nversion: 0.1.0\n",
			},
			{
				"path": "argo-apps/argo-apps-local-k3d/demo-application.yaml",
				"content": sprintf(
					"apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  source:\n    repoURL: %v\n",
					[PLATFORM_URL],
				),
			},
		],
	},
	"context": {"platform_repo_url": PLATFORM_URL},
}

# A canonical "complete" EnvironmentProfile data set — every category has
# at least one entry. Tests that need a happy `data.env` substitute this
# whole map via `with data.env as ...`.
complete_env := {"tooling_categories": {
	"ci_cd_platform": ["github_actions"],
	"container_registry": ["ghcr"],
	"image_scanning": ["trivy"],
	"sast_sca": ["semgrep"],
	"secret_scanning": ["gitleaks"],
	"sbom_signing": ["cosign"],
	"gitops_controller": ["argocd"],
	"service_mesh_ingress": ["traefik"],
	"secrets_management": ["external_secrets_operator"],
	"observability": ["prometheus_grafana"],
	"ticketing_change_mgmt": ["jira"],
	"compliance_evidence": ["drata"],
}}

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

# ---- rule 5: repoURL_is_canonical ---------------------------------------

test_deny_when_argocd_repoURL_is_placeholder if {
	bad_repo := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		{
			"path": "argo-apps/argo-apps-local-k3d/demo-application.yaml",
			"content": "apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  source:\n    repoURL: https://github.com/your-org/your-platform-repo.git\n",
		},
	]})})
	violations := proposal.deny with input as bad_repo
	some v in violations
	v.rule_id == "argocd.repoURL_is_canonical"
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

# ---- Gate vs posture (ADR-0050 decision 3) -------------------------------
# A posture rule scores a category and never blocks a proposal. The
# distinction has to be readable from the metadata, because the rules
# inventory shows both to customers and "rule" must not mean two things.

test_posture_rules_are_marked_as_posture if {
	every rid in [
		"posture.image_scanning_declared",
		"posture.sast_sca_declared",
		"posture.secret_scanning_declared",
		"posture.sbom_signing_declared",
	] {
		proposal.rule_enforcement(rid) == "posture"
	}
}

test_gate_rules_default_to_gate if {
	# Absence of the field means gate, so a new gate rule cannot inherit
	# "posture" by forgetting to say so.
	proposal.rule_enforcement("proposal.has_workflow") == "gate"
	proposal.rule_enforcement("practice.dockerfile_runs_as_nonroot") == "gate"
}

test_posture_rules_never_deny if {
	# The whole reason they carry no deny block: a deny here would reject
	# every proposal whose pipeline has no image scan — including every
	# proposal our own DevOps Engineer emits.
	#
	# Deliberately run against an input that DOES deny. Asserted over
	# `good_input` this passes on an empty deny set, which is the state it
	# is supposed to be ruling out — a test that holds because nothing
	# happened proves nothing about what happens.
	violations := proposal.deny with input as empty_proposal_input
	fired := {v.rule_id | some v in violations}

	# The premise: this input really does fire gate rules.
	count(fired) > 0

	# The claim: not one of them is a posture rule.
	every rid in fired {
		proposal.rule_enforcement(rid) == "gate"
	}
}

# A proposal declaring no image scanner, no SAST, no secret scanning and no
# SBOM — every condition the four posture rules describe. If any of them could
# deny, this is the input that would prove it.
empty_proposal_input := {
	"proposal": {"files": [], "explanation": {}},
	"context": {"platform_repo_url": "https://example.com/platform.git"},
}

test_posture_categories_still_surface_as_gaps if {
	# The other half of "posture": it does not deny, but it must still be
	# reportable, or the rule is inert rather than advisory.
	gaps := proposal.gap with data.env as {"tooling_categories": {
		"ci_cd_platform": ["github_actions"],
		"gitops_controller": ["argocd"],
	}}
	categories := {item.category | some item in gaps}
	categories == {"image_scanning", "sast_sca", "secret_scanning", "sbom_signing"}
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

# ---- Slice 14.5 practice rules -------------------------------------------

test_practice_workflow_has_test_step_denies_workflow_with_no_test_command if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  build:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - run: ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_has_test_step"
}

test_practice_workflow_has_lint_step_denies_workflow_with_no_lint_command if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - run: pytest -q",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_has_lint_step"
}

# Surfaced live 2026-05-06 walking the deploy loop end-to-end:
# the Go framework pack canonically emits `go vet ./...` as its
# static-analysis step, but the rule's substring list didn't accept
# it. Same shape would block .NET (`dotnet format`) once it lands a
# real lint step. Pin the accepted Go substrings here so the
# constitution-vs-pack alignment can't silently regress.
test_practice_workflow_has_lint_step_accepts_go_vet if {
	go_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5",
		"      - run: go vet ./...",
		"      - run: go test -race ./...",
		"",
	])
	candidate := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": go_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as candidate
	not _has_rule(violations, "practice.workflow_has_lint_step")
}

test_practice_workflow_has_lint_step_accepts_staticcheck if {
	go_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5",
		"      - run: go install honnef.co/go/tools/cmd/staticcheck@latest && staticcheck ./...",
		"      - run: go test ./...",
		"",
	])
	candidate := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": go_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as candidate
	not _has_rule(violations, "practice.workflow_has_lint_step")
}

_has_rule(violations, rule_id) if {
	some v in violations
	v.rule_id == rule_id
}

test_practice_argocd_prod_requires_manual_sync_denies_automated_sync if {
	prod_app_content := concat("\n", [
		"apiVersion: argoproj.io/v1alpha1",
		"kind: Application",
		"spec:",
		"  syncPolicy:",
		"    automated:",
		"      prune: true",
		sprintf("  source:\n    repoURL: %v", [PLATFORM_URL]),
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		{
			"path": "argo-apps/argo-apps-prod/demo-application.yaml",
			"content": prod_app_content,
		},
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.argocd_prod_requires_manual_sync"
}

test_practice_argocd_prod_only_fires_on_prod_path if {
	# Same automated-sync content but on a non-prod cluster path —
	# the rule should NOT fire (tier_scope is ["prod"]).
	dev_app_content := concat("\n", [
		"apiVersion: argoproj.io/v1alpha1",
		"kind: Application",
		"spec:",
		"  syncPolicy:",
		"    automated:",
		"      prune: true",
		sprintf("  source:\n    repoURL: %v", [PLATFORM_URL]),
		"",
	])
	dev_input := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		{
			"path": "argo-apps/argo-apps-local-k3d/demo-application.yaml",
			"content": dev_app_content,
		},
	]})})
	violations := proposal.deny with input as dev_input
	# practice.argocd_prod_requires_manual_sync should NOT appear among
	# the rule_ids — automated sync is fine on non-prod clusters.
	rule_ids := {v.rule_id | some v in violations}
	not "practice.argocd_prod_requires_manual_sync" in rule_ids
}

test_practice_dockerfile_runs_as_nonroot_denies_root_user if {
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		good_input.proposal.files[2],
		{
			"path": "gitops/checkout/local-k3d/demo/Dockerfile",
			"content": "FROM alpine:3\nUSER root\nCMD ['/bin/sh']\n",
		},
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.dockerfile_runs_as_nonroot"
}

test_practice_dockerfile_passes_with_nonroot_user if {
	good := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		good_input.proposal.files[2],
		{
			"path": "gitops/checkout/local-k3d/demo/Dockerfile",
			"content": "FROM alpine:3\nUSER 1001\nCMD ['/bin/sh']\n",
		},
	]})})
	violations := proposal.deny with input as good
	rule_ids := {v.rule_id | some v in violations}
	not "practice.dockerfile_runs_as_nonroot" in rule_ids
}

test_practice_workflow_pins_action_versions_denies_unpinned_third_party if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: docker/build-push-action@v5", # third-party + tag, not SHA
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	# Tag-shaped ref (`v5`) gets the original "should pin to a SHA, not a tag" message.
	contains(v.message, "should pin to a SHA, not a tag")
}

# Slice 20a.1 — agents that hallucinate a 39-char "SHA" get a more
# diagnostic message that names the length defect, not "use a SHA"
# (which is misleading when they were trying to).
test_practice_workflow_pins_action_versions_diagnoses_near_sha if {
	near_sha := "f325610c9f50a54015d37c8d16cb3b0e2c8f4de" # 39 chars — one short
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		sprintf("      - uses: anchore/sbom-action@%s", [near_sha]),
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	# Diagnostic message names the length defect.
	contains(v.message, "not exactly 40 characters")
	contains(v.message, "got 39")
}

# A 41-char hex string also lands in the near-SHA bucket.
test_practice_workflow_pins_action_versions_diagnoses_too_long_near_sha if {
	too_long := "f325610c9f50a54015d37c8d16cb3b0e2c8f4dee1" # 41 chars
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		sprintf("      - uses: anchore/sbom-action@%s", [too_long]),
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "got 41")
}

# A short 7-char hex (git's default short-SHA length) also classifies
# as near-SHA. Some agents emit truncated SHAs from training data.
test_practice_workflow_pins_action_versions_diagnoses_short_hex if {
	short := "deadbee" # 7 chars hex
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		sprintf("      - uses: anchore/sbom-action@%s", [short]),
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "not exactly 40 characters")
}

# A real semver tag (`v1.2.3`) is NOT hex — falls into the tag bucket
# and gets the original message.
test_practice_workflow_pins_action_versions_real_tag_gets_tag_message if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: anchore/sbom-action@v0.20.5",
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "should pin to a SHA, not a tag")
	# AND the diagnostic-message branch should NOT also fire for the same ref.
	count([violation |
		some violation in violations
		violation.rule_id == "practice.workflow_pins_action_versions"
	]) == 1
}

# Branch-name-shaped refs (`main`) classify as tag too.
test_practice_workflow_pins_action_versions_branch_name_gets_tag_message if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: anchore/sbom-action@main",
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "should pin to a SHA, not a tag")
}
