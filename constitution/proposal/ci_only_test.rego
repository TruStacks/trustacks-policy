# Tests for the ci-only target kind (ADR-0077 §9) and its first-run blank
# starter (§10). Run with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

_ci_target := {"name": "ci", "tier": "prod", "kind": "ci-only"}

_workflow := {
	"path": ".github/workflows/ci.yaml",
	"content": "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ruff check .\n      - run: pytest\n",
}

_ci_input(files) := {"proposal": {"files": files}, "context": {"target": _ci_target}}

_starter_input(files) := {
	"proposal": {"files": files},
	"context": {"target": _ci_target, "starter_profile": true},
}

_starter(content) := {"path": "environment-profile.yaml", "content": content}

_denied(rule_id, inp) := {d |
	some d in proposal.deny with input as inp
	d.rule_id == rule_id
}

# ---- the kind ----------------------------------------------------------------

test_ci_only_is_a_known_kind if {
	"ci-only" in proposal.known_target_kinds
	proposal.ci_only with input as _ci_input([])
}

test_a_workflow_alone_passes_for_ci_only if {
	count(proposal.deny) == 0 with input as _ci_input([_workflow])
}

# No deploy-artifact rule fires: there is nothing to deploy.
test_no_deploy_artifact_rule_fires_for_ci_only if {
	denied := {d.rule_id | some d in proposal.deny} with input as _ci_input([_workflow])
	every rid in {
		"proposal.has_helm_chart",
		"proposal.has_kustomization",
		"proposal.has_argocd_application",
		"proposal.has_ecs_task_definition",
		"proposal.has_ecs_deploy_workflow",
	} {
		not rid in denied
	}
}

test_ci_only_still_needs_a_pipeline if {
	count(_denied("proposal.has_workflow", _ci_input([]))) == 1
}

# ---- allowed_paths -----------------------------------------------------------

test_ci_only_may_not_write_deploy_paths if {
	files := [
		_workflow,
		{"path": "gitops/app/ci/svc/values.yaml", "content": "x: 1\n"},
		{"path": "argo-apps/argo-apps-ci/app.yaml", "content": "kind: Application\n"},
	]
	count(_denied("proposal.allowed_paths", _ci_input(files))) == 2
}

test_kubernetes_may_still_write_deploy_paths if {
	inp := {
		"proposal": {"files": [{"path": "gitops/app/dev/svc/values.yaml", "content": "x: 1\n"}]},
		"context": {"target": {"name": "dev", "tier": "dev", "kind": "kubernetes"}},
	}
	count(_denied("proposal.allowed_paths", inp)) == 0
}

test_ci_only_may_not_write_the_stack_file_outside_a_starter_run if {
	files := [_workflow, _starter("schema_version: \"1\"\n")]
	count(_denied("proposal.allowed_paths", _ci_input(files))) == 1
}

# ---- the starter (ADR-0077 §10) ----------------------------------------------

_blank := "schema_version: \"1\"\nname: acme-api\nci_cd_platform: []\nimage_scanning: []\npractices: {}\n"

test_a_blank_starter_passes if {
	count(proposal.deny) == 0 with input as _starter_input([_starter(_blank)])
}

test_a_commented_starter_passes if {
	content := "# Fill in your tools below.\nschema_version: \"1\"\nname: acme-api\n# image_scanning:\n#   - provider: trivy\n"
	count(proposal.deny) == 0 with input as _starter_input([_starter(content)])
}

test_a_starter_naming_a_tool_is_denied if {
	content := "schema_version: \"1\"\nci_cd_platform:\n  - provider: github_actions\n    primary: true\n"
	denies := _denied("proposal.starter_profile_is_blank", _starter_input([_starter(content)]))
	count(denies) == 1
	some d in denies
	contains(d.message, "ci_cd_platform")
}

# Pre-attesting a practice is the exact defect #458 shipped.
test_a_starter_attesting_a_practice_is_denied if {
	content := "schema_version: \"1\"\npractices:\n  ci_runs_tests: true\n"
	count(_denied("proposal.starter_profile_is_blank", _starter_input([_starter(content)]))) == 1
}

test_a_starter_denying_a_practice_is_also_a_claim if {
	content := "schema_version: \"1\"\npractices:\n  ci_runs_tests: false\n"
	count(_denied("proposal.starter_profile_is_blank", _starter_input([_starter(content)]))) == 1
}

test_a_starter_with_an_unknown_key_carrying_a_value_is_denied if {
	every content in [
		"schema_version: \"1\"\nnotes: we scan everything\n",
		"schema_version: \"1\"\nscanned: true\n",
		"schema_version: \"1\"\nlevel: 3\n",
	] {
		count(_denied("proposal.starter_profile_is_blank", _starter_input([_starter(content)]))) == 1
	}
}

test_a_starter_must_be_a_yaml_mapping if {
	every content in ["- a\n- b\n", "key: [unclosed\n"] {
		count(_denied("proposal.starter_profile_is_blank", _starter_input([_starter(content)]))) == 1
	}
}

test_a_starter_proposal_is_the_stack_file_alone if {
	denies := _denied("proposal.starter_profile_is_blank", _starter_input([_starter(_blank), _workflow]))
	count(denies) == 1
}

test_a_starter_run_must_add_the_stack_file if {
	count(_denied("proposal.starter_profile_is_blank", _starter_input([]))) == 1
}

# The starter carries no pipeline, and that is not a has_workflow failure.
test_a_starter_needs_no_pipeline if {
	count(_denied("proposal.has_workflow", _starter_input([_starter(_blank)]))) == 0
}

# Only ci-only has a starter run: on any other kind the flag is ignored, so the
# Stack file stays off-limits and a pipeline is still required.
test_the_starter_flag_means_nothing_off_ci_only if {
	inp := {
		"proposal": {"files": [_starter(_blank)]},
		"context": {"target": {"name": "dev", "tier": "dev", "kind": "kubernetes"}, "starter_profile": true},
	}
	not proposal.starter_profile_run with input as inp
	count(_denied("proposal.allowed_paths", inp)) == 1
	count(_denied("proposal.has_workflow", inp)) == 1
}

test_a_truthy_but_not_true_flag_is_not_a_starter_run if {
	every flag in ["true", 1, "yes"] {
		inp := {
			"proposal": {"files": [_starter(_blank)]},
			"context": {"target": _ci_target, "starter_profile": flag},
		}
		not proposal.starter_profile_run with input as inp
	}
}

# ---- metadata ----------------------------------------------------------------

test_repo_url_rule_is_scoped_to_kubernetes if {
	idx := proposal.rule_index with input as _ci_input([])
	idx["argocd.repoURL_is_canonical"].target_kinds == ["kubernetes"]
	idx["proposal.starter_profile_is_blank"].target_kinds == ["ci-only"]
}

_argo_app := {
	"path": "argo-apps/argo-apps-ci-application.yaml",
	"content": "spec:\n  source:\n    repoURL: https://example.com/wrong.git\n",
}

# The metadata tag is enforced in the body: a ci-only proposal is never judged
# by it (allowed_paths refuses the file on its own account).
test_repo_url_rule_does_not_fire_on_ci_only if {
	inp := object.union(_ci_input([_workflow, _argo_app]), {"context": {
		"target": _ci_target,
		"platform_repo_url": "https://example.com/platform.git",
	}})
	count(_denied("argocd.repoURL_is_canonical", inp)) == 0
	count(_denied("proposal.allowed_paths", inp)) == 1
}

test_repo_url_rule_still_fires_on_kubernetes if {
	inp := {
		"proposal": {"files": [_argo_app]},
		"context": {
			"target": {"name": "ci", "tier": "dev", "kind": "kubernetes"},
			"platform_repo_url": "https://example.com/platform.git",
		},
	}
	count(_denied("argocd.repoURL_is_canonical", inp)) == 1
}

# An overlay rule scoped to Kubernetes stays silent on a ci-only proposal, now
# that the kind is one the constitution knows (ADR-0065 §1).
test_a_kubernetes_scoped_overlay_rule_skips_ci_only if {
	overlay := {"acme": {
		"rule_metadata": {"acme.k8s_only": {"description": "x", "target_kinds": ["kubernetes"]}},
		"deny": {{"rule_id": "acme.k8s_only", "message": "k8s"}},
	}}
	count(_denied("acme.k8s_only", _ci_input([_workflow]))) == 0 with data.overlay as overlay
}
