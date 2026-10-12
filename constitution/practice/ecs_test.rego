# Tests for the ECS Fargate rules (ADR-0062): the practice rules in this
# directory, the two structural rules in proposal/, and the target-kind gating
# of the Kubernetes rules. Run with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

# ---- fixtures ---------------------------------------------------------------

ecs_task_def := {
	"family": "shop-api-shop-prod",
	"requiresCompatibilities": ["FARGATE"],
	"networkMode": "awsvpc",
	"cpu": "256",
	"memory": "512",
	"containerDefinitions": [{
		"name": "api",
		"image": "ghcr.io/acme/api:3f2c9d1e0b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
		"essential": true,
		"user": "1001",
		"readonlyRootFilesystem": true,
		"environment": [{"name": "LOG_LEVEL", "value": "info"}, {"name": "TOKEN_URL", "value": "https://idp.example/token"}],
		"secrets": [{"name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:shop/db-AbCdEf"}],
		"logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": "/ecs/shop/api"}},
	}],
}

ecs_deploy_workflow(job_extra) := yaml.marshal({
	"name": "deploy-api-shop-prod",
	"on": {"push": {"branches": ["main"]}},
	"permissions": {},
	"jobs": {"deploy": object.union(
		{
			"runs-on": "ubuntu-latest",
			"permissions": {"contents": "read", "id-token": "write"},
			"steps": [
				{"uses": "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"},
				{"uses": "aws-actions/amazon-ecs-deploy-task-definition@c465972ecbd160473f22e683363b422a5412a3de"},
			],
		},
		job_extra,
	)},
})

ecs_files(task_def, deploy_job_extra) := [
	{"path": ".github/workflows/ci-api.yaml", "content": good_workflow_content},
	{"path": "gitops/shop/shop-prod/api/task-definition.json", "content": json.marshal(task_def)},
	{"path": ".github/workflows/deploy-api-shop-prod.yaml", "content": ecs_deploy_workflow(deploy_job_extra)},
]

ecs_input(task_def, deploy_job_extra, tier) := {
	"proposal": {"files": ecs_files(task_def, deploy_job_extra)},
	"context": {
		"platform_repo_url": PLATFORM_URL,
		"renderer": "helm",
		"target": {"name": "shop-prod", "tier": tier, "kind": "ecs-fargate"},
	},
}

good_ecs_input := ecs_input(ecs_task_def, {"environment": "shop-prod"}, "prod")

container_set(field, value) := json.patch(
	ecs_task_def,
	[{"op": "add", "path": sprintf("/containerDefinitions/0/%v", [field]), "value": value}],
)

container_remove(field) := json.patch(
	ecs_task_def,
	[{"op": "remove", "path": sprintf("/containerDefinitions/0/%v", [field])}],
)

denied_ids(inp) := {v.rule_id | some v in proposal.deny with input as inp}

# ---- the whole canonical Fargate proposal passes -----------------------------

test_canonical_ecs_fargate_proposal_is_allowed if {
	count(proposal.deny) == 0 with input as good_ecs_input
}

test_kubernetes_structural_rules_do_not_fire_for_ecs_fargate if {
	ids := denied_ids(good_ecs_input)
	not "proposal.has_argocd_application" in ids
	not "proposal.has_helm_chart" in ids
}

test_the_deploy_workflow_is_not_asked_for_tests_or_lint if {
	ids := denied_ids(good_ecs_input)
	not "practice.workflow_has_test_step" in ids
	not "practice.workflow_has_lint_step" in ids
}

test_a_ci_workflow_still_needs_its_test_step_on_fargate if {
	files := [
		{"path": ".github/workflows/ci-api.yaml", "content": "jobs:\n  build:\n    steps:\n      - run: echo hi\n"},
		{"path": "gitops/shop/shop-prod/api/task-definition.json", "content": json.marshal(ecs_task_def)},
		{"path": ".github/workflows/deploy-api-shop-prod.yaml", "content": ecs_deploy_workflow({"environment": "shop-prod"})},
	]
	inp := object.union(good_ecs_input, {"proposal": {"files": files}})
	"practice.workflow_has_test_step" in denied_ids(inp)
}

# ---- structural ----------------------------------------------------------------

test_fargate_without_a_task_definition_is_denied if {
	files := [f | some f in ecs_files(ecs_task_def, {"environment": "shop-prod"}); not endswith(f.path, ".json")]
	inp := object.union(good_ecs_input, {"proposal": {"files": files}})
	"proposal.has_ecs_task_definition" in denied_ids(inp)
}

test_fargate_without_a_deploy_workflow_is_denied if {
	files := [f | some f in ecs_files(ecs_task_def, {"environment": "shop-prod"}); not contains(f.path, "deploy-")]
	inp := object.union(good_ecs_input, {"proposal": {"files": files}})
	"proposal.has_ecs_deploy_workflow" in denied_ids(inp)
}

test_ecs_structural_rules_do_not_fire_for_kubernetes if {
	ids := denied_ids(good_input)
	not "proposal.has_ecs_task_definition" in ids
	not "proposal.has_ecs_deploy_workflow" in ids
}

test_an_absent_kind_is_kubernetes if {
	proposal.target_kind == "kubernetes" with input as good_input
	"proposal.has_argocd_application" in denied_ids({"proposal": {"files": []}, "context": {}})
}

# ---- practice.ecs_task_runs_as_nonroot -----------------------------------------

test_ecs_root_user_is_denied if {
	every user in ["root", "0", "0:0", "root:root", " 0 "] {
		"practice.ecs_task_runs_as_nonroot" in denied_ids(ecs_input(container_set("user", user), {"environment": "x"}, "prod"))
	}
}

test_ecs_absent_user_is_denied if {
	"practice.ecs_task_runs_as_nonroot" in denied_ids(ecs_input(container_remove("user"), {"environment": "x"}, "prod"))
}

test_ecs_nonroot_uid_with_group_is_allowed if {
	not "practice.ecs_task_runs_as_nonroot" in denied_ids(ecs_input(container_set("user", "1001:1001"), {"environment": "x"}, "prod"))
}

# ---- practice.ecs_task_readonly_root_filesystem --------------------------------

test_ecs_writable_root_is_denied if {
	"practice.ecs_task_readonly_root_filesystem" in denied_ids(ecs_input(container_set("readonlyRootFilesystem", false), {"environment": "x"}, "prod"))
}

test_ecs_miscased_readonly_key_is_denied if {
	# AWS silently drops `readOnlyRootFilesystem`; the container then runs writable.
	td := json.patch(container_remove("readonlyRootFilesystem"), [{"op": "add", "path": "/containerDefinitions/0/readOnlyRootFilesystem", "value": true}])
	"practice.ecs_task_readonly_root_filesystem" in denied_ids(ecs_input(td, {"environment": "x"}, "prod"))
}

# ---- practice.ecs_task_secrets_not_in_environment ------------------------------

test_ecs_secret_named_env_var_is_denied if {
	every name in ["DB_PASSWORD", "AUTH_TOKEN", "STRIPE_API_KEY", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"] {
		td := container_set("environment", [{"name": name, "value": "hunter2"}])
		"practice.ecs_task_secrets_not_in_environment" in denied_ids(ecs_input(td, {"environment": "x"}, "prod"))
	}
}

test_ecs_credential_looking_value_is_denied_whatever_its_name if {
	every value in ["AKIAIOSFODNN7EXAMPLE", "postgres://app:s3cret@db:5432/app", "-----BEGIN RSA PRIVATE KEY-----\nabc"] {
		td := container_set("environment", [{"name": "CONFIG", "value": value}])
		"practice.ecs_task_secrets_not_in_environment" in denied_ids(ecs_input(td, {"environment": "x"}, "prod"))
	}
}

test_ecs_configuration_that_merely_mentions_token_is_allowed if {
	# TOKEN_URL, AUTH_SERVER: configuration, not credentials. Suffix match only.
	td := container_set("environment", [{"name": "TOKEN_URL", "value": "https://idp/token"}, {"name": "AUTH_SERVER", "value": "idp"}])
	not "practice.ecs_task_secrets_not_in_environment" in denied_ids(ecs_input(td, {"environment": "x"}, "prod"))
}

test_ecs_secret_value_from_must_be_an_arn if {
	every value_from in ["shop/db", "/shop/db-password", ""] {
		td := container_set("secrets", [{"name": "DB_PASSWORD", "valueFrom": value_from}])
		"practice.ecs_task_secrets_not_in_environment" in denied_ids(ecs_input(td, {"environment": "x"}, "prod"))
	}
}

test_ecs_ssm_parameter_arn_is_allowed if {
	td := container_set("secrets", [{"name": "DB_PASSWORD", "valueFrom": "arn:aws:ssm:us-east-1:123456789012:parameter/shop/db-password"}])
	not "practice.ecs_task_secrets_not_in_environment" in denied_ids(ecs_input(td, {"environment": "x"}, "prod"))
}

# ---- practice.ecs_task_image_is_pinned -----------------------------------------

test_ecs_floating_or_missing_tag_is_denied if {
	every image in ["ghcr.io/acme/api", "ghcr.io/acme/api:latest", "ghcr.io/acme/api:LATEST", "ghcr.io/acme/api:main", "registry.internal:5000/acme/api"] {
		"practice.ecs_task_image_is_pinned" in denied_ids(ecs_input(container_set("image", image), {"environment": "x"}, "prod"))
	}
}

test_ecs_digest_and_sha_tag_are_allowed if {
	every image in [
		"ghcr.io/acme/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"registry.internal:5000/acme/api:3f2c9d1e0b7a",
	] {
		not "practice.ecs_task_image_is_pinned" in denied_ids(ecs_input(container_set("image", image), {"environment": "x"}, "prod"))
	}
}

# ---- practice.ecs_task_configures_logging --------------------------------------

test_ecs_container_without_a_log_driver_is_denied if {
	"practice.ecs_task_configures_logging" in denied_ids(ecs_input(container_remove("logConfiguration"), {"environment": "x"}, "prod"))
}

# ---- practice.workflow_prod_deploy_requires_environment ------------------------

test_prod_deploy_job_without_environment_is_denied if {
	"practice.workflow_prod_deploy_requires_environment" in denied_ids(ecs_input(ecs_task_def, {}, "prod"))
}

test_prod_deploy_job_with_a_blank_environment_is_denied if {
	"practice.workflow_prod_deploy_requires_environment" in denied_ids(ecs_input(ecs_task_def, {"environment": " "}, "prod"))
}

test_prod_deploy_job_with_an_environment_object_is_allowed if {
	not "practice.workflow_prod_deploy_requires_environment" in denied_ids(ecs_input(ecs_task_def, {"environment": {"name": "shop-prod", "url": "https://shop"}}, "prod"))
}

test_dev_deploy_job_may_omit_environment if {
	not "practice.workflow_prod_deploy_requires_environment" in denied_ids(ecs_input(ecs_task_def, {}, "dev"))
}

test_the_environment_rule_scores_nothing if {
	# Presence of a reference, not enforcement (ADR-0062 decision 4): its
	# silence must never verify `manual_promotion_to_prod`.
	proposal.rule_metadata["practice.workflow_prod_deploy_requires_environment"].practice_dimensions == []
}

# ---- target helpers (ADR-0060 decision 3) --------------------------------------

test_target_tier_prefers_the_target_object if {
	proposal.target_tier == "prod" with input as {"context": {"target": {"tier": "prod"}, "target_tier": "dev"}}
}

test_target_tier_falls_back_to_the_flat_key if {
	proposal.target_tier == "uat" with input as {"context": {"target_tier": "uat"}}
}

test_target_tier_is_undefined_without_context if {
	not proposal.target_tier with input as {"context": {}}
}

test_the_argocd_prod_rule_reads_the_target_object if {
	app := "apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  syncPolicy:\n    automated: {}\n"
	inp := {
		"proposal": {"files": [{"path": "argo-apps/argo-apps-gke-us-east/demo-application.yaml", "content": app}]},
		"context": {"target": {"name": "gke-us-east", "tier": "prod", "kind": "kubernetes"}},
	}
	"practice.argocd_prod_requires_manual_sync" in denied_ids(inp)
}
