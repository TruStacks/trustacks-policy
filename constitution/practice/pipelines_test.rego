# Tests for the neutral pipeline model (ADR-0071 §2): the universal practice
# rules judge GitHub Actions and Azure Pipelines the same way, pinning stays per
# runtime, and a runner that sends no model is judged exactly as before.
# Run with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

# ---- fixtures -----------------------------------------------------------------

pl_gh_ci := `on: workflow_call
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: ruff check .
      - run: pytest
`

pl_gh_no_test := `on: workflow_call
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: ruff check .
      - uses: docker/build-push-action@v5
`

pl_input(files, extra) := object.union(
	{"proposal": {"files": files}, "context": {"platform_repo_url": "https://example.invalid/acme/platform"}},
	extra,
)

pl_denied(inp) := {v.rule_id | some v in proposal.deny with input as inp}

pl_messages(inp, rule_id) := {v.message |
	some v in proposal.deny with input as inp
	v.rule_id == rule_id
}

# An Azure Pipelines model entry, the shape the runner's normaliser builds.
pl_azure(path, jobs) := {"path": path, "runtime": "azure_pipelines", "extends": null, "triggers": [], "jobs": jobs}

pl_job(name, steps) := {"name": name, "kind": "job", "environment": null, "steps": steps}

pl_ci_job := pl_job("build", [
	{"run": "pip install -r requirements.txt"},
	{"run": "ruff check ."},
	{"run": "pytest"},
	{"uses": "PublishTestResults@2.252.0"},
])

pl_azure_input(pipelines) := pl_input(
	[{"path": p.path, "content": "(model only)"} | some p in pipelines],
	{"proposal": {"pipelines": pipelines}, "context": {"ci_runtime": "azure_pipelines"}},
)

# ---- the model and the fallback agree -----------------------------------------

# Whatever rego builds from raw GitHub YAML, handed back as the runner's model,
# must judge identically: that is what keeps an older runner's verdicts and a
# newer runner's verdicts the same for GitHub Actions.
pl_equivalent(files) if {
	without := pl_input(files, {})
	fallback := [p | some p in proposal._pipelines with input as without]
	with_model := pl_input(files, {"proposal": {"pipelines": fallback}})
	pl_denied(without) == pl_denied(with_model)
}

test_model_and_fallback_agree_on_a_good_workflow if {
	pl_equivalent([{"path": ".github/workflows/ci-api.yaml", "content": pl_gh_ci}])
}

test_model_and_fallback_agree_on_a_workflow_missing_its_test_and_pin if {
	files := [{"path": ".github/workflows/ci-api.yaml", "content": pl_gh_no_test}]
	pl_equivalent(files)
	denied := pl_denied(pl_input(files, {}))
	"practice.workflow_has_test_step" in denied
	"practice.workflow_pins_action_versions" in denied
}

# A runner that sends no model is judged from the raw YAML.
test_fallback_reads_raw_github_yaml_when_no_model_is_sent if {
	files := [{"path": ".github/workflows/ci-api.yaml", "content": pl_gh_no_test}]
	"practice.workflow_has_test_step" in pl_denied(pl_input(files, {}))
}

# When a model is sent it is what's judged, not the raw file.
test_the_model_is_judged_when_present if {
	files := [{"path": ".github/workflows/ci-api.yaml", "content": pl_gh_no_test}]
	model := [{"path": ".github/workflows/ci-api.yaml", "runtime": "github_actions", "extends": null, "jobs": [pl_job("t", [{"run": "pytest && ruff check ."}])]}]
	not "practice.workflow_has_test_step" in pl_denied(pl_input(files, {"proposal": {"pipelines": model}}))
}

# ---- Azure Pipelines: the universal step rules ---------------------------------

test_azure_ci_template_with_test_and_lint_passes if {
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [pl_ci_job])])
	denied := pl_denied(inp)
	not "practice.workflow_has_test_step" in denied
	not "practice.workflow_has_lint_step" in denied
}

test_azure_ci_template_without_a_test_step_is_denied if {
	job := pl_job("build", [{"run": "ruff check ."}])
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [job])])
	"practice.workflow_has_test_step" in pl_denied(inp)
}

test_azure_ci_template_without_a_lint_step_is_denied if {
	job := pl_job("build", [{"run": "dotnet test"}])
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [job])])
	"practice.workflow_has_lint_step" in pl_denied(inp)
}

test_azure_step_template_is_not_judged_on_its_own if {
	job := pl_job("default", [{"run": "echo fragment"}])
	inp := pl_azure_input([
		pl_azure("azure-pipelines/templates/ci.yml", [pl_ci_job]),
		pl_azure("azure-pipelines/templates/steps/extra.yml", [job]),
	])
	denied := pl_denied(inp)
	not "practice.workflow_has_test_step" in denied
	not "practice.workflow_has_lint_step" in denied
}

test_azure_extends_caller_is_judged_through_its_template if {
	caller := {"path": "azure-pipelines.yml", "runtime": "azure_pipelines", "extends": "templates/ci.yml@platform", "triggers": ["trigger"], "jobs": []}
	inp := pl_azure_input([caller, pl_azure("azure-pipelines/templates/ci.yml", [pl_ci_job])])
	not "practice.workflow_has_test_step" in pl_denied(inp)
}

test_azure_deploy_only_pipeline_needs_no_test_step if {
	deploy := {"name": "deploy", "kind": "deployment", "environment": "prod", "steps": [{"run": "helm upgrade --install api ./chart"}]}
	inp := pl_azure_input([
		pl_azure("azure-pipelines/templates/ci.yml", [pl_ci_job]),
		pl_azure("azure-pipelines/deploy-api.yml", [deploy]),
	])
	not "practice.workflow_has_test_step" in pl_denied(inp)
}

# ---- pinning, per runtime -------------------------------------------------------

test_azure_task_at_a_major_version_is_denied if {
	job := pl_job("build", [{"run": "pytest && ruff check ."}, {"uses": "Docker@2"}])
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [job])])
	some m in pl_messages(inp, "practice.workflow_pins_action_versions")
	contains(m, "Docker@2")
}

test_azure_task_at_a_full_version_is_allowed if {
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [pl_ci_job])])
	count(pl_messages(inp, "practice.workflow_pins_action_versions")) == 0
}

test_azure_container_by_tag_is_denied if {
	job := object.union(pl_ci_job, {"image": "aquasec/trivy:0.56.2"})
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [job])])
	some m in pl_messages(inp, "practice.workflow_pins_action_versions")
	contains(m, "aquasec/trivy:0.56.2")
}

test_azure_step_container_by_tag_is_denied if {
	job := pl_job("build", [{"run": "pytest && ruff check ."}, {"run": "trivy fs .", "image": "aquasec/trivy:latest"}])
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [job])])
	some m in pl_messages(inp, "practice.workflow_pins_action_versions")
	contains(m, "aquasec/trivy:latest")
}

test_azure_container_by_digest_is_allowed if {
	digest := "aquasec/trivy@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	job := object.union(pl_ci_job, {"image": digest})
	inp := pl_azure_input([pl_azure("azure-pipelines/templates/ci.yml", [job])])
	count(pl_messages(inp, "practice.workflow_pins_action_versions")) == 0
}

# The GitHub SHA rule does not apply to Azure tasks, and vice versa.
test_github_tag_pin_is_still_denied_through_the_model if {
	model := [{"path": ".github/workflows/ci-api.yaml", "runtime": "github_actions", "extends": null, "jobs": [pl_job("t", [{"run": "pytest && ruff check ."}, {"uses": "docker/build-push-action@v5"}])]}]
	inp := pl_input([{"path": ".github/workflows/ci-api.yaml", "content": "x"}], {"proposal": {"pipelines": model}})
	some m in pl_messages(inp, "practice.workflow_pins_action_versions")
	contains(m, "should pin to a SHA")
}

# ---- prod environment ------------------------------------------------------------

pl_prod := {"context": {"target": {"name": "prod-east", "tier": "prod", "kind": "ecs-fargate"}}}

test_azure_prod_deployment_job_without_environment_is_denied if {
	deploy := {"name": "deploy", "kind": "deployment", "environment": null, "steps": []}
	inp := object.union(pl_azure_input([pl_azure("azure-pipelines/deploy-api.yml", [deploy])]), pl_prod)
	"practice.workflow_prod_deploy_requires_environment" in pl_denied(inp)
}

test_azure_prod_deployment_job_with_environment_is_allowed if {
	deploy := {"name": "deploy", "kind": "deployment", "environment": "prod", "steps": []}
	inp := object.union(pl_azure_input([pl_azure("azure-pipelines/deploy-api.yml", [deploy])]), pl_prod)
	not "practice.workflow_prod_deploy_requires_environment" in pl_denied(inp)
}

# ---- allowed paths and has_workflow, by CI runtime --------------------------------

pl_paths_denied(paths, runtime) := {f.path |
	some v in proposal.deny with input as pl_input(
		[{"path": p, "content": ""} | some p in paths],
		{"context": {"ci_runtime": runtime}},
	)
	v.rule_id == "proposal.allowed_paths"
	some f in [{"path": p} | some p in paths]
	contains(v.message, f.path)
}

test_github_runtime_may_not_write_azure_pipeline_files if {
	denied := pl_paths_denied(["azure-pipelines.yml", "azure-pipelines/templates/ci.yml"], "github_actions")
	denied == {"azure-pipelines.yml", "azure-pipelines/templates/ci.yml"}
}

test_azure_runtime_may_not_write_github_workflows if {
	pl_paths_denied([".github/workflows/ci-api.yaml"], "azure_pipelines") == {".github/workflows/ci-api.yaml"}
}

test_azure_runtime_may_write_its_pipeline_files if {
	count(pl_paths_denied(["azure-pipelines.yml", "azure-pipelines/templates/ci.yml", "gitops/a/b/c/Chart.yaml"], "azure_pipelines")) == 0
}

test_default_runtime_is_github_actions if {
	proposal.ci_runtime == "github_actions" with input as {"proposal": {"files": []}}
	proposal.allowed_prefixes == ["gitops/", "argo-apps/", ".github/workflows/"] with input as {"proposal": {"files": []}}
}

test_has_workflow_follows_the_runtime if {
	az := pl_input([{"path": "azure-pipelines/templates/ci.yml", "content": ""}], {"context": {"ci_runtime": "azure_pipelines"}})
	not "proposal.has_workflow" in pl_denied(az)
	gh_only := pl_input([{"path": ".github/workflows/ci.yaml", "content": ""}], {"context": {"ci_runtime": "azure_pipelines"}})
	"proposal.has_workflow" in pl_denied(gh_only)
}
