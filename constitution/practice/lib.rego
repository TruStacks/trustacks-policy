# Practice rules (slice 14.5) — shared helpers.
#
# These answer "are you using your tools correctly?" rather than "do you have
# the tools?" Each rule fires deny on a proposal when the emitted artifact
# violates the practice; each is also linked to a `practice_dimensions` key
# the customer self-attests to in EnvironmentProfile.practices, so the
# maturity scorer can blend practice posture into coverage_pct.
#
# One rule per file in this directory, every rule_id in the `practice.`
# namespace. This file holds no rule — only the matchers more than one of them
# use.

package proposal

import rego.v1

_is_workflow(path) if {
	startswith(path, ".github/workflows/")
	endswith(path, ".yaml")
}

_is_workflow(path) if {
	startswith(path, ".github/workflows/")
	endswith(path, ".yml")
}

_is_dockerfile(path) if endswith(path, "/Dockerfile")

_is_dockerfile(path) if path == "Dockerfile"

# ---- Pipelines (ADR-0071 §2) ------------------------------------------------
#
# The CI pipelines in this proposal, in the neutral model the runner builds
# (`input.proposal.pipelines`): one entry per pipeline file with its path, its
# runtime (`github_actions`, `azure_pipelines`, `gitlab_ci`), and its jobs and
# steps. The universal practice rules read this, so they judge any runtime the
# same way.
#
# When the runner sent no model (a runner older than ADR-0071), the model is
# built here from the raw GitHub Actions YAML, the only runtime such a runner
# emits, with exactly the reads the rules made before: so an older runner is
# judged as it always was.

# The runner sent the model. A named rule rather than `not is_array(...)`
# inline: negating a built-in whose argument is undefined does not evaluate to
# true in OPA, so the fallback below would never run.
_has_pipeline_model if is_array(input.proposal.pipelines)

_pipelines contains p if {
	_has_pipeline_model
	some p in input.proposal.pipelines
	is_object(p)
}

_pipelines contains p if {
	not _has_pipeline_model
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	p := {
		"path": f.path,
		"runtime": "github_actions",
		"extends": null,
		"jobs": [_github_model_job(name, job) | some name, job in wf.jobs],
	}
}

_github_model_job(name, job) := {
	"name": name,
	"kind": "job",
	"environment": _github_environment_name(job),
	"steps": [_github_model_step(step) | some step in job.steps],
}

_github_model_step(step) := object.union(_github_run(step), _github_uses(step))

_github_run(step) := {"run": step.run} if is_string(step.run)

else := {}

_github_uses(step) := {"uses": step.uses} if is_string(step.uses)

else := {}

_github_environment_name(job) := trim_space(job.environment) if {
	is_string(job.environment)
	trim_space(job.environment) != ""
} else := trim_space(job.environment.name) if {
	is_string(job.environment.name)
	trim_space(job.environment.name) != ""
} else := null

# ---- Pinning without the model ------------------------------------------------
#
# The CI policy check (ADR-0067 decision 3) runs this bundle on a repository's
# own files with no normaliser, so it sends no model, and the fallback above
# reads GitHub Actions only. A repository's `azure-pipelines.yml` or
# `.gitlab-ci.yml` would be collected and then judged by nothing. For the one
# CI rule that judges repositories (pinning), the Azure Pipelines and GitLab CI
# files are read here too, coarsely: every `image:` anywhere in the file, every
# GitLab `services:` entry and `include:`, every Azure `task:`. That is
# stricter than the runner's model (an unused hidden GitLab job counts), never
# looser. Only the pinning rule reads these, so the step rules (test, lint)
# never judge a pipeline they can't see the steps of.
_pinned_pipelines contains p if some p in _pipelines

_pinned_pipelines contains p if {
	not _has_pipeline_model
	some f in input.proposal.files
	runtime := _raw_pipeline_runtime(f.path)
	doc := yaml.unmarshal(f.content)
	is_object(doc)
	p := {
		"path": f.path,
		"runtime": runtime,
		"extends": null,
		"includes": _raw_gitlab_includes(runtime, doc),
		"jobs": array.concat(
			[_raw_job(image, []) | some image in _raw_images(doc)],
			[_raw_job(null, [{"uses": task} | some task in _raw_azure_tasks(runtime, doc)])],
		),
	}
}

_raw_pipeline_runtime(path) := "gitlab_ci" if path in {".gitlab-ci.yml", ".gitlab-ci.yaml"}

_raw_pipeline_runtime(path) := "gitlab_ci" if {
	startswith(path, ".gitlab/ci/")
	_is_yaml_path(path)
}

_raw_pipeline_runtime(path) := "azure_pipelines" if path in {"azure-pipelines.yml", "azure-pipelines.yaml"}

_raw_pipeline_runtime(path) := "azure_pipelines" if {
	startswith(path, "azure-pipelines/")
	_is_yaml_path(path)
}

_is_yaml_path(path) if endswith(path, ".yml")

_is_yaml_path(path) if endswith(path, ".yaml")

_raw_job(image, steps) := {"name": "(raw)", "kind": "job", "environment": null, "image": image, "services": [], "steps": steps}

_raw_images(doc) := {image |
	walk(doc, [path, value])
	count(path) > 0
	path[count(path) - 1] == "image"
	image := _raw_image_name(value)
} | {image |
	walk(doc, [path, value])
	count(path) > 0
	path[count(path) - 1] == "services"
	is_array(value)
	some entry in value
	image := _raw_image_name(entry)
}

_raw_image_name(v) := trim_space(v) if {
	is_string(v)
	trim_space(v) != ""
}

_raw_image_name(v) := trim_space(v.name) if {
	is_object(v)
	is_string(v.name)
	trim_space(v.name) != ""
}

_raw_azure_tasks(runtime, doc) := {task |
	runtime == "azure_pipelines"
	walk(doc, [path, task])
	count(path) > 0
	path[count(path) - 1] == "task"
	is_string(task)
}

_raw_gitlab_includes(runtime, _) := [] if runtime != "gitlab_ci"

_raw_gitlab_includes("gitlab_ci", doc) := [inc |
	some entry in _raw_list(object.get(doc, "include", null))
	some inc in _raw_gitlab_include(entry)
]

_raw_list(v) := v if is_array(v)

else := [] if v == null

else := [v]

_raw_gitlab_include(entry) := {{"kind": "remote", "location": entry, "ref": null}} if {
	is_string(entry)
	regex.match(`^https?://`, entry)
}

_raw_gitlab_include(entry) := {{"kind": "local", "location": entry, "ref": null}} if {
	is_string(entry)
	not regex.match(`^https?://`, entry)
}

_raw_gitlab_include(entry) := {inc |
	some kind in ["project", "component", "remote", "template", "local"]
	location := entry[kind]
	is_string(location)
	inc := {"kind": kind, "location": location, "ref": _raw_include_ref(kind, location, entry)}
} if {
	is_object(entry)
}

# A component's ref is its `@<version>`; a project's is its `ref:`.
_raw_include_ref(kind, location, entry) := ref if {
	kind == "component"
	parts := split(location, "@")
	count(parts) > 1
	ref := parts[count(parts) - 1]
} else := entry.ref if {
	kind != "component"
	is_string(entry.ref)
} else := null

# A pipeline that only deploys: the GitHub workflow that runs the ECS deploy
# action (ADR-0062), an Azure pipeline whose every job is a `deployment:` job,
# or a GitLab pipeline whose every job names an `environment:`. It applies an
# artifact; it has no suite to run.
_pipeline_is_deploy(p) if {
	p.runtime == "github_actions"
	some job in p.jobs
	_model_job_deploys_to_ecs(job)
}

_pipeline_is_deploy(p) if {
	p.runtime in {"azure_pipelines", "gitlab_ci"}
	count(p.jobs) > 0
	every job in p.jobs {
		job.kind == "deployment"
	}
}

# Azure step templates are fragments, included only from inside the `extends`
# root (ADR-0071 §4); a caller that only `extends` a template has no jobs of
# its own. Both are judged through the template that holds the steps.
_pipeline_is_fragment(p) if {
	p.runtime == "azure_pipelines"
	startswith(p.path, "azure-pipelines/templates/steps/")
}

_pipeline_is_fragment(p) if {
	p.runtime == "azure_pipelines"
	is_string(p.extends)
	count(p.jobs) == 0
}

# GitLab step templates (`.gitlab/ci/steps/`) are included only from the
# template, and a file that only `include:`s has no jobs of its own: both are
# judged through the template that holds the jobs.
_pipeline_is_fragment(p) if {
	p.runtime == "gitlab_ci"
	startswith(p.path, ".gitlab/ci/steps/")
}

_pipeline_is_fragment(p) if {
	p.runtime == "gitlab_ci"
	count(object.get(p, "includes", [])) > 0
	count(p.jobs) == 0
}

# The pipelines the step rules (test, lint) judge.
_ci_pipelines contains p if {
	some p in _pipelines
	not _pipeline_is_deploy(p)
	not _pipeline_is_fragment(p)
}

_model_job_deploys_to_ecs(job) if {
	some step in job.steps
	is_string(step.uses)
	startswith(step.uses, concat("", [_ecs_deploy_action, "@"]))
}

# A job that deploys, per runtime.
_model_job_deploys(p, job) if {
	p.runtime == "github_actions"
	_model_job_deploys_to_ecs(job)
}

_model_job_deploys(p, job) if {
	p.runtime == "azure_pipelines"
	job.kind == "deployment"
}

_model_job_has_environment(job) if {
	is_string(job.environment)
	trim_space(job.environment) != ""
}

# Needles are matched against a LOWERCASED command, so they must be lowercase
# themselves. `mvn -B verify -Dlint` used to live in the lint list and could
# never match anything — the command was lowercased and the needle was not, so
# Java could not satisfy the rule no matter what the agent emitted (#551). The
# comparison lowercases both sides now, which makes that class of bug
# impossible rather than fixed once.
_pipeline_has_step_matching(p, needles) if {
	some job in p.jobs
	some step in job.steps
	cmd := lower(step.run)
	some needle in needles
	contains(cmd, lower(needle))
}

_pipeline_has_step_matching_re(p, pattern) if {
	some job in p.jobs
	some step in job.steps
	regex.match(pattern, lower(step.run))
}
