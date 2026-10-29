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
# runtime (`github_actions`, `azure_pipelines`), and its jobs and steps. The
# universal practice rules read this, so they judge any runtime the same way.
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

# A pipeline that only deploys: the GitHub workflow that runs the ECS deploy
# action (ADR-0062), or an Azure pipeline whose every job is a `deployment:`
# job. It applies an artifact; it has no suite to run.
_pipeline_is_deploy(p) if {
	p.runtime == "github_actions"
	some job in p.jobs
	_model_job_deploys_to_ecs(job)
}

_pipeline_is_deploy(p) if {
	p.runtime == "azure_pipelines"
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
