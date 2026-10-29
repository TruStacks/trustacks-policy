# practice.workflow_pins_action_versions — every third-party `uses:` entry
# pins to a SHA. Allow `actions/*` (GitHub-owned) and `./local` refs to use
# unpinned tags; reject every other `uses: <owner>/<repo>@<ref>` whose ref
# isn't a 40-char hex SHA.
#
# The deny rule splits on whether the bad ref *looks like* a near-SHA
# (hex-only + wrong length) vs an actual tag. Agents that hallucinate
# a 39-char "SHA" get a more diagnostic message than agents that emit
# `@v1.2.3`. Both paths emit the same rule_id so callers don't need
# to handle two error codes.
#
# Pinning is per runtime (ADR-0071 §2, §4), read from the neutral pipeline
# model. GitHub Actions: the SHA rule above. Azure Pipelines: a task can't be
# pinned to a commit (Marketplace tasks aren't git repositories), so a task
# step must name a FULL version (`Name@X.Y.Z`; `@2` silently takes new minor
# versions), and every container a job or step runs in must be pinned by
# digest (`@sha256:` and 64 hex). A full task version is version-pinned, not
# immutable: the docs and the PR body say so.

package proposal

import rego.v1

rule_metadata["practice.workflow_pins_action_versions"] := {
	"description": "Every third-party `uses:` action in a workflow pins to a SHA, not just a tag.",
	"required_tooling_categories": [],
	"practice_dimensions": ["supply_chain_pinning"],
	"tier_scope": ["any"],
	# ADR-0067: a repository's own file is enough to judge this rule.
	"subjects": ["proposal", "repo"],
}

deny contains msg if {
	some p in _pipelines
	p.runtime == "github_actions"
	some unpinned in _unpinned_uses_refs(p)
	parts := split(unpinned, "@")
	ref_part := parts[1]
	_looks_like_near_sha(ref_part)
	msg := {
		"rule_id": "practice.workflow_pins_action_versions",
		"message": sprintf(
			"workflow %v: third-party action `uses: %v` ref is hex-only but not exactly 40 characters (got %d). Pin to the full 40-char immutable SHA.",
			[p.path, unpinned, count(ref_part)],
		),
	}
}

deny contains msg if {
	some p in _pipelines
	p.runtime == "github_actions"
	some unpinned in _unpinned_uses_refs(p)
	parts := split(unpinned, "@")
	ref_part := parts[1]
	not _looks_like_near_sha(ref_part)
	msg := {
		"rule_id": "practice.workflow_pins_action_versions",
		"message": sprintf(
			"workflow %v: third-party action `uses: %v` should pin to a SHA, not a tag",
			[p.path, unpinned],
		),
	}
}

# Azure Pipelines: a task step names a full version.
deny contains msg if {
	some p in _pipelines
	p.runtime == "azure_pipelines"
	some job in p.jobs
	some step in job.steps
	is_string(step.uses)
	not regex.match(`^[A-Za-z0-9][A-Za-z0-9_.-]*@[0-9]+\.[0-9]+\.[0-9]+$`, step.uses)
	msg := {
		"rule_id": "practice.workflow_pins_action_versions",
		"message": sprintf(
			"pipeline %v: task `%v` should pin a full version (Name@X.Y.Z); a major version alone takes new minor versions automatically",
			[p.path, step.uses],
		),
	}
}

# Azure Pipelines: every container a job or step runs in is pinned by digest.
deny contains msg if {
	some p in _pipelines
	p.runtime == "azure_pipelines"
	some image in _azure_pipeline_images(p)
	not regex.match(`@sha256:[0-9a-f]{64}$`, image)
	msg := {
		"rule_id": "practice.workflow_pins_action_versions",
		"message": sprintf(
			"pipeline %v: container `%v` should be pinned by digest (image@sha256:...), not a tag",
			[p.path, image],
		),
	}
}

_azure_pipeline_images(p) := {image |
	some job in p.jobs
	image := job.image
	is_string(image)
} | {image |
	some job in p.jobs
	some step in job.steps
	image := step.image
	is_string(image)
}

# A ref "looks like" a near-SHA when it's hex-only AND the length is in
# the realistic-mistake band (7-41 chars, but not exactly 40). 7 is git's
# default short-SHA length; 41 covers off-by-one-too-long typos. Tags
# like `v1.2.3` or `main` fail the hex check.
_looks_like_near_sha(ref) if {
	regex.match("^[0-9a-f]+$", ref)
	count(ref) >= 7
	count(ref) <= 41
	count(ref) != 40
}

# Walk a workflow's jobs.steps[].uses fields, return refs that look
# unpinned (third-party + ref isn't a 40-char hex SHA).
_unpinned_uses_refs(p) := {ref |
	some job in p.jobs
	some step in job.steps
	uses := step.uses
	uses != ""
	parts := split(uses, "@")
	count(parts) == 2
	owner_repo := parts[0]
	ref := uses
	not startswith(owner_repo, "actions/")
	not startswith(owner_repo, "./")
	not regex.match("^[0-9a-f]{40}$", parts[1])
}
