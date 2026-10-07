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

package proposal

import rego.v1

rule_metadata["practice.workflow_pins_action_versions"] := {
	"description": "Every third-party `uses:` action in a workflow pins to a SHA, not just a tag.",
	"required_tooling_categories": [],
	"practice_dimensions": ["supply_chain_pinning"],
	"tier_scope": ["any"],
}

deny contains msg if {
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	some unpinned in _unpinned_uses_refs(wf)
	parts := split(unpinned, "@")
	ref_part := parts[1]
	_looks_like_near_sha(ref_part)
	msg := {
		"rule_id": "practice.workflow_pins_action_versions",
		"message": sprintf(
			"workflow %v: third-party action `uses: %v` ref is hex-only but not exactly 40 characters (got %d). Pin to the full 40-char immutable SHA.",
			[f.path, unpinned, count(ref_part)],
		),
	}
}

deny contains msg if {
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	some unpinned in _unpinned_uses_refs(wf)
	parts := split(unpinned, "@")
	ref_part := parts[1]
	not _looks_like_near_sha(ref_part)
	msg := {
		"rule_id": "practice.workflow_pins_action_versions",
		"message": sprintf(
			"workflow %v: third-party action `uses: %v` should pin to a SHA, not a tag",
			[f.path, unpinned],
		),
	}
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
_unpinned_uses_refs(wf) := {ref |
	some _, job in wf.jobs
	some _, step in job.steps
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
