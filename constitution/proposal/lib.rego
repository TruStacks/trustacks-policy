# Constitution rules for PlatformChangeProposals — shared machinery.
#
# Phase 3a — first 5 rules of the constitution. Each `deny` rule emits one
# message per violation; `allow` is implicit (no denies). The runner shells
# `opa eval data.proposal.deny` and treats a non-empty result set as a
# block.
#
# Phase 3b — rules now carry metadata (description + required tooling
# categories). The metadata is exposed via `data.proposal.rule_index` so
# the DevOps agent can cite real rule ids in its rationale, and consumed
# by `data.proposal.gap` to surface tooling categories the customer's
# EnvironmentProfile leaves empty. Required-category names match the
# field names on EnvironmentProfile (see runner/.../env_profile/models.py).
#
# ---- Layout (rule-naming standard v2) -------------------------------------
#
# Every rule lives in the directory named for its namespace:
#
#   constitution/proposal/<name>.rego   → rule_id `proposal.<name>`
#   constitution/argocd/<name>.rego     → rule_id `argocd.<name>`
#   constitution/practice/<name>.rego   → rule_id `practice.<name>`
#   constitution/posture/<name>.rego    → rule_id `posture.<name>`
#
# The rule_id is written out in full in each file and never derived from the
# path — rule ids are persisted in customer history (denial counts, scores,
# evidence), so a file move must not silently re-ID a rule. CI checks instead
# that each id's namespace equals its directory, so a move without a rename
# fails loudly.
#
# All four directories declare `package proposal`; OPA merges every file of a
# package, so `data.proposal.deny`, `data.proposal.gap`,
# `data.proposal.rule_metadata` and `data.proposal.rule_index` are exactly the
# query paths they were when the constitution was one file. Each rule file
# contributes one `rule_metadata[<id>]` entry beside its deny block.
#
# This file holds no rule of its own — only what every rule shares: the
# enforcement default, the rule index, the renderer, the overlay aggregator
# and gap analysis.
#
# Input shape (from runner/src/.../policy/evaluator.py):
#
#   input = {
#     "proposal": {
#       "files": [{"path": "...", "content": "..."}, ...],
#       "explanation": {...}
#     },
#     "context": {
#       "platform_repo_url": "https://example.invalid/acme/platform.git"
#     }
#   }
#
# Data shape (passed via `opa eval --data` when the runner has loaded an
# overlay; absent for unit tests that don't need gap analysis):
#
#   data.env = {
#     "tooling_categories": {
#       "ci_cd_platform":     ["github_actions"],
#       "gitops_controller":  ["argocd"],
#       ...                   # all 12 EnvironmentProfile category fields
#     }
#   }
#
# Tests live next to the rules as `*_test.rego`; run with
# `opa test policy/constitution`.

package proposal

import rego.v1

# ---- Rule metadata --------------------------------------------------------
# `rule_metadata` is a partial object: each rule file adds its own
# `rule_metadata["<namespace>.<name>"] := {...}` entry. `rule_index`
# re-publishes it for external consumers (DevOps agent prompt, gap query,
# Coordinator agent). Adding a rule = adding a file with a deny block + its
# metadata entry, in the directory named for the rule's namespace.

# Every rule that is not explicitly `posture` gates a proposal. Stated as a
# default rather than written onto each of the eleven gate rules, so adding a
# gate rule cannot accidentally inherit "posture" by forgetting a field.
rule_enforcement(rule_id) := enforcement if {
	enforcement := rule_metadata[rule_id].enforcement
} else := "gate"

rule_index := rule_metadata

# ---- Renderer -------------------------------------------------------------
#
# ADR-0052. The renderer arrives on `input.context`, beside
# `platform_repo_url`, and NOT from `data.env`. It is a property of the
# artifacts being judged, not of the customer's environment — sourcing it from
# the profile would let the same set of files pass or fail depending on state
# edited somewhere else, and leave the rule unable to answer "is what I am
# looking at internally consistent?"
#
# Absent renderer means helm: every proposal before this one was, and an older
# runner must be judged exactly as it was. Read by `has_helm_chart` and
# `has_kustomization`.

default renderer := "helm"

renderer := r if {
	r := input.context.renderer
	is_string(r)
}

# ---- Customer overlay aggregator ------------------------------------------
# Phase 4 slice 9a — the runner loads the customer's overlay bundle
# alongside the constitution. Each overlay rule lives under
# `data.overlay.<package_leaf>.deny` per `trustacks rule new`'s template.
# Walk every overlay package and merge its denies into our top-level
# `data.proposal.deny` so callers query one key and get the union.
#
# Same pattern for `gap`: overlays can declare
# `required_tooling_categories` on their rule_metadata; the join works
# identically once the overlay's metadata is exposed in the data tree.

deny contains msg if {
	some _, pkg in data.overlay
	some msg in pkg.deny
}

gap contains item if {
	some _, pkg in data.overlay
	some rule_id, meta in pkg.rule_metadata
	some category in meta.required_tooling_categories
	not _category_satisfied(category)
	item := {
		"rule_id": rule_id,
		"category": category,
	}
}

# ---- Gap analysis ---------------------------------------------------------
# `data.proposal.gap` returns one item per (rule, category) pair where a
# rule declares a `required_tooling_categories` entry but the customer's
# EnvironmentProfile (under `data.env.tooling_categories`) has no entry
# in that category. Advisory in 3b — not consumed by deny — but the
# wiring is what 3c's gap_check event will read.

gap contains item if {
	some rule_id, meta in rule_metadata
	some category in meta.required_tooling_categories
	not _category_satisfied(category)
	item := {
		"rule_id": rule_id,
		"category": category,
	}
}

# A category is satisfied when the customer has declared at least one
# entry. Missing data.env or missing category key = not satisfied.
_category_satisfied(category) if {
	entries := data.env.tooling_categories[category]
	count(entries) > 0
}
