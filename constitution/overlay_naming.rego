# Constitution: customer-overlay rule-naming standard (ADR-0023, layer A4).
#
# This rule is distinct from the proposal-eval rules in `proposal.rego`:
# it operates on a customer's *overlay rule_metadata*, not on a
# platform-repo proposal. The package is `constitution.overlay_rule_naming`
# so the input shape is unambiguous from a quick eyeball:
#
#   input = {
#     "overlay": {
#       "rules": {
#         "<rule_id>": { ...rule_metadata fields... },
#         ...
#       }
#     }
#   }
#
# The standard itself (regex, reserved set, length cap) is sourced from
# a sidecar `data.naming.json` that `make policy-bundle` emits from the
# canonical Python module at `runner/src/trustacks_runner/policy/rule_naming.py`.
# OPA reads it as `data.naming.*` at eval time:
#
#   data.naming = {
#     "rule_id_pattern": "^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$",
#     "reserved_namespaces": ["argocd", "constitution", "proposal", "trustacks"],
#     "max_rule_id_length": 64
#   }
#
# That sidecar is the only place the regex string lives in this bundle;
# the rule body never hardcodes it. A CI lockstep test asserts that
# `data.naming.json` matches the canonical Python constants.
#
# Fires at `trustacks rule sign` time (today via the CLI's Python-side
# `validate_rule_id` call, which is the canonical source — this rule's
# job is to make the standard visible + auditable inside the signed
# constitution bundle; the runtime evaluator picks it up automatically
# when the standard becomes part of the runner's gap-analysis path).

package constitution.overlay_rule_naming

import rego.v1

# `deny` produces one entry per violating rule_id. Each entry's shape
# matches the proposal-rule convention (`{"rule_id": ..., "message": ...}`)
# so consumers can render naming-rule denies the same way they render
# proposal-rule denies. The `rule_id` field here refers to the
# *constitution rule that fired*, not the offending overlay rule_id —
# the offending id is in the message.

# ---- Deny 1: pattern violation ------------------------------------------

deny contains msg if {
	some id, _ in input.overlay.rules
	not regex.match(data.naming.rule_id_pattern, id)
	msg := {
		"rule_id": "constitution.overlay_rule_naming.pattern",
		"message": sprintf(
			"overlay rule_id %q does not match the rule-naming standard (%v)",
			[id, data.naming.rule_id_pattern],
		),
	}
}

# ---- Deny 2: reserved namespace -----------------------------------------
# Only fires when the pattern matches — otherwise the namespace split
# is meaningless. ``regex.match`` is the same check used in deny 1, so
# we re-run it here rather than introducing a shared helper (keeps each
# deny self-contained and readable on a quick scan).

deny contains msg if {
	some id, _ in input.overlay.rules
	regex.match(data.naming.rule_id_pattern, id)
	parts := split(id, ".")
	parts[0] in data.naming.reserved_namespaces
	msg := {
		"rule_id": "constitution.overlay_rule_naming.reserved",
		"message": sprintf(
			"overlay rule_id %q uses the reserved namespace %q",
			[id, parts[0]],
		),
	}
}

# ---- Deny 3: length cap -------------------------------------------------

deny contains msg if {
	some id, _ in input.overlay.rules
	count(id) > data.naming.max_rule_id_length
	msg := {
		"rule_id": "constitution.overlay_rule_naming.length",
		"message": sprintf(
			"overlay rule_id %q exceeds the %v-character rule_id length cap (%v chars)",
			[id, data.naming.max_rule_id_length, count(id)],
		),
	}
}
