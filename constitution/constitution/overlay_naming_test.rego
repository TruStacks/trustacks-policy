package constitution.overlay_rule_naming_test

import data.constitution.overlay_rule_naming
import rego.v1

# Stand-in for the data.naming.json sidecar that ``make policy-bundle``
# emits at build time. Tests must declare ``with data.naming as naming_data``
# on every call so the rule sees the same shape it gets at runtime.

naming_data := {
	"rule_id_pattern": "^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$",
	"reserved_namespaces": ["argocd", "constitution", "posture", "practice", "proposal", "trustacks"],
	"max_rule_id_length": 64,
	"version": 2,
}

# The stand-in above must be what actually ships. `opa test` loads the real
# data.naming.json beside these files, so compare the two: a stand-in that
# drifted from the sidecar would test a standard nobody enforces.
test_stand_in_matches_the_shipped_sidecar if {
	data.naming == naming_data
}

# ---- Valid rule_ids: no denies -----------------------------------------

test_valid_rule_id_no_deny if {
	input_doc := {"overlay": {"rules": {
		"acme.requires_runbook_link": {},
		"contoso.denies_public_ingress": {},
	}}}
	count(overlay_rule_naming.deny) == 0 with data.naming as naming_data with input as input_doc
}

# ---- Pattern denies ----------------------------------------------------

test_uppercase_id_denies if {
	input_doc := {"overlay": {"rules": {"Acme.RequiresRunbookLink": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.pattern"
}

test_no_dot_id_denies if {
	input_doc := {"overlay": {"rules": {"requires_runbook_link": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.pattern"
}

test_hyphen_id_denies if {
	input_doc := {"overlay": {"rules": {"acme-corp.requires_runbook": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.pattern"
}

test_leading_digit_id_denies if {
	input_doc := {"overlay": {"rules": {"9acme.foo": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.pattern"
}

# ---- Reserved-namespace denies ----------------------------------------

test_reserved_namespace_proposal_denies if {
	input_doc := {"overlay": {"rules": {"proposal.requires_runbook_link": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.reserved"
}

test_reserved_namespace_constitution_denies if {
	input_doc := {"overlay": {"rules": {"constitution.foo": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.reserved"
}

# Standard v2: every constitution directory is a reserved namespace. Before
# v2 the constitution shipped `practice.*` and `posture.*` rules without
# reserving either, so an overlay could have claimed `practice.foo` and had it
# read as a TruStacks-shipped practice rule.

test_reserved_namespace_practice_denies if {
	input_doc := {"overlay": {"rules": {"practice.requires_runbook_link": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.reserved"
}

test_reserved_namespace_posture_denies if {
	input_doc := {"overlay": {"rules": {"posture.vault_declared": {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.reserved"
}

# ---- Length denies ----------------------------------------------------
# 65 chars exceeds the cap of 64. Slug-shaped so only the length deny
# fires (not the pattern deny).

test_over_length_id_denies if {
	# 65 chars exceeds the cap of 64. "acme." (5) + 60 x's = 65 total.
	long_id := concat("", ["acme.", concat("", [
		"xxxxxxxxxx", "xxxxxxxxxx", "xxxxxxxxxx",
		"xxxxxxxxxx", "xxxxxxxxxx", "xxxxxxxxxx",
	])])
	count(long_id) == 65
	input_doc := {"overlay": {"rules": {long_id: {}}}}
	some msg in overlay_rule_naming.deny with data.naming as naming_data with input as input_doc
	msg.rule_id == "constitution.overlay_rule_naming.length"
}

# ---- Boundary: exactly 64 chars passes --------------------------------

test_at_length_cap_no_deny if {
	# 64-char slug: "acme." (5) + 59 x's = 64 total. Build with
	# concat so the count is unambiguous and the test stays robust
	# against editor-mangling of long runs of identical chars.
	id_at_cap := concat("", ["acme.", concat("", [
		"xxxxxxxxxx", "xxxxxxxxxx", "xxxxxxxxxx",
		"xxxxxxxxxx", "xxxxxxxxxx", "xxxxxxxxx",
	])])
	count(id_at_cap) == 64
	input_doc := {"overlay": {"rules": {id_at_cap: {}}}}
	count(overlay_rule_naming.deny) == 0 with data.naming as naming_data with input as input_doc
}

# ---- Multiple violations across multiple rules ------------------------

test_multiple_rules_multiple_denies if {
	input_doc := {"overlay": {"rules": {
		"acme.valid_one": {},
		"Acme.uppercase": {},
		"proposal.reserved": {},
	}}}
	count(overlay_rule_naming.deny) >= 2 with data.naming as naming_data with input as input_doc
}
