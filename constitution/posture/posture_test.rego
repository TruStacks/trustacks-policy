# Tests for the `posture.*` rules — scored, never a deny.
#
# Every test file in the constitution shares `package proposal_test`, so the
# fixtures in proposal/fixtures_test.rego are visible here. Run the whole
# tree with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

# ---- Gate vs posture (ADR-0050 decision 3) -------------------------------
# A posture rule scores a category and never blocks a proposal. The
# distinction has to be readable from the metadata, because the rules
# inventory shows both to customers and "rule" must not mean two things.

test_posture_rules_are_marked_as_posture if {
	every rid in [
		"posture.image_scanning_declared",
		"posture.sast_sca_declared",
		"posture.secret_scanning_declared",
		"posture.sbom_signing_declared",
	] {
		proposal.rule_enforcement(rid) == "posture"
	}
}

test_gate_rules_default_to_gate if {
	# Absence of the field means gate, so a new gate rule cannot inherit
	# "posture" by forgetting to say so.
	proposal.rule_enforcement("proposal.has_workflow") == "gate"
	proposal.rule_enforcement("practice.dockerfile_runs_as_nonroot") == "gate"
}

test_posture_rules_never_deny if {
	# The whole reason they carry no deny block: a deny here would reject
	# every proposal whose pipeline has no image scan — including every
	# proposal our own DevOps Engineer emits.
	#
	# Deliberately run against an input that DOES deny. Asserted over
	# `good_input` this passes on an empty deny set, which is the state it
	# is supposed to be ruling out — a test that holds because nothing
	# happened proves nothing about what happens.
	violations := proposal.deny with input as empty_proposal_input
	fired := {v.rule_id | some v in violations}

	# The premise: this input really does fire gate rules.
	count(fired) > 0

	# The claim: not one of them is a posture rule.
	every rid in fired {
		proposal.rule_enforcement(rid) == "gate"
	}
}

test_posture_categories_still_surface_as_gaps if {
	# The other half of "posture": it does not deny, but it must still be
	# reportable, or the rule is inert rather than advisory.
	gaps := proposal.gap with data.env as {"tooling_categories": {
		"ci_cd_platform": ["github_actions"],
		"gitops_controller": ["argocd"],
	}}
	categories := {item.category | some item in gaps}
	categories == {"image_scanning", "sast_sca", "secret_scanning", "sbom_signing"}
}
