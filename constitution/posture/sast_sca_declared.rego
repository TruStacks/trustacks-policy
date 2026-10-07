# posture.sast_sca_declared — posture rule (ADR-0050 decision 3).
#
# Ten of the twelve tooling categories were named by NO rule, so a customer
# could declare eight categories of real work and move their score by exactly
# zero. The four posture rules close that for the categories the tool-actions
# packs can already corroborate — trivy, semgrep, gitleaks, syft/cosign — so
# the evidence machinery from amendment 1 has something to bite on.
#
# **No deny block, deliberately, and that is a different kind of rule.** A deny
# here would reject every proposal whose pipeline has no SAST/SCA step —
# including every proposal our own DevOps Engineer emits — turning a posture
# gap into a hard delivery stop on the day it shipped. The category question is
# "what is your posture", answered by the gap report and the score; it is not
# "is this artifact valid", which is what deny decides.
#
# `enforcement` makes the distinction explicit rather than leaving it to be
# inferred from the absence of a deny block, because the rules inventory shows
# these to customers and "rule" must not quietly mean two things (#512 is the
# same complaint about "attested").

package proposal

import rego.v1

rule_metadata["posture.sast_sca_declared"] := {
	"description": "A SAST/SCA tool (semgrep, codeql, snyk) is declared and observed running in the pipeline.",
	"required_tooling_categories": ["sast_sca"],
	"practice_dimensions": [],
	"tier_scope": ["any"],
	"enforcement": "posture",
}
