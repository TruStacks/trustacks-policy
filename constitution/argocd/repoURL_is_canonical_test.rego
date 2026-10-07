# Tests for `argocd.repoURL_is_canonical`.
#
# Every test file in the constitution shares `package proposal_test`, so the
# fixtures in proposal/fixtures_test.rego are visible here. Run the whole
# tree with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

# ---- rule 5: repoURL_is_canonical ---------------------------------------

test_deny_when_argocd_repoURL_is_placeholder if {
	bad_repo := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		{
			"path": "argo-apps/argo-apps-local-k3d/demo-application.yaml",
			"content": "apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  source:\n    repoURL: https://github.com/your-org/your-platform-repo.git\n",
		},
	]})})
	violations := proposal.deny with input as bad_repo
	some v in violations
	v.rule_id == "argocd.repoURL_is_canonical"
}
