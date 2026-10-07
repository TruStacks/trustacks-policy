# Shared fixtures for the constitution's `package proposal` tests.
# No tests here — only the canonical inputs the per-namespace test files use.
#
# Every test file in the constitution shares `package proposal_test`, so these
# fixtures are visible to the tests in proposal/, argocd/, practice/ and
# posture/. Run the whole tree with: opa test policy/constitution

package proposal_test

import rego.v1

PLATFORM_URL := "https://example.invalid/acme/platform.git"

# A canonical "good" proposal — passes all five rules. Phase 4 layout:
# gitops/<app>/<cluster>/<svc>/Chart.yaml + argo-apps/argo-apps-<cluster>/<svc>-application.yaml.
# Slice 14.5 — the workflow now includes practice-satisfying steps
# (test + lint) and pinned action versions so the canonical proposal
# also passes the new practice rules. The cluster suffix stays
# `local-k3d` (non-prod) so the prod-manual-sync practice rule
# doesn't fire either.
good_workflow_content := concat("\n", [
	"name: ci",
	"on: [push]",
	"jobs:",
	"  test:",
	"    runs-on: ubuntu-latest",
	"    steps:",
	"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
	"      - run: ruff check .",
	"      - run: pytest -q",
	"",
])

good_input := {
	"proposal": {
		"files": [
			{
				"path": ".github/workflows/ci.yaml",
				"content": good_workflow_content,
			},
			{
				"path": "gitops/checkout/local-k3d/demo/Chart.yaml",
				"content": "name: demo\nversion: 0.1.0\n",
			},
			{
				"path": "argo-apps/argo-apps-local-k3d/demo-application.yaml",
				"content": sprintf(
					"apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  source:\n    repoURL: %v\n",
					[PLATFORM_URL],
				),
			},
		],
	},
	"context": {"platform_repo_url": PLATFORM_URL},
}

# A canonical "complete" EnvironmentProfile data set — every category has
# at least one entry. Tests that need a happy `data.env` substitute this
# whole map via `with data.env as ...`.
complete_env := {"tooling_categories": {
	"ci_cd_platform": ["github_actions"],
	"container_registry": ["ghcr"],
	"image_scanning": ["trivy"],
	"sast_sca": ["semgrep"],
	"secret_scanning": ["gitleaks"],
	"sbom_signing": ["cosign"],
	"gitops_controller": ["argocd"],
	"service_mesh_ingress": ["traefik"],
	"secrets_management": ["external_secrets_operator"],
	"observability": ["prometheus_grafana"],
	"ticketing_change_mgmt": ["jira"],
	"compliance_evidence": ["drata"],
}}

# A proposal declaring no image scanner, no SAST, no secret scanning and no
# SBOM — every condition the four posture rules describe. If any of them could
# deny, this is the input that would prove it.
empty_proposal_input := {
	"proposal": {"files": [], "explanation": {}},
	"context": {"platform_repo_url": "https://example.com/platform.git"},
}
