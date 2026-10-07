# Tests for the `practice.*` rules (slice 14.5).
#
# Every test file in the constitution shares `package proposal_test`, so the
# fixtures in proposal/fixtures_test.rego are visible here. Run the whole
# tree with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

# ---- Slice 14.5 practice rules -------------------------------------------

test_practice_workflow_has_test_step_denies_workflow_with_no_test_command if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  build:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - run: ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_has_test_step"
}

test_practice_workflow_has_lint_step_denies_workflow_with_no_lint_command if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - run: pytest -q",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_has_lint_step"
}

# Surfaced live 2026-05-06 walking the deploy loop end-to-end:
# the Go framework pack canonically emits `go vet ./...` as its
# static-analysis step, but the rule's substring list didn't accept
# it. Same shape would block .NET (`dotnet format`) once it lands a
# real lint step. Pin the accepted Go substrings here so the
# constitution-vs-pack alignment can't silently regress.
test_practice_workflow_has_lint_step_accepts_go_vet if {
	go_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5",
		"      - run: go vet ./...",
		"      - run: go test -race ./...",
		"",
	])
	candidate := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": go_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as candidate
	not _has_rule(violations, "practice.workflow_has_lint_step")
}

test_practice_workflow_has_lint_step_accepts_staticcheck if {
	go_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5",
		"      - run: go install honnef.co/go/tools/cmd/staticcheck@latest && staticcheck ./...",
		"      - run: go test ./...",
		"",
	])
	candidate := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": go_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as candidate
	not _has_rule(violations, "practice.workflow_has_lint_step")
}

_has_rule(violations, rule_id) if {
	some v in violations
	v.rule_id == rule_id
}

test_practice_argocd_prod_requires_manual_sync_denies_automated_sync if {
	prod_app_content := concat("\n", [
		"apiVersion: argoproj.io/v1alpha1",
		"kind: Application",
		"spec:",
		"  syncPolicy:",
		"    automated:",
		"      prune: true",
		sprintf("  source:\n    repoURL: %v", [PLATFORM_URL]),
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		{
			"path": "argo-apps/argo-apps-prod/demo-application.yaml",
			"content": prod_app_content,
		},
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.argocd_prod_requires_manual_sync"
}

test_practice_argocd_prod_only_fires_on_prod_path if {
	# Same automated-sync content but on a non-prod cluster path —
	# the rule should NOT fire (tier_scope is ["prod"]).
	dev_app_content := concat("\n", [
		"apiVersion: argoproj.io/v1alpha1",
		"kind: Application",
		"spec:",
		"  syncPolicy:",
		"    automated:",
		"      prune: true",
		sprintf("  source:\n    repoURL: %v", [PLATFORM_URL]),
		"",
	])
	dev_input := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		{
			"path": "argo-apps/argo-apps-local-k3d/demo-application.yaml",
			"content": dev_app_content,
		},
	]})})
	violations := proposal.deny with input as dev_input
	# practice.argocd_prod_requires_manual_sync should NOT appear among
	# the rule_ids — automated sync is fine on non-prod clusters.
	rule_ids := {v.rule_id | some v in violations}
	not "practice.argocd_prod_requires_manual_sync" in rule_ids
}

test_practice_dockerfile_runs_as_nonroot_denies_root_user if {
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		good_input.proposal.files[2],
		{
			"path": "gitops/checkout/local-k3d/demo/Dockerfile",
			"content": "FROM alpine:3\nUSER root\nCMD ['/bin/sh']\n",
		},
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.dockerfile_runs_as_nonroot"
}

test_practice_dockerfile_passes_with_nonroot_user if {
	good := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		good_input.proposal.files[0],
		good_input.proposal.files[1],
		good_input.proposal.files[2],
		{
			"path": "gitops/checkout/local-k3d/demo/Dockerfile",
			"content": "FROM alpine:3\nUSER 1001\nCMD ['/bin/sh']\n",
		},
	]})})
	violations := proposal.deny with input as good
	rule_ids := {v.rule_id | some v in violations}
	not "practice.dockerfile_runs_as_nonroot" in rule_ids
}

test_practice_workflow_pins_action_versions_denies_unpinned_third_party if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: docker/build-push-action@v5", # third-party + tag, not SHA
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	# Tag-shaped ref (`v5`) gets the original "should pin to a SHA, not a tag" message.
	contains(v.message, "should pin to a SHA, not a tag")
}

# Slice 20a.1 — agents that hallucinate a 39-char "SHA" get a more
# diagnostic message that names the length defect, not "use a SHA"
# (which is misleading when they were trying to).
test_practice_workflow_pins_action_versions_diagnoses_near_sha if {
	near_sha := "f325610c9f50a54015d37c8d16cb3b0e2c8f4de" # 39 chars — one short
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		sprintf("      - uses: anchore/sbom-action@%s", [near_sha]),
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	# Diagnostic message names the length defect.
	contains(v.message, "not exactly 40 characters")
	contains(v.message, "got 39")
}

# A 41-char hex string also lands in the near-SHA bucket.
test_practice_workflow_pins_action_versions_diagnoses_too_long_near_sha if {
	too_long := "f325610c9f50a54015d37c8d16cb3b0e2c8f4dee1" # 41 chars
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		sprintf("      - uses: anchore/sbom-action@%s", [too_long]),
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "got 41")
}

# A short 7-char hex (git's default short-SHA length) also classifies
# as near-SHA. Some agents emit truncated SHAs from training data.
test_practice_workflow_pins_action_versions_diagnoses_short_hex if {
	short := "deadbee" # 7 chars hex
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		sprintf("      - uses: anchore/sbom-action@%s", [short]),
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "not exactly 40 characters")
}

# A real semver tag (`v1.2.3`) is NOT hex — falls into the tag bucket
# and gets the original message.
test_practice_workflow_pins_action_versions_real_tag_gets_tag_message if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: anchore/sbom-action@v0.20.5",
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "should pin to a SHA, not a tag")
	# AND the diagnostic-message branch should NOT also fire for the same ref.
	count([violation |
		some violation in violations
		violation.rule_id == "practice.workflow_pins_action_versions"
	]) == 1
}

# Branch-name-shaped refs (`main`) classify as tag too.
test_practice_workflow_pins_action_versions_branch_name_gets_tag_message if {
	bad_workflow := concat("\n", [
		"name: ci",
		"on: [push]",
		"jobs:",
		"  test:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		"      - uses: anchore/sbom-action@main",
		"      - run: pytest -q && ruff check .",
		"",
	])
	bad := object.union(good_input, {"proposal": object.union(good_input.proposal, {"files": [
		{"path": ".github/workflows/ci.yaml", "content": bad_workflow},
		good_input.proposal.files[1],
		good_input.proposal.files[2],
	]})})
	violations := proposal.deny with input as bad
	some v in violations
	v.rule_id == "practice.workflow_pins_action_versions"
	contains(v.message, "should pin to a SHA, not a tag")
}
