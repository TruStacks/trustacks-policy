# Constitution rules for PlatformChangeProposals.
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
# Tests live in proposal_test.rego; run with `opa test policy/constitution`.

package proposal

import rego.v1

# ---- Rule metadata --------------------------------------------------------
# Single source of truth for every rule the constitution exports.
# `rule_index` re-publishes this for external consumers (DevOps agent
# prompt, gap query, future Coordinator agent). Adding a rule = adding
# a deny block + an entry here.

rule_metadata := {
	"proposal.allowed_paths": {
		"description": "Every artifact path lives under gitops/, argo-apps/, or .github/workflows/.",
		"required_tooling_categories": [],
		"practice_dimensions": [],
		"tier_scope": ["any"],
	},
	"proposal.no_path_traversal": {
		"description": "No artifact path is absolute or contains a `..` segment.",
		"required_tooling_categories": [],
		"practice_dimensions": [],
		"tier_scope": ["any"],
	},
	"proposal.has_workflow": {
		"description": "Proposal includes at least one .github/workflows/*.yaml file.",
		"required_tooling_categories": ["ci_cd_platform"],
		"practice_dimensions": [],
		"tier_scope": ["any"],
	},
	"proposal.has_helm_chart": {
		"description": "Proposal includes at least one Chart.yaml under the gitops/ service root (helm renderer).",
		"required_tooling_categories": [],
		"practice_dimensions": [],
		"tier_scope": ["any"],
	},
	"proposal.has_kustomization": {
		"description": "Proposal includes at least one kustomization.yaml under the gitops/ service root (kustomize renderer).",
		"required_tooling_categories": [],
		"practice_dimensions": [],
		"tier_scope": ["any"],
	},
	"proposal.has_argocd_application": {
		"description": "Proposal includes at least one argo-apps/argo-apps-<cluster>/<svc>-application.yaml.",
		"required_tooling_categories": ["gitops_controller"],
		"practice_dimensions": [],
		"tier_scope": ["any"],
	},
	"argocd.repoURL_is_canonical": {
		"description": "Every ArgoCD Application's spec.source.repoURL equals the platform repo URL.",
		"required_tooling_categories": [],
		"practice_dimensions": [],
		"tier_scope": ["any"],
	},
	# ---- Practice rules (slice 14.5) ----------------------------------
	# These answer "are you using your tools correctly?" rather than "do
	# you have the tools?" Each rule fires deny on a proposal when the
	# emitted artifact violates the practice; each is also linked to a
	# `practice_dimensions` key the customer self-attests to in
	# EnvironmentProfile.practices, so the maturity scorer can blend
	# practice posture into coverage_pct.
	"practice.workflow_has_test_step": {
		"description": "Every CI workflow declares a step that runs the test suite (pytest / npm / yarn / pnpm / dotnet test / go test, or a Maven or Gradle test, verify or check).",
		"required_tooling_categories": [],
		"practice_dimensions": ["tests_in_ci"],
		"tier_scope": ["any"],
	},
	"practice.workflow_has_lint_step": {
		"description": "Every CI workflow declares a lint/static-analysis step (ruff / eslint / biome / golangci-lint / go vet / staticcheck / dotnet format / checkstyle / spotless / spotbugs / pmd / -Dlint).",
		"required_tooling_categories": [],
		"practice_dimensions": ["linting_in_ci"],
		"tier_scope": ["any"],
	},
	"practice.argocd_prod_requires_manual_sync": {
		"description": "ArgoCD Applications targeting prod must opt out of automated sync (spec.syncPolicy.automated absent).",
		"required_tooling_categories": [],
		"practice_dimensions": ["manual_promotion_to_prod"],
		"tier_scope": ["prod"],
	},
	"practice.dockerfile_runs_as_nonroot": {
		"description": "Every Dockerfile in the proposal declares a USER directive other than root/0.",
		"required_tooling_categories": [],
		"practice_dimensions": ["non_root_containers"],
		"tier_scope": ["any"],
	},
	"practice.workflow_pins_action_versions": {
		"description": "Every third-party `uses:` action in a workflow pins to a SHA, not just a tag.",
		"required_tooling_categories": [],
		"practice_dimensions": ["supply_chain_pinning"],
		"tier_scope": ["any"],
	},
	# ---- Posture rules (ADR-0050 decision 3) ---------------------------
	# Ten of the twelve tooling categories were named by NO rule, so a
	# customer could declare eight categories of real work and move their
	# score by exactly zero. These four close that for the categories the
	# tool-actions packs can already corroborate — trivy, semgrep,
	# gitleaks, syft/cosign — so the evidence machinery from amendment 1
	# has something to bite on. Until now the two sets were disjoint and
	# it verified nothing.
	#
	# **These carry no deny block, deliberately, and that is a different
	# kind of rule.** A deny here would reject every proposal whose
	# pipeline has no image scan — including every proposal our own DevOps
	# Engineer emits — turning a posture gap into a hard delivery stop on
	# the day it shipped. The category question is "what is your posture",
	# answered by the gap report and the score; it is not "is this
	# artifact valid", which is what deny decides.
	#
	# `enforcement` makes the distinction explicit rather than leaving it
	# to be inferred from the absence of a deny block, because the rules
	# inventory shows these to customers and "rule" must not quietly mean
	# two things (#512 is the same complaint about "attested").
	"posture.image_scanning_declared": {
		"description": "An image scanner (trivy, grype, snyk) is declared and observed running in the pipeline.",
		"required_tooling_categories": ["image_scanning"],
		"practice_dimensions": [],
		"tier_scope": ["any"],
		"enforcement": "posture",
	},
	"posture.sast_sca_declared": {
		"description": "A SAST/SCA tool (semgrep, codeql, snyk) is declared and observed running in the pipeline.",
		"required_tooling_categories": ["sast_sca"],
		"practice_dimensions": [],
		"tier_scope": ["any"],
		"enforcement": "posture",
	},
	"posture.secret_scanning_declared": {
		"description": "A secret scanner (gitleaks, trufflehog) is declared and observed running in the pipeline.",
		"required_tooling_categories": ["secret_scanning"],
		"practice_dimensions": [],
		"tier_scope": ["any"],
		"enforcement": "posture",
	},
	"posture.sbom_signing_declared": {
		"description": "An SBOM generator and/or signer (syft, cosign) is declared and observed running in the pipeline.",
		"required_tooling_categories": ["sbom_signing"],
		"practice_dimensions": [],
		"tier_scope": ["any"],
		"enforcement": "posture",
	},
}

# Every rule that is not explicitly `posture` gates a proposal. Stated as a
# default rather than written onto each of the eleven gate rules, so adding a
# gate rule cannot accidentally inherit "posture" by forgetting a field.
rule_enforcement(rule_id) := enforcement if {
	enforcement := rule_metadata[rule_id].enforcement
} else := "gate"

rule_index := rule_metadata

# ---- Helpers --------------------------------------------------------------

allowed_prefixes := ["gitops/", "argo-apps/", ".github/workflows/"]

is_allowed_path(path) if {
	some prefix in allowed_prefixes
	startswith(path, prefix)
}

# ---- Rule 1: every artifact path must live under the whitelist -----------

deny contains msg if {
	some f in input.proposal.files
	not is_allowed_path(f.path)
	msg := {
		"rule_id": "proposal.allowed_paths",
		"message": sprintf(
			"file %v is outside the allowed path whitelist (%v)",
			[f.path, allowed_prefixes],
		),
	}
}

# ---- Rule 1b: reject absolute paths or `..` segments --------------------
# A path that starts with `helm/` still passes Rule 1 even if it's
# `helm/../../../etc/passwd`. This rule catches the escape — the writer
# used to enforce it inline, but in 3b rego is the single source of truth.

deny contains msg if {
	some f in input.proposal.files
	_path_traverses(f.path)
	msg := {
		"rule_id": "proposal.no_path_traversal",
		"message": sprintf(
			"file %v escapes the platform repo (absolute path or `..` segment)",
			[f.path],
		),
	}
}

_path_traverses(path) if startswith(path, "/")

_path_traverses(path) if {
	parts := split(path, "/")
	some part in parts
	part == ".."
}

# ---- Rule 2: at least one CI workflow ------------------------------------

deny contains msg if {
	count([f | some f in input.proposal.files; startswith(f.path, ".github/workflows/")]) == 0
	msg := {
		"rule_id": "proposal.has_workflow",
		"message": "proposal must include at least one .github/workflows/*.yaml file",
	}
}

# ---- Rule 3: the deploy artifact this Application's renderer requires -----
#
# ADR-0052. Until now this rule asked one question — "is there a Chart.yaml?" —
# and a correct Kustomize proposal has none. So the gate would have DENIED the
# right artifact and ALLOWED the wrong one, which is the worst direction for a
# rule to be wrong in: the customer picks kustomize, receives a chart, and the
# constitution confirms it.
#
# The renderer arrives on `input.context`, beside `platform_repo_url`, and NOT
# from `data.env`. It is a property of the artifacts being judged, not of the
# customer's environment — sourcing it from the profile would let the same set
# of files pass or fail depending on state edited somewhere else, and leave the
# rule unable to answer "is what I am looking at internally consistent?"
#
# Absent renderer means helm: every proposal before this one was, and an older
# runner must be judged exactly as it was.

default renderer := "helm"

renderer := r if {
	r := input.context.renderer
	is_string(r)
}

deny contains msg if {
	renderer == "helm"
	count([
	f |
		some f in input.proposal.files
		startswith(f.path, "gitops/")
		endswith(f.path, "/Chart.yaml")
	]) == 0
	msg := {
		"rule_id": "proposal.has_helm_chart",
		"message": "proposal must include at least one Chart.yaml under gitops/",
	}
}

deny contains msg if {
	renderer == "kustomize"
	count([
	f |
		some f in input.proposal.files
		startswith(f.path, "gitops/")
		endswith(f.path, "/kustomization.yaml")
	]) == 0
	msg := {
		"rule_id": "proposal.has_kustomization",
		"message": "proposal must include at least one kustomization.yaml under gitops/",
	}
}

# ---- Rule 4: at least one ArgoCD Application under argo-apps/argo-apps-<cluster>/

deny contains msg if {
	count([
	f |
		some f in input.proposal.files
		startswith(f.path, "argo-apps/argo-apps-")
		endswith(f.path, "-application.yaml")
	]) == 0
	msg := {
		"rule_id": "proposal.has_argocd_application",
		"message": "proposal must include at least one argo-apps/argo-apps-<cluster>/<svc>-application.yaml",
	}
}

# ---- Rule 5: ArgoCD Application repoURL must equal the canonical URL ----
# Catches the placeholder regression we hit during 2b.2 — agents have
# historically substituted "your-org/your-platform-repo.git" instead of
# using the URL the dispatcher passes in. The repoURL must match exactly.

deny contains msg if {
	some f in input.proposal.files
	startswith(f.path, "argo-apps/argo-apps-")
	endswith(f.path, "-application.yaml")
	doc := yaml.unmarshal(f.content)
	repo_url := doc.spec.source.repoURL
	repo_url != input.context.platform_repo_url
	msg := {
		"rule_id": "argocd.repoURL_is_canonical",
		"message": sprintf(
			"file %v: spec.source.repoURL is %v but must be %v",
			[f.path, repo_url, input.context.platform_repo_url],
		),
	}
}

# ---- Practice rules (slice 14.5) -----------------------------------------
# Behavior-level checks that fire when an emitted artifact violates a
# baseline practice. Each is paired with a `practice_dimensions` entry
# in rule_metadata so the maturity scorer can attribute the failure to
# a self-attested practice key.

# practice.workflow_has_test_step — every CI workflow includes at least
# one job step whose `run:` command invokes a recognised test runner.
deny contains msg if {
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	not _workflow_has_step_matching(wf, _test_runner_substrings)
	not _workflow_has_step_matching_re(wf, _jvm_test_pattern)
	msg := {
		"rule_id": "practice.workflow_has_test_step",
		"message": sprintf(
			"workflow %v has no step running the test suite (looked for pytest / npm test / yarn test / pnpm test / dotnet test / go test, or a Maven or Gradle invocation of `test`, `verify` or `check`, in `run:` commands)",
			[f.path],
		),
	}
}

# practice.workflow_has_lint_step — same shape, lint runners.
deny contains msg if {
	some f in input.proposal.files
	_is_workflow(f.path)
	wf := yaml.unmarshal(f.content)
	not _workflow_has_step_matching(wf, _lint_runner_substrings)
	msg := {
		"rule_id": "practice.workflow_has_lint_step",
		"message": sprintf(
			"workflow %v has no lint/static-analysis step (looked for any of: ruff, eslint, biome, golangci-lint, go vet, staticcheck, dotnet format, checkstyle, spotless, spotbugs, pmd, -Dlint in `run:` commands)",
			[f.path],
		),
	}
}

# practice.argocd_prod_requires_manual_sync — ArgoCD Applications
# under argo-apps/argo-apps-prod/ must NOT have automated sync.
deny contains msg if {
	some f in input.proposal.files
	startswith(f.path, "argo-apps/argo-apps-prod/")
	endswith(f.path, "-application.yaml")
	doc := yaml.unmarshal(f.content)
	doc.spec.syncPolicy.automated
	msg := {
		"rule_id": "practice.argocd_prod_requires_manual_sync",
		"message": sprintf(
			"file %v: prod ArgoCD Application has spec.syncPolicy.automated set; remove it so a human approves the sync",
			[f.path],
		),
	}
}

# practice.dockerfile_runs_as_nonroot — every Dockerfile declares a
# non-root USER. Reject any Dockerfile with no USER, or USER root /
# USER 0.
deny contains msg if {
	some f in input.proposal.files
	_is_dockerfile(f.path)
	not _dockerfile_runs_as_nonroot(f.content)
	msg := {
		"rule_id": "practice.dockerfile_runs_as_nonroot",
		"message": sprintf(
			"file %v: missing a non-root USER directive (declares no USER, or USER root / USER 0)",
			[f.path],
		),
	}
}

# practice.workflow_pins_action_versions — every third-party `uses:`
# entry pins to a SHA. Allow `actions/*` (GitHub-owned) and `./local`
# refs to use unpinned tags; reject every other `uses: <owner>/<repo>@<ref>`
# whose ref isn't a 40-char hex SHA.
#
# The deny rule splits on whether the bad ref *looks like* a near-SHA
# (hex-only + wrong length) vs an actual tag. Agents that hallucinate
# a 39-char "SHA" get a more diagnostic message than agents that emit
# `@v1.2.3`. Both paths emit the same rule_id so callers don't need
# to handle two error codes.
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

# ---- Practice helpers ----

_is_workflow(path) if {
	startswith(path, ".github/workflows/")
	endswith(path, ".yaml")
}

_is_workflow(path) if {
	startswith(path, ".github/workflows/")
	endswith(path, ".yml")
}

_is_dockerfile(path) if endswith(path, "/Dockerfile")

_is_dockerfile(path) if path == "Dockerfile"

# Needles are matched against a LOWERCASED command, so they must be lowercase
# themselves. `mvn -B verify -Dlint` used to live in the lint list and could
# never match anything — the command was lowercased and the needle was not, so
# Java could not satisfy the rule no matter what the agent emitted (#551). The
# comparison lowercases both sides now, which makes that class of bug
# impossible rather than fixed once.
_test_runner_substrings := ["pytest", "npm test", "yarn test", "pnpm test", "dotnet test", "go test"]

# JVM builds name a lifecycle phase or a task rather than a test runner, and
# flags sit between the tool and the goal — `mvn -B test`, `./gradlew test`,
# `mvn -B verify`. A substring list cannot express that without encoding one
# flag order, which is exactly how the dead needle above came to exist.
#
# `\btest\b` deliberately does not match `-DskipTests`: that flag turns the
# test phase OFF, and counting it would be worse than missing it.
# Maven and Gradle are listed separately because their vocabularies differ:
# `verify` runs tests in Maven and `check` does in Gradle, while Maven's
# `check` is a plugin goal (`mvn checkstyle:check`) that runs no tests at all.
# One combined alternation accepted that as a test step — a false pass, which
# is the direction that matters most here.
#
# The goal must be a whole word at the end or followed by a space, so
# `-DskipTests` (which turns tests off) and `test-compile` (which does not run
# them) are both excluded.
_jvm_test_pattern := `(^|[\s;&|(])(mvn\s+([^;&|]*\s+)?(test|verify)|(\./)?gradlew?\s+([^;&|]*\s+)?(test|check|build))(\s|$)`

# Industry-standard analysers, named rather than inferred from an invocation:
# spotless/spotbugs/pmd/checkstyle are the JVM equivalents of ruff and eslint,
# and `-dlint` catches the pack's `-Dlint=true` convention for a pom that gates
# its plugins on that property.
_lint_runner_substrings := [
	"ruff",
	"eslint",
	"biome",
	"golangci-lint",
	"go vet",
	"staticcheck",
	"dotnet format",
	"checkstyle",
	"spotless",
	"spotbugs",
	"pmd",
	"-dlint",
]

_workflow_has_step_matching(wf, needles) if {
	some _, job in wf.jobs
	some _, step in job.steps
	cmd := lower(step.run)
	some needle in needles
	contains(cmd, lower(needle))
}

_workflow_has_step_matching_re(wf, pattern) if {
	some _, job in wf.jobs
	some _, step in job.steps
	regex.match(pattern, lower(step.run))
}

# A Dockerfile passes when *some* USER directive declares a non-root
# identity. Strict definition: the value isn't `root` or `0` (after
# trimming whitespace). USER appearing later in the file overrides
# earlier ones, but for "passes" semantics we only need at least one
# non-root USER line — multi-stage builds with a final non-root USER
# satisfy this even if an earlier stage ran as root for build deps.
_dockerfile_runs_as_nonroot(content) if {
	some line in split(content, "\n")
	trimmed := trim_space(line)
	startswith(lower(trimmed), "user ")
	user := trim_space(substring(trimmed, 5, -1))
	user != ""
	user != "root"
	user != "0"
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
