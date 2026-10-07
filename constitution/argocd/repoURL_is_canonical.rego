# argocd.repoURL_is_canonical — an ArgoCD Application's repoURL must equal the
# canonical platform repo URL.
#
# Rule 5 of the original five. Catches the placeholder regression we hit
# during 2b.2 — agents have historically substituted
# "your-org/your-platform-repo.git" instead of using the URL the dispatcher
# passes in. The repoURL must match exactly.
#
# `package proposal`, like every gate rule, so it is part of
# `data.proposal.deny`; the directory names the rule's namespace, not its
# package (see proposal/lib.rego).

package proposal

import rego.v1

rule_metadata["argocd.repoURL_is_canonical"] := {
	"description": "Every ArgoCD Application's spec.source.repoURL equals the platform repo URL.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

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
