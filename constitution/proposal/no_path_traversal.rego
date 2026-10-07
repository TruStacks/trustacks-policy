# proposal.no_path_traversal — reject absolute paths or `..` segments.
#
# Rule 1b. A path that starts with `helm/` still passes `allowed_paths` even
# if it's `helm/../../../etc/passwd`. This rule catches the escape — the
# writer used to enforce it inline, but in 3b rego is the single source of
# truth.

package proposal

import rego.v1

rule_metadata["proposal.no_path_traversal"] := {
	"description": "No artifact path is absolute or contains a `..` segment.",
	"required_tooling_categories": [],
	"practice_dimensions": [],
	"tier_scope": ["any"],
}

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
