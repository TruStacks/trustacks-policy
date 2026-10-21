# practice.dockerfile_runs_as_nonroot — every Dockerfile declares a non-root
# USER. Reject any Dockerfile with no USER, or USER root / USER 0.

package proposal

import rego.v1

rule_metadata["practice.dockerfile_runs_as_nonroot"] := {
	"description": "Every Dockerfile in the proposal declares a USER directive other than root/0.",
	"required_tooling_categories": [],
	"practice_dimensions": ["non_root_containers"],
	"tier_scope": ["any"],
}

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

# A Dockerfile passes when the user its final image runs as is not root.
# That is the LAST `USER` instruction in the FINAL stage, the instructions
# after the last `FROM`: earlier stages only build, and a later `USER`
# overrides an earlier one. The user part (before any `:group`) must not be
# `root` or `0`.
#
# #696: this used to pass if *any* USER line anywhere was non-root, so
# `USER 1001` then `USER root`, `USER 0:0` and `USER root:root` all passed
# while the container ran as root. A final stage with no USER fails, because
# it runs as whatever the base image defaults to, which is usually root.
#
# Two more ways to look non-root while running as root (review on #698):
# - Lines inside a here-document (`COPY <<EOF ... EOF`) are file content, not
#   instructions, so they are never read as USER or FROM.
# - A USER built from a variable (`USER ${APP_USER}`) fails closed: a build
#   argument can override the default, so the effective user cannot be known
#   from the Dockerfile.
_dockerfile_runs_as_nonroot(content) if {
	user := _final_user(content)
	user != ""
	user != "root"
	user != "0"
	not contains(user, "$")
}

# Logical instruction lines, joined the way Docker's parser joins them (review
# on trustacks-policy#11). Each case below was checked with a real
# `docker build`:
# - An instruction line ending in the escape character continues onto the
#   next, so `RUN echo hi \` then `USER 1001` is one RUN, not a USER.
# - Comment and blank lines inside a continuation are dropped.
# - A comment line never continues: `# note \` then `USER root` is a USER.
# - An escape that follows another escape does not continue: `RUN echo hi \\`
#   then `USER root` is a USER, and so is three of them. This mirrors
#   buildkit's own test, `([^E])E[ \t]*$|^E[ \t]*$` for escape E.
_lines(content) := [trim_space(l) | some l in split(_joined(content), "\n")]

_joined(content) := regex.replace(content, _continuation(_escape(content)), "${1} ")

# Group 1 is the instruction line without its continuing escape: a line that
# doesn't start with `#`, whose final escape follows a non-escape character,
# or a line that is only the escape.
_continuation(e) := concat("", [
	`(?m)^([ \t]*(?:[^#\s\n][^\n]*[^`, e, `\n]|[^#\s`, e, `\n])?)`,
	e, `[ \t]*\r?\n(?:[ \t]*(?:#[^\n]*)?\r?\n)*`,
])

# The escape character: backslash, or backtick when an `# escape=`` parser
# directive says so. Directives must open the file, and only the ones Docker
# knows (`syntax`, `check`) may come before `escape`: an unknown one is a
# comment, and after a comment Docker stops reading directives.
_escape(content) := "\u0060" if {
	regex.match(`(?i)\A(?:[ \t]*#[ \t]*(?:syntax|check)[ \t]*=[^\n]*\n)*[ \t]*#[ \t]*escape[ \t]*=[ \t]*\x60`, content)
} else := `\\`

# Indices of lines that are here-document bodies (and their terminators).
_heredoc_lines(lines) := {k |
	some i
	m := regex.find_all_string_submatch_n(`<<-?["']?([A-Za-z_][A-Za-z0-9_]*)["']?`, lines[i], 1)
	count(m) > 0
	delim := m[0][1]
	ends := {j | some j; j > i; lines[j] == delim}
	count(ends) > 0
	some k in numbers.range(i + 1, min(ends))
}

_instructions(lines) := {i | some i; lines[i]; not i in _heredoc_lines(lines)}

_final_stage_start(lines) := max(froms) if {
	froms := {i | some i in _instructions(lines); regex.match(`^(?i)from\s`, lines[i])}
	count(froms) > 0
} else := -1

_final_user(content) := user if {
	lines := _lines(content)
	start := _final_stage_start(lines)
	users := {i | some i in _instructions(lines); i > start; regex.match(`^(?i)user\s+\S`, lines[i])}
	count(users) > 0
	value := trim_space(regex.replace(lines[max(users)], `^(?i)user\s+`, ""))
	user := trim_space(split(value, ":")[0])
}
