# practice.k8s_workload_restricted — every emitted Kubernetes Deployment
# carries the restricted workload baseline and nothing that breaks it.
#
# ADR-0070 §2. One baseline for every distribution: it runs unchanged under
# OpenShift's restricted-v2 SCC and passes Pod Security Admission `restricted`
# on vanilla Kubernetes. Required, written literally in the Deployment:
#
#   pod:       runAsNonRoot: true, seccompProfile type RuntimeDefault
#   container: allowPrivilegeEscalation: false, capabilities drop ALL,
#              resources with requests and limits
#
# Refused: a fixed runAsUser / runAsGroup / fsGroup (OpenShift assigns them
# from the namespace's range and rejects a pod that asks for its own; on
# vanilla the image's numeric USER already satisfies runAsNonRoot), added
# capabilities, privileged, hostPath, hostNetwork, hostPID, hostIPC, and a literal
# containerPort at or below 1024.
#
# Text checks, not YAML: a Helm template is not parseable YAML until it is
# rendered, and the DevOps Engineer is told to write the baseline literally
# rather than through `toYaml .Values...` so this rule can read it. A value
# pulled from values.yaml reads as missing, which fails closed.
#
# Applicability is by path — `gitops/**/deployment.yaml` — so the Control
# Plane can mirror it without evaluating rego (proposal_evidence.py
# _APPLICABILITY): the rule judges exactly the files the CP counts as judged.
#
# Shares the `non_root_containers` dimension with the Dockerfile rule: the
# image declares a non-root user, the workload refuses to run as root. Either
# one denying contradicts the claim.

package proposal

import rego.v1

rule_metadata["practice.k8s_workload_restricted"] := {
	"description": "Every Kubernetes Deployment sets runAsNonRoot, RuntimeDefault seccomp, allowPrivilegeEscalation: false, drops ALL capabilities and declares requests and limits; every container drops ALL, disallows privilege escalation and declares cpu or memory requests and limits; no fixed runAsUser/runAsGroup/fsGroup, privileged, hostNetwork/hostPID/hostIPC, hostPath, added capabilities or ports <= 1024.",
	"required_tooling_categories": [],
	"practice_dimensions": ["non_root_containers"],
	"tier_scope": ["any"],
	"target_kinds": ["kubernetes"],
	"subjects": ["proposal"],
}

_k8s_restricted_required := {
	"runAsNonRoot: true": `(?m)^\s*runAsNonRoot:\s*true\s*$`,
	"seccompProfile type RuntimeDefault": `(?m)^\s*(type:\s*RuntimeDefault|seccompProfile:\s*\{\s*type:\s*RuntimeDefault\s*\})\s*$`,
}

# Per-container settings, each required once per container. A text rule cannot
# tell which container a line belongs to, so it counts: every container has
# exactly one `image:` (initContainers included), and each setting must appear
# at least that many times. One hardened container no longer covers the rest.
# `requests` / `limits` must name cpu or memory: `requests: {}` is not a request.
_k8s_restricted_per_container := {
	"allowPrivilegeEscalation: false": `(?m)^\s*allowPrivilegeEscalation:\s*false\s*$`,
	"capabilities drop ALL": `(?m)^\s*(drop:\s*\[\s*["']?ALL["']?\s*\]|drop:\s*\n\s*-\s*["']?ALL["']?)\s*$`,
	"resources.requests with cpu or memory": `(?m)^\s*requests:\s*(\{[^}]*\b(cpu|memory)\s*:[^}]*\}\s*$|\n\s+(cpu|memory):)`,
	"resources.limits with cpu or memory": `(?m)^\s*limits:\s*(\{[^}]*\b(cpu|memory)\s*:[^}]*\}\s*$|\n\s+(cpu|memory):)`,
}

_k8s_restricted_forbidden := {
	"a fixed runAsUser": `(?m)^\s*runAsUser:`,
	"a fixed runAsGroup": `(?m)^\s*runAsGroup:`,
	"a fixed fsGroup": `(?m)^\s*fsGroup:`,
	"privileged: true": `(?m)^\s*privileged:\s*true\b`,
	"a hostPath volume": `(?m)^\s*-?\s*hostPath:`,
	"hostNetwork: true": `(?m)^\s*hostNetwork:\s*true\b`,
	"hostPID: true": `(?m)^\s*hostPID:\s*true\b`,
	"hostIPC: true": `(?m)^\s*hostIPC:\s*true\b`,
	"added capabilities": `(?m)^\s*add:|capabilities:\s*\{[^}]*\badd\s*:`,
}

deny contains msg if {
	target_kind == "kubernetes"
	some f in input.proposal.files
	_is_k8s_deployment(f.path)
	text := _k8s_uncommented(f.content)
	some label, pattern in _k8s_restricted_required
	not regex.match(pattern, text)
	msg := {
		"rule_id": "practice.k8s_workload_restricted",
		"message": sprintf(
			"file %v: the Deployment must set %v, written literally (not via toYaml .Values) so it can be checked",
			[f.path, label],
		),
	}
}

deny contains msg if {
	target_kind == "kubernetes"
	some f in input.proposal.files
	_is_k8s_deployment(f.path)
	text := _k8s_uncommented(f.content)
	containers := count(regex.find_n(`(?m)^\s*-?\s*image:\s*\S`, text, -1))
	some label, pattern in _k8s_restricted_per_container
	count(regex.find_n(pattern, text, -1)) < max([containers, 1])
	msg := {
		"rule_id": "practice.k8s_workload_restricted",
		"message": sprintf(
			"file %v: every container must set %v, written literally (not via toYaml .Values) so it can be checked",
			[f.path, label],
		),
	}
}

deny contains msg if {
	target_kind == "kubernetes"
	some f in input.proposal.files
	_is_k8s_deployment(f.path)
	text := _k8s_uncommented(f.content)
	some label, pattern in _k8s_restricted_forbidden
	regex.match(pattern, text)
	msg := {
		"rule_id": "practice.k8s_workload_restricted",
		"message": sprintf(
			"file %v: the Deployment must not set %v (it breaks OpenShift's restricted-v2 SCC or Pod Security Admission `restricted`)",
			[f.path, label],
		),
	}
}

deny contains msg if {
	target_kind == "kubernetes"
	some f in input.proposal.files
	_is_k8s_deployment(f.path)
	text := _k8s_uncommented(f.content)
	some m in regex.find_all_string_submatch_n(`(?m)^\s*-?\s*containerPort:\s*["']?(\d+)["']?\s*(#.*)?$`, text, -1)
	to_number(m[1]) <= 1024
	msg := {
		"rule_id": "practice.k8s_workload_restricted",
		"message": sprintf(
			"file %v: containerPort %v must be above 1024 (binding a low port needs a capability the baseline drops)",
			[f.path, m[1]],
		),
	}
}

_is_k8s_deployment(path) if {
	startswith(path, "gitops/")
	endswith(path, "/deployment.yaml")
}

_is_k8s_deployment(path) if {
	startswith(path, "gitops/")
	endswith(path, "/deployment.yml")
}

# The file with comment lines removed, so a commented-out `runAsUser:` neither
# satisfies nor trips anything.
_k8s_uncommented(content) := concat("\n", [l |
	some l in split(content, "\n")
	not startswith(trim_space(l), "#")
])
