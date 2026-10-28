# Tests for practice.k8s_workload_restricted (ADR-0070 §2).
# Run with: opa test policy/constitution

package proposal_test

import data.proposal
import rego.v1

k8s_restricted_path := "gitops/shop/prod/api/templates/deployment.yaml"

# A Helm template that carries the full baseline. `{{ }}` stays in: the rule
# reads text precisely because templates are not YAML until rendered.
k8s_restricted_good := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
`

k8s_restricted_input(content) := {"proposal": {"files": [{"path": k8s_restricted_path, "content": content}]}}

k8s_restricted_denials(content) := {m.message |
	some m in proposal.deny with input as k8s_restricted_input(content)
	m.rule_id == "practice.k8s_workload_restricted"
}

test_k8s_restricted_allows_the_baseline if {
	count(k8s_restricted_denials(k8s_restricted_good)) == 0
}

test_k8s_restricted_allows_block_style_drop_and_inline_seccomp if {
	content := replace(
		replace(k8s_restricted_good, `drop: ["ALL"]`, "drop:\n                - ALL"),
		"seccompProfile:\n          type: RuntimeDefault",
		"seccompProfile: { type: RuntimeDefault }",
	)
	count(k8s_restricted_denials(content)) == 0
}

test_k8s_restricted_denies_each_missing_field if {
	every field in [
		"runAsNonRoot: true",
		"type: RuntimeDefault",
		"allowPrivilegeEscalation: false",
		`drop: ["ALL"]`,
		"requests:",
		"limits:",
	] {
		count(k8s_restricted_denials(replace(k8s_restricted_good, field, ""))) > 0
	}
}

test_k8s_restricted_denies_a_baseline_pulled_from_values if {
	content := replace(
		k8s_restricted_good,
		"      securityContext:\n        runAsNonRoot: true\n        seccompProfile:\n          type: RuntimeDefault\n",
		"      securityContext: {{- toYaml .Values.podSecurityContext | nindent 8 }}\n",
	)
	count(k8s_restricted_denials(content)) > 0
}

test_k8s_restricted_denies_fixed_ids_and_host_access if {
	every extra in [
		"        runAsUser: 1001\n",
		"        runAsGroup: 0\n",
		"        fsGroup: 1001\n",
		"      hostNetwork: true\n",
		"      hostPID: true\n",
	] {
		content := replace(k8s_restricted_good, "        runAsNonRoot: true\n", concat("", ["        runAsNonRoot: true\n", extra]))
		count(k8s_restricted_denials(content)) > 0
	}
}

test_k8s_restricted_denies_privileged_added_capabilities_and_hostpath if {
	every swap in [
		["allowPrivilegeEscalation: false", "allowPrivilegeEscalation: false\n            privileged: true"],
		[`drop: ["ALL"]`, "drop: [\"ALL\"]\n              add: [\"NET_ADMIN\"]"],
		["      containers:", "      volumes:\n        - name: host\n          hostPath:\n            path: /var\n      containers:"],
	] {
		count(k8s_restricted_denials(replace(k8s_restricted_good, swap[0], swap[1]))) > 0
	}
}

test_k8s_restricted_denies_a_low_port if {
	count(k8s_restricted_denials(replace(k8s_restricted_good, "containerPort: 8080", "containerPort: 80"))) > 0
}

test_k8s_restricted_ignores_comment_lines if {
	content := replace(k8s_restricted_good, "        runAsNonRoot: true\n", "        runAsNonRoot: true\n        # runAsUser: 1001\n")
	count(k8s_restricted_denials(content)) == 0
	commented_only := replace(k8s_restricted_good, "        runAsNonRoot: true\n", "        # runAsNonRoot: true\n")
	count(k8s_restricted_denials(commented_only)) > 0
}

test_k8s_restricted_applies_to_kustomize_base if {
	inp := {"proposal": {"files": [{"path": "gitops/shop/api/base/deployment.yaml", "content": "kind: Deployment\n"}]}}
	denied := {m | some m in proposal.deny with input as inp; m.rule_id == "practice.k8s_workload_restricted"}
	count(denied) > 0
}

test_k8s_restricted_ignores_files_outside_gitops_and_other_kinds if {
	outside := {"proposal": {"files": [{"path": "deploy/deployment.yaml", "content": "kind: Deployment\n"}]}}
	count({m | some m in proposal.deny with input as outside; m.rule_id == "practice.k8s_workload_restricted"}) == 0
	ecs := object.union(k8s_restricted_input("kind: Deployment\n"), {"context": {"target": {"kind": "ecs-fargate"}}})
	count({m | some m in proposal.deny with input as ecs; m.rule_id == "practice.k8s_workload_restricted"}) == 0
}

# Review on trustacks-mvp#767: an empty map is not a request or a limit.
test_k8s_restricted_denies_empty_requests_and_limits if {
	content := replace(
		replace(k8s_restricted_good, "requests:\n              cpu: 100m\n              memory: 128Mi", "requests: {}"),
		"limits:\n              cpu: 500m\n              memory: 512Mi", "limits: {}",
	)
	denials := k8s_restricted_denials(content)
	some m in denials
	contains(m, "resources.requests")
	some n in denials
	contains(n, "resources.limits")
}

test_k8s_restricted_allows_inline_requests_and_limits if {
	content := replace(
		replace(k8s_restricted_good, "requests:\n              cpu: 100m\n              memory: 128Mi", "requests: { cpu: 100m, memory: 128Mi }"),
		"limits:\n              cpu: 500m\n              memory: 512Mi", "limits: { cpu: 500m, memory: 512Mi }",
	)
	count(k8s_restricted_denials(content)) == 0
}

test_k8s_restricted_denies_host_ipc if {
	content := replace(k8s_restricted_good, "      securityContext:\n        runAsNonRoot", "      hostIPC: true\n      securityContext:\n        runAsNonRoot")
	some m in k8s_restricted_denials(content)
	contains(m, "hostIPC")
}

# Review on trustacks-mvp#767: one hardened container must not cover a second.
test_k8s_restricted_denies_a_second_container_without_the_baseline if {
	content := concat("", [k8s_restricted_good, `        - name: sidecar
          image: "busybox:1.36"
`])
	denials := k8s_restricted_denials(content)
	some m in denials
	contains(m, "every container must set allowPrivilegeEscalation")
}

test_k8s_restricted_allows_two_hardened_containers if {
	second := `        - name: sidecar
          image: "busybox:1.36"
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 32Mi
`
	count(k8s_restricted_denials(concat("", [k8s_restricted_good, second]))) == 0
}

# Review on trustacks-mvp#767: an inline comment must not hide a low port.
test_k8s_restricted_denies_a_low_port_with_an_inline_comment if {
	content := replace(k8s_restricted_good, "containerPort: 8080", "containerPort: 80 # http")
	some m in k8s_restricted_denials(content)
	contains(m, "containerPort 80")
}
