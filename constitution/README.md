# The constitution

The universal rules every TruStacks proposal must respect, whatever the
customer, the stack, or the tier. This is the foundation layer of the three in
the repository README: a customer overlay can ratchet **stricter** than these
rules, never looser.

Apache 2.0, like everything else here. ADR-0013 put the constitution in the open
column deliberately — a rule you cannot read is a rule you cannot trust, and the
product's claim is *agents propose, policy decides, humans approve*. That claim
is weaker, not stronger, if the deciding half is a black box.

## What is here

| File | What it holds |
|---|---|
| `proposal.rego` | the rules — path safety, required artifacts, and the five practice rules |
| `proposal_test.rego` | their tests |
| `overlay_naming.rego` | the rule-naming gate for customer-authored overlay rules (see `../standards/rule-naming.md`) |
| `overlay_naming_test.rego` | its tests |

Eleven `rule_id`s ship today, in two families:

- **`proposal.*`** — shape and safety of the change itself: `allowed_paths`,
  `no_path_traversal`, `has_workflow`, `has_helm_chart`, `has_kustomization`,
  `has_argocd_application`.
- **`practice.*`** — the delivery behaviours a proposal must demonstrate:
  `workflow_has_test_step`, `workflow_has_lint_step`,
  `workflow_pins_action_versions`, `dockerfile_runs_as_nonroot`,
  `argocd_prod_requires_manual_sync`.

## Running the tests

```sh
opa test constitution
```

Pin OPA to the version CI uses (`v0.69.0`). Testing the constitution on a
different evaluator than the one that builds and signs the shipped bundle is a
gap, not a convenience.

## A rule and its pack travel together

ADR-0013's cooperating-layers principle, and the reason `../tests/` exists: a
practice rule describes a behaviour, and a framework pack prescribes the CI
workflow that demonstrates it. **Change one without the other and a customer
gets denied for an artifact we authored.**

That is not hypothetical. `frameworks/spring_boot.yaml` once prescribed
`mvn -B verify -Dlint=true` beneath a comment asserting it satisfied
`practice.workflow_has_lint_step`. The claim was false — the matcher lowercases
the command and the needle list did not — so **no Spring Boot service could pass
the gate at all**, after a full agent run, every time. Two artifacts, each
correct on its own terms, and nothing ran them together.

`tests/test_pack_workflows_pass_the_constitution.py` now evaluates every pack's
canonical workflow against these rules on every PR. If you add a practice rule,
add the pack template that satisfies it in the same PR — and the reverse.

## A note on the comments

Some comments in these files cite issue numbers (`#551`, `#374`, …). Those refer
to the **TruStacks product tracker**, not to issues in this repository. They are
kept because the reasoning is worth more than the tidiness: each one marks a
failure that reached production and the rule that exists because of it.
