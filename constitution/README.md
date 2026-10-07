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

One file per rule, in the directory named for the rule's namespace
(`../standards/rule-naming.md`, version 2):

| Directory | What it holds |
|---|---|
| `proposal/` | `proposal.*` rules, plus `lib.rego` — what every rule shares: the rule index, gap analysis, the renderer, and the customer-overlay aggregator |
| `argocd/` | `argocd.*` rules |
| `practice/` | `practice.*` rules, plus `lib.rego` — the workflow and Dockerfile matchers they share |
| `posture/` | `posture.*` rules — metadata only, no deny block |
| `constitution/` | `overlay_naming.rego`, the rule-naming gate for customer-authored overlay rules (it emits `constitution.*` ids) |
| `data.naming.json` | the rule-naming grammar the naming gate reads (`data.naming.*`) |

Tests sit beside the rules as `*_test.rego`. They share one package
(`proposal_test`) and the fixtures in `proposal/fixtures_test.rego`, so run the
whole tree rather than one directory.

**The directory names the namespace; it does not name the package or build the
id.** `proposal/`, `argocd/`, `practice/` and `posture/` all declare
`package proposal`, and OPA merges a package's files, so the runner's queries —
`data.proposal.deny`, `data.proposal.gap`, `data.proposal.rule_metadata`,
`data.proposal.rule_index` — are what they were when this was one file. Each
rule file adds its own `rule_metadata["<namespace>.<name>"] := {...}` entry, with
the id written out in full. Ids are never derived from the path: they are
persisted in customer history (denial counts, scores, evidence), and a file
move must not silently re-ID a rule. `../tests/test_namespace_equals_directory.py`
checks instead that each id's namespace equals its directory, so a move without
a rename fails CI.

### Adding a rule

1. Create `<namespace>/<name>.rego` — `package proposal`, the
   `rule_metadata["<namespace>.<name>"]` entry, and the deny block (none for a
   posture rule). Helpers more than one rule uses go in the directory's
   `lib.rego`.
2. Add tests in a `*_test.rego` beside it.
3. A new directory is a new **reserved namespace**: every directory here is one,
   so `data.naming.json` must list it. That file is generated in the TruStacks
   product repo from its canonical rule-naming module — regenerate it there and
   copy it here; `test_namespace_equals_directory.py` fails until you do.
4. Never rename an existing `rule_id` to tidy it up. `argocd.repoURL_is_canonical`
   predates the lowercase grammar and keeps its spelling for that reason.

Sixteen `rule_id`s ship today, in four families:

- **`proposal.*`** — shape and safety of the change itself: `allowed_paths`,
  `no_path_traversal`, `has_workflow`, `has_helm_chart`, `has_kustomization`,
  `has_argocd_application`.
- **`argocd.*`** — `repoURL_is_canonical`: an emitted ArgoCD Application points
  at the platform repo it was written to.
- **`practice.*`** — the delivery behaviours a proposal must demonstrate:
  `workflow_has_test_step`, `workflow_has_lint_step`,
  `workflow_pins_action_versions`, `dockerfile_runs_as_nonroot`,
  `argocd_prod_requires_manual_sync`.
- **`posture.*`** — declared tooling, scored but never a deny:
  `image_scanning_declared`, `sast_sca_declared`, `secret_scanning_declared`,
  `sbom_signing_declared`.

## Running the tests

```sh
opa test constitution
uv run --with pytest --with pyyaml pytest tests -q   # layout, naming and pack lockstep
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
