# Tool-action packs

One YAML per security or supply-chain tool, mapping a tool a customer declares
in their environment profile (`trivy`, `cosign`, `syft`, …) to its canonical
GitHub Action **pinned to a commit SHA**.

## Why these exist

Without a pack, the agent emitting a customer's CI workflow has to recall an
action version from training data. That produces plausible, unreproducible, and
sometimes non-existent `uses:` lines. A pack replaces recall with a curated
fact, reviewed on a cadence (`CURATION.md`) and pinned to a SHA rather than a
tag — **tags can be moved; a SHA cannot.** The product's own constitution rule
`practice.workflow_pins_action_versions` requires exactly this of the customer,
so emitting an unpinned action would be us failing our own gate.

## Shipped packs

| Tool | Purpose |
|---|---|
| `trivy.yaml` | vulnerability + misconfiguration scanning |
| `semgrep.yaml` | static analysis |
| `gitleaks.yaml` | secret detection |
| `syft.yaml` | SBOM generation |
| `cosign.yaml` | artifact signing |

## The honest limit

**A declared tool with no pack here produces no pipeline step.** The customer's
posture rule may still go green on the declaration while their pipeline gains
nothing — the gap tracked as #558 in the product repo. If you add a tool to a
profile, adding its pack here is what makes the declaration real.

Adding one is a good first contribution: copy the closest existing pack, follow
`CURATION.md` to resolve the tag to a SHA, and open a PR with `git commit -s`.
