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
| `codeql-upload-sarif.yaml` | uploads a scanner's SARIF to GitHub code scanning (rides along with `trivy`/`semgrep`; non-fatal, since code scanning needs a public repo or GitHub Advanced Security) |
| `upload-artifact.yaml` | keeps that SARIF as a workflow artifact, so results survive where code scanning isn't available |

## Token permissions

A pack's `permissions:` lists the `GITHUB_TOKEN` permissions the job running
its step must grant (gitleaks lists a PR's commits, so `pull-requests: read`;
the SARIF upload needs `security-events: write` and `actions: read`). The
product refuses a workflow whose tool step's job lacks them, and a service
repo calling the workflow must grant the union of every job's permissions:
a called workflow can only keep or reduce its caller's token, so GitHub
refuses a run whose job asks for more.

## The honest limit

**A declared tool with no pack here produces no pipeline step.** The customer's
posture rule may still go green on the declaration while their pipeline gains
nothing — the gap tracked as #558 in the product repo. If you add a tool to a
profile, adding its pack here is what makes the declaration real.

Adding one is a good first contribution: copy the closest existing pack, follow
`CURATION.md` to resolve the tag to a SHA, and open a PR with `git commit -s`.
