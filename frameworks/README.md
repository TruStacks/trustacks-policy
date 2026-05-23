# Framework knowledge packs

Framework packs encode what a TruStacks agent crew needs to know about a programming framework — how to detect it in a customer repo, what a canonical Dockerfile looks like, what a CI workflow that builds + tests + lints it looks like.

This directory is the open-source home for community-contributed framework packs. The TruStacks agents read these packs at runtime when they recognize a customer repo using a framework that has a pack.

---

## Status — bootstrap

This directory is **empty by design** as of repository bootstrap. Framework packs currently ship inside the TruStacks runner image (see `packs/frameworks/` in the [trustacks-mvp](https://github.com/TruStacks/trustacks-mvp) repo). The four packs that ship today — `python_fastapi`, `spring_boot`, `dotnet`, `go` — will migrate here at the start of the open-core distribution arc (Phase 5.2 of the TruStacks roadmap).

The reference shape of a pack lives at:

> https://github.com/TruStacks/trustacks-mvp/blob/main/packs/frameworks/python_fastapi.yaml

Read that file before designing a new pack. The YAML schema is also documented in the runner-side loader at `runner/src/trustacks_runner/frameworks/models.py` in the same product repo.

---

## What a pack looks like

A framework pack is a single YAML file (`<framework-id>.yaml`) with five top-level sections:

| Section | Purpose |
|---|---|
| `framework`, `display_name`, `language` | Identity. The framework id is the canonical machine-readable name agents use; `display_name` is what surfaces in the UI. |
| `detection` | A list of detection rules; each rule combines file-presence and file-content checks. The detector uses **AND-within / OR-across** semantics — every check inside a rule must match for the rule to fire, and any one rule firing is enough to identify the framework. |
| `prompt_addendum` | Plain-English prose injected into the DevOps Engineer's seed message when this pack matches. Names canonical artifacts (Dockerfile shape, CI runner, healthcheck path) so the agent doesn't fabricate framework-specific details. |
| `dockerfile_template` | A worked-example multi-stage Dockerfile the agent uses as a *shape* to imitate. Calibrated to a known-good runtime version; the agent adapts the version to what it sees in the customer repo. |
| `ci_workflow_template` | A worked-example CI workflow (currently GitHub Actions; CI runtime packs in `ci-runtimes/` will let the agent emit other formats). |

The pack format is intentionally schema-strict. New top-level keys require a runner-side loader change in `trustacks-mvp`; that's a deliberate constraint that keeps the open subset stable.

---

## Design principle — packs and behavior rules cooperate

Framework packs and the constitution's baseline behavior rules are **two halves of the same expectation**, not parallel surfaces. See **[ADR-0013 § Cooperating-layers principle](https://github.com/TruStacks/trustacks-mvp/blob/main/docs/decisions/0013-open-core-boundary.md#cooperating-layers-principle)** for the full architectural framing.

The summary, in one line: **the framework pack is the recipe; the constitution's behavior rule is the required outcome.** Each pack's CI workflow template includes the steps (`mvn test`, `dotnet test`, …) that the constitution's `practice.workflow_has_test_step` rule then validates; each Dockerfile template ends with a non-root `USER` so the `practice.dockerfile_runs_as_nonroot` rule passes; every `uses:` line is pinned to a SHA so `practice.workflow_pins_action_versions` passes.

**Practical contributor implication:** when you propose a new framework pack, the review will check it against the behavior rules it pairs with — not just *"does this Dockerfile build?"* but *"does emitting this pack's templates produce artifacts the constitution will accept?"* If a new framework introduces a delivery shape the existing rules don't cover (e.g., a language whose CI conventions don't fit `mvn test`/`pytest`/`npm test`-style invocations), propose the matching constitution rule update in the same design conversation — the pack alone is best-effort guidance; the pack + rule is enforcement with a recipe.

The Rego namespace for behavior rules is internally `practice.*` (locked identifier; customer-facing label is **Behaviors**).

---

## Contributing a new pack

Priority order driven by customer signal — at the time of writing the most-requested-but-not-yet-shipped frameworks are:

1. **Rust** (axum / actix-web)
2. **Node.js** (Express / NestJS / Fastify)
3. **Ruby** (Rails / Sinatra)

If you want to contribute one, read `CONTRIBUTING.md` at the repo root for the DCO + PR flow, then:

1. Open a GitHub issue with the `discussion` label first. Tell us what framework you want to pack and what the canonical Dockerfile + CI workflow shape is. We'll respond with design feedback before you sink time into the YAML.
2. Once design is aligned, draft `frameworks/<framework-id>.yaml`. Use `python_fastapi.yaml` (in trustacks-mvp) as the structural template.
3. If the pack benefits from a worked example, add a minimal sample app under `frameworks/<framework-id>/sample/`. Sample apps must be small (single file is ideal); they exist to anchor the pack, not demonstrate the framework.
4. Submit the PR with DCO sign-off and the design rationale in the PR description.

Reviews focus on *durability* (will this pack still be correct after the next major framework version?) and *safety* (does the reference Dockerfile actually build? does the CI workflow run?).

---

## What doesn't belong here

- **Compliance content.** Framework packs encode the *shape* of the framework, not regulatory rules. SOC2 evidence collection for a Java service belongs in a SOC2 compliance pack (paid, separate channel) — not in `spring_boot.yaml`.
- **Customer-specific overrides.** If your team's Spring Boot service uses an internal base image, that goes in your customer overlay, not in this pack.
- **Closed-source deps.** Pack content must be reproducible from publicly-available container images, dependencies, and tooling.
