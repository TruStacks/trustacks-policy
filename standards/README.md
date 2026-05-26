# Standards

This directory holds **standards** — written conventions that govern
how customer overlays and community contributions to this repository
are shaped. Each standard is documented here for human readers, and
each is enforced by code somewhere in the TruStacks stack (the
constitution, the CLI, the Control Plane, the UI — depending on which
authoring surface is in scope).

Unlike the per-layer subdirectories (`frameworks/`, `ci-runtimes/`,
`industry-overlays/`, `compliance-overlays/`), standards in this
directory are not rule packs — they're meta-rules about how rules are
shaped.

## What's here today

- [**`rule-naming.md`**](./rule-naming.md) — the grammar + reserved
  namespaces + length cap that govern every `rule_id` in a customer
  overlay. Enforced by the TruStacks Constitution at bundle-sign
  time, and validated at every authoring surface (CLI, UI, Control
  Plane API).

## Contributing a new standard

Standards typically emerge from a recurring "how should I name /
shape this?" question across multiple customer overlays or community
contributions. If you're contemplating adding one, open an issue
first describing what convention you want to codify and what
recurring confusion it would resolve — we'd rather discuss the
shape before reviewing a draft.

Once accepted, a standard ships in three pieces:

1. The standard doc in this directory (auditor-readable, customer-facing).
2. The enforcement code somewhere in the TruStacks stack (the
   constitution is the typical home; the per-authoring-surface
   validators serve as friendly-error pre-checks).
3. A CI lockstep test asserting that the standard's literal values
   stay byte-identical across the canonical source and all mirrors.
