# Rule-naming standard

> Customer-facing reference for how TruStacks names every `rule_id` in a
> customer overlay. Enforced by the TruStacks Constitution at bundle-sign
> time (a malformed `rule_id` aborts `trustacks rule sign`); also
> validated at every authoring surface (CLI, UI, Coordinator) so you get
> friendly feedback before you hit the signing gate.

Status: Active — version 1 (the baseline; future revisions will declare
a version number alongside).

---

## TL;DR

A `rule_id` looks like this:

```
<namespace>.<name>
```

- **Lowercase letters, digits, and underscores.** No hyphens, no
  uppercase, no spaces, no punctuation other than the single dot
  separator.
- **Exactly one dot.** `<namespace>.<name>` — that's it. No
  `<ns>.<sub>.<name>` nesting; that's reserved for a future schema
  revision.
- **Leading character of each part is a letter.** `9foo.bar` is
  rejected; `foo9.bar` is fine.
- **64 characters total or fewer.** Counted across the whole `rule_id`
  including the dot. The TruStacks Control Plane's wire layer caps at
  128 chars; this tighter standard cap is the load-bearing one.
- **Reserved namespaces** belong to TruStacks-shipped layers and
  cannot be used by customer overlays:
  - `proposal`
  - `argocd`
  - `constitution`
  - `trustacks`

Valid examples:

```
acme.requires_runbook_link
acme.requires_approvers_group
contoso.denies_public_ingress
fintech_inc.mandates_change_window
```

Invalid examples and why:

| `rule_id`                                            | Why it's rejected                                       |
| ---------------------------------------------------- | ------------------------------------------------------- |
| `Acme.RequiresRunbookLink`                           | uppercase letters                                       |
| `acme-corp.requires_runbook`                         | hyphen in namespace part                                |
| `acme.requires runbook`                              | space in name part                                      |
| `acme.security.requires_runbook`                     | nested namespace (two dots)                             |
| `9acme.requires_runbook`                             | leading digit on namespace                              |
| `proposal.requires_runbook_link`                     | reserved namespace `proposal`                           |
| `I need a rule to require an approvers group`        | not slug-shaped (free-form prose)                       |
| 70-character all-x slug                              | exceeds 64-character cap                                |

---

## Why this standard exists

A customer overlay accumulates rules over time. Without a written
standard, a six-month-old overlay typically ends up with three or four
different naming conventions side by side:

```
acme.requires_approvers
customer.approvers_required
acme.deny_no_approvers
sec-team-requires-runbook-link
```

Each one expresses an intent perfectly well in isolation, but an
auditor reading the overlay sees naming chaos — and a future engineer
extending the overlay can't predict what shape a new rule should take.

The standard fixes that with three properties:

1. **Predictability.** A reader can guess the slug shape of a new rule
   without checking prior art.
2. **Auditability.** All rules in the same overlay look like they
   belong to the same overlay.
3. **Tool-friendliness.** The slug is a valid Rego identifier suffix,
   so it can be reused as a package name without escape gymnastics.

---

## How the standard is enforced

The standard is enforced at four surfaces, all sourced from a single
canonical module in the TruStacks product repo:

1. **`trustacks rule new <id>` (CLI).** The CLI rejects malformed
   `rule_id` arguments before scaffolding any files.

2. **`/rule new` in the TruStacks UI.** The Coordinator's chat surface
   validates the slug client-side before dispatching, and (in a future
   release) will *propose* a slug from your prose if you describe a
   rule without naming it first.

3. **The TruStacks Control Plane API.** The `POST /api/rule-drafts`
   wire validator rejects malformed `rule_id` payloads with a `422`
   carrying a structured error message.

4. **The TruStacks Constitution.** At `trustacks rule sign` time, a
   constitution rule (`constitution.overlay_rule_naming`) runs against
   the overlay's `rule_metadata` and aborts the sign if any `rule_id`
   violates the standard. **This is the load-bearing gate** — no
   bundle ships with a malformed slug, regardless of which authoring
   path produced it (including hand-edited `rule_metadata.yaml`
   files).

The constitution rule reads the regex string + reserved-namespace set +
length cap from a `data.naming.json` sidecar baked into the signed
constitution bundle at build time. The sidecar is generated from the
canonical Python module that the CLI / UI / Control Plane also import,
so the four surfaces always agree.

---

## Recommended naming conventions

Beyond the grammar enforced above, the following conventions are
recommended (not enforced; the constitution rule won't reject a
slug that violates them, but reviewers will likely ask you to rename):

- **Namespace = your workspace slug.** Use the same prefix across all
  rules in your overlay. The TruStacks UI proposes a namespace from
  your workspace name by default (e.g. `acme_corp` from the workspace
  name "Acme Corp").

- **Name = `<verb>_<noun>`** in present tense. Common verbs that read
  naturally:

  - `requires_` — the rule fails when the input is missing the noun
    (`acme.requires_runbook_link`)
  - `denies_` — the rule fails when the noun is present
    (`acme.denies_public_ingress`)
  - `mandates_` — same shape as `requires_` but used for procedural /
    process rules (`acme.mandates_change_window`)
  - `forbids_` — same shape as `denies_` but used for stronger
    prohibitions (`acme.forbids_root_containers`)

- **Be specific.** `acme.requires_approvers_group` is better than
  `acme.requires_approvers` if approver groups are what you're
  actually checking for.

- **Don't repeat the namespace in the name.** `acme.requires_acme_runbook`
  is redundant; `acme.requires_runbook` reads cleaner.

---

## Description style (recommended)

The `description` field on `rule_metadata` is what the gap-analysis
report and the auditor evidence reports show to humans. A few
conventions that keep the report readable:

- **One line.** Wrap at ~120 characters.
- **Present tense, declarative.** "Every change requires an approvers
  group" — not "This rule requires changes to have an approvers group"
  or "Changes must have approvers".
- **State the property, not the implementation.** Say what the rule
  guarantees, not how the Rego body checks it.

---

## What about TruStacks-shipped rules?

The reserved namespaces above (`proposal`, `argocd`, `constitution`,
`trustacks`) host the constitution rules + the TruStacks-shipped
overlay rules (in regulatory packs like SOC2 / HIPAA / FedRAMP, which
ship through TruStacks's paid distribution channel rather than this
repository). The constitution rule that enforces this standard does
not check itself — TruStacks-internal rules follow a closely-related
but separately-versioned convention, since they carry additional
required metadata (control-family mappings, evidence hints).

If you're contributing to an *industry overlay* in this repository
(`industry-overlays/`), use a namespace that names the industry
(e.g. `banking_baseline.`, `healthcare_hipaa_adjacent.`) — not a
customer name. Reviewers will guide on this in the PR.

---

## Versioning

This is version 1 of the standard — the baseline.

Future revisions will:

- Declare an explicit `data.naming.version` field in the bundle
  sidecar so existing signed bundles continue to verify against the
  version they were signed under.
- Document migration paths if/when a revision tightens an existing
  rule.

Today there is no migration concern because every signed bundle
predating the standard was either (a) authored through `trustacks
rule new` (which enforced the underlying regex) or (b) hand-authored
and subject to reviewer scrutiny. If your pre-existing overlay
contains a slug that doesn't pass the standard now, the next sign
will fail with a clear error — rename the rule directory + the
metadata entry to a conforming slug, and re-sign.

---

## Related

- **TruStacks product ADR-0023** — the architectural decision record
  behind this standard (in the closed-source `trustacks-mvp` repo
  during Beta; will publish at open-core split).
- **Constitution overview** — see the `Constitution` row of the
  three-layer model in [`../README.md`](../README.md).
- **Open-core boundary** — [ADR-0013](https://github.com/TruStacks/trustacks-mvp/blob/main/docs/decisions/0013-open-core-boundary.md)
  explains why the enforcement code (the constitution rule) lives in
  the closed-source TruStacks product repo while this standard doc
  lives here.

---

## Feedback

Standards work best when they reflect the realities of the
contributors who use them. If a rule you've written runs afoul of
this standard in a way that feels wrong, please open an issue on this
repository — we'd rather fix the standard than block the rule.
