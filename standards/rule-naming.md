# Rule-naming standard

> Customer-facing reference for how TruStacks names every `rule_id` — in a
> customer overlay, in an industry overlay, and in the constitution itself.
> Enforced by the TruStacks Constitution at bundle-sign time (a malformed
> `rule_id` aborts `trustacks rule sign`); also validated at every
> authoring surface (CLI, UI, Coordinator) so you get friendly feedback
> before you hit the signing gate.

Status: Active — **version 2**. Version 2 adds one rule — *a rule's
namespace is the directory it lives in* — and, because of it, reserves
`practice` and `posture`. The grammar and the length cap are unchanged
from version 1. See [Versioning](#versioning).

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
- **The namespace is the directory.** A rule shipped in this
  repository lives in the directory named for its namespace —
  `constitution/practice/…` holds `practice.*` rules. See
  [Namespace = directory](#namespace--directory).
- **Reserved namespaces** belong to TruStacks-shipped layers and
  cannot be used by customer overlays. Every directory under
  `constitution/` is one, plus `trustacks`:
  - `argocd`
  - `constitution`
  - `posture`
  - `practice`
  - `proposal`
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
| `practice.requires_runbook_link`                     | reserved namespace `practice` (since version 2)         |
| `I need a rule to require an approvers group`        | not slug-shaped (free-form prose)                       |
| 70-character all-x slug                              | exceeds 64-character cap                                |

---

## Namespace = directory

*New in version 2.*

**A rule's namespace must equal the directory it lives in.**

| Layer | Where a rule lives | Its `rule_id` |
|---|---|---|
| Constitution (this repository) | `constitution/<namespace>/<name>.rego` | `<namespace>.<name>` |
| Industry overlay (this repository) | `industry-overlays/<namespace>/…` | `<namespace>.<name>` |
| Customer overlay (your repository) | your overlay's `rules/` | `<your workspace slug>.<name>` — unchanged |

So `constitution/practice/dockerfile_runs_as_nonroot.rego` holds
`practice.dockerfile_runs_as_nonroot`, and nothing in `constitution/proposal/`
may declare a `practice.*` id. A reader who knows a rule's id knows where to
find it, and the reverse.

### The id is never derived from the path

The `rule_id` is written out in full inside the file, and **nothing builds
it from the file's location**. That is deliberate. Rule ids are persisted
in customer history — denial counts, maturity scores, audit evidence all
cite them — so an id must not change because someone moved a file. If ids
were computed from paths, a tidy-up refactor would silently re-ID a rule:
the old id's history would stop accruing, a new id would start from zero,
and no review would have said "we are renaming a rule".

Instead, CI **checks** that each id's namespace matches its directory
(`tests/test_namespace_equals_directory.py`). Moving a file without
renaming the rule fails CI, loudly, and the fix is to move the file back —
not to rename the id. Renaming a shipped id is a breaking change to
customer history and needs its own migration.

The directory names the namespace; it does not name the Rego package.
Every constitution directory except `constitution/` declares
`package proposal`, so the queries the runner makes
(`data.proposal.deny`, `data.proposal.gap`, `data.proposal.rule_index`)
are the same however the files are arranged.

### Every constitution directory is reserved

Because a constitution namespace *is* a directory, the reserved set is
derived from the directories: every directory under `constitution/`, plus
`trustacks`. Adding a directory reserves a namespace; CI fails until the
naming data says so.

This closes a gap version 1 left open. The constitution has shipped
`practice.*` and `posture.*` rules since before version 1 was written, but
neither namespace was reserved — so a customer overlay could declare
`practice.requires_runbook_link`, and it would sit beside TruStacks's own
practice rules looking like one of them.

### Customer overlays

Unchanged: your namespace is your workspace slug (see
[Recommended naming conventions](#recommended-naming-conventions)). The
directory rule governs the layers TruStacks ships from this repository.
How `trustacks rule new` lays out a customer overlay's files is a separate
question and is not changed by version 2.

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
length cap + standard version from `constitution/data.naming.json`. That
file is generated from the canonical Python module that the CLI / UI /
Control Plane also import, so the four surfaces always agree; a lockstep
test in the product repository fails if any of them drifts, and
`constitution/constitution/overlay_naming_test.rego` fails if the gate's
tests stop matching the committed file.

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

The reserved namespaces above host the constitution rules + the
TruStacks-shipped overlay rules (in regulatory packs like SOC2 / HIPAA /
FedRAMP, which ship through TruStacks's paid distribution channel rather
than this repository). The constitution rule that enforces this standard
checks customer overlays, not itself; the constitution is held to the
same grammar and to the directory rule by this repository's CI instead.

One constitution id predates the grammar: `argocd.repoURL_is_canonical`
is camelCase, and the grammar is lowercase-only. It keeps its spelling
for the reason ids are never derived from paths — it has been recorded
against real proposals since the constitution's first release, and
renaming it would orphan that history. CI lists it as grandfathered; the
list may shrink but must never grow.

If you're contributing to an *industry overlay* in this repository
(`industry-overlays/`), use a namespace that names the industry
(e.g. `banking_baseline.`, `healthcare_hipaa_adjacent.`) — not a
customer name. Reviewers will guide on this in the PR.

---

## Versioning

**Version 2** (current):

- Adds *namespace = directory* for rules shipped from this repository
  (constitution and industry overlays). IDs are never derived from
  paths; CI checks the two agree.
- Reserves every constitution directory, which adds `practice` and
  `posture` to the reserved set.
- Records the version: `data.naming.json` now carries
  `"version": 2`, as version 1 promised a revision would.
- Grammar and length cap: unchanged.

*Migration.* The only change that can affect a customer overlay is the
two newly reserved namespaces. An overlay whose rules use `practice.` or
`posture.` as their namespace will fail its next `trustacks rule sign`
with a clear error. We expect none — the recommended namespace has always
been your workspace slug — but if yours does, move the rule to your
workspace namespace and re-sign. Note that this gives the rule a new id,
so its history (denials, score contribution) starts fresh under the new
name; bundles already signed are unaffected until you re-sign.

**Version 1** — the baseline: the grammar, the length cap, and the
reserved set `argocd`, `constitution`, `proposal`, `trustacks`.

---

## Related

- **TruStacks product ADR-0023** — the architectural decision record
  behind this standard (in the closed-source `trustacks-mvp` repo
  during Beta; will publish at open-core split).
- **Constitution overview** — see the `Constitution` row of the
  three-layer model in [`../README.md`](../README.md).
- **The enforcing rule** — [`../constitution/constitution/overlay_naming.rego`](../constitution/constitution/overlay_naming.rego),
  and the directory check in
  [`../tests/test_namespace_equals_directory.py`](../tests/test_namespace_equals_directory.py).
- **Open-core boundary** — [ADR-0013](https://github.com/TruStacks/trustacks-mvp/blob/main/docs/decisions/0013-open-core-boundary.md)
  explains which layers are open; the constitution, and the rule that
  enforces this standard, are now published here.

---

## Feedback

Standards work best when they reflect the realities of the
contributors who use them. If a rule you've written runs afoul of
this standard in a way that feels wrong, please open an issue on this
repository — we'd rather fix the standard than block the rule.
