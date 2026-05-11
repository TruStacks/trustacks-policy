# Compliance overlays

> **This directory is intentionally empty.**
> Compliance content is **not** in this open-source repository.

---

## Why this directory exists

We ship this directory + README in the bootstrap content so the structure is documented up front and contributors don't waste effort drafting compliance content that won't be accepted here.

If you arrived here looking for a SOC2 / HIPAA / PCI / FedRAMP / ITIL pack, see *Where compliance content lives* below.

---

## Where compliance content lives

Compliance overlays — packs that codify rules tied to a regulated framework (SOC2, HIPAA, PCI-DSS, FedRAMP, ITIL, and others) — are **TruStacks-curated paid content**. They ship through a separate, signed distribution channel that's not part of this repository.

The architectural reasoning (auditor-defensibility, curation cadence, commercial sustainability + the open-core boundary that this directory sits *outside* of) is documented in full at **[ADR-0013 § Where SOC2 lives](https://github.com/TruStacks/trustacks-mvp/blob/main/docs/decisions/0013-open-core-boundary.md#where-soc2-lives)** — including the diagram showing how the customer's signed overlay, the constitution's baseline behavior rules, the TruStacks-curated compliance overlays, and the customer's EnvironmentProfile cooperate at runtime. That ADR is the durable single source; this README points to it rather than duplicating the rationale.

---

## What you can contribute related to compliance

You **can** contribute these adjacent things to this open repository:

- **Industry overlays** (`../industry-overlays/`) that capture cross-organizational patterns in a specific industry without rising to the level of a regulated framework — for example, a "payments-systems" overlay that codifies typical change-management constraints without claiming PCI-DSS coverage.
- **Framework pack content** (`../frameworks/`) that makes compliance work easier — for example, a Java framework pack whose CI workflow template includes evidence-collection steps that downstream compliance packs can build on.
- **Discussion** on how the open layers should expose hooks that compliance packs can plug into. Open a GitHub issue with the `discussion` label.

---

## Reaching the TruStacks compliance team

For commercial questions about TruStacks compliance packs (pricing, framework coverage, audit support, custom industry packs), see https://trustacks.com.

For security issues in compliance content (e.g., you discovered a SOC2 pack rule that can be bypassed), email **security@trustacks.com**. Compliance security issues are handled with the same severity as product security issues.
