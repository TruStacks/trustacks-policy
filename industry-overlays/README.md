# Industry overlays

Industry overlays encode rule patterns that are typical for a specific industry vertical — banking, healthcare, gaming, regulated commerce, public sector — without rising to the level of a regulated compliance framework (which lives in paid TruStacks packs, not here).

This directory is the open-source home for community-contributed industry overlays.

---

## Status — bootstrap

This directory is **empty by design** as of repository bootstrap. The product today ships zero industry overlays; the customer overlay layer (in customer workspaces) is where industry-specific intelligence currently lives.

The contribution surface opens once the open-core distribution pipeline lands (Phase 5.2 of the product roadmap). Until then, see `frameworks/README.md` for the contribution shape; industry overlays follow the same Rego pattern.

---

## What an industry overlay is — and isn't

**Is:** a curated set of Rego rules that codify *industry-typical* constraints. Examples:

- **Banking**: rules requiring transaction-tracing tags on services that handle account events; rules requiring deploy windows that exclude end-of-month / quarter-close.
- **Healthcare** (non-HIPAA): rules requiring patient-data services to declare a specific category in the EnvironmentProfile; rules requiring zero-data-retention for log collectors that scrape PHI-adjacent endpoints.
- **Gaming**: rules requiring chaos-test workflows on services that handle real-money in-game transactions.

**Isn't:**

- A regulated compliance framework. **HIPAA, PCI-DSS, SOX, FedRAMP, SOC2** are *paid* TruStacks packs — they require auditor-defensible curation that we don't ask volunteers to take liability for. If your contribution starts to read like an audit checklist for a recognized standard, it belongs in a paid pack, not here.
- A customer-specific overlay. "My bank's deploy windows are 6pm-2am on weekdays" is your customer overlay, not an industry overlay. Industry overlays should be patterns that apply across multiple organizations in the industry.

---

## The ratchet rule

Every overlay layer (industry, customer, or otherwise) can only **ratchet stricter** than the constitution + framework packs above it. The TruStacks policy linter enforces this at compile time — an overlay cannot waive a constitutional rule, only add additional constraints.

Industry overlays should be designed with this in mind:

- ✅ Add a deny rule that fires on patterns the constitution doesn't cover ("services in the `payments` category must declare a transaction-tracing tag").
- ✅ Tighten an existing rule's threshold ("payments services must run lint on every PR; the constitution only requires it on main").
- ❌ Try to allow something the constitution denies. The linter will reject it.

---

## Contributing

Wait for the open-core distribution pipeline to land before contributing a full overlay. If you want to help shape what the first industry overlays look like, open a GitHub issue with the `discussion` label describing the industry + the cross-organizational patterns you've seen.

Reviews focus on *applicability across multiple organizations in the industry* (not "my company does this") and *ratchet correctness* (the overlay never tries to weaken something).
