# trustacks-policy

The open-source policy + framework knowledge that powers [TruStacks](https://trustacks.com).

TruStacks is an AI agent crew that proposes every software-delivery change as a reviewed, policy-checked pull request. This repository is one of the three sources from which those policies come.

---

## The three voices that contribute to TruStacks rules

```
┌──────────────────────────────────────────────────────────────────┐
│  Customer Overlay (your architects, SREs, compliance officer)    │  ← deepest, most authoritative
│  - your domain rules; private to your TruStacks workspace        │
├──────────────────────────────────────────────────────────────────┤
│  Packs (signed, all layered in same priority order):             │
│  - Regulatory: SOC2 / HIPAA / PCI / FedRAMP / ITIL              │
│    (TruStacks-curated, paid, not in this repo)                  │
│  - Industry / Framework / CI runtime:                            │
│    (community-contributed — THIS REPO)                          │
├──────────────────────────────────────────────────────────────────┤
│  Constitution (TruStacks, signed, immutable, free at all tiers)  │  ← foundation
│  - the universal rules every proposal must respect              │
└──────────────────────────────────────────────────────────────────┘

         The agent crew reads all three and proposes PRs.
         Each layer can only ratchet stricter than the one above.
```

This repository hosts the **community layer**: framework knowledge packs, CI runtime packs, and industry-specific rule overlays. All content here is **Apache 2.0 licensed** and contributed under DCO sign-off.

What lives where:

| Layer | Where | License | Who maintains |
|---|---|---|---|
| Constitution (universal rules) | TruStacks (closed source today) | proprietary | TruStacks |
| **Framework packs** (Python, Java, Go, .NET, …) | **this repo** | **Apache 2.0** | **community + TruStacks** |
| **CI runtime packs** (GitHub Actions, GitLab CI, Azure DevOps, …) | **this repo** | **Apache 2.0** | **community + TruStacks** |
| **Industry overlays** (banking, healthcare, …) | **this repo** | **Apache 2.0** | **community + TruStacks** |
| Regulatory packs (SOC2, HIPAA, FedRAMP, …) | TruStacks (paid, separate distribution channel) | commercial | TruStacks |
| Customer overlays (your domain rules) | your private TruStacks workspace | yours | your engineering team |

The architecture decision behind this split is recorded in [ADR-0013 — open-core boundary](https://github.com/TruStacks/trustacks-mvp/blob/main/docs/decisions/0013-open-core-boundary.md) in the TruStacks product repo.

---

## Repository layout

```
trustacks-policy/
├── README.md
├── LICENSE                      # Apache 2.0
├── CONTRIBUTING.md              # how to propose changes (DCO sign-off required)
├── CODE_OF_CONDUCT.md           # Contributor Covenant 2.1
├── TRADEMARK.md                 # TruStacks trademark policy
│
├── frameworks/                  # framework knowledge packs
│   └── README.md
├── ci-runtimes/                 # CI runtime packs
│   └── README.md
├── industry-overlays/           # industry-specific rule overlays
│   └── README.md
└── compliance-overlays/         # placeholder — paid content, not in this repo
    └── README.md
```

Each subdirectory's README explains what that layer is, what shape contributions take, and how reviews work.

---

## Status

This repository is in **bootstrap phase**. The directory structure and contribution shell are in place; **no content has been migrated yet**. The current TruStacks product (in [`trustacks-mvp`](https://github.com/TruStacks/trustacks-mvp)) ships framework packs baked into the runner image at `packs/frameworks/`. Those will migrate to this repo once the open-core distribution pipeline (Phase 5.2 of the product roadmap) lands.

If you want to see what a framework pack looks like today, the canonical reference is `packs/frameworks/python_fastapi.yaml` in the product repo.

The repository is private during the TruStacks Beta program. It will become public when the open-core distribution pipeline is ready, projected at Beta launch in 2026.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide. The short version:

1. Fork + branch from `main`.
2. Make your change. Sign each commit with `git commit -s` (Developer Certificate of Origin — see CONTRIBUTING.md).
3. Open a PR. Reviews target durability + safety: **does this rule express a real constraint, and can it survive future framework/runtime changes?**
4. The maintainer team (currently TruStacks core engineers) reviews and merges.

By contributing, you agree to license your work under [Apache 2.0](./LICENSE) and you affirm the [Developer Certificate of Origin](https://developercertificate.org/) on every commit.

---

## Trademark + brand

"TruStacks" is a trademark of TruStacks. Code in this repository is open-source under Apache 2.0; the *name* and *brand* are not. See [TRADEMARK.md](./TRADEMARK.md) for what use is permitted.

---

## Questions

- **Rule design questions**: open a GitHub issue with the `discussion` label.
- **Security issues**: do **not** open a public issue. Email security@trustacks.com.
- **Commercial questions about TruStacks**: see https://trustacks.com.
