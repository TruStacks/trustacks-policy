# Contributing to trustacks-policy

Thank you for your interest in contributing. This repo holds the open-source policy and framework knowledge that powers the [TruStacks](https://trustacks.com) agent crew. Every contribution here gets read by AI agents on real customer repos — durability and safety matter more than cleverness.

---

## Before you contribute

1. **Read the [README](./README.md)** to understand the three-voice architecture and which kinds of content belong here vs. in the closed-source TruStacks product or in private customer overlays.
2. **Read the relevant subdirectory README** for the layer you're contributing to (`frameworks/README.md`, `ci-runtimes/README.md`, etc.). Each layer has its own contribution shape.
3. **Read the [Code of Conduct](./CODE_OF_CONDUCT.md).** Participation is contingent on agreement.

---

## Developer Certificate of Origin (DCO)

All contributions to this repository are made under the [Developer Certificate of Origin (DCO) version 1.1](https://developercertificate.org/). By signing off on your commits, you affirm that you wrote the contribution (or otherwise have the right to submit it under the project's license) and that you agree to license it under [Apache 2.0](./LICENSE).

The DCO text is short — read it. The mechanical part is one extra flag on `git commit`:

```bash
git commit -s -m "feat(frameworks): add Rust framework pack for axum"
```

The `-s` adds a `Signed-off-by: Your Name <your.email@example.com>` line to the commit message. That line **is** the affirmation. Commits without a DCO sign-off will be rejected by CI.

If you've already committed without `-s`, amend with `git commit --amend -s` (or interactively rebase with `git rebase -i <base>` and add `-s` to each commit).

We use DCO sign-offs (not a CLA) for the same reasons the Linux kernel, ArgoCD, and sigstore do: it's lightweight, it's well-understood, and it doesn't require contributors to give up rights they care about.

---

## Contribution flow

### 1. Fork + branch

```bash
gh repo fork TruStacks/trustacks-policy --clone --remote
cd trustacks-policy
git checkout -b feat/<short-description>
```

Branch naming follows the same convention as TruStacks itself:

- `feat/<short-description>` — new content (a new framework pack, a new industry overlay, etc.)
- `fix/<short-description>` — corrections to existing content
- `docs/<short-description>` — documentation changes
- `chore/<short-description>` — tooling, CI, repo housekeeping

### 2. Make your change

Each layer has its own contribution shape. Example for a new framework pack:

- Create `frameworks/<framework-id>.yaml` (or `frameworks/<framework-id>/pack.yaml` if your pack needs sample files alongside).
- Validate the YAML against the pack schema (see `frameworks/README.md` for the schema location).
- Run `opa test` against any rego rules you ship.
- Add a sample app under `frameworks/<framework-id>/sample/` if the pack benefits from a worked example. Sample apps must be minimal — they exist to anchor the pack, not to demonstrate the framework.

### 3. Test locally

If your change touches Rego rules, run:

```bash
opa test path/to/rules/
```

If your change touches a framework pack YAML, validate it:

```bash
# Schema validation runs in CI; you can run it locally if you have the
# trustacks-mvp checkout — see that repo's frameworks loader test.
```

### 4. Sign off + commit

```bash
git commit -s -m "feat(frameworks): add Rust framework pack for axum"
```

Conventional-commits format with a layer scope (`frameworks`, `ci-runtimes`, `industry-overlays`) is preferred but not required.

### 5. Open a PR

```bash
git push -u origin feat/<short-description>
gh pr create --title "..." --body "..."
```

Your PR description should answer:

- **What does this rule / pack assert?** A one-paragraph summary in plain English.
- **Why is it durable?** What property of the framework/runtime/industry makes this rule still correct in 18 months?
- **What didn't you ship?** What edge cases are out of scope, and why?

CI runs DCO check + schema validation + rule tests. Once green, a maintainer reviews.

### 6. Review

Review focuses on:

- **Durability.** Will this rule still be correct after the next major version of the framework / runtime?
- **Safety.** Does the rule fire false-positives that would block a legitimate proposal? Are deny messages clear enough that a customer can fix the violation without asking us?
- **Layer fit.** Does this content belong in the layer it was contributed to? (E.g., a healthcare-specific HIPAA-relevant rule belongs in a paid compliance pack, not in `industry-overlays/healthcare/`.)
- **Open-core boundary.** Does this content require closed-source TruStacks code to function? If so, the contribution likely belongs in the product repo, not here.

---

## What goes where

| Layer | Typical contribution | Maintainer concern |
|---|---|---|
| `frameworks/` | New framework knowledge pack (Rust, Node.js, Ruby, …) | Detection rules unambiguous; reference Dockerfile/CI shape buildable; pack survives next major framework version |
| `ci-runtimes/` | New CI runtime pack (GitLab CI, Azure DevOps, Tekton, …) | Pack maps cleanly onto the agent's emit logic; doesn't require closed-source runner changes |
| `industry-overlays/` | Industry-specific rules (banking, healthcare, gaming, …) | Rules express *industry-typical* constraints; they ratchet stricter than the constitution; they don't accidentally encode regulatory compliance (those are paid packs) |
| `compliance-overlays/` | **Nothing in this repo.** Compliance content is paid. | n/a (see directory README) |

If you're not sure where your contribution fits, **open a GitHub issue first** with the `discussion` label. We'd rather scope the design before the PR than reject a PR after you've put work into it.

---

## Maintainers

The TruStacks core engineering team currently maintains this repo. As the contributor community grows, we expect to add layer-specific maintainers (a "frameworks maintainer," a "ci-runtimes maintainer," etc.) — both to scale review throughput and to share governance. The path to becoming a maintainer is consistent merged contributions plus engagement with the contribution review process.

---

## Security issues

If you discover a security issue in any rule shipped from this repo (e.g., a deny rule that can be trivially bypassed, or an `allow` rule that grants too much), do **not** open a public GitHub issue. Email **security@trustacks.com** with the details. We'll respond within 5 business days.

---

## Questions

- **Is this the right layer for my contribution?** Open an issue with the `discussion` label.
- **Did my PR get reviewed yet?** Tag `@TruStacks/maintainers` if it's been more than 7 days.
- **General questions about TruStacks the product**: see https://trustacks.com.
