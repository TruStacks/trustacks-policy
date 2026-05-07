# CI runtime packs

CI runtime packs let the TruStacks DevOps Engineer agent emit CI workflow content in formats other than GitHub Actions. Each pack maps a generic CI workflow shape (build, test, lint, scan, sign, deploy) onto a specific runtime's syntax.

This directory is the open-source home for community-contributed CI runtime packs.

---

## Status — bootstrap

This directory is **empty by design** as of repository bootstrap. The TruStacks agent today emits **GitHub Actions** workflows only. GitLab CI, Azure DevOps, Tekton, and Dagger packs are queued in the product roadmap as Slices 27–30 (post-Beta).

The first contribution windows will open when:

- **GitLab CI pack** — when the product runner gains the multi-format-emit capability (Slice 28 of the trustacks-mvp roadmap).
- **Azure DevOps pack** — same dependency (Slice 27).
- **Tekton pack** — same dependency (Slice 29).
- **Dagger pack** — same dependency (Slice 30, lower priority).

A community contribution to this directory before the runner-side support lands is welcome but won't ship to customers until the product side catches up. Expect the pack format to evolve during that window.

---

## Why this is its own layer

Framework packs (`frameworks/`) describe what the *application* looks like. CI runtime packs describe what the *automation* looks like. The two are orthogonal — a Spring Boot service can run on GitHub Actions or GitLab CI; a GitLab CI pack should work for any framework. Splitting them keeps each pack small and contributable independently.

---

## What a pack will look like (preview)

The format is not yet locked. The expected shape, drawn from the framework pack pattern:

```yaml
ci_runtime: gitlab_ci
display_name: GitLab CI
detection:
  - file_present: [.gitlab-ci.yml]
  - profile_declares_ci_runtime: gitlab_ci

# Templates per common workflow shape. The agent picks the
# right template based on the customer's framework + tooling.
templates:
  build_test_lint:
    file_path: .gitlab-ci.yml
    content: |
      ...
  build_scan_sign:
    file_path: .gitlab-ci.yml
    content: |
      ...
```

A canonical schema lands when Slice 27 (Azure DevOps, the first non-GitHub-Actions runtime) lands in the product. Until then, this README is a placeholder.

---

## Contributing

Wait for the schema to land before contributing a full pack. If you want to help shape it earlier, open a GitHub issue with the `discussion` label describing your CI runtime + the workflow shapes your team uses. We'll fold that into the schema design.
