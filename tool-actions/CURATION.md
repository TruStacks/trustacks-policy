# Tool actions packs — curation cadence

Each YAML in this directory pins one Profile-tool-name to its canonical
GitHub Action + SHA. The pack's `last_verified` field records when the
SHA was last reviewed against the action's marketplace listing.

## Refresh cadence (recommended)

Quarterly. The action authors release new versions on their own
schedule; CVE patches arrive ad-hoc. Re-verify each pack's SHA against
the marketplace and update if a newer release is preferred.

## How to refresh one pack

1. Visit the action's marketplace page (e.g. <https://github.com/marketplace/actions/anchore-sbom-action>)
2. Note the latest release tag (e.g. `v0.20.5`)
3. Resolve the tag to its commit SHA via the GitHub API:
   ```
   gh api /repos/anchore/sbom-action/git/refs/tags/v0.20.5 \
     --jq '.object.url' \
     | xargs gh api --jq '.object.sha'
   ```
   For lightweight tags this returns the SHA directly. For annotated
   tags resolve the dereferenced object.
4. Update `action:` (in `<owner>/<repo>@<sha>` form) and
   `action_version_label:` in the pack YAML. Set `last_verified:` to
   today's ISO-8601 date.
5. If the action's documented inputs have changed, update the `inputs:`
   block to match.
6. Open a PR. CI parses every pack in this directory, so a
   format-broken SHA fails the build rather than reaching a customer's
   pipeline. (The loader's own unit tests live in the TruStacks product
   repo, which consumes these packs.)
7. Commit + PR.

## Why pin SHAs (not tags)

Tags can be moved. A malicious actor with push access to an action
repo can re-point `v0.20.5` to a different commit and hijack workflows
that pin to the tag. SHAs are immutable. Per OpenSSF SLSA guidance and
GitHub's own [security hardening
docs](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions),
production workflows should pin third-party actions to SHAs.

The constitution's `practice.workflow_pins_action_versions` rule
enforces this on the agent's emitted workflows. This pack ensures the
agent has correct SHAs to emit so the rule never has to fire on
TruStacks-curated tools.

## Why not auto-refresh

A bot that auto-bumps SHAs without review defeats the purpose of
pinning. SHA refreshes are a curation decision — does the new release
patch a CVE? Does it change the action's input schema? Are there
breaking changes that affect our emitted workflows? A human reviews
each refresh before it ships.
