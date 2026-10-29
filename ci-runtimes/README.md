# CI runtime packs

CI runtime packs let the TruStacks DevOps Engineer agent emit CI pipelines in formats other than GitHub Actions. A pack describes what is the same for every framework on one CI system: where the pipeline files go, how the service repo consumes them, which tasks may be used and at what version, and what the customer has to set up outside YAML.

Framework packs (`frameworks/`) describe what the *application* looks like and carry one reference pipeline per runtime. CI runtime packs describe the *automation*. The two are orthogonal: a Spring Boot service can run on GitHub Actions or Azure Pipelines.

**GitHub Actions is the default runtime and has no pack.** Its shape lives in each framework pack's `ci_workflow_template`.

## Status

| Runtime | Pack | Runner support |
|---|---|---|
| Azure Pipelines | [`azure_pipelines.yaml`](azure_pipelines.yaml) | trustacks-mvp ADR-0071 step 4b |
| GitLab CI | [`gitlab_ci.yaml`](gitlab_ci.yaml) | trustacks-mvp ADR-0071 decision 5 (`tasks: []`: every step is a script line in a digest-pinned image) |
| Tekton, Dagger | — | on demand |

A runtime is used for a proposal only when the customer's Stack file declares it as the primary `ci_cd_platform` **and** the runner has its pack. Anything else gets GitHub Actions.

## Schema

The file name is the runtime id (`azure_pipelines.yaml` holds `ci_runtime: azure_pipelines`). A pack is rejected, not skipped, when it doesn't match this schema.

```yaml
ci_runtime: azure_pipelines        # matches the file name; never github_actions
display_name: Azure Pipelines

paths:                              # relative to the platform repo root
  template: azure-pipelines/templates/ci-{service}.yml   # one per service; {service} required
  step_templates: azure-pipelines/templates/steps/       # fragments included only from the template
  deploy: azure-pipelines/deploy-{service}.yml           # non-GitOps delivery; {service} required

caller:                             # shown in the PR body for the SERVICE repo, never written
  path: azure-pipelines.yml
  template: |
    ...                             # <service> is filled in by the runner

tasks:                              # the only tasks the agent may use
  - name: Docker
    major: 2
    recommended: 2.282.0            # a full X.Y.Z version
    purpose: ...
    source: <where the version came from>
    verified_in_org: false          # true once seen working in a real organization

image_pinning: digest               # every container image is image@sha256:<64 hex>

setup_checklist:                    # what the customer sets up outside YAML; listed in the PR body
  - ...

cannot_verify:                      # read through the API and labelled observed, never asserted
  - ...
```

A framework pack adds its reference pipeline for the runtime under `ci_templates`, keyed by runtime id. The key is additive: a loader that predates it reads the pack exactly as before.

```yaml
ci_templates:
  azure_pipelines: |
    ...
```

## What the gate checks

The constitution judges every runtime's pipelines on one neutral model (`input.proposal.pipelines`), so the test, lint and prod-environment rules mean the same thing everywhere. Pinning is per runtime: for Azure Pipelines, a task must name a full version and a container must be pinned by digest. `tests/test_pack_workflows_pass_the_constitution.py` runs every framework pack's template for every runtime through those rules.

## Contributing

A new runtime needs, in one change: the runtime pack, a template in each framework pack, runner support in trustacks-mvp (a normaliser in `policy/pipelines.py` and a prompt addendum), and the pinning rule for its step references. Open an issue first; the shape of "pinned" differs a lot between CI systems.
