# Target-kind packs

One YAML per **deployment-target kind** that is not Kubernetes. A deployment
target is `{name, tier, kind}`. Tier means the same thing for every kind, and
the kind decides what a deploy physically is. Kubernetes targets are described
by the [renderer packs](../renderers/); a pack here is used only when the
target's kind is something else.

## Shipped packs

| Pack | Kind | What TruStacks emits, per service per target |
|---|---|---|
| `ecs-fargate.yaml` | AWS ECS on Fargate | a hardened `task-definition.json`; a blank, customer-owned `deploy-target.json` (account, region, roles, cluster, service); a push-to-`main` deploy workflow that assumes an AWS role via GitHub OIDC and applies the merged task definition |

TruStacks writes these artifacts and the customer runs them. The pack never
creates infrastructure: no ECS cluster or service, VPC, IAM roles, OIDC
provider or log group.

## What a pack declares

- **`default_root_template`**: where the artifacts live. It must contain
  `{cluster}` (the target name), because the task definition is per target.
- **`task_definition`**: the canonical skeleton the agent adapts. The agent
  never removes its hardening.
- **`binding`**: the keys of the customer-owned binding file and the format
  each value must have.
  - The product emits every value blank, because these are facts about the
    customer's account.
  - The deploy workflow refuses to run until they are filled in.
- **`deploy_workflow`**: the resolved deploy workflow. Every `uses:` in it is
  pinned to a full commit SHA. Refresh them per
  [`tool-actions/CURATION.md`](../tool-actions/CURATION.md).
- **`deploy_action`**: the action whose presence makes a workflow a deploy
  workflow. The constitution's `_ecs_deploy_action` names the same one.

## Like renderer packs, a missing pack is fatal

For a target of a kind with no pack, the product refuses to emit. It does not
fall back to Kubernetes artifacts, which would pass every Kubernetes rule and
deploy nowhere.

## Status

These packs are authored here. Until the policy build moves to this repo, the
product still ships its own copy inside the runner image, so a change here needs
the matching change there.
