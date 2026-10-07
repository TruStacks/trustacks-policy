# Renderer packs

One YAML per renderer — the tool that turns a service's deploy config into
Kubernetes manifests. A pack tells the TruStacks DevOps Engineer exactly which
files to emit for that renderer, where they go in the platform repo, what the
ArgoCD Application points at, and which command proves the result renders.

## Shipped packs

| Pack | Renderer | Layout |
|---|---|---|
| `helm.yaml` | Helm | one chart per cluster: `gitops/{application}/{cluster}/{service}` |
| `kustomize.yaml` | Kustomize | a shared base plus one overlay per cluster: `gitops/{application}/{service}/{base,overlays/{cluster}}` |

The renderer is a per-Application setting in TruStacks (ADR-0052 in the product
repo). The Application may override the default root template; the pack's
`default_root_template` is what applies otherwise.

## Why these exist

Without a pack, the layout lived in prose inside the agent's prompt, and a second
renderer would have been a branch in code. As a pack, a new renderer is a file:
which files exist, where they go, what ArgoCD points at, and the command that
proves they work (`helm template`, `kustomize build`). The product runs that
command against every emitted artifact before a PR opens, so a pack that
describes a layout which cannot render fails before a customer ever sees it.

## One difference from the other pack families

**A missing renderer pack is fatal, not degraded.** A missing framework pack
means the agent works without framework-specific grounding; a missing tool-action
pack means no pipeline step for that tool. There is no free-style fallback for a
layout, so the product refuses to emit rather than guess. Keep that in mind when
reviewing a change that renames or removes a pack.

## Status

These packs are authored here. Until the policy build moves to this repo, the
product still ships its own copy inside the runner image, so a change here needs
the matching change there.

## Contributing

Copy the closest existing pack, keep every top-level key (the product's loader is
schema-strict), and open a PR with `git commit -s`. A new renderer also needs
loader and validation support in the product before it can be selected.
