"""Every action SHA the packs pin is one somebody resolved and reviewed.

`practice.workflow_pins_action_versions` proves a pin *looks* like a
SHA. That is not the same as being one. Four tool-action pins had the right
shape and named no commit at all (three are fixed; semgrep needs a redesign),
and the framework packs pinned `actions/checkout` v4.1.1 and other Node 20
actions after GitHub removed Node 20
from its hosted runners (2026-09-23). Every proposal built on those pins either
failed to resolve the action or ran on a runtime GitHub no longer ships.

So the pins are listed here with the tag each SHA was resolved from (annotated
tags dereferenced). Changing a pin means re-resolving it and updating this
table in the same PR, which is the review. Framework templates also carry the
tag as a trailing `# vX.Y.Z` comment, and it must match. The packs are
byte-identical in trustacks-mvp (ADR-0058), which carries the same table.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PACKS = Path(__file__).resolve().parents[1]

#: action -> {sha: tag}. Resolved 2026-11-02 from the tag ref via the GitHub
#: API; the runtime noted is what action.yml declares at that SHA.
REVIEWED: dict[str, dict[str, str]] = {
    # node24
    "actions/checkout": {
        "de0fac2e4500dabe0009e67214ff5f5447ce83dd": "v6.0.2",  # framework packs, our CI
        "d23441a48e516b6c34aea4fa41551a30e30af803": "v6.1.0",  # ECS target kind
    },
    "actions/setup-go": {"b7ad1dad31e06c5925ef5d2fc7ad053ef454303e": "v7.0.0"},
    "actions/setup-python": {"6d4fd22b20465ccc0f7354476588e8df7c9ca0e0": "v7.1.0"},
    "actions/setup-java": {"b843ebf9b913146b38da2eaa7aeddf76074ae1ad": "v6.1.0"},
    "actions/setup-dotnet": {"a98b56852c35b8e3190ac28c8c2271da59106c68": "v6.0.0"},
    "docker/setup-qemu-action": {"ce360397dd3f832beb865e1373c09c0e9f86d70a": "v4.0.0"},
    "docker/setup-buildx-action": {"d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5": "v4.1.0"},
    "docker/login-action": {"650006c6eb7dba73a995cc03b0b2d7f5ca915bee": "v4.2.0"},
    "docker/build-push-action": {"f9f3042f7e2789586610d6e8b85c8f03e5195baf": "v7.2.0"},
    "gitleaks/gitleaks-action": {"e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e": "v3.0.0"},
    "anchore/sbom-action": {"66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c": "v0.24.3"},
    "github/codeql-action/upload-sarif": {
        "6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee": "v4.39.0",
    },
    "aws-actions/configure-aws-credentials": {
        "e1253824e5c10ff9df46874f81ed3ec929e19cfd": "v6.3.0",
    },
    "aws-actions/amazon-ecs-deploy-task-definition": {
        "c465972ecbd160473f22e683363b422a5412a3de": "v2.6.3",
    },
    # composite (no Node runtime)
    "sigstore/cosign-installer": {"dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da": "v3.7.0"},
    "aquasecurity/trivy-action": {"ed142fd0673e97e23eac54620cfb913e5ce36c25": "v0.36.0"},
}

#: Pins that do not resolve and have no fix in this table. `semgrep/semgrep`
#: is not a GitHub Action (its repo has no action.yml); the pack needs a
#: redesign (container image + `semgrep ci`), not a new SHA. Listed so the gap
#: is visible rather than passing as reviewed.
UNRESOLVED = {"semgrep/semgrep@b6c8e8b4f9e8b4a5e8b4f9e8b4a5e8b4f9e8b4a5"}

_PIN = re.compile(r"(?:uses|action):\s*(?P<action>[\w.-]+/[\w./-]+)@(?P<sha>[0-9a-f]{40})")
_TEMPLATE_USES = re.compile(
    r"uses:\s*(?P<action>[\w.-]+/[\w./-]+)@(?P<sha>[0-9a-f]{40})(?P<rest>[^\n]*)"
)


def _pack_files() -> list[Path]:
    files = sorted(
        p
        for sub in ("frameworks", "tool-actions", "target-kinds")
        for p in (PACKS / sub).glob("*.yaml")
    )
    assert files, "premise — the shipped packs exist"
    return files


@pytest.mark.parametrize("path", _pack_files(), ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_every_pinned_sha_is_a_reviewed_one(path: Path) -> None:
    for m in _PIN.finditer(path.read_text(encoding="utf-8")):
        ref = f"{m['action']}@{m['sha']}"
        if ref in UNRESOLVED:
            continue
        reviewed = REVIEWED.get(m["action"], {})
        assert m["sha"] in reviewed, (
            f"{path.name}: `{ref}` is not in the reviewed table (reviewed: {reviewed})"
        )


@pytest.mark.parametrize(
    "path", sorted((PACKS / "frameworks").glob("*.yaml")), ids=lambda p: p.stem
)
def test_framework_template_pins_name_their_tag(path: Path) -> None:
    """`uses: owner/repo@<sha> # vX.Y.Z` — the comment is how a reviewer reads a
    SHA, so it must be the tag the SHA was resolved from."""
    found = 0
    for m in _TEMPLATE_USES.finditer(path.read_text(encoding="utf-8")):
        found += 1
        tag = REVIEWED[m["action"]][m["sha"]]
        assert m["rest"].strip() == f"# {tag}", (
            f"{path.name}: `{m['action']}@{m['sha']}` should carry `# {tag}`, has {m['rest']!r}"
        )
    assert found, f"{path.name}: no pinned `uses:` found (premise)"
