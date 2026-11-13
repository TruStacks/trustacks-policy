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
import yaml

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
    # Resolved 2026-11-06 (lightweight tag); keeps SARIF where code scanning
    # isn't available. The same pin trustacks-mvp's own CI uses.
    "actions/upload-artifact": {"cf430e030ddbb5b0abf93d22962f4752f3646cd9": "v7.0.2"},
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

#: Container steps (`docker://image:tag@sha256:<digest>`): image -> {digest:
#: tag}. A tool that ships no GitHub Action runs from its image (#828: the
#: semgrep pack pinned `semgrep/semgrep@<sha>`, which named no commit and is not
#: an action). The digest is the multi-arch index digest of the tag, resolved
#: from the registry, and the ref must carry that same tag.
REVIEWED_IMAGES: dict[str, dict[str, str]] = {
    # Resolved 2026-11-13 from Docker Hub (index: linux/amd64 + linux/arm64).
    "semgrep/semgrep": {
        "sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d": "1.185.0",
    },
}

#: Every `uses:` value, whatever its ref looks like: a tag, a branch, a short
#: SHA and a full SHA are all found, so a ref that is not a reviewed SHA fails
#: instead of going unseen. Matches inside templates and comments too, since
#: the agent copies both.
_USES = re.compile(r"""uses:\s*['"]?(?P<ref>[^\s#'"]+)['"]?(?P<rest>[^\n]*)""")
_FULL_SHA = re.compile(r"^(?P<action>[\w.-]+/[\w./-]+)@(?P<sha>[0-9a-f]{40})$")
_IMAGE = re.compile(
    r"^docker://(?P<image>[\w./-]+):(?P<tag>[\w.-]+)@(?P<digest>sha256:[0-9a-f]{64})$"
)


def _is_local(ref: str) -> bool:
    """Local actions and container images are not pinned by commit SHA."""
    return ref.startswith(("./", "docker://"))


def action_refs(text: str, action_field: str | None = None) -> list[str]:
    """Every action reference in a pack: each `uses:` plus a tool-action pack's
    `action:` field."""
    refs = [m["ref"] for m in _USES.finditer(text) if not _is_local(m["ref"])]
    if action_field is not None:
        refs.append(action_field.strip())
    return refs


def unreviewed(refs: list[str]) -> list[str]:
    """The refs that are not exactly a reviewed 40-char SHA (or image digest) from the tables."""
    bad: list[str] = []
    for ref in refs:
        if ref.startswith("docker://"):
            img = _IMAGE.match(ref)
            if (
                img is None
                or REVIEWED_IMAGES.get(img["image"], {}).get(img["digest"]) != img["tag"]
            ):
                bad.append(ref)
            continue
        m = _FULL_SHA.match(ref)
        if m is None or m["sha"] not in REVIEWED.get(m["action"], {}):
            bad.append(ref)
    return bad


def _pack_files() -> list[Path]:
    files = sorted(
        p
        for sub in ("frameworks", "tool-actions", "target-kinds")
        for p in (PACKS / sub).glob("*.yaml")
    )
    assert files, "premise — the shipped packs exist"
    return files


def _refs_in(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    field = None
    if path.parent.name == "tool-actions":
        field = yaml.safe_load(text).get("action")
        assert isinstance(field, str) and field, f"{path.name}: no `action:` field"
    return action_refs(text, field)


@pytest.mark.parametrize("path", _pack_files(), ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_every_action_reference_is_a_reviewed_sha(path: Path) -> None:
    refs = _refs_in(path)
    assert refs, f"{path.name}: no action reference found (premise)"
    bad = unreviewed(refs)
    assert not bad, f"{path.name}: not a reviewed SHA or image digest from the tables: {bad}"


@pytest.mark.parametrize(
    "text",
    [
        "action: gitleaks/gitleaks-action@v3\n",
        "steps:\n  - uses: actions/checkout@main\n",
        "steps:\n  - uses: 'actions/checkout@v6'\n",
        "steps:\n  - uses: actions/checkout@de0fac2\n",
        "steps:\n  - uses: actions/checkout\n",
        # a real-looking SHA that is not the reviewed one
        "steps:\n  - uses: actions/checkout@" + "a" * 40 + "\n",
        # a reviewed SHA under another action's name
        "steps:\n  - uses: evil/action@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n",
        # a container by tag, and the reviewed digest under the wrong tag
        "action: docker://semgrep/semgrep:1.185.0\n",
        "action: docker://semgrep/semgrep:1.184.0@"
        "sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d\n",
    ],
)
def test_a_tag_branch_or_unreviewed_ref_fails(text: str) -> None:
    """The scan must see a ref that is not a full SHA, not skip it."""
    field = None
    if text.startswith("action:"):
        field = yaml.safe_load(text)["action"]
        text = ""
    refs = action_refs(text, field)
    assert refs, "the reference was not found at all"
    assert unreviewed(refs) == refs


def test_local_actions_are_not_references() -> None:
    assert action_refs("- uses: ./.github/actions/x\n- uses: docker://alpine:3\n") == []


@pytest.mark.parametrize(
    "path", sorted((PACKS / "frameworks").glob("*.yaml")), ids=lambda p: p.stem
)
def test_framework_template_pins_name_their_tag(path: Path) -> None:
    """`uses: owner/repo@<sha> # vX.Y.Z` — the comment is how a reviewer reads a
    SHA, so it must be the tag the SHA was resolved from."""
    found = 0
    for m in _USES.finditer(path.read_text(encoding="utf-8")):
        pin = _FULL_SHA.match(m["ref"])
        assert pin is not None, f"{path.name}: `{m['ref']}` is not a full SHA"
        found += 1
        tag = REVIEWED[pin["action"]][pin["sha"]]
        assert m["rest"].strip() == f"# {tag}", (
            f"{path.name}: `{m['ref']}` should carry `# {tag}`, has {m['rest']!r}"
        )
    assert found, f"{path.name}: no pinned `uses:` found (premise)"
