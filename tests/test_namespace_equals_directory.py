"""Rule-naming standard v2: a rule's namespace is the directory it lives in.

``constitution/<namespace>/<name>.rego`` holds the rule whose id is
``<namespace>.<name>``; ``industry-overlays/<namespace>/…`` the same. The id is
written out in the file and **never derived from the path** — rule ids are
persisted in customer history (denial counts, scores, evidence), so moving a
file must not silently re-ID a rule. This test makes the two agree instead:
move a rule without renaming it and CI fails here, rather than shipping a
``practice.*`` rule out of ``proposal/``.

Every directory under ``constitution/`` is also a reserved namespace, and
``data.naming.json`` — the copy the naming gate reads — must say so. Before v2
the constitution shipped ``practice.*`` and ``posture.*`` without reserving
either, so a customer overlay could claim them.

See ``standards/rule-naming.md``. The ids are read from each file's AST with
``opa parse``, the same way ``scripts/build_inventory.py`` attributes a rule to
its file, so this checks what the published inventory will say.

Requires a real ``opa`` binary; skipped when absent (CI proves it is present).
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSTITUTION = REPO_ROOT / "constitution"
INDUSTRY_OVERLAYS = REPO_ROOT / "industry-overlays"
NAMING = json.loads((CONSTITUTION / "data.naming.json").read_text(encoding="utf-8"))["naming"]

#: Reserved with no directory: the brand namespace.
RESERVED_WITHOUT_A_DIRECTORY = frozenset({"trustacks"})

#: Ids that predate the grammar and keep their spelling, because ids are
#: customer history. ``repoURL`` is camelCase and the grammar is lowercase-only;
#: renaming it would orphan every denial, score and evidence record that cites
#: it. This list may shrink; it must never grow.
GRANDFATHERED_IDS = frozenset({"argocd.repoURL_is_canonical"})

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="needs a real opa binary")


def _builder():
    spec = importlib.util.spec_from_file_location(
        "build_inventory", REPO_ROOT / "scripts" / "build_inventory.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rule_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.rego") if not p.name.endswith("_test.rego"))


def _declared(path: Path) -> set[str]:
    return _builder().declared_rule_ids(shutil.which("opa"), path)


def _constitution_dirs() -> set[str]:
    return {p.name for p in CONSTITUTION.iterdir() if p.is_dir()}


@pytest.mark.parametrize("root", [CONSTITUTION, INDUSTRY_OVERLAYS], ids=lambda p: p.name)
def test_every_rule_id_namespace_equals_its_directory(root: Path) -> None:
    mismatched = sorted(
        f"{path.relative_to(REPO_ROOT)}: {rule_id}"
        for path in _rule_files(root)
        for rule_id in _declared(path)
        if rule_id.split(".", 1)[0] != path.relative_to(root).parts[0]
    )
    assert not mismatched, (
        "a rule's namespace must equal its directory (standards/rule-naming.md v2). "
        "Never rename the id to match a move — ids are customer history; move the "
        f"file back instead: {mismatched}"
    )


def test_no_constitution_rego_outside_a_namespace_directory() -> None:
    misplaced = [
        str(p.relative_to(CONSTITUTION))
        for p in CONSTITUTION.rglob("*.rego")
        if len(p.relative_to(CONSTITUTION).parts) != 2
    ]
    assert not misplaced, f"rego outside constitution/<namespace>/: {misplaced}"


def test_every_constitution_directory_is_reserved() -> None:
    assert set(NAMING["reserved_namespaces"]) == _constitution_dirs() | RESERVED_WITHOUT_A_DIRECTORY, (
        "every directory under constitution/ is a reserved namespace; data.naming.json "
        "must list exactly those plus `trustacks`. It is generated in the product repo "
        "from the canonical rule-naming module — regenerate it there and copy it here."
    )


def test_industry_overlays_do_not_claim_a_reserved_namespace() -> None:
    if not INDUSTRY_OVERLAYS.is_dir():
        return
    claimed = {p.name for p in INDUSTRY_OVERLAYS.iterdir() if p.is_dir()}
    assert not claimed & set(NAMING["reserved_namespaces"])


def test_every_rule_id_matches_the_grammar() -> None:
    pattern = re.compile(NAMING["rule_id_pattern"])
    bad = [
        rule_id
        for root in (CONSTITUTION, INDUSTRY_OVERLAYS)
        for path in _rule_files(root)
        for rule_id in _declared(path)
        if rule_id not in GRANDFATHERED_IDS
        and (not pattern.fullmatch(rule_id) or len(rule_id) > NAMING["max_rule_id_length"])
    ]
    assert not bad, bad


def test_grandfathered_ids_still_exist_and_still_need_it() -> None:
    ids = {rule_id for path in _rule_files(CONSTITUTION) for rule_id in _declared(path)}
    assert ids >= GRANDFATHERED_IDS
    pattern = re.compile(NAMING["rule_id_pattern"])
    assert not any(pattern.fullmatch(rule_id) for rule_id in GRANDFATHERED_IDS)


def test_the_constitution_ships_the_sixteen_ids_it_always_has() -> None:
    """The directory split moved files, not ids. A changed set is customer history."""
    ids = {rule_id for path in _rule_files(CONSTITUTION) for rule_id in _declared(path)}
    assert ids == {
        "proposal.allowed_paths",
        "proposal.no_path_traversal",
        "proposal.has_workflow",
        "proposal.has_helm_chart",
        "proposal.has_kustomization",
        "proposal.has_argocd_application",
        "argocd.repoURL_is_canonical",
        "practice.workflow_has_test_step",
        "practice.workflow_has_lint_step",
        "practice.argocd_prod_requires_manual_sync",
        "practice.dockerfile_runs_as_nonroot",
        "practice.workflow_pins_action_versions",
        "posture.image_scanning_declared",
        "posture.sast_sca_declared",
        "posture.secret_scanning_declared",
        "posture.sbom_signing_declared",
    }


def test_the_inventory_attributes_each_rule_to_its_own_file(tmp_path: Path) -> None:
    """The published inventory's rego_body is the declaring file, not the tree.

    The practice rules cannot be evaluated alone — they call practice/lib.rego —
    so this also proves the builder's whole-tree fallback lists them.
    """
    out = tmp_path / "rule_inventory.json"
    subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "build_inventory.py"),
         "--source", str(CONSTITUTION), "--out", str(out), "--label", "constitution"],
        check=True, capture_output=True, text=True, timeout=120,
    )  # fmt: skip
    entries = json.loads(out.read_text(encoding="utf-8"))["constitution_inventory"]
    declared_in = {
        rule_id: path.read_text(encoding="utf-8")
        for path in _rule_files(CONSTITUTION)
        for rule_id in _declared(path)
    }
    assert {e["rule_id"] for e in entries} == set(declared_in)
    for entry in entries:
        assert entry["rego_body"] == declared_in[entry["rule_id"]], entry["rule_id"]
