"""Every framework pack's CI carries the TruStacks policy check (ADR-0067 decision 3).

The reusable CI a pack ships judges every PR to the service repo with this
repo's signed constitution, whoever or whatever wrote the change. Each runtime
gets one read-only job running the same script, which verifies the bundle's
keyless signature against this repo's publish workflow before evaluating, and
reports only rules that declare `subjects: repo`. Report-only by default.

The job adds a `uses:` (checkout) to every GitHub template, so the pack must
still pass `practice.workflow_pins_action_versions`; that half needs a real
`opa` binary and is skipped without one.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSTITUTION = REPO_ROOT / "constitution"
FRAMEWORK_PACKS = sorted((REPO_ROOT / "frameworks").glob("*.yaml"))
IDENTITY = (
    r"^https://github\.com/TruStacks/trustacks-policy/\.github/workflows/publish\.yml"
    r"@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$"
)


def _pack(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _github(path: Path) -> dict[Any, Any]:
    return yaml.safe_load(_pack(path)["ci_workflow_template"])


def _azure_policy_job(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(_pack(path)["ci_templates"]["azure_pipelines"])
    return next(j for st in doc["stages"] for j in st["jobs"] if j.get("job") == "policy_check")


@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_both_runtimes_ship_a_read_only_policy_check(pack_path: Path) -> None:
    job = _github(pack_path)["jobs"]["policy-check"]
    assert job["permissions"] == {"contents": "read"}
    step = next(s for s in _azure_policy_job(pack_path)["steps"] if "script" in s)
    assert step["target"]["commands"] == "restricted"


def test_the_script_is_identical_and_verifies_this_repos_signature() -> None:
    scripts = set()
    for path in FRAMEWORK_PACKS:
        gh = _github(path)["jobs"]["policy-check"]["steps"]
        scripts.add(next(s["run"] for s in gh if "run" in s))
        az = _azure_policy_job(path)["steps"]
        scripts.add(next(s["script"] for s in az if "script" in s))
    assert len(scripts) == 1
    script = scripts.pop()
    assert IDENTITY in script
    assert script.index('cosign" verify') < script.index('opa" eval')
    assert '"repo" in object.get(' in script


@pytest.mark.skipif(shutil.which("opa") is None, reason="needs a real opa binary")
@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_the_github_workflow_still_passes_the_pinning_rule(pack_path: Path) -> None:
    payload = {
        "proposal": {
            "files": [
                {
                    "path": ".github/workflows/ci-svc.yaml",
                    "content": _pack(pack_path)["ci_workflow_template"],
                }
            ]
        },
        "context": {"platform_repo_url": "https://example.invalid/acme/platform"},
    }
    proc = subprocess.run(
        ["opa", "eval", "-d", str(CONSTITUTION), "-I", "data.proposal.deny", "--format", "json"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    result = json.loads(proc.stdout)["result"]
    denied = {v["rule_id"] for v in result[0]["expressions"][0]["value"]} if result else set()
    assert "practice.workflow_pins_action_versions" not in denied


def test_the_github_checkout_does_not_persist_credentials() -> None:
    """Fork-safe: no token stays on disk for later steps."""
    for path in FRAMEWORK_PACKS:
        steps = _github(path)["jobs"]["policy-check"]["steps"]
        checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@"))
        assert checkout["with"]["persist-credentials"] is False, path.name


def test_a_file_it_cannot_check_fails_enforce(tmp_path: Path) -> None:
    """Fail closed (review on trustacks-mvp#795): never drop a delivery file silently."""
    script = next(
        s["run"] for s in _github(FRAMEWORK_PACKS[0])["jobs"]["policy-check"]["steps"] if "run" in s
    )
    collector, reporter = (b.split("\nPY\n", 1)[0] for b in script.split("<<'PY'\n")[1:])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\nUSER 1001\n")
    (repo / "latin1.dockerfile").write_bytes(b"FROM x\n# caf\xe9\n")
    inp, unchecked, violations = (tmp_path / n for n in ("in.json", "un.json", "v.json"))
    subprocess.run(
        ["python3", "-", str(repo), str(inp), str(unchecked)], input=collector, text=True, check=True
    )
    assert [u["path"] for u in json.loads(unchecked.read_text())["unchecked"]] == [
        "latin1.dockerfile"
    ]
    violations.write_text("[]")
    enforced = subprocess.run(
        ["python3", "-", str(violations), str(unchecked), "true"],
        input=reporter,
        text=True,
        capture_output=True,
        check=False,
    )
    assert enforced.returncode == 1
    assert "could not check 1" in enforced.stdout
