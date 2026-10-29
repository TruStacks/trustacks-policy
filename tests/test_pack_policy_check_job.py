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
import os
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


def _gitlab(path: Path) -> dict[str, Any]:
    return yaml.safe_load(_pack(path)["ci_templates"]["gitlab_ci"])


@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_the_gitlab_policy_check_is_read_only_and_report_only(pack_path: Path) -> None:
    """Fetch only, no variable but the enforce switch, findings exit 3 (a warning)."""
    doc = _gitlab(pack_path)
    job = doc["policy_check"]
    assert job["variables"]["GIT_STRATEGY"] == "fetch"
    assert set(job["variables"]) == {"GIT_STRATEGY", "GIT_DEPTH", "TRUSTACKS_ENFORCE"}
    assert job["allow_failure"] == {"exit_codes": [3]}
    assert doc["variables"] == {"TRUSTACKS_ENFORCE_POLICY": "false"}
    assert "only" not in job and "except" not in job


def test_the_script_is_identical_and_verifies_this_repos_signature() -> None:
    scripts = set()
    for path in FRAMEWORK_PACKS:
        gh = _github(path)["jobs"]["policy-check"]["steps"]
        scripts.add(next(s["run"] for s in gh if "run" in s))
        az = _azure_policy_job(path)["steps"]
        scripts.add(next(s["script"] for s in az if "script" in s))
        scripts.add(_gitlab(path)["policy_check"]["script"][0])
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

    # On GitLab, report-only findings exit 3, which `allow_failure: exit_codes`
    # shows as a warning rather than a pass that hides them.
    on_gitlab = subprocess.run(
        ["python3", "-", str(violations), str(unchecked), "false"],
        input=reporter,
        text=True,
        capture_output=True,
        check=False,
        env={"PATH": os.environ.get("PATH", ""), "GITLAB_CI": "true"},
    )
    assert on_gitlab.returncode == 3


#: Where each CI runtime keeps its pipeline files, and look-alikes that aren't.
CI_FILES = {
    ".github/workflows/ci.yaml": True,
    ".gitlab-ci.yml": True,
    ".gitlab/ci/ci-api.yml": True,
    "azure-pipelines.yml": True,
    "azure-pipelines/templates/ci.yml": True,
    ".gitlab/issue_templates/bug.yml": False,
    "ci/gitlab-ci.yml": False,
    ".github/dependabot.yml": False,
}


def _collector() -> str:
    script = _gitlab(FRAMEWORK_PACKS[0])["policy_check"]["script"][0]
    return script.split("<<'PY'\n")[1].split("\nPY\n", 1)[0]


def test_every_runtimes_ci_files_are_collected(tmp_path: Path) -> None:
    """Not only `.github/workflows/`: a GitLab or Azure repo's own pipeline too
    (review on trustacks-mvp#807)."""
    repo = tmp_path / "repo"
    for rel in CI_FILES:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("jobs: {}\n")
    inp, unchecked = tmp_path / "in.json", tmp_path / "un.json"
    subprocess.run(
        ["python3", "-", str(repo), str(inp), str(unchecked)],
        input=_collector(),
        text=True,
        check=True,
    )
    collected = {f["path"] for f in json.loads(inp.read_text())["proposal"]["files"]}
    assert collected == {rel for rel, ci in CI_FILES.items() if ci}


@pytest.mark.skipif(shutil.which("opa") is None, reason="needs a real opa binary")
def test_a_gitlab_repos_unpinned_image_is_reported_without_a_model(tmp_path: Path) -> None:
    """The CI job sends no pipeline model; the bundle still judges GitLab pinning."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitlab-ci.yml").write_text("test:\n  image: python:3.12-slim\n  script: [pytest]\n")
    inp, unchecked = tmp_path / "in.json", tmp_path / "un.json"
    subprocess.run(
        ["python3", "-", str(repo), str(inp), str(unchecked)],
        input=_collector(),
        text=True,
        check=True,
    )
    proc = subprocess.run(
        ["opa", "eval", "-d", str(CONSTITUTION), "-i", str(inp), "--format", "json",
         "data.proposal.deny"],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )  # fmt: skip
    result = json.loads(proc.stdout)["result"]
    messages = [
        v["message"]
        for v in result[0]["expressions"][0]["value"]
        if v["rule_id"] == "practice.workflow_pins_action_versions"
    ]
    assert any("python:3.12-slim" in m for m in messages)


@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_the_gitlab_build_jobs(pack_path: Path) -> None:
    """Merge requests build without a login or push; the push isn't interruptible."""
    doc = _gitlab(pack_path)
    assert doc["default"] == {"interruptible": True}
    check = doc["build_check"]
    assert check["rules"] == [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'}]
    assert not any("login" in s or "push" in s for s in check["script"])
    assert doc["build"]["interruptible"] is False
    assert doc["build"]["rules"] == [{"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"}]
