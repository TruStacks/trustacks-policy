"""Every framework pack's canonical CI workflow must satisfy the constitution.

The bug this exists to prevent (#551): `frameworks/spring_boot.yaml`
emitted `mvn -B verify -Dlint=true` under a comment asserting

    Matches the constitution's `practice.workflow_has_lint_step` accepted
    substring `mvn -B verify -Dlint`.

The claim was false. The matcher lowercases the command and the needle list was
never lowercased, so that needle could not match anything — Java could not pass
the gate no matter what the agent emitted, and every Spring Boot proposal was
denied after a full agent run.

Two artifacts we ship, each correct on its own terms, and nothing ran them
together. That is the gap this file closes: it is not a test of the rules or of
the packs, it is a test of the *pair*.

Requires a real `opa` binary. Skipped when absent rather than silently passing —
a check that could not run is not a pass (ADR-0038).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSTITUTION = REPO_ROOT / "constitution"  # the whole tree: rules call lib helpers
FRAMEWORK_PACKS = sorted((REPO_ROOT / "frameworks").glob("*.yaml"))

# The practice rules that read a workflow's `run:` commands. Path-shape rules
# (allowed_paths, has_helm_chart, …) are not in scope here: a pack template is
# one file, not a whole proposal, so those would fail for the wrong reason.
WORKFLOW_PRACTICE_RULES = frozenset(
    {"practice.workflow_has_test_step", "practice.workflow_has_lint_step"}
)

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None, reason="needs a real opa binary to evaluate the constitution"
)


def _deny_rule_ids(workflow_yaml: str) -> set[str]:
    """Rule ids the constitution raises for a proposal containing this workflow."""
    payload = {
        "proposal": {
            "files": [{"path": ".github/workflows/ci-svc.yaml", "content": workflow_yaml}]
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
    if not result:
        return set()
    return {v["rule_id"] for v in result[0]["expressions"][0]["value"]}


@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_the_packs_canonical_workflow_passes_the_practice_rules(pack_path: Path) -> None:
    """What we tell the agent to emit must survive what we then judge it with.

    A failure here means one of two things, and both are ours: the pack
    prescribes a command the rules do not recognise, or the rules describe a
    practice the pack does not follow. Either way the customer sees a denial
    naming *their* practice for an artifact we authored.
    """
    pack = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    workflow = pack.get("ci_workflow_template")
    assert workflow, f"{pack_path.name} ships no ci_workflow_template"

    denied = _deny_rule_ids(workflow) & WORKFLOW_PRACTICE_RULES

    assert not denied, (
        f"{pack_path.name}'s canonical CI workflow is denied by {sorted(denied)}. "
        "The agent following this pack cannot produce a proposal that passes."
    )


def test_the_java_regression_stays_fixed() -> None:
    """The exact command the Spring Boot pack prescribes, pinned by itself.

    Kept separate from the parametrised test above so the failure that reached a
    customer is named, not merely covered: `mvn -B verify -Dlint=true` was
    denied by BOTH workflow practice rules.
    """
    workflow = "jobs:\n  test:\n    steps:\n      - run: mvn -B verify -Dlint=true\n"
    assert not (_deny_rule_ids(workflow) & WORKFLOW_PRACTICE_RULES)


@pytest.mark.parametrize(
    ("command", "runs_tests"),
    [
        ("mvn -B test", True),
        ("mvn -B verify -Dlint=true", True),
        ("./gradlew test", True),
        ("gradle check", True),
        # `-DskipTests` turns the test phase off. Counting it would be worse
        # than missing it: the customer is told they test when they do not.
        ("mvn -B package -DskipTests", False),
        # A plugin goal, not a lifecycle phase — Maven's `check` runs no tests.
        ("mvn -B checkstyle:check", False),
        # Compiles tests without running them.
        ("mvn -B test-compile", False),
    ],
)
def test_jvm_test_detection_distinguishes_running_from_skipping(
    command: str, runs_tests: bool
) -> None:
    workflow = f"jobs:\n  b:\n    steps:\n      - run: {command}\n"
    denied = "practice.workflow_has_test_step" in _deny_rule_ids(workflow)
    assert denied is not runs_tests, f"{command!r} was judged wrongly"


# ---- Azure Pipelines (ADR-0071) -------------------------------------------
#
# The same promise for the packs' Azure Pipelines templates: what we tell the
# agent to emit must pass the rules that judge it. Azure files are judged on the
# neutral pipeline model the runner sends (`input.proposal.pipelines`); the
# Rego fallback reads GitHub YAML only. The runner's normaliser isn't in this
# repo, so `_azure_model` reads the shape the packs emit (stages, jobs, steps;
# `script` is a run, `task` a uses, a job `container` an image) into the same
# model. Practice rules that read steps, plus the per-runtime pinning rule.

AZURE_PATH = "azure-pipelines/templates/ci-svc.yml"
AZURE_PRACTICE_RULES = WORKFLOW_PRACTICE_RULES | {"practice.workflow_pins_action_versions"}


def _azure_step(step: dict[str, object]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key in ("script", "bash", "pwsh", "powershell"):
        if isinstance(step.get(key), str):
            out["run"] = step[key]
    if isinstance(step.get("task"), str):
        out["uses"] = step["task"]
    return out


def _azure_model(path: str, content: str) -> dict[str, object]:
    doc = yaml.safe_load(content)
    jobs = []
    for stage in doc.get("stages", []):
        for job in stage.get("jobs", []):
            container = job.get("container")
            jobs.append(
                {
                    "name": job.get("job") or job.get("deployment"),
                    "kind": "deployment" if "deployment" in job else "job",
                    "environment": job.get("environment"),
                    "image": container if isinstance(container, str) else None,
                    "steps": [_azure_step(s) for s in job.get("steps", [])],
                }
            )
    return {
        "path": path,
        "runtime": "azure_pipelines",
        "extends": None,
        "triggers": [],
        "jobs": jobs,
    }


def _azure_deny_rule_ids(content: str) -> set[str]:
    payload = {
        "proposal": {
            "files": [{"path": AZURE_PATH, "content": content}],
            "pipelines": [_azure_model(AZURE_PATH, content)],
        },
        "context": {
            "platform_repo_url": "https://example.invalid/acme/platform",
            "ci_runtime": "azure_pipelines",
        },
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
    if not result:
        return set()
    return {v["rule_id"] for v in result[0]["expressions"][0]["value"]}


@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_the_packs_azure_pipelines_template_passes_the_practice_rules(pack_path: Path) -> None:
    pack = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    template = (pack.get("ci_templates") or {}).get("azure_pipelines")
    assert template, f"{pack_path.name} ships no Azure Pipelines template"
    denied = _azure_deny_rule_ids(template) & AZURE_PRACTICE_RULES
    assert not denied, (
        f"{pack_path.name}'s Azure Pipelines template is denied by {sorted(denied)}. "
        "The agent following this pack cannot produce a proposal that passes."
    )


def test_the_azure_rules_really_judge_the_template() -> None:
    """Without its test command, and with a major-only task, the template is denied."""
    pack = yaml.safe_load((REPO_ROOT / "frameworks" / "dotnet.yaml").read_text(encoding="utf-8"))
    broken = (
        pack["ci_templates"]["azure_pipelines"]
        .replace("dotnet test", "dotnet pack")
        .replace("Docker@2.282.0", "Docker@2")
    )
    denied = _azure_deny_rule_ids(broken)
    assert "practice.workflow_has_test_step" in denied
    assert "practice.workflow_pins_action_versions" in denied
