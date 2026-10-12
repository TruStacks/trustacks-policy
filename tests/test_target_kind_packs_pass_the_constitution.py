"""Every target-kind pack's canonical artifacts must satisfy the constitution.

The same pairing as `test_pack_workflows_pass_the_constitution.py`, for the
non-Kubernetes target kinds: what we tell the agent to emit for an ECS Fargate
target must survive what we then judge it with — evaluated as a whole Fargate
proposal at tier prod, because that is where the most rules apply. And the
pack's hardening must be load-bearing: remove it and the gate must refuse.

Requires a real `opa` binary. Skipped when absent rather than silently passing.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSTITUTION = REPO_ROOT / "constitution"
TARGET_KIND_PACKS = sorted((REPO_ROOT / "target-kinds").glob("*.yaml"))
FASTAPI = yaml.safe_load((REPO_ROOT / "frameworks" / "python_fastapi.yaml").read_text())

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None, reason="needs a real opa binary to evaluate the constitution"
)

TOKENS = {
    "application": "shop",
    "cluster": "shop-prod",
    "service": "api",
    "tier": "prod",
    "service_root": "gitops/shop/shop-prod/api",
    "workflow_name": "deploy-api-shop-prod",
    "image": "ghcr.io/acme/api:3f2c9d1e0b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    "family": "shop-api-shop-prod",
    "container_name": "api",
    "user": "1001",
    "log_group": "/ecs/shop/api",
}


def _render(template: str) -> str:
    return re.sub(r"@@([a-z_]+)@@", lambda m: TOKENS[m.group(1)], template)


def _proposal(pack: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    task_definition = json.loads(_render(pack["task_definition"]["template"]))
    deploy = _render(pack["deploy_workflow"]["template"])
    ci = FASTAPI["ci_workflow_template"].replace("ci-<service>", "ci-api")
    return task_definition, deploy, ci


def _deny(task_definition: dict[str, Any], deploy: str, ci: str) -> set[str]:
    payload = {
        "proposal": {
            "files": [
                {"path": ".github/workflows/ci-api.yaml", "content": ci},
                {
                    "path": "gitops/shop/shop-prod/api/task-definition.json",
                    "content": json.dumps(task_definition),
                },
                {"path": ".github/workflows/deploy-api-shop-prod.yaml", "content": deploy},
            ]
        },
        "context": {
            "platform_repo_url": "https://example.invalid/acme/platform",
            "target": {"name": "shop-prod", "tier": "prod", "kind": "ecs-fargate"},
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
    return {v["rule_id"] for v in result[0]["expressions"][0]["value"]} if result else set()


@pytest.mark.parametrize("pack_path", TARGET_KIND_PACKS, ids=lambda p: p.stem)
def test_the_packs_canonical_artifacts_pass_the_whole_constitution(pack_path: Path) -> None:
    pack = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    assert pack["kind"] == pack_path.stem
    assert not _deny(*_proposal(pack))


@pytest.mark.parametrize("pack_path", TARGET_KIND_PACKS, ids=lambda p: p.stem)
def test_the_packs_deploy_action_is_the_one_the_constitution_recognises(pack_path: Path) -> None:
    pack = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    lib = (CONSTITUTION / "proposal" / "lib.rego").read_text(encoding="utf-8")
    assert f'_ecs_deploy_action := "{pack["deploy_action"]}"' in lib


@pytest.mark.parametrize(
    ("mutate", "rule_id"),
    [
        (lambda c: c.update(user="0"), "practice.ecs_task_runs_as_nonroot"),
        (lambda c: c.pop("readonlyRootFilesystem"), "practice.ecs_task_readonly_root_filesystem"),
        (lambda c: c.update(image="ghcr.io/acme/api:latest"), "practice.ecs_task_image_is_pinned"),
        (lambda c: c.pop("logConfiguration"), "practice.ecs_task_configures_logging"),
        (
            lambda c: c.update(environment=[{"name": "DB_PASSWORD", "value": "x"}]),
            "practice.ecs_task_secrets_not_in_environment",
        ),
    ],
)
def test_the_ecs_fargate_hardening_is_load_bearing(mutate: Any, rule_id: str) -> None:
    pack = yaml.safe_load((REPO_ROOT / "target-kinds" / "ecs-fargate.yaml").read_text())
    task_definition, deploy, ci = _proposal(pack)
    mutate(task_definition["containerDefinitions"][0])
    assert rule_id in _deny(task_definition, deploy, ci)


def test_a_prod_deploy_without_an_environment_is_refused() -> None:
    pack = yaml.safe_load((REPO_ROOT / "target-kinds" / "ecs-fargate.yaml").read_text())
    task_definition, deploy, ci = _proposal(pack)
    ungated = deploy.replace("    environment: shop-prod\n", "")
    assert ungated != deploy
    assert "practice.workflow_prod_deploy_requires_environment" in _deny(task_definition, ungated, ci)
