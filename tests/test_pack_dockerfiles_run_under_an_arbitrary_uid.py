"""Every framework pack's reference Dockerfile must pass the gate and run on OpenShift.

Two bugs this exists to prevent (trustacks-mvp#277):

- `frameworks/dotnet.yaml` ran `useradd --uid 1001 --create-home app` on the
  aspnet:8.0 image, which already ships a user named `app` (UID 1654). The
  build fails with exit code 9 on every cluster, so every .NET proposal
  carried a Dockerfile that could not build.
- OpenShift's restricted-v2 SCC starts the container as an arbitrary UID in
  group 0. An image whose files belong only to its own user, with nothing
  granted to group 0, can't write to its own directories there.

The first half asks the constitution, so it needs a real `opa` binary and is
skipped without one (a check that could not run is not a pass, ADR-0038). The
second half reads the template.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSTITUTION = REPO_ROOT / "constitution"
FRAMEWORK_PACKS = sorted((REPO_ROOT / "frameworks").glob("*.yaml"))

# Distroless images have no shell to chgrp with, and the Go pack's static
# binary writes nothing; its WORKDIR is readable by any UID.
NO_SHELL_RUNTIME = re.compile(r"^FROM\s+gcr\.io/distroless/", re.MULTILINE)


def _dockerfile(pack_path: Path) -> str:
    pack = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    dockerfile = pack.get("dockerfile_template")
    assert dockerfile, f"{pack_path.name} ships no dockerfile_template"
    return str(dockerfile)


def _final_stage(dockerfile: str) -> str:
    return re.split(r"^FROM\s", dockerfile, flags=re.MULTILINE)[-1]


@pytest.mark.skipif(shutil.which("opa") is None, reason="needs a real opa binary")
@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_the_reference_dockerfile_passes_the_nonroot_rule(pack_path: Path) -> None:
    payload = {
        "proposal": {"files": [{"path": "Dockerfile", "content": _dockerfile(pack_path)}]},
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
    assert "practice.dockerfile_runs_as_nonroot" not in denied


@pytest.mark.parametrize("pack_path", FRAMEWORK_PACKS, ids=lambda p: p.stem)
def test_the_runtime_stage_grants_group_zero(pack_path: Path) -> None:
    dockerfile = _dockerfile(pack_path)
    if NO_SHELL_RUNTIME.search(dockerfile):
        pytest.skip("distroless runtime: no shell, nothing written")
    final = _final_stage(dockerfile)
    assert "chgrp -R 0" in final and "chmod -R g=u" in final, (
        f"{pack_path.name}: the runtime stage must give group 0 the owner's permissions"
    )
    assert re.search(r"^\s*USER\s+[1-9]\d*:0\s*$", final, re.MULTILINE), (
        f"{pack_path.name}: the final USER must be numeric, non-root, in group 0"
    )


def test_dotnet_reuses_the_images_own_user() -> None:
    final = _final_stage(_dockerfile(REPO_ROOT / "frameworks" / "dotnet.yaml"))
    assert "useradd" not in final, "aspnet:8.0 already has an `app` user; useradd fails the build"
    assert re.search(r"^\s*USER\s+1654:0\s*$", final, re.MULTILINE)
