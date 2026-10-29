"""No framework pack pins a runtime that is end of life, or about to be (#798).

The bug this exists to prevent: the Go pack pinned ``golang:1.23`` a year
after Go 1.23 reached end of life (2025-08-12), and the .NET pack pinned .NET 8
twelve days before its end of life (2026-11-10). Every proposal emitted for
those frameworks started the customer on an unsupported runtime — the opposite
of what TruStacks sells.

The source of truth is a copy of the endoflife.date snapshot trustacks-mvp
ships (``control-plane/src/trustacks_control/runtime_eol/endoflife.json``,
trustacks-mvp#797), kept at ``tests/data/endoflife.json`` (MIT, endoflife.date;
snapshot date inside the file). Refresh it from trustacks-mvp whenever that
one is refreshed.
Every runtime version a pack pins — Dockerfile ``FROM`` images, the GitHub
Actions setup versions, the Azure Pipelines container images — must be
supported for at least :data:`HORIZON` from today.

**This test is dated on purpose.** It reads today's date, so it goes red as a
pinned runtime approaches its end of life, with time to bump it. When it
fails, bump the pack (both repos, ADR-0058), and refresh the snapshot (``make
runtime-eol-refresh`` in trustacks-mvp, then copy it here) if a newer release
is missing from it.
"""

from __future__ import annotations

import json
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
PACKS_DIR = REPO / "frameworks"
SNAPSHOT = REPO / "tests" / "data" / "endoflife.json"

#: How far ahead a pinned runtime must stay supported.
HORIZON = timedelta(days=90)

# (pattern over a pack's text, endoflife.date product). Group 1 is the cycle.
_PINS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bgolang:(\d+\.\d+)"), "go"),
    (re.compile(r"go-version:\s*[\"']?(\d+\.\d+)"), "go"),
    (re.compile(r"mcr\.microsoft\.com/dotnet/(?:sdk|aspnet|runtime):(\d+)\.\d"), "dotnet"),
    (re.compile(r"dotnet-version:\s*[\"']?(\d+)\.\d"), "dotnet"),
    (re.compile(r"\bpython:(\d+\.\d+)"), "python"),
    (re.compile(r"python-version:\s*[\"']?(\d+\.\d+)"), "python"),
    (re.compile(r"eclipse-temurin[:-](\d+)"), "eclipse-temurin"),
    (re.compile(r"java-version:\s*[\"']?(\d+)"), "eclipse-temurin"),
)


def _snapshot() -> dict[str, list[dict[str, Any]]]:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))["products"]


def _pinned(text: str) -> set[tuple[str, str]]:
    """Every (product, cycle) a pack's text pins."""
    found: set[tuple[str, str]] = set()
    for pattern, product in _PINS:
        found.update((product, m.group(1)) for m in pattern.finditer(text))
    return found


def _eol(products: dict[str, list[dict[str, Any]]], product: str, cycle: str) -> date | None:
    """The cycle's end-of-life date; ``None`` when it has none yet (still supported)."""
    for row in products[product]:
        if str(row["cycle"]) == cycle:
            eol = row.get("eol")
            if eol is False or eol is None:
                return None
            if eol is True:
                return date.min
            return date.fromisoformat(str(eol))
    raise AssertionError(f"{product} {cycle} is not in the snapshot; refresh it or fix the pin")


def _pack_files() -> list[Path]:
    files = sorted(PACKS_DIR.glob("*.yaml"))
    assert files, "premise — the shipped framework packs exist"
    return files


@pytest.mark.parametrize("pack_path", _pack_files(), ids=lambda p: p.stem)
def test_every_pinned_runtime_is_supported_past_the_horizon(pack_path: Path) -> None:
    products = _snapshot()
    pins = _pinned(pack_path.read_text(encoding="utf-8"))
    deadline = date.today() + HORIZON
    expiring = sorted(
        f"{product} {cycle} (end of life {eol.isoformat()})"
        for product, cycle in pins
        if (eol := _eol(products, product, cycle)) is not None and eol <= deadline
    )
    assert not expiring, (
        f"{pack_path.name} pins runtimes that are end of life or within "
        f"{HORIZON.days} days of it: {expiring}. Bump the pack in both repos (ADR-0058)."
    )


def test_the_packs_pin_the_runtimes_this_guard_knows_about() -> None:
    """The guard is only as good as its patterns: every framework pack must pin
    at least one runtime it recognises, or a renamed image would pass silently."""
    for pack_path in _pack_files():
        pins = _pinned(pack_path.read_text(encoding="utf-8"))
        assert pins, f"{pack_path.name}: no recognised runtime pin (update _PINS)"


def test_go_and_dotnet_are_on_the_current_releases() -> None:
    """The specific #798 regressions: Go 1.23 and .NET 8 are not pinned anywhere."""
    for name in ("go", "dotnet"):
        raw = yaml.safe_load((PACKS_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
        text = json.dumps(raw)
        assert "golang:1.23" not in text and '"1.23"' not in text
        assert "dotnet/sdk:8.0" not in text and "aspnet:8.0" not in text
        assert '"8.0.x"' not in text
