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

- The reference templates are written at the pack's **default** runtime, which
  must be supported for at least :data:`HORIZON` from today.
- A pack may carry older runtime entries (so a ``net8.0`` project builds on
  .NET 8, not a silent upgrade), each with the snapshot's end-of-life date. An
  older entry may stay only until that date; then this test fails so it gets
  removed.

**This test is dated on purpose.** It reads today's date, so it goes red as a
pinned runtime approaches its end of life, with time to act. When it fails,
bump or remove the entry (both repos, ADR-0058), and refresh the snapshot
(``make runtime-eol-refresh`` in trustacks-mvp, then copy it here) if a newer
release is missing from it.
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

#: How far ahead the default runtime must stay supported.
HORIZON = timedelta(days=90)

# (pattern over a pack's templates, endoflife.date product). Group 1 is the cycle.
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

#: Packs with runtime entries, and their endoflife.date product.
_PRODUCT = {"dotnet": "dotnet", "go": "go"}


def _snapshot() -> dict[str, list[dict[str, Any]]]:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))["products"]


def _pinned(text: str) -> set[tuple[str, str]]:
    """Every (product, cycle) a text pins."""
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


def _raw(pack_path: Path) -> dict[str, Any]:
    return yaml.safe_load(pack_path.read_text(encoding="utf-8"))


def _templates(pack_path: Path) -> str:
    """The pack's reference templates only: what is emitted by default."""
    raw = _raw(pack_path)
    ci_templates: dict[str, Any] = raw.get("ci_templates") or {}
    parts: list[Any] = [raw.get("dockerfile_template", ""), raw.get("ci_workflow_template", "")]
    parts.extend(ci_templates.values())
    return "\n".join(str(p) for p in parts)


def _as_date(value: Any) -> date | None:
    if value is None or value is False:
        return None
    return value if isinstance(value, date) else date.fromisoformat(str(value))


@pytest.mark.parametrize("pack_path", _pack_files(), ids=lambda p: p.stem)
def test_the_default_runtime_is_supported_past_the_horizon(pack_path: Path) -> None:
    products = _snapshot()
    deadline = date.today() + HORIZON
    expiring = sorted(
        f"{product} {cycle} (end of life {eol.isoformat()})"
        for product, cycle in _pinned(_templates(pack_path))
        if (eol := _eol(products, product, cycle)) is not None and eol <= deadline
    )
    assert not expiring, (
        f"{pack_path.name}'s templates pin runtimes that are end of life or within "
        f"{HORIZON.days} days of it: {expiring}. Bump the default in both repos (ADR-0058)."
    )


@pytest.mark.parametrize("pack_path", _pack_files(), ids=lambda p: p.stem)
def test_runtime_entries_follow_the_snapshot(pack_path: Path) -> None:
    runtimes = _raw(pack_path).get("runtimes")
    if runtimes is None:
        pytest.skip("pack has a single pinned runtime")
    products = _snapshot()
    product = _PRODUCT[pack_path.stem]
    today = date.today()
    for entry in runtimes["entries"]:
        entry_id = str(entry["id"])
        snap = _eol(products, product, entry_id)
        assert _as_date(entry.get("eol")) == snap, (
            f"{pack_path.name} entry {entry_id}: eol {entry.get('eol')!r} != snapshot {snap}"
        )
        if entry_id == str(runtimes["default"]):
            assert snap is None or snap > today + HORIZON, (
                f"{pack_path.name}: the default runtime {entry_id} ends {snap}; bump it"
            )
        else:
            assert snap is None or snap > today, (
                f"{pack_path.name}: runtime {entry_id} reached end of life on {snap}; "
                "remove its entry (both repos)"
            )


@pytest.mark.parametrize("pack_path", _pack_files(), ids=lambda p: p.stem)
def test_default_entry_pins_are_what_the_templates_say(pack_path: Path) -> None:
    """Selecting another entry swaps the default's pins in the templates, so
    every default pin must appear there, or the swap would silently do nothing."""
    runtimes = _raw(pack_path).get("runtimes")
    if runtimes is None:
        pytest.skip("pack has a single pinned runtime")
    entries = runtimes["entries"]
    default = next(e for e in entries if str(e["id"]) == str(runtimes["default"]))
    text = _templates(pack_path)
    missing = [slot for slot, value in default["pins"].items() if value not in text]
    assert not missing, f"{pack_path.name}: default pins not in the templates: {missing}"
    for entry in entries:
        assert set(entry["pins"]) == set(default["pins"]), (
            f"{pack_path.name} entry {entry['id']} pins different slots from the default"
        )


def test_the_packs_pin_the_runtimes_this_guard_knows_about() -> None:
    """The guard is only as good as its patterns: every framework pack must pin
    at least one runtime it recognises, or a renamed image would pass silently."""
    for pack_path in _pack_files():
        assert _pinned(_templates(pack_path)), (
            f"{pack_path.name}: no recognised runtime pin (update _PINS)"
        )


def test_go_and_dotnet_default_to_the_current_releases() -> None:
    """The specific #798 regression: the templates (the default) are not on
    Go 1.23 or .NET 8."""
    for name in ("go", "dotnet"):
        text = _templates(PACKS_DIR / f"{name}.yaml")
        assert "golang:1.23" not in text and 'go-version: "1.23"' not in text
        assert "dotnet/sdk:8.0" not in text and "aspnet:8.0" not in text
        assert '"8.0.x"' not in text
