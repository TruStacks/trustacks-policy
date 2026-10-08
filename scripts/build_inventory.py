#!/usr/bin/env python3
"""Build ``rule_inventory.json`` for a rego source tree.

The published constitution bundle carries this sidecar so a runner can list
every rule it enforces (with description, tooling categories, practice
dimensions and rego source) without evaluating anything. OPA's ``opa build``
skips non-``data.json`` files, so the publish workflow splices this file into
the bundle tarball after the build.

Ported from the TruStacks product's ``trustacks_runner.policy.inventory`` so
the bundle can be built from this repository alone (ADR-0058 Phase 2). The
output shape is a contract with the runner's reader — keep it identical:

    {"<label>_inventory": [ {rule_id, package, description,
                             required_tooling_categories, practice_dimensions,
                             tier_scope, kind, rego_body, source}, ... ]}

Each rule is attributed to the file that declares it, and its ``rego_body``
is that file's source. A file that does not compile alone — a rule calling a
helper from a sibling ``lib.rego``, as every ``constitution/practice/`` rule
does — is evaluated with the whole tree loaded, keeping only the rule ids the
file itself declares (read from ``opa parse``). Same behaviour as the product's
builder; keep the two in step.

Standard library only; needs ``opa`` on PATH.

Usage::

    python3 scripts/build_inventory.py --source constitution \\
        --out .build/rule_inventory.json --label constitution
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

PACKAGE_RE = re.compile(r"^\s*package\s+([a-zA-Z_][\w.]*)\s*$", re.MULTILINE)
LABELS = ("constitution", "overlay")


def derive_kind(rule_id: str, practice_dimensions: list[str]) -> str:
    """``behavior`` for practice rules, ``structural`` for everything else."""
    if rule_id.startswith("practice.") or practice_dimensions:
        return "behavior"
    return "structural"


def _strings(raw: Any) -> list[str]:
    return [str(x) for x in raw] if isinstance(raw, list) else []


class OpaError(RuntimeError):
    """``opa`` exited non-zero."""


def rule_metadata(opa: str, data_paths: list[Path], package: str) -> dict[str, Any]:
    """Evaluate ``data.<package>.rule_metadata`` with ``data_paths`` loaded.

    Evaluated by OPA rather than parsed, so every rego syntax the metadata block
    may use is handled by the engine that will enforce it.
    """
    args = [opa, "eval"]
    for path in data_paths:
        args += ["--data", str(path)]
    proc = subprocess.run(
        [*args, "--format", "json", f"data.{package}.rule_metadata"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if proc.returncode != 0:
        # `--format json` reports compile errors on stdout, not stderr.
        detail = (proc.stderr or proc.stdout).strip()
        where = data_paths[0] if len(data_paths) == 1 else f"{len(data_paths)} files"
        raise OpaError(f"opa eval failed on {where}: {detail}")
    try:
        value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, json.JSONDecodeError):
        return {}  # no rule_metadata in this file: a helper, not a rule
    return value if isinstance(value, dict) else {}


def declared_rule_ids(opa: str, rego_path: Path) -> set[str]:
    """The rule ids one file declares in ``rule_metadata``, read from its AST.

    Handles the partial object ``rule_metadata["ns.name"] := {...}`` and the
    literal ``rule_metadata := {"ns.name": {...}}``. Needs no other file, so it
    works for a rule whose body calls helpers defined elsewhere. A key that is
    not a string literal cannot be attributed and is refused, not guessed.
    """
    proc = subprocess.run(
        [opa, "parse", "--format", "json", str(rego_path)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if proc.returncode != 0:
        raise OpaError(f"opa parse failed on {rego_path}: {(proc.stderr or proc.stdout).strip()}")
    declared: set[str] = set()
    for rule in json.loads(proc.stdout).get("rules") or []:
        head = rule.get("head") or {}
        ref = head.get("ref") or []
        name = ref[0].get("value") if ref else head.get("name")
        if name != "rule_metadata":
            continue
        if len(ref) == 2 and ref[1].get("type") == "string":  # rule_metadata[<key>]
            declared.add(str(ref[1]["value"]))
            continue
        value = head.get("value") or {}
        if len(ref) <= 1 and value.get("type") == "object":
            for key_term, _ in value.get("value") or []:
                if key_term.get("type") != "string":
                    raise OpaError(f"{rego_path}: rule_metadata key is not a string literal")
                declared.add(str(key_term["value"]))
            continue
        raise OpaError(f"{rego_path}: rule_metadata is not statically attributable")
    return declared


def harvest(
    opa: str, rego_path: Path, label: str, tree: list[Path], cache: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    body = rego_path.read_text(encoding="utf-8")
    match = PACKAGE_RE.search(body)
    if match is None:
        return []
    package = match.group(1)
    try:
        metadata = rule_metadata(opa, [rego_path], package)
    except OpaError:
        # Does not compile alone: it calls a sibling's helper. Evaluate the
        # whole tree once per package, keep only what this file declares.
        declared = declared_rule_ids(opa, rego_path)
        if not declared:
            return []  # a helper file (e.g. lib.rego) — no rules to list
        if package not in cache:
            cache[package] = rule_metadata(opa, tree, package)
        metadata = {k: v for k, v in cache[package].items() if k in declared}
    entries = []
    for rule_id, meta in metadata.items():
        if not isinstance(meta, dict):
            continue
        description = meta.get("description")
        if not isinstance(description, str) or not description:
            continue
        practice = _strings(meta.get("practice_dimensions", []))
        tiers = _strings(meta.get("tier_scope", ["any"])) or ["any"]
        entries.append(
            {
                "rule_id": str(rule_id),
                "package": package,
                "description": description,
                "required_tooling_categories": _strings(
                    meta.get("required_tooling_categories", [])
                ),
                "practice_dimensions": practice,
                "tier_scope": tiers,
                "kind": derive_kind(str(rule_id), practice),
                "rego_body": body,
                "source": label,
            }
        )
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--label", choices=LABELS, required=True)
    args = parser.parse_args()

    opa = shutil.which("opa")
    if opa is None:
        print("opa is not on PATH", file=sys.stderr)
        return 1
    if not args.source.is_dir():
        print(f"not a directory: {args.source}", file=sys.stderr)
        return 1

    entries: list[dict[str, Any]] = []
    tree = [p for p in sorted(args.source.rglob("*.rego")) if not p.name.endswith("_test.rego")]
    cache: dict[str, dict[str, Any]] = {}
    for rego_path in tree:
        entries.extend(harvest(opa, rego_path, args.label, tree, cache))
    if not entries:
        # A bundle that lists no rules is the failure #600 shipped to
        # production silently. Refuse rather than publish one.
        print(f"no rule_metadata found under {args.source}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Wrapped, not a bare array: the runner loads bundle JSON with
    # `opa eval --data`, which rejects non-object roots and merges every file
    # into one tree, so the key is namespaced by label.
    args.out.write_text(
        json.dumps({f"{args.label}_inventory": entries}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"wrote {args.out} ({len(entries)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
