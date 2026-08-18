#!/usr/bin/env python3
"""Validate HIGHBALL route pair manifests."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
BUILDER = load_module("build_route_pairing_report", ROOT / "bin" / "build-route-pairing-report.py")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError("route pair manifest must be a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL route pair manifest")
    parser.add_argument("manifest_file", type=Path)
    args = parser.parse_args()

    try:
        manifest = load_manifest(args.manifest_file)
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    errors = BUILDER.validate_pair_manifest(manifest)
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    print("[HIGHBALL] route pair manifest valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
