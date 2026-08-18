#!/usr/bin/env python3
"""Scan debate archives for residual trace adoption.

The scanner is read-only. It reports how much of an archive has moved from
historical prose verdicts to machine-readable residual traces.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
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
VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")
MEASURE = load_module("measure_residual_trace", ROOT / "bin" / "measure-residual-trace.py")


DEFAULT_PATTERNS = ("*.md", "*.json")
VERDICT_HINTS = ("verdict", "r3", "R3", "audit", "review")


def iter_files(root: Path, include_all: bool) -> list[Path]:
    files: list[Path] = []
    for pattern in DEFAULT_PATTERNS:
        files.extend(path for path in root.rglob(pattern) if path.is_file())
    files = sorted(set(files))
    if include_all:
        return files
    return [path for path in files if any(hint in path.name for hint in VERDICT_HINTS)]


def validate_trace_object(trace: dict[str, Any]) -> dict[str, Any]:
    findings = VALIDATOR.validate_trace(trace, 1)
    errors = [str(item) for item in findings if item.severity == "ERROR"]
    blocks = [str(item) for item in findings if item.severity == "BLOCK"]
    if errors:
        status = "invalid"
    elif blocks:
        status = "blocked"
    else:
        status = "valid"
    return {
        "validation_status": status,
        "validation_errors": errors,
        "validation_blocks": blocks,
    }


def inspect_file(path: Path, root: Path, max_size_bytes: int) -> dict[str, Any]:
    rel = str(path.relative_to(root))
    size_bytes = path.stat().st_size
    result: dict[str, Any] = {
        "path": rel,
        "size_bytes": size_bytes,
        "trace_count": 0,
        "status": "no_trace",
        "validation_statuses": [],
        "quality_gates": [],
        "residual_count": 0,
        "high_risk_count": 0,
        "open_high_risk_count": 0,
        "warnings": [],
    }

    if size_bytes > max_size_bytes:
        result["status"] = "skipped_size"
        result["warnings"] = [f"file exceeds max size {max_size_bytes} bytes"]
        return result

    try:
        traces = MEASURE.load_traces(path)
    except Exception:
        return result

    measurements = [MEASURE.measure_trace(trace) for trace in traces]
    validations = [validate_trace_object(trace) for trace in traces]
    combined = MEASURE.combine(measurements)
    validation_statuses = [item["validation_status"] for item in validations]

    if any(status == "invalid" for status in validation_statuses):
        status = "invalid_trace"
    elif any(status == "blocked" for status in validation_statuses):
        status = "blocked_trace"
    else:
        status = "valid_trace"

    result.update({
        "trace_count": len(traces),
        "status": status,
        "validation_statuses": validation_statuses,
        "quality_gates": [item["quality_gate"] for item in measurements],
        "residual_count": combined["residual_count"],
        "high_risk_count": combined["high_risk_count"],
        "open_high_risk_count": combined["open_high_risk_count"],
        "warnings": [warning for item in measurements for warning in item["warnings"]],
    })
    return result


def git_tracked_count(root: Path) -> int | None:
    try:
        completed = subprocess.run(
            ["git", "ls-files", "*.md", "*.json"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return len([line for line in completed.stdout.splitlines() if line.strip()])


def summarize(records: list[dict[str, Any]], root: Path, scanned_count: int) -> dict[str, Any]:
    with_trace = [item for item in records if item["trace_count"] > 0]
    valid = [item for item in records if item["status"] == "valid_trace"]
    blocked = [item for item in records if item["status"] == "blocked_trace"]
    invalid = [item for item in records if item["status"] == "invalid_trace"]
    no_trace = [item for item in records if item["status"] == "no_trace"]
    skipped = [item for item in records if item["status"] == "skipped_size"]
    gate_counts = {"pass": 0, "review": 0, "block": 0}
    for item in records:
        for gate in item["quality_gates"]:
            if gate in gate_counts:
                gate_counts[gate] += 1

    return {
        "root": str(root),
        "scanned_files": scanned_count,
        "files_with_trace": len(with_trace),
        "files_without_trace": len(no_trace),
        "skipped_size_files": len(skipped),
        "valid_trace_files": len(valid),
        "blocked_trace_files": len(blocked),
        "invalid_trace_files": len(invalid),
        "trace_adoption_rate": round(len(with_trace) / scanned_count, 4) if scanned_count else None,
        "valid_trace_rate": round(len(valid) / len(with_trace), 4) if with_trace else None,
        "quality_gate_counts": gate_counts,
        "residual_count": sum(item["residual_count"] for item in records),
        "high_risk_count": sum(item["high_risk_count"] for item in records),
        "open_high_risk_count": sum(item["open_high_risk_count"] for item in records),
        "git_tracked_md_json_count": git_tracked_count(root),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan an archive for residual trace adoption")
    parser.add_argument("root", type=Path, help="archive or repository root to scan")
    parser.add_argument("--all", action="store_true", help="scan all markdown/json files, not only verdict-like names")
    parser.add_argument("--max-size-mb", type=float, default=5.0, help="skip files larger than this size")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.exists() or not root.is_dir():
        print(f"[HIGHBALL] ERROR: scan root is not a directory: {root}", file=sys.stderr)
        return 2

    files = iter_files(root, args.all)
    max_size_bytes = int(args.max_size_mb * 1024 * 1024)
    records = [inspect_file(path, root, max_size_bytes) for path in files]
    payload = {
        "summary": summarize(records, root, len(files)),
        "files": records,
    }
    indent = 2 if args.pretty else None
    print(json.dumps(payload, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
