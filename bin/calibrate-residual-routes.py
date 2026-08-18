#!/usr/bin/env python3
"""Calibrate residual routes across a cohort of trace files."""

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
MEASURE = load_module("measure_residual_trace", ROOT / "bin" / "measure-residual-trace.py")
SCORER = load_module("score_residual_trial", ROOT / "bin" / "score-residual-trial.py")
VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")


DEFAULT_PATTERNS = ("*.json", "*.md")


def iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for pattern in DEFAULT_PATTERNS:
        files.extend(path for path in root.rglob(pattern) if path.is_file())
    return sorted(set(files))


def load_scored_traces(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], {
            "source_file": str(path),
            "status": "invalid",
            "reason": f"read error: {exc}",
        }

    blocks, raw_json_mode = MEASURE.candidate_blocks(text, path)
    if not blocks:
        return [], {
            "source_file": str(path),
            "status": "ignored",
            "reason": "no JSON residual trace candidate found",
        }

    invalid_reasons: list[str] = []
    scored: list[dict[str, Any]] = []
    saw_trace_candidate = False
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            invalid_reasons.append(f"{label} invalid JSON: {exc.msg}")
            continue

        if not (isinstance(parsed, dict) and isinstance(parsed.get("residuals"), list)):
            continue

        saw_trace_candidate = True
        findings = VALIDATOR.validate_trace(parsed, block_number)
        errors = [str(finding) for finding in findings if finding.severity == "ERROR"]
        if errors:
            invalid_reasons.extend(errors)
            continue

        trace = parsed
        score = SCORER.score_trace(trace)
        score["source_file"] = str(path)
        score["trace_index"] = block_number
        scored.append(score)

    if scored and invalid_reasons:
        status = "scored_with_invalid"
    elif scored:
        status = "scored"
    elif saw_trace_candidate or invalid_reasons:
        status = "invalid"
    else:
        status = "ignored"

    return scored, {
        "source_file": str(path),
        "status": status,
        "reason": "; ".join(invalid_reasons) if invalid_reasons else "no residual trace object found",
    }


def mean(values: list[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 4)


def count_by(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = item.get(field)
        if key is None:
            key = "unknown"
        counts[str(key)] = counts.get(str(key), 0) + 1
    return dict(sorted(counts.items()))


def group_key(score: dict[str, Any]) -> str:
    instrument = score.get("instrument") or "unknown"
    relation = score.get("base_model_relation") or "unknown"
    boundary = score.get("action_boundary") or "unknown"
    return f"{instrument}:{relation}:{boundary}"


def route_recommendation(group: list[dict[str, Any]]) -> str:
    recommendations = {item["recommendation"] for item in group}
    mean_score = mean([item["evidence_score"] for item in group])
    if "block" in recommendations:
        return "block"
    if mean_score is not None and mean_score < 0.35:
        return "reroute"
    if "reroute" in recommendations:
        return "reroute"
    if "review" in recommendations:
        return "review"
    return "adopt"


def summarize_group(group: list[dict[str, Any]]) -> dict[str, Any]:
    tokens_yield = [
        item["residuals_per_10k_tokens"]
        for item in group
        if isinstance(item.get("residuals_per_10k_tokens"), (int, float))
    ]
    action_tokens_yield = [
        item["action_blocking_per_10k_tokens"]
        for item in group
        if isinstance(item.get("action_blocking_per_10k_tokens"), (int, float))
    ]
    caveats = sorted({caveat for item in group for caveat in item.get("caveats", [])})
    return {
        "trace_count": len(group),
        "recommendation": route_recommendation(group),
        "mean_evidence_score": mean([item["evidence_score"] for item in group]),
        "mean_residual_yield": mean([item["residual_yield"] for item in group]),
        "mean_closure_strength": mean([item["closure_strength"] for item in group]),
        "mean_manifest_strength": mean([item["manifest_strength"] for item in group]),
        "mean_risk_penalty": mean([item["risk_penalty"] for item in group]),
        "mean_residuals_per_10k_tokens": mean(tokens_yield),
        "mean_action_blocking_per_10k_tokens": mean(action_tokens_yield),
        "residual_count": sum(item["residual_count"] for item in group),
        "action_blocking_count": sum(item["action_blocking_count"] for item in group),
        "recommendation_counts": count_by(group, "recommendation"),
        "quality_gate_counts": count_by(group, "quality_gate"),
        "caveats": caveats,
        "sources": sorted({item["source_file"] for item in group}),
    }


def calibrate(paths: list[Path]) -> dict[str, Any]:
    scores: list[dict[str, Any]] = []
    file_statuses: list[dict[str, Any]] = []
    scanned_files = 0
    for root in paths:
        files = iter_files(root)
        scanned_files += len(files)
        for file_path in files:
            file_scores, file_status = load_scored_traces(file_path)
            scores.extend(file_scores)
            file_statuses.append(file_status)

    groups: dict[str, list[dict[str, Any]]] = {}
    for score in scores:
        groups.setdefault(group_key(score), []).append(score)

    route_groups = {
        key: summarize_group(group)
        for key, group in sorted(groups.items())
    }
    recommendations = {group["recommendation"] for group in route_groups.values()}
    invalid_files = [
        item for item in file_statuses
        if item["status"] in {"invalid", "scored_with_invalid"}
    ]
    if "block" in recommendations:
        recommendation = "block"
    elif "reroute" in recommendations:
        recommendation = "reroute"
    elif invalid_files:
        recommendation = "review"
    elif "review" in recommendations:
        recommendation = "review"
    elif route_groups:
        recommendation = "adopt"
    else:
        recommendation = "no_data"

    return {
        "report_version": "1.0",
        "inputs": [str(path) for path in paths],
        "scanned_files": scanned_files,
        "candidate_files": sum(1 for item in file_statuses if item["status"] != "ignored"),
        "trace_files": sum(1 for item in file_statuses if item["status"] in {"scored", "scored_with_invalid"}),
        "invalid_trace_files": len(invalid_files),
        "ignored_files": sum(1 for item in file_statuses if item["status"] == "ignored"),
        "trace_count": len(scores),
        "recommendation": recommendation,
        "invalid_files": invalid_files,
        "route_groups": route_groups,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate residual routes across trace cohorts")
    parser.add_argument("paths", nargs="+", type=Path, help="trace files or directories")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    missing = [path for path in args.paths if not path.exists()]
    if missing:
        for path in missing:
            print(f"[HIGHBALL] ERROR: path does not exist: {path}", file=sys.stderr)
        return 2

    result = calibrate([path.resolve() for path in args.paths])
    indent = 2 if args.pretty else None
    print(json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
