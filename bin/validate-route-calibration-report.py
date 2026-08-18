#!/usr/bin/env python3
"""Validate HIGHBALL residual route calibration reports."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


TOP_LEVEL_FIELDS = {
    "report_version",
    "inputs",
    "scanned_files",
    "candidate_files",
    "trace_files",
    "invalid_trace_files",
    "ignored_files",
    "trace_count",
    "recommendation",
    "invalid_files",
    "route_groups",
}
RECOMMENDATIONS = {"adopt", "review", "reroute", "block", "no_data"}
FILE_STATUSES = {"ignored", "scored", "invalid", "scored_with_invalid"}
GROUP_FIELDS = {
    "trace_count",
    "recommendation",
    "mean_evidence_score",
    "mean_residual_yield",
    "mean_closure_strength",
    "mean_manifest_strength",
    "mean_risk_penalty",
    "mean_residuals_per_10k_tokens",
    "mean_action_blocking_per_10k_tokens",
    "residual_count",
    "action_blocking_count",
    "recommendation_counts",
    "quality_gate_counts",
    "caveats",
    "sources",
}


def extract_json_blocks(text: str) -> list[tuple[int, str]]:
    pattern = re.compile(r"^```json[ \t]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
    return [(index + 1, match.group(1)) for index, match in enumerate(pattern.finditer(text))]


def candidate_blocks(text: str, path: Path) -> tuple[list[tuple[int, str]], bool]:
    blocks = extract_json_blocks(text)
    if blocks:
        return blocks, False

    stripped = text.strip()
    if path.suffix.lower() == ".json" or stripped.startswith("{"):
        return [(1, stripped)], True

    return [], False


def is_string_list(value: Any, *, min_items: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(isinstance(item, str) for item in value)
    )


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_nullable_number(value: Any) -> bool:
    return value is None or (
        isinstance(value, (int, float)) and not isinstance(value, bool)
    )


def load_report(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    blocks, raw_json_mode = candidate_blocks(text, path)
    if not blocks:
        raise ValueError("no JSON route calibration report found")

    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            errors.append(f"{label} is invalid JSON: {exc.msg}")
            continue
        if isinstance(parsed, dict) and parsed.get("report_version") == "1.0":
            reports.append(parsed)

    if len(reports) != 1:
        detail = "; ".join(errors) if errors else f"found {len(reports)} route calibration reports"
        raise ValueError(f"expected exactly one route calibration report; {detail}")
    return reports[0]


def validate_counts(name: str, counts: Any, errors: list[str]) -> int:
    if not isinstance(counts, dict):
        errors.append(f"{name} must be an object")
        return 0

    total = 0
    for key, value in counts.items():
        if not isinstance(key, str) or key == "":
            errors.append(f"{name} has an empty or non-string key")
        if not is_nonnegative_int(value):
            errors.append(f"{name}.{key} must be a non-negative integer")
        else:
            total += value
    return total


def validate_group(key: str, group: Any, errors: list[str]) -> int:
    prefix = f"route_groups.{key}"
    if not isinstance(group, dict):
        errors.append(f"{prefix} must be an object")
        return 0

    unknown = sorted(set(group) - GROUP_FIELDS)
    if unknown:
        errors.append(f"{prefix} has unknown fields: {', '.join(unknown)}")

    missing = sorted(GROUP_FIELDS - set(group))
    if missing:
        errors.append(f"{prefix} is missing fields: {', '.join(missing)}")

    trace_count = group.get("trace_count")
    if not is_nonnegative_int(trace_count):
        errors.append(f"{prefix}.trace_count must be a non-negative integer")
        trace_count = 0

    if group.get("recommendation") not in RECOMMENDATIONS - {"no_data"}:
        errors.append(f"{prefix}.recommendation is invalid")

    for field in (
        "mean_evidence_score",
        "mean_residual_yield",
        "mean_closure_strength",
        "mean_manifest_strength",
        "mean_risk_penalty",
        "mean_residuals_per_10k_tokens",
        "mean_action_blocking_per_10k_tokens",
    ):
        if not is_nullable_number(group.get(field)):
            errors.append(f"{prefix}.{field} must be a number or null")

    for field in ("residual_count", "action_blocking_count"):
        if not is_nonnegative_int(group.get(field)):
            errors.append(f"{prefix}.{field} must be a non-negative integer")

    recommendation_total = validate_counts(f"{prefix}.recommendation_counts", group.get("recommendation_counts"), errors)
    quality_total = validate_counts(f"{prefix}.quality_gate_counts", group.get("quality_gate_counts"), errors)
    if isinstance(trace_count, int) and recommendation_total != trace_count:
        errors.append(f"{prefix}.recommendation_counts must sum to trace_count")
    if isinstance(trace_count, int) and quality_total != trace_count:
        errors.append(f"{prefix}.quality_gate_counts must sum to trace_count")

    if not is_string_list(group.get("caveats")):
        errors.append(f"{prefix}.caveats must be an array of strings")
    if not is_string_list(group.get("sources")):
        errors.append(f"{prefix}.sources must be an array of strings")

    return trace_count if isinstance(trace_count, int) else 0


def validate_report(report: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["report must be an object"]

    unknown = sorted(set(report) - TOP_LEVEL_FIELDS)
    if unknown:
        errors.append(f"report has unknown fields: {', '.join(unknown)}")

    missing = sorted(TOP_LEVEL_FIELDS - set(report))
    if missing:
        errors.append(f"report is missing fields: {', '.join(missing)}")

    if report.get("report_version") != "1.0":
        errors.append("report_version must be 1.0")

    if not is_string_list(report.get("inputs"), min_items=1):
        errors.append("inputs must be a non-empty array of strings")

    for field in (
        "scanned_files",
        "candidate_files",
        "trace_files",
        "invalid_trace_files",
        "ignored_files",
        "trace_count",
    ):
        if not is_nonnegative_int(report.get(field)):
            errors.append(f"{field} must be a non-negative integer")

    if report.get("recommendation") not in RECOMMENDATIONS:
        errors.append("recommendation is invalid")

    invalid_files = report.get("invalid_files")
    if not isinstance(invalid_files, list):
        errors.append("invalid_files must be an array")
        invalid_files = []
    else:
        for index, item in enumerate(invalid_files, start=1):
            prefix = f"invalid_files[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{prefix} must be an object")
                continue
            if set(item) != {"source_file", "status", "reason"}:
                errors.append(f"{prefix} must contain source_file, status, and reason")
            if not isinstance(item.get("source_file"), str) or item.get("source_file") == "":
                errors.append(f"{prefix}.source_file must be a non-empty string")
            if item.get("status") not in FILE_STATUSES - {"ignored", "scored"}:
                errors.append(f"{prefix}.status must be invalid or scored_with_invalid")
            if not isinstance(item.get("reason"), str) or item.get("reason") == "":
                errors.append(f"{prefix}.reason must be a non-empty string")

    route_groups = report.get("route_groups")
    group_trace_total = 0
    if not isinstance(route_groups, dict):
        errors.append("route_groups must be an object")
    else:
        for key, group in route_groups.items():
            if not isinstance(key, str) or key == "":
                errors.append("route_groups has an empty or non-string key")
                continue
            group_trace_total += validate_group(key, group, errors)

    scanned_files = report.get("scanned_files")
    candidate_files = report.get("candidate_files")
    ignored_files = report.get("ignored_files")
    trace_files = report.get("trace_files")
    invalid_trace_files = report.get("invalid_trace_files")
    trace_count = report.get("trace_count")

    if all(isinstance(value, int) for value in (scanned_files, candidate_files, ignored_files)):
        if candidate_files + ignored_files != scanned_files:
            errors.append("candidate_files plus ignored_files must equal scanned_files")
    if all(isinstance(value, int) for value in (trace_files, candidate_files)):
        if trace_files > candidate_files:
            errors.append("trace_files cannot exceed candidate_files")
    if all(isinstance(value, int) for value in (invalid_trace_files, candidate_files)):
        if invalid_trace_files > candidate_files:
            errors.append("invalid_trace_files cannot exceed candidate_files")
    if isinstance(invalid_trace_files, int) and invalid_trace_files != len(invalid_files):
        errors.append("invalid_trace_files must equal invalid_files length")
    if isinstance(trace_count, int) and group_trace_total != trace_count:
        errors.append("route group trace_count total must equal trace_count")

    expected = derive_recommendation(report)
    actual = report.get("recommendation")
    if expected is not None and actual != expected:
        errors.append(f"recommendation should be {expected}, got {actual}")

    return errors


def derive_recommendation(report: dict[str, Any]) -> str | None:
    route_groups = report.get("route_groups")
    invalid_files = report.get("invalid_files")
    if not isinstance(route_groups, dict) or not isinstance(invalid_files, list):
        return None

    recommendations = {
        group.get("recommendation")
        for group in route_groups.values()
        if isinstance(group, dict)
    }
    if "block" in recommendations:
        return "block"
    if "reroute" in recommendations:
        return "reroute"
    if invalid_files:
        return "review"
    if "review" in recommendations:
        return "review"
    if route_groups:
        return "adopt"
    return "no_data"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL route calibration report")
    parser.add_argument("report_file", type=Path)
    args = parser.parse_args()

    try:
        report = load_report(args.report_file)
    except (OSError, ValueError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    errors = validate_report(report)
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    if report["recommendation"] == "block":
        print("[HIGHBALL] route calibration report valid; recommendation is block", file=sys.stderr)
        return 1

    print(f"[HIGHBALL] route calibration report valid; recommendation is {report['recommendation']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
