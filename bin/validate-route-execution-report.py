#!/usr/bin/env python3
"""Validate HIGHBALL route execution reports."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
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
BUILDER = load_module("build_route_execution_report", ROOT / "bin" / "build-route-execution-report.py")


TOP_LEVEL_FIELDS = {
    "execution_report_version",
    "route_group",
    "inputs",
    "packet_count",
    "required_execution_count",
    "complete_count",
    "missing_count",
    "blocked_count",
    "degraded_count",
    "invalid_count",
    "not_required_count",
    "completion_rate",
    "execution_gate",
    "packet_summaries",
    "invalid_packet_refs",
    "out_of_scope_packet_refs",
    "decision_reasons",
    "non_authorization",
}
INPUT_FIELDS = {"action_packet_refs"}
PACKET_SUMMARY_FIELDS = {
    "packet_ref",
    "route_group",
    "route",
    "trace_instrument",
    "action_boundary",
    "action_decision",
    "execution_required",
    "execution_status",
    "dispatch_ledger_count",
    "complete_phase_count",
    "missing_phases",
    "errors",
    "warnings",
}
INVALID_REF_FIELDS = {"packet_ref", "reason"}
EXECUTION_STATUSES = {"not_required", "missing", "complete", "blocked", "degraded", "invalid"}
EXECUTION_GATES = {"accepted", "watch", "reroute", "block", "insufficient"}
PHASES = {"R1", "R2", "R3"}
NON_AUTHORIZATION = BUILDER.NON_AUTHORIZATION


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


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_string_list(value: Any, *, min_items: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(isinstance(item, str) for item in value)
    )


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def load_report(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    blocks, raw_json_mode = candidate_blocks(text, path)
    if not blocks:
        raise ValueError("no JSON route execution report found")

    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            errors.append(f"{label} is invalid JSON: {exc.msg}")
            continue
        if isinstance(parsed, dict) and parsed.get("execution_report_version") == "1.0":
            reports.append(parsed)

    if len(reports) != 1:
        detail = "; ".join(errors) if errors else f"found {len(reports)} route execution reports"
        raise ValueError(f"expected exactly one route execution report; {detail}")
    return reports[0]


def validate_object_fields(name: str, value: Any, fields: set[str], errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{name} must be an object")
        return {}
    unknown = sorted(set(value) - fields)
    if unknown:
        errors.append(f"{name} has unknown fields: {', '.join(unknown)}")
    missing = sorted(fields - set(value))
    if missing:
        errors.append(f"{name} is missing fields: {', '.join(missing)}")
    return value


def validate_packet_summary(index: int, value: Any, errors: list[str]) -> dict[str, Any]:
    prefix = f"packet_summaries[{index}]"
    item = validate_object_fields(prefix, value, PACKET_SUMMARY_FIELDS, errors)
    if not item:
        return {}
    for field in ("packet_ref", "route_group", "route", "trace_instrument", "action_boundary", "action_decision"):
        if not is_nonempty_string(item.get(field)):
            errors.append(f"{prefix}.{field} must be a non-empty string")
    if not isinstance(item.get("execution_required"), bool):
        errors.append(f"{prefix}.execution_required must be boolean")
    if item.get("execution_status") not in EXECUTION_STATUSES:
        errors.append(f"{prefix}.execution_status is invalid")
    for field in ("dispatch_ledger_count", "complete_phase_count"):
        if not is_nonnegative_int(item.get(field)):
            errors.append(f"{prefix}.{field} must be a non-negative integer")
    if not is_string_list(item.get("missing_phases")):
        errors.append(f"{prefix}.missing_phases must be an array of strings")
    elif any(phase not in PHASES for phase in item.get("missing_phases", [])):
        errors.append(f"{prefix}.missing_phases contains an invalid phase")
    for field in ("errors", "warnings"):
        if not is_string_list(item.get(field)):
            errors.append(f"{prefix}.{field} must be an array of strings")
    return item


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

    if report.get("execution_report_version") != "1.0":
        errors.append("execution_report_version must be 1.0")
    if not is_nonempty_string(report.get("route_group")):
        errors.append("route_group must be a non-empty string")

    inputs = validate_object_fields("inputs", report.get("inputs"), INPUT_FIELDS, errors)
    if inputs and not is_string_list(inputs.get("action_packet_refs"), min_items=1):
        errors.append("inputs.action_packet_refs must be a non-empty array of strings")

    for field in (
        "packet_count",
        "required_execution_count",
        "complete_count",
        "missing_count",
        "blocked_count",
        "degraded_count",
        "invalid_count",
        "not_required_count",
    ):
        if not is_nonnegative_int(report.get(field)):
            errors.append(f"{field} must be a non-negative integer")

    completion = report.get("completion_rate")
    if completion is not None and not (isinstance(completion, (int, float)) and not isinstance(completion, bool) and 0 <= completion <= 1):
        errors.append("completion_rate must be a number between 0 and 1 or null")
    if report.get("execution_gate") not in EXECUTION_GATES:
        errors.append("execution_gate is invalid")

    parsed_summaries: list[dict[str, Any]] = []
    summaries = report.get("packet_summaries")
    if not isinstance(summaries, list):
        errors.append("packet_summaries must be an array")
    else:
        for index, item in enumerate(summaries, start=1):
            parsed = validate_packet_summary(index, item, errors)
            if parsed:
                parsed_summaries.append(parsed)

    invalid_refs = report.get("invalid_packet_refs")
    if not isinstance(invalid_refs, list):
        errors.append("invalid_packet_refs must be an array")
    else:
        for index, item in enumerate(invalid_refs, start=1):
            prefix = f"invalid_packet_refs[{index}]"
            parsed = validate_object_fields(prefix, item, INVALID_REF_FIELDS, errors)
            if parsed:
                for field in ("packet_ref", "reason"):
                    if not is_nonempty_string(parsed.get(field)):
                        errors.append(f"{prefix}.{field} must be a non-empty string")

    if not is_string_list(report.get("out_of_scope_packet_refs")):
        errors.append("out_of_scope_packet_refs must be an array of strings")
    if not is_string_list(report.get("decision_reasons"), min_items=1):
        errors.append("decision_reasons must be a non-empty array of strings")
    if report.get("non_authorization") != NON_AUTHORIZATION:
        errors.append("non_authorization text is invalid")

    if parsed_summaries:
        route_group = report.get("route_group")
        if any(item.get("route_group") != route_group for item in parsed_summaries):
            errors.append("packet_summaries must all match route_group")

        status_counts = {
            "complete_count": sum(1 for item in parsed_summaries if item.get("execution_status") == "complete"),
            "missing_count": sum(1 for item in parsed_summaries if item.get("execution_status") == "missing"),
            "blocked_count": sum(1 for item in parsed_summaries if item.get("execution_status") == "blocked"),
            "degraded_count": sum(1 for item in parsed_summaries if item.get("execution_status") == "degraded"),
            "invalid_count": sum(1 for item in parsed_summaries if item.get("execution_status") == "invalid") + (len(invalid_refs) if isinstance(invalid_refs, list) else 0),
            "not_required_count": sum(1 for item in parsed_summaries if item.get("execution_status") == "not_required"),
            "required_execution_count": sum(1 for item in parsed_summaries if item.get("execution_required") is True),
            "packet_count": len(parsed_summaries),
        }
        for field, expected in status_counts.items():
            if report.get(field) != expected:
                errors.append(f"{field} should be {expected}, got {report.get(field)}")
        expected_completion = BUILDER.completion_rate(status_counts["complete_count"], status_counts["required_execution_count"])
        if report.get("completion_rate") != expected_completion:
            errors.append(f"completion_rate should be {expected_completion}, got {report.get('completion_rate')}")

        expected_gate = BUILDER.derive_gate({
            "packet_count": status_counts["packet_count"],
            "required_execution_count": status_counts["required_execution_count"],
            "complete_count": status_counts["complete_count"],
            "missing_count": status_counts["missing_count"],
            "blocked_count": status_counts["blocked_count"],
            "degraded_count": status_counts["degraded_count"],
            "invalid_count": status_counts["invalid_count"],
            "not_required_count": status_counts["not_required_count"],
            "completion_rate": expected_completion,
        })
        if report.get("execution_gate") != expected_gate:
            errors.append(f"execution_gate should be {expected_gate}, got {report.get('execution_gate')}")

    return errors


def validate_recomputable(report_path: Path, report: dict[str, Any]) -> list[str]:
    try:
        expected = BUILDER.expected_report(report_path, report)
    except ValueError as exc:
        return [str(exc)]
    if report != expected:
        return ["route execution report differs from referenced Action Packets"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL route execution report")
    parser.add_argument("report_file", type=Path)
    args = parser.parse_args()

    try:
        report_path = args.report_file.resolve()
        report = load_report(report_path)
    except (OSError, ValueError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    errors = validate_report(report)
    if not errors:
        errors.extend(validate_recomputable(report_path, report))
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    gate = report["execution_gate"]
    if gate in {"reroute", "block"}:
        print(f"[HIGHBALL] route execution report valid; execution gate is {gate}", file=sys.stderr)
        return 1

    print(f"[HIGHBALL] route execution report valid; execution gate is {gate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
