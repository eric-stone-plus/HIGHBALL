#!/usr/bin/env python3
"""Validate HIGHBALL route policy reports."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


TOP_LEVEL_FIELDS = {
    "policy_report_version",
    "route_group",
    "inputs",
    "calibration",
    "outcome",
    "baseline",
    "experiment_review",
    "execution",
    "policy_recommendation",
    "decision_reasons",
    "required_next_steps",
    "non_authorization",
}
INPUT_FIELDS = {
    "calibration_report_ref",
    "outcome_ledger_ref",
    "baseline_report_ref",
    "experiment_review_ref",
    "execution_report_ref",
}
CALIBRATION_FIELDS = {"recommendation", "trace_count", "invalid_trace_files", "route_group_summary"}
OUTCOME_FIELDS = {
    "calibration_signal",
    "entry_count",
    "verified_positive_count",
    "verified_negative_count",
    "inconclusive_count",
    "regression_count",
}
BASELINE_FIELDS = {
    "comparison_count",
    "target_preferred_count",
    "baseline_preferred_count",
    "target_blocked_count",
    "watch_count",
    "insufficient_count",
    "recommendation",
}
CALIBRATION_RECOMMENDATIONS = {"adopt", "review", "reroute", "block", "no_data"}
OUTCOME_SIGNALS = {"supports_route", "weakens_route", "mixed", "insufficient"}
BASELINE_RECOMMENDATIONS = {
    "prefer_target",
    "prefer_baseline",
    "block_target",
    "watch",
    "insufficient",
    "not_provided",
}
EXPERIMENT_REVIEW_FIELDS = {
    "review_ref",
    "review_verdict",
    "policy_gate",
    "required_before_policy_change",
}
EXPERIMENT_REVIEW_VERDICTS = {
    "supports_policy_review",
    "needs_more_evidence",
    "stop_blocked",
    "plan_violation",
    "not_provided",
}
EXPERIMENT_POLICY_GATES = {"accepted", "watch", "block", "insufficient", "not_provided"}
EXECUTION_FIELDS = {
    "report_ref",
    "execution_gate",
    "packet_count",
    "required_execution_count",
    "complete_count",
    "missing_count",
    "blocked_count",
    "degraded_count",
    "invalid_count",
    "completion_rate",
}
EXECUTION_GATES = {"accepted", "watch", "reroute", "block", "insufficient", "not_provided"}
POLICY_RECOMMENDATIONS = {"keep", "watch", "reroute", "block", "insufficient"}


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


def is_nullable_string(value: Any) -> bool:
    return value is None or isinstance(value, str)


def is_string_list(value: Any, *, min_items: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(is_nonempty_string(item) for item in value)
    )


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def load_report(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    blocks, raw_json_mode = candidate_blocks(text, path)
    if not blocks:
        raise ValueError("no JSON route policy report found")

    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            errors.append(f"{label} is invalid JSON: {exc.msg}")
            continue
        if isinstance(parsed, dict) and parsed.get("policy_report_version") == "1.0":
            reports.append(parsed)

    if len(reports) != 1:
        detail = "; ".join(errors) if errors else f"found {len(reports)} route policy reports"
        raise ValueError(f"expected exactly one route policy report; {detail}")
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


def derive_policy(calibration_recommendation: str, outcome_signal: str, baseline_recommendation: str) -> str:
    if baseline_recommendation == "block_target":
        return "block"
    if calibration_recommendation == "block":
        return "block"
    if baseline_recommendation == "prefer_baseline":
        return "reroute"
    if outcome_signal == "weakens_route":
        return "reroute"
    if calibration_recommendation in {"reroute", "no_data"}:
        return "reroute" if outcome_signal != "supports_route" else "watch"
    if outcome_signal in {"mixed", "insufficient"}:
        return "watch" if calibration_recommendation in {"adopt", "review"} else "insufficient"
    if calibration_recommendation == "adopt" and outcome_signal == "supports_route":
        return "keep"
    if calibration_recommendation == "review":
        return "watch"
    return "insufficient"


def apply_experiment_gate(policy: str, experiment_gate: str) -> str:
    if experiment_gate in {"not_provided", "accepted"}:
        return policy
    if experiment_gate == "block":
        return "block"
    if experiment_gate == "insufficient":
        return "block" if policy == "block" else "insufficient"
    if experiment_gate == "watch":
        if policy in {"block", "reroute"}:
            return policy
        if policy == "keep":
            return "watch"
    return policy


def apply_execution_gate(policy: str, execution_gate: str) -> str:
    if execution_gate in {"not_provided", "accepted", "insufficient"}:
        return policy
    if execution_gate == "block":
        return "block"
    if execution_gate == "reroute":
        return "block" if policy == "block" else "reroute"
    if execution_gate == "watch":
        if policy == "keep":
            return "watch"
    return policy


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

    if report.get("policy_report_version") != "1.0":
        errors.append("policy_report_version must be 1.0")
    if not is_nonempty_string(report.get("route_group")):
        errors.append("route_group must be a non-empty string")

    inputs = validate_object_fields("inputs", report.get("inputs"), INPUT_FIELDS, errors)
    if inputs:
        for field in ("calibration_report_ref", "outcome_ledger_ref"):
            if not is_nonempty_string(inputs.get(field)):
                errors.append(f"inputs.{field} must be a non-empty string")
        if not is_nullable_string(inputs.get("baseline_report_ref")):
            errors.append("inputs.baseline_report_ref must be a string or null")
        if not is_nullable_string(inputs.get("experiment_review_ref")):
            errors.append("inputs.experiment_review_ref must be a string or null")
        if not is_nullable_string(inputs.get("execution_report_ref")):
            errors.append("inputs.execution_report_ref must be a string or null")

    calibration = validate_object_fields("calibration", report.get("calibration"), CALIBRATION_FIELDS, errors)
    if calibration:
        if calibration.get("recommendation") not in CALIBRATION_RECOMMENDATIONS:
            errors.append("calibration.recommendation is invalid")
        for field in ("trace_count", "invalid_trace_files"):
            if not is_nonnegative_int(calibration.get(field)):
                errors.append(f"calibration.{field} must be a non-negative integer")
        if calibration.get("route_group_summary") is not None and not isinstance(calibration.get("route_group_summary"), dict):
            errors.append("calibration.route_group_summary must be an object or null")

    outcome = validate_object_fields("outcome", report.get("outcome"), OUTCOME_FIELDS, errors)
    if outcome:
        if outcome.get("calibration_signal") not in OUTCOME_SIGNALS:
            errors.append("outcome.calibration_signal is invalid")
        for field in (
            "entry_count",
            "verified_positive_count",
            "verified_negative_count",
            "inconclusive_count",
            "regression_count",
        ):
            if not is_nonnegative_int(outcome.get(field)):
                errors.append(f"outcome.{field} must be a non-negative integer")
        if all(isinstance(outcome.get(field), int) for field in (
            "entry_count",
            "verified_positive_count",
            "verified_negative_count",
            "inconclusive_count",
            "regression_count",
        )):
            total = (
                outcome["verified_positive_count"]
                + outcome["verified_negative_count"]
                + outcome["inconclusive_count"]
                + outcome["regression_count"]
            )
            if total != outcome["entry_count"]:
                errors.append("outcome counts must sum to entry_count")

    baseline = validate_object_fields("baseline", report.get("baseline"), BASELINE_FIELDS, errors)
    if baseline:
        for field in BASELINE_FIELDS - {"recommendation"}:
            if not is_nonnegative_int(baseline.get(field)):
                errors.append(f"baseline.{field} must be a non-negative integer")
        if baseline.get("recommendation") not in BASELINE_RECOMMENDATIONS:
            errors.append("baseline.recommendation is invalid")
        if all(isinstance(baseline.get(field), int) for field in (
            "comparison_count",
            "target_preferred_count",
            "baseline_preferred_count",
            "target_blocked_count",
            "watch_count",
            "insufficient_count",
        )):
            total = (
                baseline["target_preferred_count"]
                + baseline["baseline_preferred_count"]
                + baseline["target_blocked_count"]
                + baseline["watch_count"]
                + baseline["insufficient_count"]
            )
            if total != baseline["comparison_count"]:
                errors.append("baseline counts must sum to comparison_count")
            if baseline["comparison_count"] == 0 and baseline.get("recommendation") not in {"not_provided", "insufficient"}:
                errors.append("baseline.recommendation must be not_provided or insufficient when comparison_count is 0")

    experiment = validate_object_fields("experiment_review", report.get("experiment_review"), EXPERIMENT_REVIEW_FIELDS, errors)
    if experiment:
        if not is_nullable_string(experiment.get("review_ref")):
            errors.append("experiment_review.review_ref must be a string or null")
        if experiment.get("review_verdict") not in EXPERIMENT_REVIEW_VERDICTS:
            errors.append("experiment_review.review_verdict is invalid")
        if experiment.get("policy_gate") not in EXPERIMENT_POLICY_GATES:
            errors.append("experiment_review.policy_gate is invalid")
        if not isinstance(experiment.get("required_before_policy_change"), bool):
            errors.append("experiment_review.required_before_policy_change must be a boolean")
        if inputs:
            if experiment.get("review_ref") != inputs.get("experiment_review_ref"):
                errors.append("experiment_review.review_ref must match inputs.experiment_review_ref")
        if experiment.get("review_verdict") == "not_provided" and experiment.get("policy_gate") != "not_provided":
            errors.append("experiment_review.policy_gate must be not_provided when review_verdict is not_provided")
        if experiment.get("review_verdict") != "not_provided" and experiment.get("review_ref") is None:
            errors.append("experiment_review.review_ref must be provided when review_verdict is provided")

    execution = validate_object_fields("execution", report.get("execution"), EXECUTION_FIELDS, errors)
    if execution:
        if not is_nullable_string(execution.get("report_ref")):
            errors.append("execution.report_ref must be a string or null")
        if execution.get("execution_gate") not in EXECUTION_GATES:
            errors.append("execution.execution_gate is invalid")
        for field in (
            "packet_count",
            "required_execution_count",
            "complete_count",
            "missing_count",
            "blocked_count",
            "degraded_count",
            "invalid_count",
        ):
            if not is_nonnegative_int(execution.get(field)):
                errors.append(f"execution.{field} must be a non-negative integer")
        completion = execution.get("completion_rate")
        if completion is not None and not (isinstance(completion, (int, float)) and not isinstance(completion, bool) and 0 <= completion <= 1):
            errors.append("execution.completion_rate must be a number between 0 and 1 or null")
        if inputs:
            if execution.get("report_ref") != inputs.get("execution_report_ref"):
                errors.append("execution.report_ref must match inputs.execution_report_ref")
        if execution.get("execution_gate") == "not_provided" and execution.get("report_ref") is not None:
            errors.append("execution.report_ref must be null when execution_gate is not_provided")
        if execution.get("execution_gate") != "not_provided" and execution.get("report_ref") is None:
            errors.append("execution.report_ref must be provided when execution_gate is provided")

    if report.get("policy_recommendation") not in POLICY_RECOMMENDATIONS:
        errors.append("policy_recommendation is invalid")
    if not is_string_list(report.get("decision_reasons"), min_items=1):
        errors.append("decision_reasons must be a non-empty array of strings")
    if not is_string_list(report.get("required_next_steps"), min_items=1):
        errors.append("required_next_steps must be a non-empty array of strings")
    if not is_nonempty_string(report.get("non_authorization")):
        errors.append("non_authorization must be a non-empty string")

    if calibration and outcome and baseline and execution:
        base_expected = derive_policy(
            calibration.get("recommendation"),
            outcome.get("calibration_signal"),
            baseline.get("recommendation"),
        )
        experiment_gate = experiment.get("policy_gate") if experiment else "not_provided"
        expected = apply_experiment_gate(base_expected, experiment_gate)
        expected = apply_execution_gate(expected, execution.get("execution_gate"))
        if report.get("policy_recommendation") != expected:
            errors.append(f"policy_recommendation should be {expected}, got {report.get('policy_recommendation')}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL route policy report")
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

    recommendation = report["policy_recommendation"]
    if recommendation in {"reroute", "block"}:
        print(f"[HIGHBALL] route policy report valid; recommendation is {recommendation}", file=sys.stderr)
        return 1

    print(f"[HIGHBALL] route policy report valid; recommendation is {recommendation}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
