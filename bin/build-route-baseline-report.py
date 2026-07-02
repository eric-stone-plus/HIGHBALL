#!/usr/bin/env python3
"""Build a baseline comparison report from route calibration and outcomes."""

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
CALIBRATION_VALIDATOR = load_module(
    "validate_route_calibration_report",
    ROOT / "bin" / "validate-route-calibration-report.py",
)
OUTCOME_VALIDATOR = load_module(
    "validate_outcome_ledger",
    ROOT / "bin" / "validate-outcome-ledger.py",
)


TOP_LEVEL_FIELDS = {
    "baseline_report_version",
    "inputs",
    "action_boundary",
    "comparisons",
    "summary",
    "non_authorization",
}
INPUT_FIELDS = {"calibration_report_ref", "outcome_ledger_ref"}
SUMMARY_FIELDS = {
    "comparison_count",
    "target_preferred_count",
    "baseline_preferred_count",
    "target_blocked_count",
    "watch_count",
    "insufficient_count",
    "recommendation",
}
COMPARISON_FIELDS = {
    "target_route_group",
    "baseline_route_group",
    "comparison_basis",
    "target",
    "baseline",
    "deltas",
    "outcomes",
    "verdict",
    "reasons",
}
GROUP_SUMMARY_FIELDS = {
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
    "caveats",
    "sources",
}
DELTA_FIELDS = {
    "mean_evidence_score",
    "mean_residual_yield",
    "mean_closure_strength",
    "mean_manifest_strength",
    "mean_risk_penalty",
    "mean_residuals_per_10k_tokens",
    "mean_action_blocking_per_10k_tokens",
}
OUTCOME_FIELDS = {
    "entry_count",
    "verified_positive_count",
    "verified_negative_count",
    "inconclusive_count",
    "regression_count",
    "calibration_signal",
}
RECOMMENDATIONS = {"prefer_target", "prefer_baseline", "block_target", "watch", "insufficient"}
VERDICTS = {"target_preferred", "baseline_preferred", "target_blocked", "watch", "insufficient"}
GROUP_RECOMMENDATIONS = {"adopt", "review", "reroute", "block", "no_data"}
OUTCOME_SIGNALS = {"supports_route", "weakens_route", "mixed", "insufficient", None}


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def route_parts(route_group: str) -> tuple[str, str, str]:
    parts = route_group.split(":")
    if len(parts) != 3:
        return route_group, "unknown", "unknown"
    return parts[0], parts[1], parts[2]


def route_boundary(route_group: str) -> str:
    return route_parts(route_group)[2]


def relation_rank(route_group: str, group: dict[str, Any]) -> tuple[int, int, str]:
    instrument, relation, _boundary = route_parts(route_group)
    recommendation = group.get("recommendation")
    blocked = 1 if recommendation == "block" else 0
    relation_priority = {
        "direct_evidence": 0,
        "human": 1,
        "heterogeneous_models": 2,
        "mixed": 3,
        "same_family": 4,
        "same_model": 5,
        "unknown": 6,
    }.get(relation, 6)
    if instrument == "direct-evidence":
        relation_priority = min(relation_priority, 0)
    return blocked, relation_priority, route_group


def choose_baseline(route_groups: dict[str, Any], target: str) -> str | None:
    boundary = route_boundary(target)
    candidates = {
        key: group
        for key, group in route_groups.items()
        if key != target and route_boundary(key) == boundary and isinstance(group, dict)
    }
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: relation_rank(item[0], item[1]))[0][0]


def copy_group_summary(group: dict[str, Any]) -> dict[str, Any]:
    return {field: group.get(field) for field in GROUP_SUMMARY_FIELDS}


def numeric_delta(target: Any, baseline: Any) -> float | None:
    if isinstance(target, (int, float)) and isinstance(baseline, (int, float)):
        return round(float(target) - float(baseline), 4)
    return None


def compute_deltas(target: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    return {
        field: numeric_delta(target.get(field), baseline.get(field))
        for field in sorted(DELTA_FIELDS)
    }


def empty_outcome() -> dict[str, Any]:
    return {
        "entry_count": 0,
        "verified_positive_count": 0,
        "verified_negative_count": 0,
        "inconclusive_count": 0,
        "regression_count": 0,
        "calibration_signal": None,
    }


def outcome_counts(outcome: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if outcome is None:
        return {}

    grouped: dict[str, dict[str, int]] = {}
    for entry in outcome.get("entries", []):
        if not isinstance(entry, dict):
            continue
        route_group = entry.get("route_group")
        result = entry.get("outcome")
        if not isinstance(route_group, str) or result not in OUTCOME_VALIDATOR.OUTCOMES:
            continue
        counts = grouped.setdefault(
            route_group,
            {"verified_positive": 0, "verified_negative": 0, "inconclusive": 0, "regression": 0},
        )
        counts[result] += 1

    summaries: dict[str, dict[str, Any]] = {}
    for route_group, counts in grouped.items():
        summaries[route_group] = {
            "entry_count": sum(counts.values()),
            "verified_positive_count": counts["verified_positive"],
            "verified_negative_count": counts["verified_negative"],
            "inconclusive_count": counts["inconclusive"],
            "regression_count": counts["regression"],
            "calibration_signal": OUTCOME_VALIDATOR.derive_signal(counts),
        }
    return summaries


def compare(
    target_route_group: str,
    baseline_route_group: str,
    target: dict[str, Any],
    baseline: dict[str, Any],
    target_outcome: dict[str, Any],
    baseline_outcome: dict[str, Any],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    target_recommendation = target.get("recommendation")
    baseline_recommendation = baseline.get("recommendation")
    target_signal = target_outcome.get("calibration_signal")
    baseline_signal = baseline_outcome.get("calibration_signal")
    deltas = compute_deltas(target, baseline)

    if target_recommendation == "block":
        return "target_blocked", [
            f"target route {target_route_group} is blocked by calibration",
        ]
    if baseline_recommendation == "block" and target_recommendation != "block":
        return "target_preferred", [
            f"baseline route {baseline_route_group} is blocked by calibration",
        ]

    if target.get("trace_count", 0) <= 0 or baseline.get("trace_count", 0) <= 0:
        return "insufficient", ["target and baseline both need at least one calibrated trace"]

    if target_signal == "weakens_route" and baseline_signal != "weakens_route":
        return "baseline_preferred", ["outcome evidence weakens the target route"]
    if baseline_signal == "weakens_route" and target_signal != "weakens_route":
        return "target_preferred", ["outcome evidence weakens the baseline route"]

    score_delta = deltas["mean_evidence_score"]
    closure_delta = deltas["mean_closure_strength"]
    risk_delta = deltas["mean_risk_penalty"]
    cost_delta = deltas["mean_residuals_per_10k_tokens"]

    if score_delta is None or closure_delta is None or risk_delta is None:
        return "insufficient", ["comparison is missing score, closure, or risk metrics"]

    reasons.append(f"target evidence score delta is {score_delta}")
    reasons.append(f"target risk penalty delta is {risk_delta}")

    if cost_delta is not None:
        reasons.append(f"target residual yield per 10k tokens delta is {cost_delta}")

    target_metric_win = score_delta >= 0.05 and closure_delta >= -0.05 and risk_delta <= 0.05
    baseline_metric_win = score_delta <= -0.05 or closure_delta <= -0.10 or risk_delta >= 0.10

    if cost_delta is not None and cost_delta < -0.10 and score_delta < 0.05:
        baseline_metric_win = True
        reasons.append("target costs more residual yield than the baseline without a compensating score gain")
    elif cost_delta is not None and cost_delta > 0.10 and risk_delta <= 0.05:
        target_metric_win = True
        reasons.append("target produces more residual yield per token without higher risk")

    if target_metric_win and not baseline_metric_win:
        return "target_preferred", reasons
    if baseline_metric_win and not target_metric_win:
        return "baseline_preferred", reasons
    return "watch", reasons + ["target and baseline signals are mixed or too close to prefer one route"]


def build_comparison(
    target_route_group: str,
    baseline_route_group: str,
    route_groups: dict[str, Any],
    outcomes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    target = copy_group_summary(route_groups[target_route_group])
    baseline = copy_group_summary(route_groups[baseline_route_group])
    target_outcome = outcomes.get(target_route_group, empty_outcome())
    baseline_outcome = outcomes.get(baseline_route_group, empty_outcome())
    verdict, reasons = compare(
        target_route_group,
        baseline_route_group,
        target,
        baseline,
        target_outcome,
        baseline_outcome,
    )
    return {
        "target_route_group": target_route_group,
        "baseline_route_group": baseline_route_group,
        "comparison_basis": "same_action_boundary",
        "target": target,
        "baseline": baseline,
        "deltas": compute_deltas(target, baseline),
        "outcomes": {
            "target": target_outcome,
            "baseline": baseline_outcome,
        },
        "verdict": verdict,
        "reasons": reasons,
    }


def summarize(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        "target_preferred": sum(1 for item in comparisons if item.get("verdict") == "target_preferred"),
        "baseline_preferred": sum(1 for item in comparisons if item.get("verdict") == "baseline_preferred"),
        "target_blocked": sum(1 for item in comparisons if item.get("verdict") == "target_blocked"),
        "watch": sum(1 for item in comparisons if item.get("verdict") == "watch"),
        "insufficient": sum(1 for item in comparisons if item.get("verdict") == "insufficient"),
    }
    if not comparisons:
        recommendation = "insufficient"
    elif counts["target_blocked"] > 0:
        recommendation = "block_target"
    elif counts["baseline_preferred"] > counts["target_preferred"]:
        recommendation = "prefer_baseline"
    elif counts["target_preferred"] > counts["baseline_preferred"]:
        recommendation = "prefer_target"
    elif counts["watch"] > 0:
        recommendation = "watch"
    else:
        recommendation = "insufficient"

    return {
        "comparison_count": len(comparisons),
        "target_preferred_count": counts["target_preferred"],
        "baseline_preferred_count": counts["baseline_preferred"],
        "target_blocked_count": counts["target_blocked"],
        "watch_count": counts["watch"],
        "insufficient_count": counts["insufficient"],
        "recommendation": recommendation,
    }


def select_comparisons(
    route_groups: dict[str, Any],
    targets: list[str],
    baseline_route_group: str | None,
) -> list[tuple[str, str]]:
    if baseline_route_group is not None and baseline_route_group not in route_groups:
        raise ValueError(f"baseline route group is absent from calibration report: {baseline_route_group}")
    for target in targets:
        if target not in route_groups:
            raise ValueError(f"target route group is absent from calibration report: {target}")

    if not targets:
        targets = list(route_groups)
        if baseline_route_group is not None:
            targets = [target for target in targets if target != baseline_route_group]

    pairs: list[tuple[str, str]] = []
    for target in targets:
        baseline = baseline_route_group if baseline_route_group is not None else choose_baseline(route_groups, target)
        if baseline is None or baseline == target:
            continue
        if route_boundary(target) != route_boundary(baseline):
            raise ValueError(f"target and baseline route groups use different action boundaries: {target}, {baseline}")
        pair = (target, baseline)
        if pair not in pairs:
            pairs.append(pair)
    return pairs


def build_report(
    calibration_path: Path,
    outcome_path: Path | None,
    targets: list[str],
    baseline_route_group: str | None,
) -> dict[str, Any]:
    calibration = load_json(calibration_path)
    errors = CALIBRATION_VALIDATOR.validate_report(calibration)
    if errors:
        raise ValueError("; ".join(f"calibration: {error}" for error in errors))

    outcome = None
    if outcome_path is not None:
        outcome = load_json(outcome_path)
        outcome_errors = OUTCOME_VALIDATOR.validate_ledger(outcome)
        if outcome_errors:
            raise ValueError("; ".join(f"outcome: {error}" for error in outcome_errors))

    route_groups = calibration.get("route_groups", {})
    if not isinstance(route_groups, dict):
        raise ValueError("calibration report route_groups must be an object")

    pairs = select_comparisons(route_groups, targets, baseline_route_group)
    outcomes = outcome_counts(outcome)
    comparisons = [
        build_comparison(target, baseline, route_groups, outcomes)
        for target, baseline in pairs
    ]
    boundaries = sorted({route_boundary(target) for target, _baseline in pairs})
    action_boundary = boundaries[0] if len(boundaries) == 1 else "mixed" if boundaries else "unknown"

    return {
        "baseline_report_version": "1.0",
        "inputs": {
            "calibration_report_ref": str(calibration_path),
            "outcome_ledger_ref": str(outcome_path) if outcome_path is not None else None,
        },
        "action_boundary": action_boundary,
        "comparisons": comparisons,
        "summary": summarize(comparisons),
        "non_authorization": "Route baseline reports do not authorize action or modify routing rules.",
    }


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_nullable_string(value: Any) -> bool:
    return value is None or isinstance(value, str)


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_nullable_number(value: Any) -> bool:
    return value is None or (
        isinstance(value, (int, float)) and not isinstance(value, bool)
    )


def is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def validate_fields(name: str, value: Any, fields: set[str], errors: list[str]) -> dict[str, Any]:
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


def validate_group_summary(name: str, value: Any, errors: list[str]) -> dict[str, Any]:
    group = validate_fields(name, value, GROUP_SUMMARY_FIELDS, errors)
    if not group:
        return {}
    if not is_nonnegative_int(group.get("trace_count")):
        errors.append(f"{name}.trace_count must be a non-negative integer")
    if group.get("recommendation") not in GROUP_RECOMMENDATIONS:
        errors.append(f"{name}.recommendation is invalid")
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
            errors.append(f"{name}.{field} must be a number or null")
    for field in ("residual_count", "action_blocking_count"):
        if not is_nonnegative_int(group.get(field)):
            errors.append(f"{name}.{field} must be a non-negative integer")
    if not is_string_list(group.get("caveats")):
        errors.append(f"{name}.caveats must be an array of strings")
    if not is_string_list(group.get("sources")):
        errors.append(f"{name}.sources must be an array of strings")
    return group


def validate_outcome_summary(name: str, value: Any, errors: list[str]) -> dict[str, Any]:
    outcome = validate_fields(name, value, OUTCOME_FIELDS, errors)
    if not outcome:
        return {}
    for field in (
        "entry_count",
        "verified_positive_count",
        "verified_negative_count",
        "inconclusive_count",
        "regression_count",
    ):
        if not is_nonnegative_int(outcome.get(field)):
            errors.append(f"{name}.{field} must be a non-negative integer")
    if outcome.get("calibration_signal") not in OUTCOME_SIGNALS:
        errors.append(f"{name}.calibration_signal is invalid")
    return outcome


def validate_comparison(index: int, value: Any, errors: list[str]) -> dict[str, Any]:
    prefix = f"comparisons[{index}]"
    comparison = validate_fields(prefix, value, COMPARISON_FIELDS, errors)
    if not comparison:
        return {}
    if not is_nonempty_string(comparison.get("target_route_group")):
        errors.append(f"{prefix}.target_route_group must be a non-empty string")
    if not is_nonempty_string(comparison.get("baseline_route_group")):
        errors.append(f"{prefix}.baseline_route_group must be a non-empty string")
    if comparison.get("comparison_basis") != "same_action_boundary":
        errors.append(f"{prefix}.comparison_basis must be same_action_boundary")
    target = validate_group_summary(f"{prefix}.target", comparison.get("target"), errors)
    baseline = validate_group_summary(f"{prefix}.baseline", comparison.get("baseline"), errors)
    deltas = validate_fields(f"{prefix}.deltas", comparison.get("deltas"), DELTA_FIELDS, errors)
    for field in DELTA_FIELDS:
        if deltas and not is_nullable_number(deltas.get(field)):
            errors.append(f"{prefix}.deltas.{field} must be a number or null")
    outcomes = validate_fields(f"{prefix}.outcomes", comparison.get("outcomes"), {"target", "baseline"}, errors)
    if outcomes:
        target_outcome = validate_outcome_summary(f"{prefix}.outcomes.target", outcomes.get("target"), errors)
        baseline_outcome = validate_outcome_summary(f"{prefix}.outcomes.baseline", outcomes.get("baseline"), errors)
    else:
        target_outcome = {}
        baseline_outcome = {}
    if comparison.get("verdict") not in VERDICTS:
        errors.append(f"{prefix}.verdict is invalid")
    if not isinstance(comparison.get("reasons"), list) or not all(is_nonempty_string(item) for item in comparison.get("reasons", [])):
        errors.append(f"{prefix}.reasons must be a non-empty array of strings")

    if target and baseline and deltas:
        expected_deltas = compute_deltas(target, baseline)
        if deltas != expected_deltas:
            errors.append(f"{prefix}.deltas do not match target and baseline summaries")
    if target and baseline and target_outcome and baseline_outcome:
        expected_verdict, expected_reasons = compare(
            comparison.get("target_route_group"),
            comparison.get("baseline_route_group"),
            target,
            baseline,
            target_outcome,
            baseline_outcome,
        )
        if comparison.get("verdict") != expected_verdict:
            errors.append(f"{prefix}.verdict should be {expected_verdict}, got {comparison.get('verdict')}")
        if comparison.get("reasons") != expected_reasons:
            errors.append(f"{prefix}.reasons do not match derived reasons")
    return comparison


def validate_report(report: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["report must be an object"]

    validate_fields("report", report, TOP_LEVEL_FIELDS, errors)
    if report.get("baseline_report_version") != "1.0":
        errors.append("baseline_report_version must be 1.0")
    inputs = validate_fields("inputs", report.get("inputs"), INPUT_FIELDS, errors)
    if inputs:
        if not is_nonempty_string(inputs.get("calibration_report_ref")):
            errors.append("inputs.calibration_report_ref must be a non-empty string")
        if not is_nullable_string(inputs.get("outcome_ledger_ref")):
            errors.append("inputs.outcome_ledger_ref must be a string or null")
    if not is_nonempty_string(report.get("action_boundary")):
        errors.append("action_boundary must be a non-empty string")

    comparisons_value = report.get("comparisons")
    comparisons: list[dict[str, Any]] = []
    if not isinstance(comparisons_value, list):
        errors.append("comparisons must be an array")
    else:
        for index, item in enumerate(comparisons_value, start=1):
            comparison = validate_comparison(index, item, errors)
            if comparison:
                comparisons.append(comparison)

    summary = validate_fields("summary", report.get("summary"), SUMMARY_FIELDS, errors)
    if summary:
        for field in SUMMARY_FIELDS - {"recommendation"}:
            if not is_nonnegative_int(summary.get(field)):
                errors.append(f"summary.{field} must be a non-negative integer")
        if summary.get("recommendation") not in RECOMMENDATIONS:
            errors.append("summary.recommendation is invalid")
        expected_summary = summarize(comparisons)
        if summary != expected_summary:
            errors.append("summary does not match comparison verdict counts")
    if not is_nonempty_string(report.get("non_authorization")):
        errors.append("non_authorization must be a non-empty string")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a HIGHBALL route baseline report")
    parser.add_argument("calibration_report", type=Path)
    parser.add_argument("--outcome-ledger", type=Path)
    parser.add_argument("--target-route-group", action="append", default=[])
    parser.add_argument("--baseline-route-group")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        report = build_report(
            args.calibration_report,
            args.outcome_ledger,
            args.target_route_group,
            args.baseline_route_group,
        )
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    print(json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
