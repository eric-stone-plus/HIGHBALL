#!/usr/bin/env python3
"""Build a route policy report from calibration and outcome artifacts."""

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
BASELINE_VALIDATOR = load_module(
    "validate_route_baseline_report",
    ROOT / "bin" / "validate-route-baseline-report.py",
)
EXPERIMENT_REVIEW_VALIDATOR = load_module(
    "validate_route_experiment_review",
    ROOT / "bin" / "validate-route-experiment-review.py",
)
EXECUTION_VALIDATOR = load_module(
    "validate_route_execution_report",
    ROOT / "bin" / "validate-route-execution-report.py",
)
BASELINE_BUILDER = load_module(
    "build_route_baseline_report",
    ROOT / "bin" / "build-route-baseline-report.py",
)


POLICY_RECOMMENDATIONS = {"keep", "watch", "reroute", "block", "insufficient"}


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is invalid JSON: {exc.msg}") from exc


def resolve_ref(base_file: Path, ref: str | None) -> Path | None:
    if ref is None or "://" in ref:
        return None
    ref_path = Path(ref)
    if ref_path.is_absolute():
        return ref_path.resolve()
    return (base_file.parent / ref_path).resolve()


def validate_inputs(
    calibration: dict[str, Any],
    outcome: dict[str, Any],
    baseline: dict[str, Any] | None,
    experiment_review: dict[str, Any] | None,
    execution: dict[str, Any] | None,
) -> list[str]:
    errors = []
    errors.extend(f"calibration: {error}" for error in CALIBRATION_VALIDATOR.validate_report(calibration))
    errors.extend(f"outcome: {error}" for error in OUTCOME_VALIDATOR.validate_ledger(outcome))
    if baseline is not None:
        errors.extend(f"baseline: {error}" for error in BASELINE_VALIDATOR.validate_report(baseline))
    if experiment_review is not None:
        errors.extend(f"experiment_review: {error}" for error in EXPERIMENT_REVIEW_VALIDATOR.validate_report(experiment_review))
    if execution is not None:
        errors.extend(f"execution: {error}" for error in EXECUTION_VALIDATOR.validate_report(execution))
    return errors


def target_route_group(calibration: dict[str, Any], outcome: dict[str, Any]) -> str | None:
    outcome_route = outcome.get("subject", {}).get("route_group")
    if isinstance(outcome_route, str) and outcome_route:
        return outcome_route

    groups = calibration.get("route_groups")
    if isinstance(groups, dict) and len(groups) == 1:
        key = next(iter(groups))
        if isinstance(key, str) and key:
            return key
    return None


def empty_baseline_summary() -> dict[str, Any]:
    return {
        "comparison_count": 0,
        "target_preferred_count": 0,
        "baseline_preferred_count": 0,
        "target_blocked_count": 0,
        "watch_count": 0,
        "insufficient_count": 0,
        "recommendation": "not_provided",
    }


def baseline_summary_for_route(baseline: dict[str, Any] | None, route_group: str) -> dict[str, Any]:
    if baseline is None:
        return empty_baseline_summary()
    comparisons = [
        comparison
        for comparison in baseline.get("comparisons", [])
        if isinstance(comparison, dict) and comparison.get("target_route_group") == route_group
    ]
    if not comparisons:
        summary = BASELINE_BUILDER.summarize([])
        summary["recommendation"] = "insufficient"
        return summary
    return BASELINE_BUILDER.summarize(comparisons)


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


def experiment_gate(experiment_review: dict[str, Any] | None) -> dict[str, Any]:
    if experiment_review is None:
        return {
            "review_ref": None,
            "review_verdict": "not_provided",
            "policy_gate": "not_provided",
            "required_before_policy_change": False,
        }

    verdict = experiment_review["review_verdict"]
    gate = {
        "supports_policy_review": "accepted",
        "needs_more_evidence": "watch",
        "stop_blocked": "block",
        "plan_violation": "insufficient",
    }[verdict]
    return {
        "review_ref": None,
        "review_verdict": verdict,
        "policy_gate": gate,
        "required_before_policy_change": True,
    }


def apply_experiment_gate(policy: str, experiment: dict[str, Any]) -> str:
    gate = experiment["policy_gate"]
    if gate in {"not_provided", "accepted"}:
        return policy
    if gate == "block":
        return "block"
    if gate == "insufficient":
        return "block" if policy == "block" else "insufficient"
    if gate == "watch":
        if policy in {"block", "reroute"}:
            return policy
        if policy == "keep":
            return "watch"
    return policy


def empty_execution_summary() -> dict[str, Any]:
    return {
        "report_ref": None,
        "execution_gate": "not_provided",
        "packet_count": 0,
        "required_execution_count": 0,
        "complete_count": 0,
        "missing_count": 0,
        "blocked_count": 0,
        "degraded_count": 0,
        "invalid_count": 0,
        "completion_rate": None,
    }


def execution_summary(execution: dict[str, Any] | None, execution_path: Path | None) -> dict[str, Any]:
    if execution is None:
        return empty_execution_summary()
    return {
        "report_ref": str(execution_path) if execution_path is not None else None,
        "execution_gate": execution["execution_gate"],
        "packet_count": execution["packet_count"],
        "required_execution_count": execution["required_execution_count"],
        "complete_count": execution["complete_count"],
        "missing_count": execution["missing_count"],
        "blocked_count": execution["blocked_count"],
        "degraded_count": execution["degraded_count"],
        "invalid_count": execution["invalid_count"],
        "completion_rate": execution["completion_rate"],
    }


def apply_execution_gate(policy: str, execution: dict[str, Any]) -> str:
    gate = execution["execution_gate"]
    if gate in {"not_provided", "accepted", "insufficient"}:
        return policy
    if gate == "block":
        return "block"
    if gate == "reroute":
        return "block" if policy == "block" else "reroute"
    if gate == "watch":
        if policy == "keep":
            return "watch"
    return policy


def validate_review_refs(
    review_path: Path,
    review: dict[str, Any],
    calibration_path: Path,
    outcome_path: Path,
    baseline_path: Path | None,
) -> list[str]:
    errors: list[str] = []
    inputs = review.get("inputs", {})
    calibration_ref = resolve_ref(review_path, inputs.get("calibration_report_ref"))
    outcome_ref = resolve_ref(review_path, inputs.get("outcome_ledger_ref"))
    baseline_ref = resolve_ref(review_path, inputs.get("baseline_report_ref"))
    if calibration_ref != calibration_path.resolve():
        errors.append("experiment review calibration ref differs from policy calibration report")
    if outcome_ref is not None and outcome_ref != outcome_path.resolve():
        errors.append("experiment review outcome ref differs from policy outcome ledger")
    if baseline_ref is not None and baseline_path is not None and baseline_ref != baseline_path.resolve():
        errors.append("experiment review baseline ref differs from policy baseline report")
    if baseline_ref is not None and baseline_path is None:
        errors.append("experiment review has a baseline ref but policy input does not")
    return errors


def build_report(
    calibration_path: Path,
    outcome_path: Path,
    baseline_path: Path | None = None,
    experiment_review_path: Path | None = None,
    execution_report_path: Path | None = None,
) -> dict[str, Any]:
    calibration = load_json(calibration_path)
    outcome = load_json(outcome_path)
    baseline = load_json(baseline_path) if baseline_path is not None else None
    experiment_review = load_json(experiment_review_path) if experiment_review_path is not None else None
    execution_report = load_json(execution_report_path) if execution_report_path is not None else None
    errors = validate_inputs(calibration, outcome, baseline, experiment_review, execution_report)
    if errors:
        raise ValueError("; ".join(errors))

    route_group = target_route_group(calibration, outcome)
    if route_group is None:
        raise ValueError("cannot derive a single route_group from inputs")
    if experiment_review is not None:
        if experiment_review.get("route_group") != route_group:
            raise ValueError("experiment review route_group differs from policy route_group")
        assert experiment_review_path is not None
        review_ref_errors = validate_review_refs(
            experiment_review_path,
            experiment_review,
            calibration_path,
            outcome_path,
            baseline_path,
        )
        if review_ref_errors:
            raise ValueError("; ".join(review_ref_errors))
    if execution_report is not None and execution_report.get("route_group") != route_group:
        raise ValueError("execution report route_group differs from policy route_group")

    calibration_recommendation = calibration["recommendation"]
    outcome_signal = outcome["summary"]["calibration_signal"]
    baseline_summary = baseline_summary_for_route(baseline, route_group)
    experiment = experiment_gate(experiment_review)
    experiment["review_ref"] = str(experiment_review_path) if experiment_review_path is not None else None
    execution = execution_summary(execution_report, execution_report_path)
    base_policy_recommendation = derive_policy(
        calibration_recommendation,
        outcome_signal,
        baseline_summary["recommendation"],
    )
    policy_after_experiment = apply_experiment_gate(base_policy_recommendation, experiment)
    policy_recommendation = apply_execution_gate(policy_after_experiment, execution)

    route_group_summary = None
    route_groups = calibration.get("route_groups", {})
    if isinstance(route_groups, dict):
        route_group_summary = route_groups.get(route_group)

    return {
        "policy_report_version": "1.0",
        "route_group": route_group,
        "inputs": {
            "calibration_report_ref": str(calibration_path),
            "outcome_ledger_ref": str(outcome_path),
            "baseline_report_ref": str(baseline_path) if baseline_path is not None else None,
            "experiment_review_ref": str(experiment_review_path) if experiment_review_path is not None else None,
            "execution_report_ref": str(execution_report_path) if execution_report_path is not None else None,
        },
        "calibration": {
            "recommendation": calibration_recommendation,
            "trace_count": calibration["trace_count"],
            "invalid_trace_files": calibration["invalid_trace_files"],
            "route_group_summary": route_group_summary,
        },
        "outcome": {
            "calibration_signal": outcome_signal,
            "entry_count": outcome["summary"]["entry_count"],
            "verified_positive_count": outcome["summary"]["verified_positive_count"],
            "verified_negative_count": outcome["summary"]["verified_negative_count"],
            "inconclusive_count": outcome["summary"]["inconclusive_count"],
            "regression_count": outcome["summary"]["regression_count"],
        },
        "baseline": baseline_summary,
        "experiment_review": experiment,
        "execution": execution,
        "policy_recommendation": policy_recommendation,
        "decision_reasons": decision_reasons(
            calibration_recommendation,
            outcome_signal,
            baseline_summary,
            experiment,
            execution,
            policy_recommendation,
            calibration,
            outcome,
        ),
        "required_next_steps": next_steps(policy_recommendation),
        "non_authorization": "Route policy reports do not authorize action or modify routing rules.",
    }


def decision_reasons(
    calibration_recommendation: str,
    outcome_signal: str,
    baseline_summary: dict[str, Any],
    experiment_review: dict[str, Any],
    execution: dict[str, Any],
    policy_recommendation: str,
    calibration: dict[str, Any],
    outcome: dict[str, Any],
) -> list[str]:
    reasons = [
        f"route calibration recommendation is {calibration_recommendation}",
        f"outcome calibration signal is {outcome_signal}",
        f"baseline recommendation is {baseline_summary['recommendation']}",
        f"experiment review verdict is {experiment_review['review_verdict']}",
        f"execution gate is {execution['execution_gate']}",
        f"derived policy recommendation is {policy_recommendation}",
    ]
    if calibration.get("invalid_trace_files", 0) > 0:
        reasons.append("calibration report contains invalid trace candidates")
    if outcome["summary"].get("regression_count", 0) > 0:
        reasons.append("outcome ledger contains regression evidence")
    if execution.get("blocked_count", 0) > 0:
        reasons.append("execution report contains blocked dispatch evidence")
    if execution.get("degraded_count", 0) > 0:
        reasons.append("execution report contains degraded dispatch evidence")
    if execution.get("missing_count", 0) > 0:
        reasons.append("execution report contains missing dispatch evidence")
    if execution.get("invalid_count", 0) > 0:
        reasons.append("execution report contains invalid dispatch evidence")
    return reasons


def next_steps(policy_recommendation: str) -> list[str]:
    return {
        "keep": ["keep the current route policy for similar boundaries, subject to normal HIGHBALL gates"],
        "watch": ["keep collecting outcome ledgers before changing route policy"],
        "reroute": ["prefer a stronger, cheaper, or more direct evidence route for similar future boundaries"],
        "block": ["do not use this route policy for similar protected boundaries until blocking risk is resolved"],
        "insufficient": ["collect more calibrated traces and follow-up outcomes"],
    }[policy_recommendation]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a HIGHBALL route policy report")
    parser.add_argument("calibration_report", type=Path)
    parser.add_argument("outcome_ledger", type=Path)
    parser.add_argument("--baseline-report", type=Path)
    parser.add_argument("--experiment-review", type=Path)
    parser.add_argument("--execution-report", type=Path)
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        report = build_report(
            args.calibration_report,
            args.outcome_ledger,
            args.baseline_report,
            args.experiment_review,
            args.execution_report,
        )
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    print(json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
