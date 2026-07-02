#!/usr/bin/env python3
"""Build and validate route experiment reviews."""

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
MANIFEST_VALIDATOR = load_module(
    "validate_route_experiment_manifest",
    ROOT / "bin" / "validate-route-experiment-manifest.py",
)
CALIBRATION_VALIDATOR = load_module(
    "validate_route_calibration_report",
    ROOT / "bin" / "validate-route-calibration-report.py",
)
BASELINE_VALIDATOR = load_module(
    "validate_route_baseline_report",
    ROOT / "bin" / "validate-route-baseline-report.py",
)
PAIRING_VALIDATOR = load_module(
    "validate_route_pairing_report",
    ROOT / "bin" / "validate-route-pairing-report.py",
)
OUTCOME_VALIDATOR = load_module(
    "validate_outcome_ledger",
    ROOT / "bin" / "validate-outcome-ledger.py",
)
BASELINE_BUILDER = load_module(
    "build_route_baseline_report",
    ROOT / "bin" / "build-route-baseline-report.py",
)


NON_AUTHORIZATION = "Route experiment reviews do not authorize action, dispatch agents, or modify routing rules."

REVIEW_VERDICTS = {"supports_policy_review", "needs_more_evidence", "stop_blocked", "plan_violation"}
INPUT_FIELDS = {
    "manifest_ref",
    "calibration_report_ref",
    "baseline_report_ref",
    "pairing_report_ref",
    "outcome_ledger_ref",
}
COHORT_FIELDS = {
    "planned_minimum_trace_count",
    "observed_trace_count",
    "minimum_trace_count_met",
    "planned_minimum_candidate_files",
    "observed_candidate_files",
    "minimum_candidate_files_met",
    "planned_maximum_invalid_trace_files",
    "observed_invalid_trace_files",
    "invalid_trace_limit_met",
    "planned_inputs_matched",
}
TARGET_FIELDS = {
    "present",
    "recommendation",
    "trace_count",
    "mean_evidence_score",
    "mean_closure_strength",
    "mean_risk_penalty",
    "mean_residuals_per_10k_tokens",
    "metric_thresholds_met",
}
BASELINE_FIELDS = {
    "required",
    "provided",
    "required_route_groups",
    "present_route_groups",
    "same_action_boundary",
    "minimum_trace_count_per_baseline_met",
    "recommendation",
    "recommendation_allowed",
}
PAIRING_FIELDS = {
    "required",
    "provided",
    "planned_pair_manifest_matched",
    "same_experiment",
    "same_route_group",
    "same_action_boundary",
    "minimum_pair_count_met",
    "pair_count",
    "invalid_pair_count",
    "recommendation",
    "recommendation_allowed",
}
OUTCOME_FIELDS = {
    "required",
    "provided",
    "entry_count",
    "minimum_entry_count_met",
    "planned_outcome_ledger_matched",
    "calibration_signal",
    "signal_allowed",
    "regression_count",
}
SUCCESS_FIELDS = {
    "calibration_recommendation_allowed",
    "baseline_recommendation_allowed",
    "pairing_recommendation_allowed",
    "outcome_signal_allowed",
    "metric_thresholds_met",
}
STOPPING_FIELDS = {
    "block_recommendation",
    "baseline_preference",
    "pairing_preference",
    "outcome_regression",
    "maximum_trace_count_reached",
}
TOP_LEVEL_FIELDS = {
    "review_version",
    "experiment_id",
    "route_group",
    "action_boundary",
    "inputs",
    "cohort",
    "target_route",
    "baseline",
    "pairing",
    "outcome",
    "success",
    "stopping_flags",
    "review_verdict",
    "decision_reasons",
    "required_next_steps",
    "non_authorization",
}


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


def resolve_ref(base_file: Path, ref: str | None) -> Path | None:
    if ref is None or "://" in ref:
        return None
    ref_path = Path(ref)
    if ref_path.is_absolute():
        return ref_path.resolve()
    return (base_file.parent / ref_path).resolve()


def ref_matches(planned_base: Path, planned_ref: str, observed_base: Path, observed_refs: list[str]) -> bool:
    if planned_ref in observed_refs:
        return True
    if "://" in planned_ref:
        return False
    planned_path = resolve_ref(planned_base, planned_ref)
    if planned_path is None:
        return False
    for observed_ref in observed_refs:
        if "://" in observed_ref:
            continue
        observed_path = resolve_ref(observed_base, observed_ref)
        if observed_path == planned_path or Path(observed_ref).resolve() == planned_path:
            return True
    return False


def route_boundary(route_group: str) -> str:
    parts = route_group.split(":")
    if len(parts) != 3:
        return "unknown"
    return parts[2]


def empty_target_summary() -> dict[str, Any]:
    return {
        "present": False,
        "recommendation": None,
        "trace_count": 0,
        "mean_evidence_score": None,
        "mean_closure_strength": None,
        "mean_risk_penalty": None,
        "mean_residuals_per_10k_tokens": None,
        "metric_thresholds_met": False,
    }


def target_summary(manifest: dict[str, Any], calibration: dict[str, Any]) -> dict[str, Any]:
    route_group = manifest["route_group"]
    group = calibration.get("route_groups", {}).get(route_group)
    if not isinstance(group, dict):
        return empty_target_summary()

    criteria = manifest["success_criteria"]
    metric_checks = []
    if criteria["minimum_mean_evidence_score"] is not None:
        metric_checks.append(group.get("mean_evidence_score") is not None and group["mean_evidence_score"] >= criteria["minimum_mean_evidence_score"])
    if criteria["minimum_mean_closure_strength"] is not None:
        metric_checks.append(group.get("mean_closure_strength") is not None and group["mean_closure_strength"] >= criteria["minimum_mean_closure_strength"])
    if criteria["maximum_mean_risk_penalty"] is not None:
        metric_checks.append(group.get("mean_risk_penalty") is not None and group["mean_risk_penalty"] <= criteria["maximum_mean_risk_penalty"])
    if criteria["minimum_mean_residuals_per_10k_tokens"] is not None:
        metric_checks.append(
            group.get("mean_residuals_per_10k_tokens") is not None
            and group["mean_residuals_per_10k_tokens"] >= criteria["minimum_mean_residuals_per_10k_tokens"]
        )

    return {
        "present": True,
        "recommendation": group.get("recommendation"),
        "trace_count": group.get("trace_count", 0),
        "mean_evidence_score": group.get("mean_evidence_score"),
        "mean_closure_strength": group.get("mean_closure_strength"),
        "mean_risk_penalty": group.get("mean_risk_penalty"),
        "mean_residuals_per_10k_tokens": group.get("mean_residuals_per_10k_tokens"),
        "metric_thresholds_met": all(metric_checks) if metric_checks else True,
    }


def policy_baseline_summary_for_route(baseline: dict[str, Any] | None, route_group: str) -> dict[str, Any]:
    if baseline is None:
        return {
            "comparison_count": 0,
            "target_preferred_count": 0,
            "baseline_preferred_count": 0,
            "target_blocked_count": 0,
            "watch_count": 0,
            "insufficient_count": 0,
            "recommendation": "not_provided",
        }
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


def baseline_summary(manifest: dict[str, Any], calibration: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    requirements = manifest["baseline_requirements"]
    required_routes = requirements["baseline_route_groups"]
    route_groups = calibration.get("route_groups", {})
    present_routes = [route for route in required_routes if route in route_groups]
    expected_boundary = manifest["action_boundary"]
    same_boundary = all(route_boundary(route) == expected_boundary for route in required_routes)
    minimum_trace_count = requirements["minimum_trace_count_per_baseline"]
    minimum_met = all(
        isinstance(route_groups.get(route), dict)
        and route_groups[route].get("trace_count", 0) >= minimum_trace_count
        for route in required_routes
    )
    recommendation = policy_baseline_summary_for_route(baseline, manifest["route_group"])["recommendation"]
    allowed = recommendation in manifest["success_criteria"]["allowed_baseline_recommendations"]
    if not requirements["required"] and recommendation == "not_provided":
        allowed = True
    return {
        "required": requirements["required"],
        "provided": baseline is not None,
        "required_route_groups": required_routes,
        "present_route_groups": present_routes,
        "same_action_boundary": same_boundary,
        "minimum_trace_count_per_baseline_met": minimum_met,
        "recommendation": recommendation,
        "recommendation_allowed": allowed,
    }


def pairing_summary(
    manifest_path: Path,
    manifest: dict[str, Any],
    pairing_path: Path | None,
    pairing: dict[str, Any] | None,
) -> dict[str, Any]:
    requirements = manifest["pairing_requirements"]
    empty = {
        "required": requirements["required"],
        "provided": pairing is not None,
        "planned_pair_manifest_matched": requirements["planned_pair_manifest_ref"] is None,
        "same_experiment": False,
        "same_route_group": False,
        "same_action_boundary": False,
        "minimum_pair_count_met": not requirements["required"] and requirements["minimum_pair_count"] == 0,
        "pair_count": 0,
        "invalid_pair_count": 0,
        "recommendation": "not_provided",
        "recommendation_allowed": not requirements["required"],
    }
    if pairing is None:
        return empty

    planned_ref = requirements["planned_pair_manifest_ref"]
    planned_matched = True
    if planned_ref is not None:
        observed_ref = pairing.get("inputs", {}).get("pair_manifest_ref")
        planned_matched = (
            is_nonempty_string(observed_ref)
            and ref_matches(manifest_path, planned_ref, pairing_path, [observed_ref])
        )

    summary = pairing.get("summary", {})
    recommendation = pairing.get("recommendation")
    allowed = recommendation in manifest["success_criteria"]["allowed_pairing_recommendations"]
    if not requirements["required"] and recommendation == "not_provided":
        allowed = True
    same_experiment = pairing.get("experiment_id") == manifest["experiment_id"]
    same_route_group = pairing.get("route_group") == manifest["route_group"]
    same_action_boundary = pairing.get("action_boundary") == manifest["action_boundary"]
    pair_count = summary.get("pair_count", 0)
    invalid_pair_count = summary.get("invalid_pair_count", 0)
    minimum_met = (
        isinstance(pair_count, int)
        and pair_count >= requirements["minimum_pair_count"]
        and invalid_pair_count == 0
    )
    return {
        "required": requirements["required"],
        "provided": True,
        "planned_pair_manifest_matched": planned_matched,
        "same_experiment": same_experiment,
        "same_route_group": same_route_group,
        "same_action_boundary": same_action_boundary,
        "minimum_pair_count_met": minimum_met,
        "pair_count": pair_count if isinstance(pair_count, int) else 0,
        "invalid_pair_count": invalid_pair_count if isinstance(invalid_pair_count, int) else 0,
        "recommendation": recommendation if isinstance(recommendation, str) else "insufficient",
        "recommendation_allowed": allowed,
    }


def empty_outcome() -> dict[str, Any]:
    return {
        "entry_count": 0,
        "verified_positive_count": 0,
        "verified_negative_count": 0,
        "inconclusive_count": 0,
        "regression_count": 0,
        "calibration_signal": "insufficient",
    }


def outcome_summary_for_route(outcome: dict[str, Any] | None, route_group: str) -> dict[str, Any]:
    if outcome is None:
        return empty_outcome()
    counts = {"verified_positive": 0, "verified_negative": 0, "inconclusive": 0, "regression": 0}
    for entry in outcome.get("entries", []):
        if not isinstance(entry, dict) or entry.get("route_group") != route_group:
            continue
        result = entry.get("outcome")
        if result in counts:
            counts[result] += 1
    return {
        "entry_count": sum(counts.values()),
        "verified_positive_count": counts["verified_positive"],
        "verified_negative_count": counts["verified_negative"],
        "inconclusive_count": counts["inconclusive"],
        "regression_count": counts["regression"],
        "calibration_signal": OUTCOME_VALIDATOR.derive_signal(counts),
    }


def outcome_block(manifest: dict[str, Any], outcome: dict[str, Any] | None) -> dict[str, Any]:
    requirements = manifest["outcome_requirements"]
    summary = outcome_summary_for_route(outcome, manifest["route_group"])
    signal = summary["calibration_signal"]
    allowed = signal in manifest["success_criteria"]["allowed_outcome_signals"]
    if not requirements["required"] and outcome is None:
        allowed = True
    return {
        "required": requirements["required"],
        "provided": outcome is not None,
        "entry_count": summary["entry_count"],
        "minimum_entry_count_met": summary["entry_count"] >= requirements["minimum_entry_count"],
        "planned_outcome_ledger_matched": True,
        "calibration_signal": signal,
        "signal_allowed": allowed,
        "regression_count": summary["regression_count"],
    }


def build_report(
    manifest_path: Path,
    calibration_path: Path,
    baseline_path: Path | None,
    pairing_path: Path | None,
    outcome_path: Path | None,
) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    calibration = load_json(calibration_path)
    baseline = load_json(baseline_path) if baseline_path is not None else None
    pairing = load_json(pairing_path) if pairing_path is not None else None
    outcome = load_json(outcome_path) if outcome_path is not None else None

    errors = []
    errors.extend(f"manifest: {error}" for error in MANIFEST_VALIDATOR.validate_manifest(manifest))
    errors.extend(f"calibration: {error}" for error in CALIBRATION_VALIDATOR.validate_report(calibration))
    if baseline is not None:
        errors.extend(f"baseline: {error}" for error in BASELINE_VALIDATOR.validate_report(baseline))
    if pairing is not None:
        errors.extend(f"pairing: {error}" for error in PAIRING_VALIDATOR.validate_report(pairing))
    if outcome is not None:
        errors.extend(f"outcome: {error}" for error in OUTCOME_VALIDATOR.validate_ledger(outcome))
    if errors:
        raise ValueError("; ".join(errors))

    planned_inputs = manifest["inputs"]["planned_trace_inputs"]
    observed_inputs = calibration["inputs"]
    planned_inputs_matched = all(ref_matches(manifest_path, item, calibration_path, observed_inputs) for item in planned_inputs)

    target = target_summary(manifest, calibration)
    cohort = {
        "planned_minimum_trace_count": manifest["cohort_requirements"]["minimum_trace_count"],
        "observed_trace_count": target["trace_count"],
        "minimum_trace_count_met": target["trace_count"] >= manifest["cohort_requirements"]["minimum_trace_count"],
        "planned_minimum_candidate_files": manifest["cohort_requirements"]["minimum_candidate_files"],
        "observed_candidate_files": calibration["candidate_files"],
        "minimum_candidate_files_met": calibration["candidate_files"] >= manifest["cohort_requirements"]["minimum_candidate_files"],
        "planned_maximum_invalid_trace_files": manifest["cohort_requirements"]["maximum_invalid_trace_files"],
        "observed_invalid_trace_files": calibration["invalid_trace_files"],
        "invalid_trace_limit_met": calibration["invalid_trace_files"] <= manifest["cohort_requirements"]["maximum_invalid_trace_files"],
        "planned_inputs_matched": planned_inputs_matched,
    }
    baseline_part = baseline_summary(manifest, calibration, baseline)
    pairing_part = pairing_summary(manifest_path, manifest, pairing_path, pairing)
    outcome_part = outcome_block(manifest, outcome)
    planned_outcome_ref = manifest["inputs"].get("planned_outcome_ledger_ref")
    if planned_outcome_ref is not None and outcome_path is not None:
        outcome_part["planned_outcome_ledger_matched"] = ref_matches(
            manifest_path,
            planned_outcome_ref,
            outcome_path,
            [str(outcome_path)],
        )
    elif planned_outcome_ref is not None:
        outcome_part["planned_outcome_ledger_matched"] = False
    success = {
        "calibration_recommendation_allowed": target["recommendation"] in manifest["success_criteria"]["allowed_calibration_recommendations"],
        "baseline_recommendation_allowed": baseline_part["recommendation_allowed"],
        "pairing_recommendation_allowed": pairing_part["recommendation_allowed"],
        "outcome_signal_allowed": outcome_part["signal_allowed"],
        "metric_thresholds_met": target["metric_thresholds_met"],
    }
    stopping = {
        "block_recommendation": (
            manifest["stopping_rule"]["stop_on_block_recommendation"]
            and (calibration["recommendation"] == "block" or target["recommendation"] == "block")
        ),
        "baseline_preference": (
            manifest["stopping_rule"]["stop_on_baseline_preference"]
            and baseline_part["recommendation"] in {"prefer_baseline", "block_target"}
        ),
        "pairing_preference": (
            manifest["stopping_rule"]["stop_on_pairing_preference"]
            and pairing_part["recommendation"] in {"prefer_baseline", "block_target"}
        ),
        "outcome_regression": (
            manifest["stopping_rule"]["stop_on_outcome_regression"]
            and outcome_part["regression_count"] > 0
        ),
        "maximum_trace_count_reached": (
            isinstance(manifest["stopping_rule"]["maximum_trace_count"], int)
            and target["trace_count"] >= manifest["stopping_rule"]["maximum_trace_count"]
        ),
    }
    verdict = derive_verdict(manifest, cohort, target, baseline_part, pairing_part, outcome_part, success, stopping)

    return {
        "review_version": "1.0",
        "experiment_id": manifest["experiment_id"],
        "route_group": manifest["route_group"],
        "action_boundary": manifest["action_boundary"],
        "inputs": {
            "manifest_ref": str(manifest_path),
            "calibration_report_ref": str(calibration_path),
            "baseline_report_ref": str(baseline_path) if baseline_path is not None else None,
            "pairing_report_ref": str(pairing_path) if pairing_path is not None else None,
            "outcome_ledger_ref": str(outcome_path) if outcome_path is not None else None,
        },
        "cohort": cohort,
        "target_route": target,
        "baseline": baseline_part,
        "pairing": pairing_part,
        "outcome": outcome_part,
        "success": success,
        "stopping_flags": stopping,
        "review_verdict": verdict,
        "decision_reasons": decision_reasons(cohort, target, baseline_part, pairing_part, outcome_part, success, stopping, verdict),
        "required_next_steps": next_steps(verdict),
        "non_authorization": NON_AUTHORIZATION,
    }


def derive_verdict(
    manifest: dict[str, Any],
    cohort: dict[str, Any],
    target: dict[str, Any],
    baseline: dict[str, Any],
    pairing: dict[str, Any],
    outcome: dict[str, Any],
    success: dict[str, Any],
    stopping: dict[str, Any],
) -> str:
    plan_violations = [
        not cohort["planned_inputs_matched"],
        not target["present"],
        not cohort["invalid_trace_limit_met"],
        baseline["required"] and not baseline["provided"],
        baseline["required"] and len(baseline["present_route_groups"]) < len(baseline["required_route_groups"]),
        not baseline["same_action_boundary"],
        pairing["required"] and not pairing["provided"],
        not pairing["planned_pair_manifest_matched"],
        pairing["provided"] and not pairing["same_experiment"],
        pairing["provided"] and not pairing["same_route_group"],
        pairing["provided"] and not pairing["same_action_boundary"],
        outcome["required"] and not outcome["provided"],
        not outcome["planned_outcome_ledger_matched"],
    ]
    if any(plan_violations):
        return "plan_violation"
    if any(stopping.values()):
        return "stop_blocked"

    evidence_gaps = [
        not cohort["minimum_trace_count_met"],
        not cohort["minimum_candidate_files_met"],
        not baseline["minimum_trace_count_per_baseline_met"],
        not pairing["minimum_pair_count_met"],
        not outcome["minimum_entry_count_met"],
        not all(success.values()),
    ]
    if any(evidence_gaps):
        return "needs_more_evidence"
    return "supports_policy_review"


def decision_reasons(
    cohort: dict[str, Any],
    target: dict[str, Any],
    baseline: dict[str, Any],
    pairing: dict[str, Any],
    outcome: dict[str, Any],
    success: dict[str, Any],
    stopping: dict[str, Any],
    verdict: str,
) -> list[str]:
    reasons = [
        f"target route recommendation is {target['recommendation']}",
        f"baseline recommendation is {baseline['recommendation']}",
        f"pairing recommendation is {pairing['recommendation']}",
        f"outcome signal is {outcome['calibration_signal']}",
        f"derived experiment review verdict is {verdict}",
    ]
    if not cohort["planned_inputs_matched"]:
        reasons.append("calibration inputs do not match planned trace inputs")
    if not cohort["minimum_trace_count_met"]:
        reasons.append("target route does not meet the planned minimum trace count")
    if not cohort["invalid_trace_limit_met"]:
        reasons.append("invalid trace count exceeds the planned maximum")
    if not outcome["planned_outcome_ledger_matched"]:
        reasons.append("outcome ledger does not match the planned outcome ledger")
    if not pairing["planned_pair_manifest_matched"]:
        reasons.append("pairing report does not match the planned pair manifest")
    if pairing["provided"] and not pairing["same_experiment"]:
        reasons.append("pairing report experiment id differs from manifest")
    if pairing["provided"] and not pairing["same_route_group"]:
        reasons.append("pairing report route group differs from manifest")
    if pairing["provided"] and not pairing["same_action_boundary"]:
        reasons.append("pairing report action boundary differs from manifest")
    if not pairing["minimum_pair_count_met"]:
        reasons.append("pairing report does not meet the planned minimum pair count")
    for field, value in success.items():
        if not value:
            reasons.append(f"success criterion failed: {field}")
    for field, value in stopping.items():
        if value:
            reasons.append(f"stopping rule triggered: {field}")
    return reasons


def next_steps(verdict: str) -> list[str]:
    return {
        "supports_policy_review": ["use this review as evidence for a route policy report, subject to evidence-chain validation"],
        "needs_more_evidence": ["collect the missing traces, baseline comparisons, outcomes, or metric evidence before policy synthesis"],
        "stop_blocked": ["do not promote this route experiment into keep policy; investigate the triggered stopping rule"],
        "plan_violation": ["repair the experiment design or rerun the cohort under a valid manifest before policy synthesis"],
    }[verdict]


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_nullable_string(value: Any) -> bool:
    return value is None or isinstance(value, str)


def is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_nullable_number(value: Any) -> bool:
    return value is None or (
        isinstance(value, (int, float)) and not isinstance(value, bool)
    )


def is_string_list(value: Any, *, min_items: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(is_nonempty_string(item) for item in value)
    )


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


def validate_report(report: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["review must be an object"]

    validate_fields("review", report, TOP_LEVEL_FIELDS, errors)
    if report.get("review_version") != "1.0":
        errors.append("review_version must be 1.0")
    for field in ("experiment_id", "route_group", "action_boundary"):
        if not is_nonempty_string(report.get(field)):
            errors.append(f"{field} must be a non-empty string")

    inputs = validate_fields("inputs", report.get("inputs"), INPUT_FIELDS, errors)
    if inputs:
        for field in ("manifest_ref", "calibration_report_ref"):
            if not is_nonempty_string(inputs.get(field)):
                errors.append(f"inputs.{field} must be a non-empty string")
        for field in ("baseline_report_ref", "pairing_report_ref", "outcome_ledger_ref"):
            if not is_nullable_string(inputs.get(field)):
                errors.append(f"inputs.{field} must be a string or null")

    cohort = validate_fields("cohort", report.get("cohort"), COHORT_FIELDS, errors)
    if cohort:
        for field in (
            "planned_minimum_trace_count",
            "observed_trace_count",
            "planned_minimum_candidate_files",
            "observed_candidate_files",
            "planned_maximum_invalid_trace_files",
            "observed_invalid_trace_files",
        ):
            if not is_nonnegative_int(cohort.get(field)):
                errors.append(f"cohort.{field} must be a non-negative integer")
        for field in (
            "minimum_trace_count_met",
            "minimum_candidate_files_met",
            "invalid_trace_limit_met",
            "planned_inputs_matched",
        ):
            if not is_bool(cohort.get(field)):
                errors.append(f"cohort.{field} must be a boolean")
        if isinstance(cohort.get("observed_trace_count"), int) and isinstance(cohort.get("planned_minimum_trace_count"), int):
            if cohort["minimum_trace_count_met"] != (cohort["observed_trace_count"] >= cohort["planned_minimum_trace_count"]):
                errors.append("cohort.minimum_trace_count_met is inconsistent")
        if isinstance(cohort.get("observed_candidate_files"), int) and isinstance(cohort.get("planned_minimum_candidate_files"), int):
            if cohort["minimum_candidate_files_met"] != (cohort["observed_candidate_files"] >= cohort["planned_minimum_candidate_files"]):
                errors.append("cohort.minimum_candidate_files_met is inconsistent")
        if isinstance(cohort.get("observed_invalid_trace_files"), int) and isinstance(cohort.get("planned_maximum_invalid_trace_files"), int):
            if cohort["invalid_trace_limit_met"] != (cohort["observed_invalid_trace_files"] <= cohort["planned_maximum_invalid_trace_files"]):
                errors.append("cohort.invalid_trace_limit_met is inconsistent")

    target = validate_fields("target_route", report.get("target_route"), TARGET_FIELDS, errors)
    if target:
        if not is_bool(target.get("present")):
            errors.append("target_route.present must be a boolean")
        if not is_nullable_string(target.get("recommendation")):
            errors.append("target_route.recommendation must be a string or null")
        if not is_nonnegative_int(target.get("trace_count")):
            errors.append("target_route.trace_count must be a non-negative integer")
        for field in (
            "mean_evidence_score",
            "mean_closure_strength",
            "mean_risk_penalty",
            "mean_residuals_per_10k_tokens",
        ):
            if not is_nullable_number(target.get(field)):
                errors.append(f"target_route.{field} must be a number or null")
        if not is_bool(target.get("metric_thresholds_met")):
            errors.append("target_route.metric_thresholds_met must be a boolean")

    baseline = validate_fields("baseline", report.get("baseline"), BASELINE_FIELDS, errors)
    if baseline:
        for field in ("required", "provided", "same_action_boundary", "minimum_trace_count_per_baseline_met", "recommendation_allowed"):
            if not is_bool(baseline.get(field)):
                errors.append(f"baseline.{field} must be a boolean")
        for field in ("required_route_groups", "present_route_groups"):
            if not is_string_list(baseline.get(field)):
                errors.append(f"baseline.{field} must be an array of strings")
        if not is_nonempty_string(baseline.get("recommendation")):
            errors.append("baseline.recommendation must be a non-empty string")

    pairing = validate_fields("pairing", report.get("pairing"), PAIRING_FIELDS, errors)
    if pairing:
        for field in (
            "required",
            "provided",
            "planned_pair_manifest_matched",
            "same_experiment",
            "same_route_group",
            "same_action_boundary",
            "minimum_pair_count_met",
            "recommendation_allowed",
        ):
            if not is_bool(pairing.get(field)):
                errors.append(f"pairing.{field} must be a boolean")
        for field in ("pair_count", "invalid_pair_count"):
            if not is_nonnegative_int(pairing.get(field)):
                errors.append(f"pairing.{field} must be a non-negative integer")
        if not is_nonempty_string(pairing.get("recommendation")):
            errors.append("pairing.recommendation must be a non-empty string")

    outcome = validate_fields("outcome", report.get("outcome"), OUTCOME_FIELDS, errors)
    if outcome:
        for field in ("required", "provided", "minimum_entry_count_met", "planned_outcome_ledger_matched", "signal_allowed"):
            if not is_bool(outcome.get(field)):
                errors.append(f"outcome.{field} must be a boolean")
        for field in ("entry_count", "regression_count"):
            if not is_nonnegative_int(outcome.get(field)):
                errors.append(f"outcome.{field} must be a non-negative integer")
        if not is_nonempty_string(outcome.get("calibration_signal")):
            errors.append("outcome.calibration_signal must be a non-empty string")

    success = validate_fields("success", report.get("success"), SUCCESS_FIELDS, errors)
    if success:
        for field in SUCCESS_FIELDS:
            if not is_bool(success.get(field)):
                errors.append(f"success.{field} must be a boolean")

    stopping = validate_fields("stopping_flags", report.get("stopping_flags"), STOPPING_FIELDS, errors)
    if stopping:
        for field in STOPPING_FIELDS:
            if not is_bool(stopping.get(field)):
                errors.append(f"stopping_flags.{field} must be a boolean")

    if report.get("review_verdict") not in REVIEW_VERDICTS:
        errors.append("review_verdict is invalid")
    if not is_string_list(report.get("decision_reasons"), min_items=1):
        errors.append("decision_reasons must be a non-empty array of strings")
    if not is_string_list(report.get("required_next_steps"), min_items=1):
        errors.append("required_next_steps must be a non-empty array of strings")
    if report.get("non_authorization") != NON_AUTHORIZATION:
        errors.append("non_authorization text is invalid")

    if not errors:
        expected = derive_verdict(
            {"stopping_rule": {}},
            report["cohort"],
            report["target_route"],
            report["baseline"],
            report["pairing"],
            report["outcome"],
            report["success"],
            report["stopping_flags"],
        )
        if report.get("review_verdict") != expected:
            errors.append(f"review_verdict should be {expected}, got {report.get('review_verdict')}")

    return errors


def expected_review(review_path: Path, report: dict[str, Any]) -> dict[str, Any]:
    inputs = report["inputs"]
    manifest_path = resolve_ref(review_path, inputs["manifest_ref"])
    calibration_path = resolve_ref(review_path, inputs["calibration_report_ref"])
    baseline_path = resolve_ref(review_path, inputs.get("baseline_report_ref"))
    pairing_path = resolve_ref(review_path, inputs.get("pairing_report_ref"))
    outcome_path = resolve_ref(review_path, inputs.get("outcome_ledger_ref"))
    if manifest_path is None or calibration_path is None:
        raise ValueError("manifest_ref and calibration_report_ref must be local file references")
    if not manifest_path.exists():
        raise ValueError(f"route experiment manifest does not exist: {manifest_path}")
    if not calibration_path.exists():
        raise ValueError(f"route calibration report does not exist: {calibration_path}")
    if baseline_path is not None and not baseline_path.exists():
        raise ValueError(f"route baseline report does not exist: {baseline_path}")
    if pairing_path is not None and not pairing_path.exists():
        raise ValueError(f"route pairing report does not exist: {pairing_path}")
    if outcome_path is not None and not outcome_path.exists():
        raise ValueError(f"outcome ledger does not exist: {outcome_path}")
    expected = build_report(manifest_path, calibration_path, baseline_path, pairing_path, outcome_path)
    expected["inputs"] = {
        "manifest_ref": inputs["manifest_ref"],
        "calibration_report_ref": inputs["calibration_report_ref"],
        "baseline_report_ref": inputs.get("baseline_report_ref"),
        "pairing_report_ref": inputs.get("pairing_report_ref"),
        "outcome_ledger_ref": inputs.get("outcome_ledger_ref"),
    }
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a HIGHBALL route experiment review")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("calibration_report", type=Path)
    parser.add_argument("--baseline-report", type=Path)
    parser.add_argument("--pairing-report", type=Path)
    parser.add_argument("--outcome-ledger", type=Path)
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        report = build_report(
            args.manifest,
            args.calibration_report,
            args.baseline_report,
            args.pairing_report,
            args.outcome_ledger,
        )
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    print(json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
