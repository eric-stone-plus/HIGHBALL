#!/usr/bin/env python3
"""Validate HIGHBALL route experiment manifests."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


NON_AUTHORIZATION = "Route experiment manifests do not authorize action, dispatch agents, or modify routing rules."

TOP_LEVEL_FIELDS = {
    "manifest_version",
    "experiment_id",
    "objective",
    "route_group",
    "action_boundary",
    "inputs",
    "cohort_requirements",
    "baseline_requirements",
    "pairing_requirements",
    "outcome_requirements",
    "success_criteria",
    "stopping_rule",
    "required_gates",
    "status",
    "non_authorization",
}
INPUT_FIELDS = {
    "planned_trace_inputs",
    "planned_outcome_ledger_ref",
}
COHORT_FIELDS = {
    "minimum_trace_count",
    "minimum_candidate_files",
    "maximum_invalid_trace_files",
}
BASELINE_FIELDS = {
    "required",
    "baseline_route_groups",
    "minimum_trace_count_per_baseline",
    "same_action_boundary",
}
PAIRING_FIELDS = {
    "required",
    "planned_pair_manifest_ref",
    "minimum_pair_count",
}
OUTCOME_FIELDS = {
    "required",
    "minimum_entry_count",
}
CRITERIA_FIELDS = {
    "minimum_mean_evidence_score",
    "minimum_mean_closure_strength",
    "maximum_mean_risk_penalty",
    "minimum_mean_residuals_per_10k_tokens",
    "allowed_calibration_recommendations",
    "allowed_baseline_recommendations",
    "allowed_pairing_recommendations",
    "allowed_outcome_signals",
}
STOPPING_FIELDS = {
    "stop_on_block_recommendation",
    "stop_on_baseline_preference",
    "stop_on_pairing_preference",
    "stop_on_outcome_regression",
    "maximum_trace_count",
}

ACTION_BOUNDARIES = {"none", "reversible", "protected_write", "irreversible"}
CALIBRATION_RECOMMENDATIONS = {"adopt", "review", "reroute", "block"}
BASELINE_RECOMMENDATIONS = {"prefer_target", "prefer_baseline", "block_target", "watch", "insufficient"}
PAIRING_RECOMMENDATIONS = {
    "prefer_target",
    "prefer_baseline",
    "block_target",
    "block_baseline",
    "watch",
    "insufficient",
}
OUTCOME_SIGNALS = {"supports_route", "weakens_route", "mixed", "insufficient"}
STATUSES = {"planned", "active", "closed", "superseded"}


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


def load_manifest(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    blocks, raw_json_mode = candidate_blocks(text, path)
    if not blocks:
        raise ValueError("no JSON route experiment manifest found")

    manifests: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            errors.append(f"{label} is invalid JSON: {exc.msg}")
            continue
        if isinstance(parsed, dict) and parsed.get("manifest_version") == "1.0":
            manifests.append(parsed)

    if len(manifests) != 1:
        detail = "; ".join(errors) if errors else f"found {len(manifests)} route experiment manifests"
        raise ValueError(f"expected exactly one route experiment manifest; {detail}")
    return manifests[0]


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_nullable_string(value: Any) -> bool:
    return value is None or isinstance(value, str)


def is_string_list(value: Any, *, min_items: int = 0, allowed: set[str] | None = None) -> bool:
    if not (
        isinstance(value, list)
        and len(value) >= min_items
        and all(is_nonempty_string(item) for item in value)
    ):
        return False
    if allowed is not None and any(item not in allowed for item in value):
        return False
    return True


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def is_nullable_positive_int(value: Any) -> bool:
    return value is None or is_positive_int(value)


def is_nullable_nonnegative_number(value: Any) -> bool:
    return value is None or (
        isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
    )


def is_nullable_unit_number(value: Any) -> bool:
    return value is None or (
        isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1
    )


def route_boundary(route_group: str) -> str | None:
    parts = route_group.split(":")
    if len(parts) != 3:
        return None
    return parts[2]


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


def validate_manifest(manifest: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be an object"]

    validate_fields("manifest", manifest, TOP_LEVEL_FIELDS, errors)
    if manifest.get("manifest_version") != "1.0":
        errors.append("manifest_version must be 1.0")

    for field in ("experiment_id", "objective", "route_group"):
        if not is_nonempty_string(manifest.get(field)):
            errors.append(f"{field} must be a non-empty string")

    action_boundary = manifest.get("action_boundary")
    route_group = manifest.get("route_group")
    if action_boundary not in ACTION_BOUNDARIES:
        errors.append("action_boundary is invalid")
    if isinstance(route_group, str):
        boundary = route_boundary(route_group)
        if boundary is None:
            errors.append("route_group must use instrument:base_model_relation:action_boundary")
        elif action_boundary in ACTION_BOUNDARIES and boundary != action_boundary:
            errors.append("route_group action boundary differs from action_boundary")

    inputs = validate_fields("inputs", manifest.get("inputs"), INPUT_FIELDS, errors)
    if inputs:
        if not is_string_list(inputs.get("planned_trace_inputs"), min_items=1):
            errors.append("inputs.planned_trace_inputs must be a non-empty array of strings")
        if not is_nullable_string(inputs.get("planned_outcome_ledger_ref")):
            errors.append("inputs.planned_outcome_ledger_ref must be a string or null")

    cohort = validate_fields("cohort_requirements", manifest.get("cohort_requirements"), COHORT_FIELDS, errors)
    if cohort:
        if not is_positive_int(cohort.get("minimum_trace_count")):
            errors.append("cohort_requirements.minimum_trace_count must be a positive integer")
        if not is_nonnegative_int(cohort.get("minimum_candidate_files")):
            errors.append("cohort_requirements.minimum_candidate_files must be a non-negative integer")
        if not is_nonnegative_int(cohort.get("maximum_invalid_trace_files")):
            errors.append("cohort_requirements.maximum_invalid_trace_files must be a non-negative integer")

    baseline = validate_fields("baseline_requirements", manifest.get("baseline_requirements"), BASELINE_FIELDS, errors)
    if baseline:
        if not isinstance(baseline.get("required"), bool):
            errors.append("baseline_requirements.required must be a boolean")
        if not is_string_list(baseline.get("baseline_route_groups")):
            errors.append("baseline_requirements.baseline_route_groups must be an array of strings")
        elif baseline.get("required") is True and len(baseline.get("baseline_route_groups", [])) == 0:
            errors.append("baseline_requirements.baseline_route_groups must be non-empty when required is true")
        if not is_nonnegative_int(baseline.get("minimum_trace_count_per_baseline")):
            errors.append("baseline_requirements.minimum_trace_count_per_baseline must be a non-negative integer")
        if baseline.get("same_action_boundary") is not True:
            errors.append("baseline_requirements.same_action_boundary must be true")
        if action_boundary in ACTION_BOUNDARIES and isinstance(baseline.get("baseline_route_groups"), list):
            for item in baseline["baseline_route_groups"]:
                if isinstance(item, str) and route_boundary(item) != action_boundary:
                    errors.append(f"baseline route group action boundary differs from action_boundary: {item}")

    pairing = validate_fields("pairing_requirements", manifest.get("pairing_requirements"), PAIRING_FIELDS, errors)
    if pairing:
        if not isinstance(pairing.get("required"), bool):
            errors.append("pairing_requirements.required must be a boolean")
        if pairing.get("planned_pair_manifest_ref") is not None and not is_nonempty_string(pairing.get("planned_pair_manifest_ref")):
            errors.append("pairing_requirements.planned_pair_manifest_ref must be a non-empty string or null")
        if pairing.get("required") is True and not is_nonempty_string(pairing.get("planned_pair_manifest_ref")):
            errors.append("pairing_requirements.planned_pair_manifest_ref must be provided when required is true")
        if not is_nonnegative_int(pairing.get("minimum_pair_count")):
            errors.append("pairing_requirements.minimum_pair_count must be a non-negative integer")
        elif pairing.get("required") is True and pairing.get("minimum_pair_count") == 0:
            errors.append("pairing_requirements.minimum_pair_count must be positive when required is true")

    outcome = validate_fields("outcome_requirements", manifest.get("outcome_requirements"), OUTCOME_FIELDS, errors)
    if outcome:
        if not isinstance(outcome.get("required"), bool):
            errors.append("outcome_requirements.required must be a boolean")
        if not is_nonnegative_int(outcome.get("minimum_entry_count")):
            errors.append("outcome_requirements.minimum_entry_count must be a non-negative integer")
        elif outcome.get("required") is True and outcome.get("minimum_entry_count") == 0:
            errors.append("outcome_requirements.minimum_entry_count must be positive when required is true")

    criteria = validate_fields("success_criteria", manifest.get("success_criteria"), CRITERIA_FIELDS, errors)
    if criteria:
        for field in (
            "minimum_mean_evidence_score",
            "minimum_mean_closure_strength",
            "maximum_mean_risk_penalty",
        ):
            if not is_nullable_unit_number(criteria.get(field)):
                errors.append(f"success_criteria.{field} must be a number from 0 to 1 or null")
        if not is_nullable_nonnegative_number(criteria.get("minimum_mean_residuals_per_10k_tokens")):
            errors.append("success_criteria.minimum_mean_residuals_per_10k_tokens must be a non-negative number or null")
        if not is_string_list(
            criteria.get("allowed_calibration_recommendations"),
            min_items=1,
            allowed=CALIBRATION_RECOMMENDATIONS,
        ):
            errors.append("success_criteria.allowed_calibration_recommendations is invalid")
        if not is_string_list(
            criteria.get("allowed_baseline_recommendations"),
            min_items=1,
            allowed=BASELINE_RECOMMENDATIONS,
        ):
            errors.append("success_criteria.allowed_baseline_recommendations is invalid")
        if not is_string_list(
            criteria.get("allowed_pairing_recommendations"),
            min_items=1,
            allowed=PAIRING_RECOMMENDATIONS,
        ):
            errors.append("success_criteria.allowed_pairing_recommendations is invalid")
        if not is_string_list(
            criteria.get("allowed_outcome_signals"),
            min_items=1,
            allowed=OUTCOME_SIGNALS,
        ):
            errors.append("success_criteria.allowed_outcome_signals is invalid")

    stopping = validate_fields("stopping_rule", manifest.get("stopping_rule"), STOPPING_FIELDS, errors)
    if stopping:
        for field in (
            "stop_on_block_recommendation",
            "stop_on_baseline_preference",
            "stop_on_pairing_preference",
            "stop_on_outcome_regression",
        ):
            if not isinstance(stopping.get(field), bool):
                errors.append(f"stopping_rule.{field} must be a boolean")
        if not is_nullable_positive_int(stopping.get("maximum_trace_count")):
            errors.append("stopping_rule.maximum_trace_count must be a positive integer or null")
        elif (
            isinstance(stopping.get("maximum_trace_count"), int)
            and isinstance(cohort.get("minimum_trace_count"), int)
            and stopping["maximum_trace_count"] < cohort["minimum_trace_count"]
        ):
            errors.append("stopping_rule.maximum_trace_count cannot be lower than minimum_trace_count")

    if not is_string_list(manifest.get("required_gates"), min_items=1):
        errors.append("required_gates must be a non-empty array of strings")
    if manifest.get("status") not in STATUSES:
        errors.append("status is invalid")
    if manifest.get("non_authorization") != NON_AUTHORIZATION:
        errors.append("non_authorization text is invalid")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL route experiment manifest")
    parser.add_argument("manifest_file", type=Path)
    args = parser.parse_args()

    try:
        manifest = load_manifest(args.manifest_file)
    except (OSError, ValueError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    errors = validate_manifest(manifest)
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    print("[HIGHBALL] route experiment manifest valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
