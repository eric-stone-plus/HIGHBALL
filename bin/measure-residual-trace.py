#!/usr/bin/env python3
"""Measure residual trace quality without asserting truth probability."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


HIGH_RISK_SEVERITIES = {"HIGH", "CRITICAL", "P0"}
SUPPORTING_STATES = {"closed", "blocked", "waived", "not_applicable"}
STRICT_BOUNDARIES = {"protected_write", "irreversible"}
WEAK_MODEL_RELATIONS = {"same_model", "same_family"}


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


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def nonempty_list_string(value: Any) -> bool:
    return isinstance(value, list) and any(isinstance(item, str) and item.strip() for item in value)


def ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def is_high_risk(residual: dict[str, Any]) -> bool:
    return residual.get("severity") in HIGH_RISK_SEVERITIES


def is_action_blocking(residual: dict[str, Any]) -> bool:
    return (
        is_high_risk(residual)
        or residual.get("required_closure") not in {None, "none"}
        or residual.get("disposition") == "escalated"
    )


def has_supported_closure(residual: dict[str, Any]) -> bool:
    state = residual.get("closure_state")
    if state not in SUPPORTING_STATES:
        return False
    return nonempty_list_string(residual.get("closure_evidence")) and nonempty_string(residual.get("scope"))


def measure_manifest(trace: dict[str, Any]) -> dict[str, Any]:
    manifest = trace.get("trial_manifest")
    if not isinstance(manifest, dict):
        return {
            "trial_manifest_present": False,
            "base_model_relation": None,
            "perspective_count": 0,
            "independent_first_pass_count": 0,
            "perturbation_axis_count": 0,
            "independence_control_count": 0,
            "contamination_risk_count": 0,
            "same_model_flag": False,
            "cost_fields_present": False,
        }

    perspectives = [
        item for item in manifest.get("perspectives", [])
        if isinstance(item, dict)
    ]
    cost = manifest.get("cost")
    cost_fields_present = (
        isinstance(cost, dict)
        and all(field in cost for field in ("total_tokens", "wall_time_seconds", "tool_calls", "human_minutes"))
    )
    base_model_relation = manifest.get("base_model_relation")

    return {
        "trial_manifest_present": True,
        "base_model_relation": base_model_relation,
        "perspective_count": manifest.get("perspective_count") if isinstance(manifest.get("perspective_count"), int) else len(perspectives),
        "independent_first_pass_count": sum(1 for item in perspectives if item.get("independent_first_pass") is True),
        "perturbation_axis_count": len(manifest.get("perturbation_axes", [])) if isinstance(manifest.get("perturbation_axes"), list) else 0,
        "independence_control_count": len(manifest.get("independence_controls", [])) if isinstance(manifest.get("independence_controls"), list) else 0,
        "contamination_risk_count": len(manifest.get("contamination_risks", [])) if isinstance(manifest.get("contamination_risks"), list) else 0,
        "same_model_flag": base_model_relation in WEAK_MODEL_RELATIONS,
        "cost_fields_present": cost_fields_present,
    }


def measure_trace(trace: dict[str, Any]) -> dict[str, Any]:
    residuals = [item for item in trace.get("residuals", []) if isinstance(item, dict)]
    action_boundary = trace.get("action_boundary")
    highball_decision = trace.get("highball_decision")
    manifest_metrics = measure_manifest(trace)

    residual_count = len(residuals)
    evidence_count = sum(1 for item in residuals if nonempty_string(item.get("evidence")))
    closure_evidence_count = sum(1 for item in residuals if nonempty_list_string(item.get("closure_evidence")))
    high_risk = [item for item in residuals if is_high_risk(item)]
    action_blocking = [item for item in residuals if is_action_blocking(item)]

    open_high_risk = [item for item in high_risk if item.get("closure_state") == "open"]
    unsupported_high_risk = [
        item for item in high_risk
        if item.get("closure_state") in SUPPORTING_STATES and not has_supported_closure(item)
    ]
    action_blocking_supported = [item for item in action_blocking if has_supported_closure(item)]
    silent_collapse = [item for item in residuals if item.get("type") == "silent_collapse"]
    unresolved = [
        item for item in residuals
        if item.get("disposition") in {"unresolved", "escalated"} or item.get("closure_state") == "open"
    ]

    decision_conflicts = 0
    if action_boundary in STRICT_BOUNDARIES and highball_decision == "pass":
        if open_high_risk:
            decision_conflicts += 1
        if unsupported_high_risk:
            decision_conflicts += 1

    warnings: list[str] = []
    if action_boundary in STRICT_BOUNDARIES and residual_count == 0:
        warnings.append("strict action boundary has an empty residual set")
    if residual_count and evidence_count < residual_count:
        warnings.append("one or more residuals lack evidence")
    if action_blocking and len(action_blocking_supported) < len(action_blocking):
        warnings.append("one or more action-blocking residuals lack supported closure")
    if silent_collapse:
        warnings.append("silent-collapse residuals require external anchoring or review")
    if action_boundary in STRICT_BOUNDARIES and not manifest_metrics["trial_manifest_present"]:
        warnings.append("strict action boundary lacks trial manifest")
    if manifest_metrics["trial_manifest_present"]:
        if manifest_metrics["perspective_count"] != manifest_metrics["independent_first_pass_count"]:
            warnings.append("one or more perspectives lack independent first pass")
        if manifest_metrics["perturbation_axis_count"] == 0:
            warnings.append("trial manifest has no perturbation axes")
        if manifest_metrics["same_model_flag"]:
            warnings.append("same-model or same-family trace is stability evidence, not independent confirmation")
        if not manifest_metrics["cost_fields_present"]:
            warnings.append("trial manifest lacks complete cost fields")

    quality_gate = "pass"
    if action_boundary in STRICT_BOUNDARIES and (open_high_risk or unsupported_high_risk or decision_conflicts):
        quality_gate = "block"
    elif warnings or unresolved:
        quality_gate = "review"

    return {
        "question": trace.get("question"),
        "instrument": trace.get("instrument"),
        "action_boundary": action_boundary,
        "highball_decision": highball_decision,
        "residual_count": residual_count,
        "high_risk_count": len(high_risk),
        "action_blocking_count": len(action_blocking),
        "open_high_risk_count": len(open_high_risk),
        "unsupported_high_risk_closure_count": len(unsupported_high_risk),
        "silent_collapse_count": len(silent_collapse),
        "unresolved_count": len(unresolved),
        "decision_conflict_count": decision_conflicts,
        "evidence_coverage": ratio(evidence_count, residual_count),
        "closure_evidence_coverage": ratio(closure_evidence_count, residual_count),
        "action_blocking_closure_coverage": ratio(len(action_blocking_supported), len(action_blocking)),
        **manifest_metrics,
        "quality_gate": quality_gate,
        "warnings": warnings,
    }


def combine(measurements: list[dict[str, Any]]) -> dict[str, Any]:
    gates = {item["quality_gate"] for item in measurements}
    if "block" in gates:
        aggregate_gate = "block"
    elif "review" in gates:
        aggregate_gate = "review"
    else:
        aggregate_gate = "pass"

    return {
        "trace_count": len(measurements),
        "residual_count": sum(item["residual_count"] for item in measurements),
        "high_risk_count": sum(item["high_risk_count"] for item in measurements),
        "action_blocking_count": sum(item["action_blocking_count"] for item in measurements),
        "open_high_risk_count": sum(item["open_high_risk_count"] for item in measurements),
        "unsupported_high_risk_closure_count": sum(item["unsupported_high_risk_closure_count"] for item in measurements),
        "silent_collapse_count": sum(item["silent_collapse_count"] for item in measurements),
        "unresolved_count": sum(item["unresolved_count"] for item in measurements),
        "decision_conflict_count": sum(item["decision_conflict_count"] for item in measurements),
        "traces_with_manifest": sum(1 for item in measurements if item["trial_manifest_present"]),
        "same_model_trace_count": sum(1 for item in measurements if item["same_model_flag"]),
        "quality_gate": aggregate_gate,
        "traces": measurements,
    }


def load_traces(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    blocks, raw_json_mode = candidate_blocks(text, path)
    if not blocks:
        raise ValueError("no JSON residual trace block found")

    traces: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            errors.append(f"{label} is invalid JSON: {exc.msg}")
            continue

        if isinstance(parsed, dict) and isinstance(parsed.get("residuals"), list):
            traces.append(parsed)

    if not traces:
        detail = "; ".join(errors) if errors else "no residuals array found"
        raise ValueError(detail)

    return traces


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure residual trace quality metrics")
    parser.add_argument("trace_file", type=Path)
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        traces = load_traces(args.trace_file)
    except (OSError, ValueError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    result = combine([measure_trace(trace) for trace in traces])
    indent = 2 if args.pretty else None
    print(json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
