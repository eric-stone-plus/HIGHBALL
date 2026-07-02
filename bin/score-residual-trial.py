#!/usr/bin/env python3
"""Score residual trial evidence without estimating truth probability."""

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


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def cost_from_manifest(trace: dict[str, Any]) -> dict[str, Any]:
    manifest = trace.get("trial_manifest")
    if not isinstance(manifest, dict):
        return {
            "total_tokens": None,
            "wall_time_seconds": None,
            "tool_calls": None,
            "human_minutes": None,
        }
    cost = manifest.get("cost")
    if not isinstance(cost, dict):
        return {
            "total_tokens": None,
            "wall_time_seconds": None,
            "tool_calls": None,
            "human_minutes": None,
        }
    return {
        "total_tokens": cost.get("total_tokens"),
        "wall_time_seconds": cost.get("wall_time_seconds"),
        "tool_calls": cost.get("tool_calls"),
        "human_minutes": cost.get("human_minutes"),
    }


def numeric(value: Any) -> float | None:
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    return None


def score_trace(trace: dict[str, Any]) -> dict[str, Any]:
    measurement = MEASURE.measure_trace(trace)
    residual_count = measurement["residual_count"]
    action_blocking_count = measurement["action_blocking_count"]
    high_risk_count = measurement["high_risk_count"]
    open_high_risk_count = measurement["open_high_risk_count"]
    unsupported_high_risk_count = measurement["unsupported_high_risk_closure_count"]
    silent_collapse_count = measurement["silent_collapse_count"]

    evidence_coverage = measurement["evidence_coverage"]
    if evidence_coverage is None:
        evidence_coverage = 0.0

    closure_coverage = measurement["action_blocking_closure_coverage"]
    if closure_coverage is None:
        closure_coverage = 1.0 if action_blocking_count == 0 else 0.0

    manifest_present = measurement["trial_manifest_present"]
    independent_ratio = ratio(
        measurement["independent_first_pass_count"],
        measurement["perspective_count"],
    )
    perturbation_strength = clamp(measurement["perturbation_axis_count"] / 3)
    independence_control_strength = clamp(measurement["independence_control_count"] / 3)

    relation = measurement["base_model_relation"]
    relation_weight = {
        "heterogeneous_models": 1.0,
        "mixed": 0.8,
        "human": 0.8,
        "direct_evidence": 0.8,
        "same_family": 0.45,
        "same_model": 0.35,
        "unknown": 0.25,
        None: 0.0,
    }.get(relation, 0.0)

    manifest_strength = 0.0
    if manifest_present:
        manifest_strength = clamp(
            0.35 * independent_ratio
            + 0.25 * perturbation_strength
            + 0.25 * independence_control_strength
            + 0.15 * relation_weight
        )

    residual_yield = clamp(
        0.35 * min(residual_count, 5) / 5
        + 0.30 * min(action_blocking_count, 3) / 3
        + 0.20 * min(high_risk_count, 3) / 3
        + 0.15 * evidence_coverage
    )

    closure_strength = clamp(closure_coverage)

    risk_penalty = clamp(
        0.45 * min(open_high_risk_count, 3) / 3
        + 0.35 * min(unsupported_high_risk_count, 3) / 3
        + 0.20 * min(silent_collapse_count, 3) / 3
    )

    evidence_score = clamp(
        0.40 * residual_yield
        + 0.25 * closure_strength
        + 0.25 * manifest_strength
        + 0.10 * evidence_coverage
        - 0.45 * risk_penalty
    )

    cost = cost_from_manifest(trace)
    token_cost = numeric(cost["total_tokens"])
    if token_cost and token_cost > 0:
        residuals_per_10k_tokens = round(residual_count / (token_cost / 10000), 4)
        action_blocking_per_10k_tokens = round(action_blocking_count / (token_cost / 10000), 4)
    else:
        residuals_per_10k_tokens = None
        action_blocking_per_10k_tokens = None

    if measurement["quality_gate"] == "block":
        recommendation = "block"
    elif evidence_score >= 0.7 and measurement["quality_gate"] == "pass":
        recommendation = "adopt"
    elif evidence_score >= 0.45:
        recommendation = "review"
    else:
        recommendation = "reroute"

    caveats: list[str] = []
    if measurement["same_model_flag"]:
        caveats.append("same-model or same-family evidence is stability evidence, not independent confirmation")
    if not manifest_present:
        caveats.append("trial manifest missing; perturbation conditions are not inspectable")
    if token_cost is None:
        caveats.append("token cost missing; cannot compare residual yield against baselines")
    if residual_count == 0:
        caveats.append("no residuals were preserved; low yield is not proof of safety")
    if risk_penalty > 0:
        caveats.append("open, unsupported, or silent-collapse risk reduces evidential value")

    return {
        "question": measurement["question"],
        "instrument": measurement["instrument"],
        "action_boundary": measurement["action_boundary"],
        "quality_gate": measurement["quality_gate"],
        "evidence_score": round(evidence_score, 4),
        "recommendation": recommendation,
        "residual_yield": round(residual_yield, 4),
        "closure_strength": round(closure_strength, 4),
        "manifest_strength": round(manifest_strength, 4),
        "risk_penalty": round(risk_penalty, 4),
        "residual_count": residual_count,
        "action_blocking_count": action_blocking_count,
        "high_risk_count": high_risk_count,
        "residuals_per_10k_tokens": residuals_per_10k_tokens,
        "action_blocking_per_10k_tokens": action_blocking_per_10k_tokens,
        "base_model_relation": relation,
        "caveats": caveats,
    }


def combine(scores: list[dict[str, Any]]) -> dict[str, Any]:
    recommendations = {item["recommendation"] for item in scores}
    if "block" in recommendations:
        recommendation = "block"
    elif "reroute" in recommendations:
        recommendation = "reroute"
    elif "review" in recommendations:
        recommendation = "review"
    else:
        recommendation = "adopt"

    return {
        "trace_count": len(scores),
        "mean_evidence_score": round(sum(item["evidence_score"] for item in scores) / len(scores), 4) if scores else None,
        "recommendation": recommendation,
        "residual_count": sum(item["residual_count"] for item in scores),
        "action_blocking_count": sum(item["action_blocking_count"] for item in scores),
        "scores": scores,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score residual trial evidence")
    parser.add_argument("trace_file", type=Path)
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        traces = MEASURE.load_traces(args.trace_file)
    except (OSError, ValueError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    result = combine([score_trace(trace) for trace in traces])
    indent = 2 if args.pretty else None
    print(json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
