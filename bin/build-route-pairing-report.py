#!/usr/bin/env python3
"""Build and validate paired route comparison reports."""

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
SCORER = load_module("score_residual_trial", ROOT / "bin" / "score-residual-trial.py")
MEASURE = load_module("measure_residual_trace", ROOT / "bin" / "measure-residual-trace.py")
TRACE_VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")


NON_AUTHORIZATION = "Route pairing reports do not authorize action, dispatch agents, or modify routing rules."

TOP_LEVEL_FIELDS = {
    "pairing_report_version",
    "experiment_id",
    "route_group",
    "baseline_route_group",
    "action_boundary",
    "inputs",
    "pairs",
    "summary",
    "recommendation",
    "non_authorization",
}
INPUT_FIELDS = {"pair_manifest_ref"}
PAIR_MANIFEST_FIELDS = {
    "pair_manifest_version",
    "experiment_id",
    "route_group",
    "baseline_route_group",
    "action_boundary",
    "minimum_pair_count",
    "pairs",
    "non_authorization",
}
PAIR_INPUT_FIELDS = {"id", "question", "target_trace_ref", "baseline_trace_ref"}
PAIR_FIELDS = {
    "id",
    "question",
    "target_trace_ref",
    "baseline_trace_ref",
    "target",
    "baseline",
    "deltas",
    "verdict",
    "reasons",
}
SCORE_FIELDS = {
    "route_group",
    "instrument",
    "base_model_relation",
    "action_boundary",
    "quality_gate",
    "recommendation",
    "evidence_score",
    "residual_count",
    "action_blocking_count",
    "risk_penalty",
    "residuals_per_10k_tokens",
}
DELTA_FIELDS = {
    "evidence_score",
    "residual_count",
    "action_blocking_count",
    "risk_penalty",
    "residuals_per_10k_tokens",
}
SUMMARY_FIELDS = {
    "pair_count",
    "target_preferred_count",
    "baseline_preferred_count",
    "target_blocked_count",
    "baseline_blocked_count",
    "watch_count",
    "invalid_pair_count",
    "minimum_pair_count",
    "minimum_pair_count_met",
}
RECOMMENDATIONS = {"prefer_target", "prefer_baseline", "block_target", "block_baseline", "watch", "insufficient"}
PAIR_VERDICTS = {"target_preferred", "baseline_preferred", "target_blocked", "baseline_blocked", "watch", "invalid"}


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


def route_group_from_score(score: dict[str, Any]) -> str:
    instrument = score.get("instrument") or "unknown"
    relation = score.get("base_model_relation") or "unknown"
    boundary = score.get("action_boundary") or "unknown"
    return f"{instrument}:{relation}:{boundary}"


def route_boundary(route_group: str) -> str:
    parts = route_group.split(":")
    if len(parts) != 3:
        return "unknown"
    return parts[2]


def route_group_is_well_formed(route_group: str) -> bool:
    parts = route_group.split(":")
    return len(parts) == 3 and all(part.strip() for part in parts)


def validate_trace(path: Path) -> dict[str, Any]:
    traces = MEASURE.load_traces(path)
    if len(traces) != 1:
        raise ValueError(f"{path} must contain exactly one residual trace")
    trace = traces[0]
    findings = TRACE_VALIDATOR.validate_trace(trace, 1)
    errors = [str(finding) for finding in findings if finding.severity == "ERROR"]
    if errors:
        raise ValueError(f"{path}: {'; '.join(errors)}")
    return trace


def score_trace(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    trace = validate_trace(path)
    score = SCORER.score_trace(trace)
    summary = {
        "route_group": route_group_from_score(score),
        "instrument": score["instrument"],
        "base_model_relation": score["base_model_relation"],
        "action_boundary": score["action_boundary"],
        "quality_gate": score["quality_gate"],
        "recommendation": score["recommendation"],
        "evidence_score": score["evidence_score"],
        "residual_count": score["residual_count"],
        "action_blocking_count": score["action_blocking_count"],
        "risk_penalty": score["risk_penalty"],
        "residuals_per_10k_tokens": score["residuals_per_10k_tokens"],
    }
    return trace, summary


def numeric_delta(target: Any, baseline: Any) -> float | None:
    if isinstance(target, (int, float)) and isinstance(baseline, (int, float)):
        return round(float(target) - float(baseline), 4)
    return None


def compute_deltas(target: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_score": numeric_delta(target.get("evidence_score"), baseline.get("evidence_score")),
        "residual_count": numeric_delta(target.get("residual_count"), baseline.get("residual_count")),
        "action_blocking_count": numeric_delta(target.get("action_blocking_count"), baseline.get("action_blocking_count")),
        "risk_penalty": numeric_delta(target.get("risk_penalty"), baseline.get("risk_penalty")),
        "residuals_per_10k_tokens": numeric_delta(target.get("residuals_per_10k_tokens"), baseline.get("residuals_per_10k_tokens")),
    }


def compare_pair(target: dict[str, Any], baseline: dict[str, Any], deltas: dict[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if target["quality_gate"] == "block":
        return "target_blocked", ["target route trace is blocked"]
    if baseline["quality_gate"] == "block":
        return "baseline_blocked", ["baseline route trace is blocked"]

    score_delta = deltas["evidence_score"]
    risk_delta = deltas["risk_penalty"]
    cost_delta = deltas["residuals_per_10k_tokens"]
    if score_delta is None or risk_delta is None:
        return "watch", ["pair lacks comparable score or risk metrics"]

    reasons.append(f"target evidence score delta is {score_delta}")
    reasons.append(f"target risk penalty delta is {risk_delta}")
    if cost_delta is not None:
        reasons.append(f"target residual yield per 10k tokens delta is {cost_delta}")

    target_win = score_delta >= 0.05 and risk_delta <= 0.05
    baseline_win = score_delta <= -0.05 or risk_delta >= 0.10
    if cost_delta is not None and cost_delta < -0.10 and score_delta < 0.05:
        baseline_win = True
        reasons.append("target has lower residual yield per token without a compensating score gain")
    elif cost_delta is not None and cost_delta > 0.10 and risk_delta <= 0.05:
        target_win = True
        reasons.append("target has higher residual yield per token without higher risk")

    if target_win and not baseline_win:
        return "target_preferred", reasons
    if baseline_win and not target_win:
        return "baseline_preferred", reasons
    return "watch", reasons + ["paired signals are mixed or too close to prefer one route"]


def build_pair(base_file: Path, manifest: dict[str, Any], pair: dict[str, Any]) -> dict[str, Any]:
    target_path = resolve_ref(base_file, pair["target_trace_ref"])
    baseline_path = resolve_ref(base_file, pair["baseline_trace_ref"])
    if target_path is None or baseline_path is None:
        return invalid_pair(pair, "trace refs must be local files")
    try:
        target_trace, target_score = score_trace(target_path)
        baseline_trace, baseline_score = score_trace(baseline_path)
    except (OSError, ValueError) as exc:
        return invalid_pair(pair, str(exc))

    errors: list[str] = []
    expected_question = pair["question"]
    if target_trace.get("question") != expected_question:
        errors.append("target trace question differs from pair question")
    if baseline_trace.get("question") != expected_question:
        errors.append("baseline trace question differs from pair question")
    if target_score["action_boundary"] != manifest["action_boundary"]:
        errors.append("target trace action boundary differs from manifest")
    if baseline_score["action_boundary"] != manifest["action_boundary"]:
        errors.append("baseline trace action boundary differs from manifest")
    if target_score["route_group"] != manifest["route_group"]:
        errors.append("target trace route group differs from manifest")
    if baseline_score["route_group"] != manifest["baseline_route_group"]:
        errors.append("baseline trace route group differs from manifest")
    if errors:
        return invalid_pair(pair, "; ".join(errors), target_score, baseline_score)

    deltas = compute_deltas(target_score, baseline_score)
    verdict, reasons = compare_pair(target_score, baseline_score, deltas)
    return {
        "id": pair["id"],
        "question": pair["question"],
        "target_trace_ref": pair["target_trace_ref"],
        "baseline_trace_ref": pair["baseline_trace_ref"],
        "target": target_score,
        "baseline": baseline_score,
        "deltas": deltas,
        "verdict": verdict,
        "reasons": reasons,
    }


def invalid_pair(
    pair: dict[str, Any],
    reason: str,
    target: dict[str, Any] | None = None,
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": pair.get("id"),
        "question": pair.get("question"),
        "target_trace_ref": pair.get("target_trace_ref"),
        "baseline_trace_ref": pair.get("baseline_trace_ref"),
        "target": target,
        "baseline": baseline,
        "deltas": {field: None for field in sorted(DELTA_FIELDS)},
        "verdict": "invalid",
        "reasons": [reason],
    }


def summarize(pairs: list[dict[str, Any]], minimum_pair_count: int) -> dict[str, Any]:
    valid_pairs = [item for item in pairs if item.get("verdict") != "invalid"]
    return {
        "pair_count": len(valid_pairs),
        "target_preferred_count": sum(1 for item in valid_pairs if item.get("verdict") == "target_preferred"),
        "baseline_preferred_count": sum(1 for item in valid_pairs if item.get("verdict") == "baseline_preferred"),
        "target_blocked_count": sum(1 for item in valid_pairs if item.get("verdict") == "target_blocked"),
        "baseline_blocked_count": sum(1 for item in valid_pairs if item.get("verdict") == "baseline_blocked"),
        "watch_count": sum(1 for item in valid_pairs if item.get("verdict") == "watch"),
        "invalid_pair_count": sum(1 for item in pairs if item.get("verdict") == "invalid"),
        "minimum_pair_count": minimum_pair_count,
        "minimum_pair_count_met": len(valid_pairs) >= minimum_pair_count,
    }


def derive_recommendation(summary: dict[str, Any]) -> str:
    if not summary["minimum_pair_count_met"] or summary["invalid_pair_count"] > 0:
        return "insufficient"
    if summary["target_blocked_count"] > 0:
        return "block_target"
    if summary["baseline_blocked_count"] > 0 and summary["target_blocked_count"] == 0:
        return "block_baseline"
    if summary["baseline_preferred_count"] > summary["target_preferred_count"]:
        return "prefer_baseline"
    if summary["target_preferred_count"] > summary["baseline_preferred_count"]:
        return "prefer_target"
    return "watch"


def validate_pair_manifest(manifest: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["pair manifest must be an object"]
    validate_fields("pair_manifest", manifest, PAIR_MANIFEST_FIELDS, errors)
    if manifest.get("pair_manifest_version") != "1.0":
        errors.append("pair_manifest_version must be 1.0")
    for field in ("experiment_id", "route_group", "baseline_route_group", "action_boundary"):
        if not is_nonempty_string(manifest.get(field)):
            errors.append(f"{field} must be a non-empty string")
    for field in ("route_group", "baseline_route_group"):
        value = manifest.get(field)
        if isinstance(value, str) and not route_group_is_well_formed(value):
            errors.append(f"{field} must use instrument:base_model_relation:action_boundary")
    if route_boundary(manifest.get("route_group", "")) != manifest.get("action_boundary"):
        errors.append("route_group action boundary differs from action_boundary")
    if route_boundary(manifest.get("baseline_route_group", "")) != manifest.get("action_boundary"):
        errors.append("baseline_route_group action boundary differs from action_boundary")
    if not is_positive_int(manifest.get("minimum_pair_count")):
        errors.append("minimum_pair_count must be a positive integer")
    pairs = manifest.get("pairs")
    if not isinstance(pairs, list) or len(pairs) == 0:
        errors.append("pairs must be a non-empty array")
    else:
        if is_positive_int(manifest.get("minimum_pair_count")) and len(pairs) < manifest["minimum_pair_count"]:
            errors.append("pairs length must be at least minimum_pair_count")
        seen: set[str] = set()
        for index, pair in enumerate(pairs, start=1):
            parsed = validate_fields(f"pairs[{index}]", pair, PAIR_INPUT_FIELDS, errors)
            if not parsed:
                continue
            pair_id = parsed.get("id")
            if not is_nonempty_string(pair_id):
                errors.append(f"pairs[{index}].id must be a non-empty string")
            elif pair_id in seen:
                errors.append(f"pairs[{index}].id is duplicated")
            else:
                seen.add(pair_id)
            for field in ("question", "target_trace_ref", "baseline_trace_ref"):
                if not is_nonempty_string(parsed.get(field)):
                    errors.append(f"pairs[{index}].{field} must be a non-empty string")
    if manifest.get("non_authorization") != NON_AUTHORIZATION:
        errors.append("non_authorization text is invalid")
    return errors


def build_report(pair_manifest_path: Path) -> dict[str, Any]:
    manifest = load_json(pair_manifest_path)
    errors = validate_pair_manifest(manifest)
    if errors:
        raise ValueError("; ".join(errors))
    pairs = [build_pair(pair_manifest_path, manifest, pair) for pair in manifest["pairs"]]
    summary = summarize(pairs, manifest["minimum_pair_count"])
    recommendation = derive_recommendation(summary)
    return {
        "pairing_report_version": "1.0",
        "experiment_id": manifest["experiment_id"],
        "route_group": manifest["route_group"],
        "baseline_route_group": manifest["baseline_route_group"],
        "action_boundary": manifest["action_boundary"],
        "inputs": {
            "pair_manifest_ref": str(pair_manifest_path),
        },
        "pairs": pairs,
        "summary": summary,
        "recommendation": recommendation,
        "non_authorization": NON_AUTHORIZATION,
    }


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_bool(value: Any) -> bool:
    return isinstance(value, bool)


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


def validate_score(name: str, value: Any, errors: list[str], *, nullable: bool = False) -> dict[str, Any] | None:
    if value is None and nullable:
        return None
    score = validate_fields(name, value, SCORE_FIELDS, errors)
    if not score:
        return {}
    for field in ("route_group", "instrument", "base_model_relation", "action_boundary", "quality_gate", "recommendation"):
        if not is_nonempty_string(score.get(field)):
            errors.append(f"{name}.{field} must be a non-empty string")
    for field in ("evidence_score", "risk_penalty", "residuals_per_10k_tokens"):
        if not is_nullable_number(score.get(field)):
            errors.append(f"{name}.{field} must be a number or null")
    for field in ("residual_count", "action_blocking_count"):
        if not is_nonnegative_int(score.get(field)):
            errors.append(f"{name}.{field} must be a non-negative integer")
    return score


def validate_pair(index: int, value: Any, errors: list[str]) -> dict[str, Any]:
    pair = validate_fields(f"pairs[{index}]", value, PAIR_FIELDS, errors)
    if not pair:
        return {}
    for field in ("id", "question", "target_trace_ref", "baseline_trace_ref"):
        if not is_nonempty_string(pair.get(field)):
            errors.append(f"pairs[{index}].{field} must be a non-empty string")
    target = validate_score(f"pairs[{index}].target", pair.get("target"), errors, nullable=True)
    baseline = validate_score(f"pairs[{index}].baseline", pair.get("baseline"), errors, nullable=True)
    deltas = validate_fields(f"pairs[{index}].deltas", pair.get("deltas"), DELTA_FIELDS, errors)
    if deltas:
        for field in DELTA_FIELDS:
            if not is_nullable_number(deltas.get(field)):
                errors.append(f"pairs[{index}].deltas.{field} must be a number or null")
    if pair.get("verdict") not in PAIR_VERDICTS:
        errors.append(f"pairs[{index}].verdict is invalid")
    if not is_string_list(pair.get("reasons"), min_items=1):
        errors.append(f"pairs[{index}].reasons must be a non-empty array of strings")
    if pair.get("verdict") != "invalid" and (target is None or baseline is None):
        errors.append(f"pairs[{index}] valid pair must include target and baseline summaries")
    if pair.get("verdict") == "invalid" and (target is not None or baseline is not None):
        # Invalid pairs may keep partial summaries for debugging.
        pass
    return pair


def validate_report(report: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["pairing report must be an object"]
    validate_fields("report", report, TOP_LEVEL_FIELDS, errors)
    if report.get("pairing_report_version") != "1.0":
        errors.append("pairing_report_version must be 1.0")
    for field in ("experiment_id", "route_group", "baseline_route_group", "action_boundary"):
        if not is_nonempty_string(report.get(field)):
            errors.append(f"{field} must be a non-empty string")
    inputs = validate_fields("inputs", report.get("inputs"), INPUT_FIELDS, errors)
    if inputs and not is_nonempty_string(inputs.get("pair_manifest_ref")):
        errors.append("inputs.pair_manifest_ref must be a non-empty string")

    pairs = report.get("pairs")
    parsed_pairs: list[dict[str, Any]] = []
    if not isinstance(pairs, list):
        errors.append("pairs must be an array")
    else:
        for index, pair in enumerate(pairs, start=1):
            parsed = validate_pair(index, pair, errors)
            if parsed:
                parsed_pairs.append(parsed)

    summary = validate_fields("summary", report.get("summary"), SUMMARY_FIELDS, errors)
    if summary:
        for field in SUMMARY_FIELDS - {"minimum_pair_count_met"}:
            if not is_nonnegative_int(summary.get(field)):
                errors.append(f"summary.{field} must be a non-negative integer")
        if not is_bool(summary.get("minimum_pair_count_met")):
            errors.append("summary.minimum_pair_count_met must be a boolean")
        expected = summarize(parsed_pairs, summary.get("minimum_pair_count", 0))
        if summary != expected:
            errors.append("summary differs from pair verdict counts")
    if report.get("recommendation") not in RECOMMENDATIONS:
        errors.append("recommendation is invalid")
    elif summary:
        expected_recommendation = derive_recommendation(summary)
        if report.get("recommendation") != expected_recommendation:
            errors.append(f"recommendation should be {expected_recommendation}, got {report.get('recommendation')}")
    if report.get("non_authorization") != NON_AUTHORIZATION:
        errors.append("non_authorization text is invalid")
    return errors


def expected_report(report_path: Path, report: dict[str, Any]) -> dict[str, Any]:
    pair_manifest_path = resolve_ref(report_path, report["inputs"]["pair_manifest_ref"])
    if pair_manifest_path is None:
        raise ValueError("pair_manifest_ref must be a local file reference")
    if not pair_manifest_path.exists():
        raise ValueError(f"pair manifest does not exist: {pair_manifest_path}")
    expected = build_report(pair_manifest_path)
    expected["inputs"] = {"pair_manifest_ref": report["inputs"]["pair_manifest_ref"]}
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a HIGHBALL route pairing report")
    parser.add_argument("pair_manifest", type=Path)
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        report = build_report(args.pair_manifest)
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    print(json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
