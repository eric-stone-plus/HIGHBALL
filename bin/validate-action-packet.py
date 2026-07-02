#!/usr/bin/env python3
"""Validate HIGHBALL Action Packets.

The validator uses only the Python standard library. It checks packet shape,
recomputes route, trace validation, quality metrics, and boundary decision, then
compares those derived values with the packet contents.
"""

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
ROUTER = load_module("route_residual_action", ROOT / "bin" / "route-residual-action.py")
TRACE_VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")
MEASURE = load_module("measure_residual_trace", ROOT / "bin" / "measure-residual-trace.py")
PACKET_BUILDER = load_module("build_action_packet", ROOT / "bin" / "build-action-packet.py")


TOP_LEVEL_FIELDS = {
    "packet_version",
    "route_request",
    "route_decision",
    "trace",
    "validation",
    "quality",
    "execution_evidence",
    "action_decision",
    "decision_reasons",
    "required_next_steps",
}
ROUTE_DECISION_FIELDS = {
    "route",
    "reason",
    "required_artifacts",
    "residual_trace_required",
    "kengen_authorization_required",
}
VALIDATION_FIELDS = {"status", "errors", "blocks"}
QUALITY_FIELDS = {
    "question",
    "instrument",
    "action_boundary",
    "highball_decision",
    "residual_count",
    "high_risk_count",
    "action_blocking_count",
    "open_high_risk_count",
    "unsupported_high_risk_closure_count",
    "silent_collapse_count",
    "unresolved_count",
    "decision_conflict_count",
    "evidence_coverage",
    "closure_evidence_coverage",
    "action_blocking_closure_coverage",
    "trial_manifest_present",
    "base_model_relation",
    "perspective_count",
    "independent_first_pass_count",
    "perturbation_axis_count",
    "independence_control_count",
    "contamination_risk_count",
    "same_model_flag",
    "cost_fields_present",
    "quality_gate",
    "warnings",
}
EXECUTION_EVIDENCE_FIELDS = {
    "required",
    "status",
    "required_phases",
    "dispatch_ledgers",
    "errors",
    "warnings",
}
DISPATCH_LEDGER_SUMMARY_FIELDS = {
    "ledger_ref",
    "phase",
    "status",
    "phase_progression_allowed",
    "required_count",
    "succeeded_count",
    "failed_count",
    "party_ids",
    "blocking_failures",
}
ROUTES = {"direct-evidence", "MAGI", "QUINTE", "human-review", "block"}
DECISIONS = {"pass", "review", "block"}
VALIDATION_STATUSES = {"valid", "blocked", "invalid"}
EXECUTION_STATUSES = {"not_required", "missing", "complete", "blocked", "degraded", "invalid"}
QUINTE_PHASES = ["R1", "R2", "R3"]
ROUTE_INSTRUMENT = {
    "direct-evidence": "direct-evidence",
    "MAGI": "MAGI",
    "QUINTE": "QUINTE",
    "human-review": "human",
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


def load_packet(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    blocks, raw_json_mode = candidate_blocks(text, path)
    if not blocks:
        raise ValueError("no JSON Action Packet found")

    packets: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            errors.append(f"{label} is invalid JSON: {exc.msg}")
            continue
        if isinstance(parsed, dict) and parsed.get("packet_version") == "1.0":
            packets.append(parsed)

    if len(packets) != 1:
        detail = "; ".join(errors) if errors else f"found {len(packets)} Action Packets"
        raise ValueError(f"expected exactly one Action Packet; {detail}")
    return packets[0]


def validate_trace(trace: dict[str, Any]) -> dict[str, Any]:
    findings = TRACE_VALIDATOR.validate_trace(trace, 1)
    errors = [str(item) for item in findings if item.severity == "ERROR"]
    blocks = [str(item) for item in findings if item.severity == "BLOCK"]
    if errors:
        status = "invalid"
    elif blocks:
        status = "blocked"
    else:
        status = "valid"
    return {
        "status": status,
        "errors": errors,
        "blocks": blocks,
    }


def decide(
    request: dict[str, Any],
    route_decision: dict[str, Any],
    trace: dict[str, Any],
    validation: dict[str, Any],
    quality: dict[str, Any],
    execution_evidence: dict[str, Any],
) -> tuple[str, list[str], list[str]]:
    decision = "pass"
    reasons: list[str] = []
    next_steps: list[str] = []

    route = route_decision["route"]
    trace_instrument = trace.get("instrument")
    expected_instrument = ROUTE_INSTRUMENT.get(route)
    request_boundary = request.get("action_boundary")
    trace_boundary = trace.get("action_boundary")

    def block(reason: str, step: str) -> None:
        nonlocal decision
        decision = "block"
        reasons.append(reason)
        next_steps.append(step)

    def review(reason: str, step: str) -> None:
        nonlocal decision
        if decision != "block":
            decision = "review"
        reasons.append(reason)
        next_steps.append(step)

    if validation["status"] == "invalid":
        block("trace has structural validation errors", "produce a schema-compatible residual trace")
    elif validation["status"] == "blocked":
        block("trace contains validator block findings", "close, block, waive, or scope high-risk residuals")

    if route == "block":
        block("route decision is block", "record block or provide corrected evidence")

    execution_status = execution_evidence.get("status")
    if execution_evidence.get("required") and execution_status != "complete":
        block(
            f"required QUINTE dispatch evidence is {execution_status}",
            "attach complete R1, R2, and R3 QUINTE dispatch ledgers",
        )
    elif execution_status == "invalid":
        block("dispatch evidence is invalid", "repair or regenerate dispatch ledgers")
    elif execution_status in {"blocked", "degraded"}:
        block(
            f"dispatch evidence is {execution_status}",
            "recover the same route and rerun the blocked QUINTE phase",
        )

    quality_gate = quality.get("quality_gate")
    if quality_gate == "block":
        block("quality gate is block", "resolve open or unsupported action-blocking residuals")
    elif quality_gate == "review":
        review("quality gate is review", "add evidence, closure evidence, scope, or human review")

    if expected_instrument is not None and trace_instrument != expected_instrument:
        review(
            f"route {route} expects trace instrument {expected_instrument}, got {trace_instrument}",
            "produce a trace from the selected route or reroute the action",
        )

    if request_boundary != trace_boundary:
        review(
            f"route request boundary {request_boundary} differs from trace boundary {trace_boundary}",
            "produce a trace scoped to the requested action boundary or reroute the action",
        )

    if route_decision.get("kengen_authorization_required") and not request.get("user_authorized_push", False):
        review("KENGEN authorization is required but not present", "obtain explicit current-session authorization")

    if not reasons:
        reasons.append("route, trace validation, and quality gate are consistent")

    return decision, reasons, next_steps


def validate_shape(packet: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(packet, dict):
        return ["Action Packet must be a JSON object"]

    unknown = sorted(set(packet) - TOP_LEVEL_FIELDS)
    missing = sorted(TOP_LEVEL_FIELDS - set(packet))
    if unknown:
        errors.append(f"unknown top-level fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"missing top-level fields: {', '.join(missing)}")

    if packet.get("packet_version") != "1.0":
        errors.append("packet_version must be 1.0")

    request = packet.get("route_request")
    if not isinstance(request, dict):
        errors.append("route_request must be an object")
    else:
        for error in ROUTER.validate_request(request):
            errors.append(f"route_request: {error}")

    route_decision = packet.get("route_decision")
    if not isinstance(route_decision, dict):
        errors.append("route_decision must be an object")
    else:
        unknown_route = sorted(set(route_decision) - ROUTE_DECISION_FIELDS)
        missing_route = sorted(ROUTE_DECISION_FIELDS - set(route_decision))
        if unknown_route:
            errors.append(f"route_decision unknown fields: {', '.join(unknown_route)}")
        if missing_route:
            errors.append(f"route_decision missing fields: {', '.join(missing_route)}")
        if route_decision.get("route") not in ROUTES:
            errors.append("route_decision.route is invalid")
        if not is_string_list(route_decision.get("reason")):
            errors.append("route_decision.reason must be an array of strings")
        if not is_string_list(route_decision.get("required_artifacts")):
            errors.append("route_decision.required_artifacts must be an array of strings")
        if not isinstance(route_decision.get("residual_trace_required"), bool):
            errors.append("route_decision.residual_trace_required must be boolean")
        if not isinstance(route_decision.get("kengen_authorization_required"), bool):
            errors.append("route_decision.kengen_authorization_required must be boolean")

    trace = packet.get("trace")
    if not isinstance(trace, dict):
        errors.append("trace must be an object")
    else:
        trace_errors = [
            str(item)
            for item in TRACE_VALIDATOR.validate_trace(trace, 1)
            if item.severity == "ERROR"
        ]
        errors.extend(f"trace: {error}" for error in trace_errors)

    validation = packet.get("validation")
    if not isinstance(validation, dict):
        errors.append("validation must be an object")
    else:
        unknown_validation = sorted(set(validation) - VALIDATION_FIELDS)
        missing_validation = sorted(VALIDATION_FIELDS - set(validation))
        if unknown_validation:
            errors.append(f"validation unknown fields: {', '.join(unknown_validation)}")
        if missing_validation:
            errors.append(f"validation missing fields: {', '.join(missing_validation)}")
        if validation.get("status") not in VALIDATION_STATUSES:
            errors.append("validation.status is invalid")
        if not is_string_list(validation.get("errors")):
            errors.append("validation.errors must be an array of strings")
        if not is_string_list(validation.get("blocks")):
            errors.append("validation.blocks must be an array of strings")

    quality = packet.get("quality")
    if not isinstance(quality, dict):
        errors.append("quality must be an object")
    else:
        unknown_quality = sorted(set(quality) - QUALITY_FIELDS)
        missing_quality = sorted(QUALITY_FIELDS - set(quality))
        if unknown_quality:
            errors.append(f"quality unknown fields: {', '.join(unknown_quality)}")
        if missing_quality:
            errors.append(f"quality missing fields: {', '.join(missing_quality)}")

    execution = packet.get("execution_evidence")
    if not isinstance(execution, dict):
        errors.append("execution_evidence must be an object")
    else:
        unknown_execution = sorted(set(execution) - EXECUTION_EVIDENCE_FIELDS)
        missing_execution = sorted(EXECUTION_EVIDENCE_FIELDS - set(execution))
        if unknown_execution:
            errors.append(f"execution_evidence unknown fields: {', '.join(unknown_execution)}")
        if missing_execution:
            errors.append(f"execution_evidence missing fields: {', '.join(missing_execution)}")
        if not isinstance(execution.get("required"), bool):
            errors.append("execution_evidence.required must be boolean")
        if execution.get("status") not in EXECUTION_STATUSES:
            errors.append("execution_evidence.status is invalid")
        if not is_string_list(execution.get("required_phases")):
            errors.append("execution_evidence.required_phases must be an array of strings")
        elif any(phase not in QUINTE_PHASES for phase in execution.get("required_phases", [])):
            errors.append("execution_evidence.required_phases contains an invalid phase")
        if not is_string_list(execution.get("errors")):
            errors.append("execution_evidence.errors must be an array of strings")
        if not is_string_list(execution.get("warnings")):
            errors.append("execution_evidence.warnings must be an array of strings")
        ledgers = execution.get("dispatch_ledgers")
        if not isinstance(ledgers, list):
            errors.append("execution_evidence.dispatch_ledgers must be an array")
        else:
            for index, ledger in enumerate(ledgers, start=1):
                prefix = f"execution_evidence.dispatch_ledgers[{index}]"
                if not isinstance(ledger, dict):
                    errors.append(f"{prefix} must be an object")
                    continue
                unknown_ledger = sorted(set(ledger) - DISPATCH_LEDGER_SUMMARY_FIELDS)
                missing_ledger = sorted(DISPATCH_LEDGER_SUMMARY_FIELDS - set(ledger))
                if unknown_ledger:
                    errors.append(f"{prefix} unknown fields: {', '.join(unknown_ledger)}")
                if missing_ledger:
                    errors.append(f"{prefix} missing fields: {', '.join(missing_ledger)}")
                if not isinstance(ledger.get("ledger_ref"), str) or not ledger.get("ledger_ref", "").strip():
                    errors.append(f"{prefix}.ledger_ref must be a non-empty string")
                if ledger.get("phase") is not None and ledger.get("phase") not in QUINTE_PHASES:
                    errors.append(f"{prefix}.phase is invalid")
                if ledger.get("status") not in {"complete", "blocked", "degraded", None}:
                    errors.append(f"{prefix}.status is invalid")
                if not isinstance(ledger.get("phase_progression_allowed"), bool):
                    errors.append(f"{prefix}.phase_progression_allowed must be boolean")
                for field in ("required_count", "succeeded_count", "failed_count"):
                    if not isinstance(ledger.get(field), int) or ledger.get(field) < 0:
                        errors.append(f"{prefix}.{field} must be a non-negative integer")
                if not is_string_list(ledger.get("party_ids")):
                    errors.append(f"{prefix}.party_ids must be an array of strings")
                if not isinstance(ledger.get("blocking_failures"), list):
                    errors.append(f"{prefix}.blocking_failures must be an array")

    if packet.get("action_decision") not in DECISIONS:
        errors.append("action_decision is invalid")
    if not is_string_list(packet.get("decision_reasons"), min_items=1):
        errors.append("decision_reasons must be a non-empty array of strings")
    if not is_string_list(packet.get("required_next_steps")):
        errors.append("required_next_steps must be an array of strings")

    return errors


def validate_consistency(packet: dict[str, Any], base_dir: Path | None = None) -> list[str]:
    errors: list[str] = []
    request = packet["route_request"]
    route_decision = packet["route_decision"]
    trace = packet["trace"]
    validation = packet["validation"]
    quality = packet["quality"]
    execution_evidence = packet["execution_evidence"]

    expected_route = ROUTER.route_request(request)
    if route_decision != expected_route:
        errors.append("route_decision does not match route_request")

    expected_validation = validate_trace(trace)
    if validation != expected_validation:
        errors.append("validation does not match derived trace validation")

    expected_quality = MEASURE.measure_trace(trace)
    if quality != expected_quality:
        errors.append("quality does not match derived residual trace metrics")

    ledger_refs = [
        ledger["ledger_ref"]
        for ledger in execution_evidence.get("dispatch_ledgers", [])
        if isinstance(ledger, dict) and isinstance(ledger.get("ledger_ref"), str)
    ]
    expected_execution = PACKET_BUILDER.build_execution_evidence(route_decision, trace, ledger_refs, base_dir=base_dir)
    if execution_evidence != expected_execution:
        errors.append("execution_evidence does not match derived dispatch evidence")

    action_decision, decision_reasons, required_next_steps = decide(
        request,
        route_decision,
        trace,
        validation,
        quality,
        execution_evidence,
    )
    if packet["action_decision"] != action_decision:
        errors.append("action_decision does not match derived packet decision")
    if packet["decision_reasons"] != decision_reasons:
        errors.append("decision_reasons do not match derived packet reasons")
    if packet["required_next_steps"] != required_next_steps:
        errors.append("required_next_steps do not match derived packet next steps")

    return errors


def validate_packet(packet: Any, base_dir: Path | None = None) -> list[str]:
    shape_errors = validate_shape(packet)
    if shape_errors:
        return shape_errors
    return validate_consistency(packet, base_dir=base_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL Action Packet")
    parser.add_argument("packet_file", type=Path)
    args = parser.parse_args()

    try:
        packet = load_packet(args.packet_file)
    except (OSError, ValueError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    errors = validate_packet(packet, base_dir=args.packet_file.resolve().parent)
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    if packet["action_decision"] == "block":
        print("[HIGHBALL] Action Packet valid; action decision is block", file=sys.stderr)
        return 1

    print(f"[HIGHBALL] Action Packet valid; action decision is {packet['action_decision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
