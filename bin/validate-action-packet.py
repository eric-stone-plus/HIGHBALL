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
CONTRACTS = load_module("highball_contracts", ROOT / "bin" / "highball-contracts.py")
ROUTER = load_module("route_residual_action", ROOT / "bin" / "route-residual-action.py")
TRACE_VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")
MEASURE = load_module("measure_residual_trace", ROOT / "bin" / "measure-residual-trace.py")
PRODUCT = load_module("verify_quinte_product", ROOT / "bin" / "verify-quinte-product.py")


TOP_LEVEL_FIELDS = {
    "packet_version",
    "route_request",
    "route_decision",
    "trace",
    "validation",
    "quality",
    "execution_evidence",
    "authorization",
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
    "binding",
    "quinte_outcome",
    "errors",
}
AUTHORIZATION_FIELDS = {
    "required",
    "status",
    "artifact_ref",
    "artifact_sha256",
    "authorization_id",
    "action_binding_sha256",
    "action_scope",
    "issued_at",
    "expires_at",
    "errors",
}
BINDINGS = {"atomic_quinte_outcome", "not_applicable"}
QUINTE_OUTCOME_FIELDS = {
    "result_ref",
    "run_id",
    "status",
    "result_version",
    "result_sha256",
    "brief_sha256",
    "question",
    "action_scope",
    "affected_paths",
    "action_binding_sha256",
}
ROUTES = {"direct-evidence", "MAGI", "QUINTE", "human-review", "block"}
DECISIONS = {"pass", "review", "block"}
VALIDATION_STATUSES = {"valid", "blocked", "invalid"}
EXECUTION_STATUSES = {"not_required", "missing", "complete", "blocked", "degraded", "invalid"}
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
        if isinstance(parsed, dict) and parsed.get("packet_version") == CONTRACTS.ACTION_PACKET_VERSION:
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
    authorization: dict[str, Any],
) -> tuple[str, list[str], list[str]]:
    decision = "pass"
    reasons: list[str] = []
    next_steps: list[str] = []

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

    route = route_decision["route"]
    if validation["status"] == "invalid":
        block("trace has structural validation errors", "produce a schema-compatible residual trace")
    elif validation["status"] == "blocked":
        block("trace contains validator block findings", "resolve the trace's blocking decision or residuals")
    if route == "block":
        block("route decision is block", "record the block or provide corrected evidence")
    status = execution_evidence.get("status")
    if execution_evidence.get("required") and status != "complete":
        block(
            f"required atomic QUINTE product outcome is {status}",
            "attach a current, completed, request-bound QUINTE result.json",
        )
    elif status in {"invalid", "blocked", "degraded"}:
        block(f"QUINTE product outcome is {status}", "repair or regenerate the bound QUINTE product outcome")
    if trace.get("highball_decision") in {"block", "escalate"}:
        block(
            f"trace highball_decision is {trace.get('highball_decision')}",
            "resolve the upstream block or escalation before action",
        )
    if quality.get("quality_gate") == "block":
        block("quality gate is block", "resolve open or unsupported action-blocking residuals")
    elif quality.get("quality_gate") == "review":
        review("quality gate is review", "add evidence, closure evidence, scope, or human review")
    expected_instrument = {
        "direct-evidence": "direct-evidence",
        "MAGI": "MAGI",
        "QUINTE": "QUINTE",
        "human-review": "human",
    }.get(route)
    if expected_instrument is not None and trace.get("instrument") != expected_instrument:
        block(
            f"route {route} expects trace instrument {expected_instrument}, got {trace.get('instrument')}",
            "produce a trace from the selected route or reroute the action",
        )
    if request.get("question") != trace.get("question"):
        block("route request question differs from trace question", "produce a trace bound to this question")
    if request.get("action_boundary") != trace.get("action_boundary"):
        block("route request boundary differs from trace boundary", "produce a trace scoped to the requested action boundary")
    if trace.get("trace_version") != CONTRACTS.RESIDUAL_TRACE_VERSION:
        block("trace contract version is not active", "produce an active residual trace contract")
    if trace.get("action_binding_sha256") != CONTRACTS.action_binding_sha256(request):
        block("trace action binding differs from the route request", "bind the trace to this action")
    if route_decision.get("kengen_authorization_required") and authorization.get("status") != "authorized":
        block(
            f"required KENGEN authorization is {authorization.get('status')}",
            "attach a current, user-issued, action-bound KENGEN authorization artifact",
        )
    elif authorization.get("status") == "invalid":
        block("KENGEN authorization is invalid", "replace the invalid authorization artifact")
    if not reasons:
        reasons.append("route, trace, execution evidence, and authorization are consistent")
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

    if packet.get("packet_version") != CONTRACTS.ACTION_PACKET_VERSION:
        errors.append(f"packet_version must be {CONTRACTS.ACTION_PACKET_VERSION}")

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
        if execution.get("binding") not in BINDINGS:
            errors.append("execution_evidence.binding is invalid")
        outcome = execution.get("quinte_outcome")
        if outcome is not None:
            if not isinstance(outcome, dict):
                errors.append("execution_evidence.quinte_outcome must be an object or null")
            else:
                unknown_outcome = sorted(set(outcome) - QUINTE_OUTCOME_FIELDS)
                missing_outcome = sorted(QUINTE_OUTCOME_FIELDS - set(outcome))
                if unknown_outcome:
                    errors.append(
                        f"execution_evidence.quinte_outcome unknown fields: {', '.join(unknown_outcome)}"
                    )
                if missing_outcome:
                    errors.append(
                        f"execution_evidence.quinte_outcome missing fields: {', '.join(missing_outcome)}"
                    )
                if not isinstance(outcome.get("result_ref"), str) or not outcome.get("result_ref", "").strip():
                    errors.append("execution_evidence.quinte_outcome.result_ref must be a non-empty string")
                if not isinstance(outcome.get("run_id"), str):
                    errors.append("execution_evidence.quinte_outcome.run_id must be a string")
                if not isinstance(outcome.get("status"), str):
                    errors.append("execution_evidence.quinte_outcome.status must be a string")
                if outcome.get("result_version") != CONTRACTS.QUINTE_RESULT_VERSION:
                    errors.append("execution_evidence.quinte_outcome.result_version is unsupported")
                for field in ("result_sha256", "brief_sha256", "action_binding_sha256"):
                    if not CONTRACTS.is_digest(outcome.get(field)):
                        errors.append(f"execution_evidence.quinte_outcome.{field} is invalid")
                if not isinstance(outcome.get("question"), str) or not outcome.get("question", "").strip():
                    errors.append("execution_evidence.quinte_outcome.question must be a non-empty string")
                if outcome.get("action_scope") is not None and not isinstance(outcome.get("action_scope"), str):
                    errors.append("execution_evidence.quinte_outcome.action_scope must be a string or null")
                if not is_string_list(outcome.get("affected_paths")):
                    errors.append("execution_evidence.quinte_outcome.affected_paths must be an array of strings")
        if not is_string_list(execution.get("errors")):
            errors.append("execution_evidence.errors must be an array of strings")

    authorization = packet.get("authorization")
    if not isinstance(authorization, dict):
        errors.append("authorization must be an object")
    else:
        unknown_authorization = sorted(set(authorization) - AUTHORIZATION_FIELDS)
        missing_authorization = sorted(AUTHORIZATION_FIELDS - set(authorization))
        if unknown_authorization:
            errors.append(f"authorization unknown fields: {', '.join(unknown_authorization)}")
        if missing_authorization:
            errors.append(f"authorization missing fields: {', '.join(missing_authorization)}")
        if not isinstance(authorization.get("required"), bool):
            errors.append("authorization.required must be boolean")
        if authorization.get("status") not in {"not_required", "missing", "authorized", "invalid"}:
            errors.append("authorization.status is invalid")
        for field in ("artifact_ref", "artifact_sha256", "authorization_id", "action_binding_sha256", "action_scope", "issued_at", "expires_at"):
            if authorization.get(field) is not None and not isinstance(authorization.get(field), str):
                errors.append(f"authorization.{field} must be a string or null")
        if not is_string_list(authorization.get("errors")):
            errors.append("authorization.errors must be an array of strings")

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
    authorization = packet["authorization"]

    expected_route = ROUTER.route_request(request)
    if route_decision != expected_route:
        errors.append("route_decision does not match route_request")

    expected_validation = validate_trace(trace)
    if validation != expected_validation:
        errors.append("validation does not match derived trace validation")

    expected_quality = MEASURE.measure_trace(trace)
    if quality != expected_quality:
        errors.append("quality does not match derived residual trace metrics")

    outcome = execution_evidence.get("quinte_outcome")
    result_refs = []
    if isinstance(outcome, dict) and isinstance(outcome.get("result_ref"), str):
        result_refs = [outcome["result_ref"]]
    expected_execution = PRODUCT.build_execution_evidence(
        request,
        route_decision,
        result_refs,
        base_dir=base_dir,
    )
    if execution_evidence != expected_execution:
        errors.append("execution_evidence does not match derived product/dispatch evidence")

    authorization_ref = authorization.get("artifact_ref")
    expected_authorization = CONTRACTS.summarize_kengen_artifact(
        authorization_ref if isinstance(authorization_ref, str) else None,
        request,
        base_dir=base_dir,
        required=route_decision.get("kengen_authorization_required", False),
    )
    if authorization != expected_authorization:
        errors.append("authorization does not match the bound KENGEN artifact")

    action_decision, decision_reasons, required_next_steps = decide(
        request,
        route_decision,
        trace,
        validation,
        quality,
        execution_evidence,
        authorization,
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

    if packet["action_decision"] != "pass":
        print(
            f"[HIGHBALL] Action Packet valid; action decision is {packet['action_decision']} (non-authorizing)",
            file=sys.stderr,
        )
        return 1

    print(f"[HIGHBALL] Action Packet valid; action decision is {packet['action_decision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
