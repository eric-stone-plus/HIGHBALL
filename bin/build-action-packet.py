#!/usr/bin/env python3
"""Build a fail-closed HIGHBALL Action Packet."""

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
CONTRACTS = load_module("highball_contracts", ROOT / "bin" / "highball-contracts.py")
ROUTER = load_module("route_residual_action", ROOT / "bin" / "route-residual-action.py")
VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")
MEASURE = load_module("measure_residual_trace", ROOT / "bin" / "measure-residual-trace.py")
PRODUCT = load_module("verify_quinte_product", ROOT / "bin" / "verify-quinte-product.py")

ROUTE_INSTRUMENT = {
    "direct-evidence": "direct-evidence",
    "MAGI": "MAGI",
    "QUINTE": "QUINTE",
    "human-review": "human",
}


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_route_request(path: Path) -> dict[str, Any]:
    request = load_json_object(path)
    errors = ROUTER.validate_request(request)
    if errors:
        raise ValueError("; ".join(errors))
    return request


def load_single_trace(path: Path) -> dict[str, Any]:
    traces = MEASURE.load_traces(path)
    if len(traces) != 1:
        raise ValueError("action packet requires exactly one residual trace")
    return traces[0]


def validate_trace(trace: dict[str, Any]) -> dict[str, Any]:
    findings = VALIDATOR.validate_trace(trace, 1)
    errors = [str(item) for item in findings if item.severity == "ERROR"]
    blocks = [str(item) for item in findings if item.severity == "BLOCK"]
    status = "invalid" if errors else "blocked" if blocks else "valid"
    return {"status": status, "errors": errors, "blocks": blocks}


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

    execution_status = execution_evidence.get("status")
    if execution_evidence.get("required") and execution_status != "complete":
        block(
            f"required atomic QUINTE product outcome is {execution_status}",
            "attach a current, completed, request-bound QUINTE result.json",
        )
    elif execution_status in {"invalid", "blocked", "degraded"}:
        block(
            f"QUINTE product outcome is {execution_status}",
            "repair or regenerate the bound QUINTE product outcome",
        )

    highball_decision = trace.get("highball_decision")
    if highball_decision in {"block", "escalate"}:
        block(
            f"trace highball_decision is {highball_decision}",
            "resolve the upstream block or escalation before action",
        )
    quality_gate = quality.get("quality_gate")
    if quality_gate == "block":
        block("quality gate is block", "resolve open or unsupported action-blocking residuals")
    elif quality_gate == "review":
        review("quality gate is review", "add evidence, closure evidence, scope, or human review")

    expected_instrument = ROUTE_INSTRUMENT.get(route)
    if expected_instrument is not None and trace.get("instrument") != expected_instrument:
        block(
            f"route {route} expects trace instrument {expected_instrument}, got {trace.get('instrument')}",
            "produce a trace from the selected route or reroute the action",
        )
    if request.get("question") != trace.get("question"):
        block("route request question differs from trace question", "produce a trace bound to this question")
    if request.get("action_boundary") != trace.get("action_boundary"):
        block(
            "route request boundary differs from trace boundary",
            "produce a trace scoped to the requested action boundary",
        )
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


def build_packet(
    request_path: Path,
    trace_path: Path,
    quinte_results: list[Path] | None = None,
    kengen_authorization: Path | None = None,
) -> dict[str, Any]:
    request = load_route_request(request_path)
    route_decision = ROUTER.route_request(request)
    trace = load_single_trace(trace_path)
    validation = validate_trace(trace)
    quality = MEASURE.measure_trace(trace)
    result_refs = [str(path.resolve()) for path in (quinte_results or [])]
    execution_evidence = PRODUCT.build_execution_evidence(request, route_decision, result_refs)
    authorization = CONTRACTS.summarize_kengen_artifact(
        str(kengen_authorization.resolve()) if kengen_authorization else None,
        request,
        required=route_decision.get("kengen_authorization_required", False),
    )
    action_decision, reasons, next_steps = decide(
        request, route_decision, trace, validation, quality, execution_evidence, authorization
    )
    return {
        "packet_version": CONTRACTS.ACTION_PACKET_VERSION,
        "route_request": request,
        "route_decision": route_decision,
        "trace": trace,
        "validation": validation,
        "quality": quality,
        "execution_evidence": execution_evidence,
        "authorization": authorization,
        "action_decision": action_decision,
        "decision_reasons": reasons,
        "required_next_steps": next_steps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a fail-closed HIGHBALL Action Packet")
    parser.add_argument("route_request", type=Path)
    parser.add_argument("trace_file", type=Path)
    parser.add_argument(
        "--quinte-result",
        action="append",
        type=Path,
        default=[],
        help="Current QUINTE result.json product bundle to bind",
    )
    parser.add_argument(
        "--kengen-authorization",
        type=Path,
        help="Short-lived, action-bound KENGEN authorization JSON",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    try:
        packet = build_packet(
            args.route_request,
            args.trace_file,
            args.quinte_result,
            args.kengen_authorization,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(packet, ensure_ascii=False, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if packet["action_decision"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
