#!/usr/bin/env python3
"""Build a HIGHBALL Action Packet from a route request and residual trace."""

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
ROUTER = load_module("route_residual_action", ROOT / "bin" / "route-residual-action.py")
VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")
MEASURE = load_module("measure_residual_trace", ROOT / "bin" / "measure-residual-trace.py")


ROUTE_INSTRUMENT = {
    "direct-evidence": "direct-evidence",
    "MAGI": "MAGI",
    "QUINTE": "QUINTE",
    "human-review": "human",
}
QUINTE_PHASES = ["R1", "R2", "R3"]
QUINTE_R1_R2_PARTIES = ["Party A", "Party B", "Party C", "Party D", "Party E"]
QUINTE_R3_PARTIES = ["Auditor B"]
DISPATCH_STATUSES = {"complete", "blocked", "degraded"}


def load_route_request(path: Path) -> dict[str, Any]:
    request = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(request, dict):
        raise ValueError("route request must be a JSON object")
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


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def execution_evidence_required(
    route_decision: dict[str, Any],
    trace: dict[str, Any],
) -> bool:
    return route_decision.get("route") == "QUINTE" and trace.get("instrument") == "QUINTE"


def resolve_ref(ref: str, base_dir: Path | None) -> Path:
    path = Path(ref)
    if path.is_absolute():
        return path.resolve()
    if base_dir is not None:
        return (base_dir / path).resolve()
    return path.resolve()


def resolve_ledger_ref(ref: str, base_dir: Path | None) -> Path:
    """Legacy alias for archived dispatch-ledger refs."""
    return resolve_ref(ref, base_dir)


def summarize_quinte_outcome(ref: str, base_dir: Path | None = None) -> tuple[dict[str, Any] | None, list[str]]:
    """Bind an atomic QUINTE product result.json without inspecting R1/R2/R3."""
    errors: list[str] = []
    path = resolve_ref(ref, base_dir)
    if not path.exists():
        return None, [f"quinte result does not exist: {ref}"]
    try:
        result = load_json_object(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return None, [f"quinte result cannot be read: {ref}: {exc}"]

    run_id = result.get("run_id")
    status = result.get("status")
    result_version = result.get("result_version")
    if not isinstance(run_id, str) or not run_id.strip():
        errors.append(f"quinte result {ref} missing run_id")
    if not isinstance(status, str) or not status.strip():
        errors.append(f"quinte result {ref} missing status")
    if result_version is not None and not isinstance(result_version, str):
        errors.append(f"quinte result {ref} result_version must be a string")

    outcome = {
        "result_ref": ref,
        "run_id": run_id if isinstance(run_id, str) else "",
        "status": status if isinstance(status, str) else "",
        "result_version": result_version if isinstance(result_version, str) else None,
    }
    return outcome, errors




def summarize_dispatch_ledger(ref: str, base_dir: Path | None = None) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    path = resolve_ledger_ref(ref, base_dir)
    if not path.exists():
        return None, [f"dispatch ledger does not exist: {ref}"]

    try:
        ledger = load_json_object(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return None, [f"dispatch ledger cannot be read: {ref}: {exc}"]

    phase = ledger.get("phase")
    status = ledger.get("status")
    phase_progression_allowed = ledger.get("phase_progression_allowed")
    summary = ledger.get("summary")
    parties = ledger.get("parties")
    blocking_failures = ledger.get("blocking_failures", [])

    if ledger.get("dispatch_ledger_version") != "1.0":
        errors.append(f"dispatch ledger {ref} version must be 1.0")
    if phase not in QUINTE_PHASES:
        errors.append(f"dispatch ledger {ref} phase is invalid")
    if status not in DISPATCH_STATUSES:
        errors.append(f"dispatch ledger {ref} status is invalid")
    if not isinstance(phase_progression_allowed, bool):
        errors.append(f"dispatch ledger {ref} phase_progression_allowed must be boolean")
    elif phase_progression_allowed != (status == "complete"):
        errors.append(f"dispatch ledger {ref} phase_progression_allowed is inconsistent with status")
    if not isinstance(summary, dict):
        errors.append(f"dispatch ledger {ref} summary must be an object")
        summary = {}
    if not isinstance(parties, list):
        errors.append(f"dispatch ledger {ref} parties must be an array")
        parties = []
    if not isinstance(blocking_failures, list):
        errors.append(f"dispatch ledger {ref} blocking_failures must be an array")
        blocking_failures = []

    party_ids = [party.get("id") for party in parties if isinstance(party, dict)]
    expected_parties = QUINTE_R3_PARTIES if phase == "R3" else QUINTE_R1_R2_PARTIES
    if phase in QUINTE_PHASES and party_ids != expected_parties:
        errors.append(f"dispatch ledger {ref} has wrong party set for {phase}")

    party_statuses = [party.get("status") for party in parties if isinstance(party, dict)]
    if status == "complete":
        if phase_progression_allowed is not True:
            errors.append(f"dispatch ledger {ref} complete status must allow phase progression")
        if party_statuses and any(item != "succeeded" for item in party_statuses):
            errors.append(f"dispatch ledger {ref} complete status has non-succeeded party")
        if summary.get("failed_count") != 0:
            errors.append(f"dispatch ledger {ref} complete status must have failed_count 0")
        if summary.get("required_count") != len(expected_parties):
            errors.append(f"dispatch ledger {ref} required_count differs from phase party count")
        if summary.get("succeeded_count") != len(expected_parties):
            errors.append(f"dispatch ledger {ref} succeeded_count differs from phase party count")
    elif phase_progression_allowed is not False:
        errors.append(f"dispatch ledger {ref} non-complete status must block phase progression")

    record = {
        "ledger_ref": ref,
        "phase": phase if isinstance(phase, str) else None,
        "status": status if isinstance(status, str) else None,
        "phase_progression_allowed": phase_progression_allowed if isinstance(phase_progression_allowed, bool) else False,
        "required_count": summary.get("required_count") if isinstance(summary.get("required_count"), int) else 0,
        "succeeded_count": summary.get("succeeded_count") if isinstance(summary.get("succeeded_count"), int) else 0,
        "failed_count": summary.get("failed_count") if isinstance(summary.get("failed_count"), int) else 0,
        "party_ids": [item for item in party_ids if isinstance(item, str)],
        "blocking_failures": blocking_failures,
    }
    return record, errors


def build_execution_evidence(
    route_decision: dict[str, Any],
    trace: dict[str, Any],
    dispatch_ledger_refs: list[str] | None = None,
    *,
    quinte_result_refs: list[str] | None = None,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    """Build execution evidence for the Action Packet.

    Active QUINTE integrations bind one atomic product outcome (result.json).
    HIGHBALL accepts or blocks that product outcome only; it does not revalidate
    R1/R2/R3 phase, lane, party, retry, or pacing state.

    Legacy per-phase dispatch ledgers remain parseable for archived packets when
    no atomic outcome is supplied and ledger refs are present.
    """
    required = execution_evidence_required(route_decision, trace)
    dispatch_ledger_refs = list(dispatch_ledger_refs or [])
    quinte_result_refs = list(quinte_result_refs or [])
    errors: list[str] = []
    warnings: list[str] = []

    # Active path: atomic QUINTE product outcome.
    if quinte_result_refs or (required and not dispatch_ledger_refs):
        if len(quinte_result_refs) > 1:
            errors.append("active QUINTE binding accepts exactly one product result")
        outcome = None
        if quinte_result_refs:
            outcome, outcome_errors = summarize_quinte_outcome(quinte_result_refs[0], base_dir)
            errors.extend(outcome_errors)
        if dispatch_ledger_refs:
            warnings.append(
                "dispatch ledgers were ignored because the active binding uses an atomic QUINTE outcome"
            )

        if errors and outcome is None:
            status = "invalid"
        elif outcome is None:
            status = "missing" if required else "not_required"
        elif errors:
            status = "invalid"
        else:
            product_status = outcome.get("status")
            if product_status == "completed":
                status = "complete"
            elif product_status == "degraded":
                status = "degraded"
            elif product_status in {
                "cancelled",
                "failed",
                "failed_policy",
                "queued",
                "preflight",
                "r1_running",
                "r1_gate",
                "r2_packet",
                "r2_running",
                "r2_gate",
                "r3_cc",
                "waiting_hm",
                "merging",
                "cancelling",
            }:
                # Non-completed product outcomes never authorize action.
                status = "blocked"
            else:
                status = "invalid"
                errors.append(
                    f"quinte product status {product_status!r} is not a recognized atomic outcome"
                )

        if required and status == "missing":
            warnings.append("missing atomic QUINTE product outcome (result.json)")

        return {
            "required": required,
            "status": status,
            "binding": "atomic_quinte_outcome" if required or quinte_result_refs else "not_applicable",
            "quinte_outcome": outcome,
            "required_phases": [],
            "dispatch_ledgers": [],
            "errors": errors,
            "warnings": warnings,
        }

    # Legacy archived path: phase dispatch ledgers only when no atomic outcome.
    records: list[dict[str, Any]] = []
    phase_seen: set[str] = set()
    for ref in dispatch_ledger_refs:
        record, ledger_errors = summarize_dispatch_ledger(ref, base_dir)
        errors.extend(ledger_errors)
        if record is None:
            continue
        records.append(record)
        phase = record.get("phase")
        if isinstance(phase, str):
            if phase in phase_seen:
                errors.append(f"duplicate QUINTE dispatch ledger phase: {phase}")
            phase_seen.add(phase)

    complete_phases = {
        record["phase"]
        for record in records
        if record.get("phase") in QUINTE_PHASES and record.get("status") == "complete"
    }
    missing_phases = [phase for phase in QUINTE_PHASES if phase not in complete_phases]

    if errors:
        status = "invalid"
    elif any(record.get("status") == "blocked" for record in records):
        status = "blocked"
    elif any(record.get("status") == "degraded" for record in records):
        status = "degraded"
    elif required and missing_phases:
        status = "missing"
    elif records:
        status = "complete"
    else:
        status = "not_required" if not required else "missing"

    if required and missing_phases:
        warnings.append(
            "legacy dispatch ledgers missing complete phases "
            f"(archived compatibility only): {', '.join(missing_phases)}"
        )
    if not required and records:
        warnings.append("dispatch ledgers were supplied for a route that does not require them")
    if records:
        warnings.append(
            "using legacy per-phase dispatch ledgers; active integrations must bind an atomic QUINTE outcome"
        )

    return {
        "required": required,
        "status": status,
        "binding": "legacy_dispatch_ledgers" if records or required else "not_applicable",
        "quinte_outcome": None,
        "required_phases": QUINTE_PHASES if required else [],
        "dispatch_ledgers": records,
        "errors": errors,
        "warnings": warnings,
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
        binding = execution_evidence.get("binding")
        if binding == "atomic_quinte_outcome":
            block(
                f"required atomic QUINTE product outcome is {execution_status}",
                "attach a completed quinte result.json product outcome",
            )
        else:
            block(
                f"required QUINTE execution evidence is {execution_status}",
                "attach a completed atomic quinte result.json (legacy phase ledgers are archived-only)",
            )
    elif execution_status == "invalid":
        block(
            "QUINTE execution evidence is invalid",
            "repair or regenerate the atomic quinte product outcome",
        )
    elif execution_status in {"blocked", "degraded"}:
        block(
            f"QUINTE product outcome is {execution_status}",
            "recover with the quinte CLI and rebind the product outcome (do not reconstruct R1/R2/R3 in HIGHBALL)",
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


def build_packet(
    request_path: Path,
    trace_path: Path,
    dispatch_ledgers: list[Path] | None = None,
    quinte_results: list[Path] | None = None,
) -> dict[str, Any]:
    request = load_route_request(request_path)
    route_decision = ROUTER.route_request(request)
    trace = load_single_trace(trace_path)
    validation = validate_trace(trace)
    quality = MEASURE.measure_trace(trace)
    ledger_refs = [str(path) for path in (dispatch_ledgers or [])]
    result_refs = [str(path) for path in (quinte_results or [])]
    execution_evidence = build_execution_evidence(
        route_decision,
        trace,
        ledger_refs,
        quinte_result_refs=result_refs,
    )
    action_decision, decision_reasons, required_next_steps = decide(
        request,
        route_decision,
        trace,
        validation,
        quality,
        execution_evidence,
    )
    return {
        "packet_version": "1.0",
        "route_request": request,
        "route_decision": route_decision,
        "trace": trace,
        "validation": validation,
        "quality": quality,
        "execution_evidence": execution_evidence,
        "action_decision": action_decision,
        "decision_reasons": decision_reasons,
        "required_next_steps": required_next_steps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a HIGHBALL Action Packet")
    parser.add_argument("route_request", type=Path)
    parser.add_argument("trace_file", type=Path)
    parser.add_argument(
        "--quinte-result",
        action="append",
        type=Path,
        default=[],
        help="Atomic QUINTE product result.json to bind (active integration path)",
    )
    parser.add_argument(
        "--dispatch-ledger",
        action="append",
        type=Path,
        default=[],
        help="Legacy archived QUINTE dispatch ledger (compatibility only; not an active control surface)",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        packet = build_packet(
            args.route_request,
            args.trace_file,
            args.dispatch_ledger,
            quinte_results=args.quinte_result,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    print(json.dumps(packet, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
