#!/usr/bin/env python3
"""Build a route execution report from HIGHBALL Action Packets."""

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
ACTION_PACKET = load_module("validate_action_packet", ROOT / "bin" / "validate-action-packet.py")
CONTRACTS = load_module("highball_contracts", ROOT / "bin" / "highball-contracts.py")

NON_AUTHORIZATION = "Route execution reports do not authorize action, dispatch agents, or modify routing rules."
EXECUTION_GATES = {"accepted", "watch", "reroute", "block", "insufficient"}
STATUS_FIELDS = {
    "complete": "complete_count",
    "missing": "missing_count",
    "blocked": "blocked_count",
    "degraded": "degraded_count",
    "invalid": "invalid_count",
    "not_required": "not_required_count",
}


def resolve_ref(base_file: Path, ref: str | None) -> Path | None:
    if ref is None or "://" in ref:
        return None
    ref_path = Path(ref)
    if ref_path.is_absolute():
        return ref_path.resolve()
    return (base_file.parent / ref_path).resolve()


def route_group_from_trace(trace: dict[str, Any]) -> str:
    manifest = trace.get("trial_manifest")
    relation = "unknown"
    if isinstance(manifest, dict) and isinstance(manifest.get("base_model_relation"), str):
        relation = manifest["base_model_relation"]
    instrument = trace.get("instrument") if isinstance(trace.get("instrument"), str) else "unknown"
    boundary = trace.get("action_boundary") if isinstance(trace.get("action_boundary"), str) else "unknown"
    return f"{instrument}:{relation}:{boundary}"


def completion_rate(complete_count: int, required_count: int) -> float | None:
    if required_count == 0:
        return None
    return round(complete_count / required_count, 4)


def summarize_packet(packet_ref: str, packet_path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        packet = ACTION_PACKET.load_packet(packet_path)
    except (OSError, ValueError) as exc:
        return None, [f"action packet cannot be loaded: {packet_ref}: {exc}"]

    packet_errors = ACTION_PACKET.validate_packet(packet, base_dir=packet_path.parent)
    trace = packet.get("trace") if isinstance(packet.get("trace"), dict) else {}
    route_decision = packet.get("route_decision") if isinstance(packet.get("route_decision"), dict) else {}
    execution = packet.get("execution_evidence") if isinstance(packet.get("execution_evidence"), dict) else {}
    status = execution.get("status") if isinstance(execution.get("status"), str) else "invalid"
    if packet_errors:
        status = "invalid"
    outcome = execution.get("quinte_outcome") if isinstance(execution.get("quinte_outcome"), dict) else {}

    summary = {
        "packet_ref": packet_ref,
        "route_group": route_group_from_trace(trace),
        "route": route_decision.get("route") if isinstance(route_decision.get("route"), str) else "unknown",
        "trace_instrument": trace.get("instrument") if isinstance(trace.get("instrument"), str) else "unknown",
        "action_boundary": trace.get("action_boundary") if isinstance(trace.get("action_boundary"), str) else "unknown",
        "action_decision": packet.get("action_decision") if isinstance(packet.get("action_decision"), str) else "unknown",
        "execution_required": execution.get("required") is True,
        "execution_status": status,
        "quinte_run_id": outcome.get("run_id") if isinstance(outcome.get("run_id"), str) else None,
        "quinte_result_sha256": outcome.get("result_sha256") if isinstance(outcome.get("result_sha256"), str) else None,
        "action_binding_sha256": outcome.get("action_binding_sha256") if isinstance(outcome.get("action_binding_sha256"), str) else None,
        "errors": [*packet_errors, *[item for item in execution.get("errors", []) if isinstance(item, str)]],
    }
    return summary, []


def derive_gate(summary: dict[str, Any]) -> str:
    required_count = summary["required_execution_count"]
    if summary["packet_count"] == 0 or required_count == 0:
        return "insufficient"
    if summary["invalid_count"] > 0 or summary["blocked_count"] > 0:
        return "block"
    if summary["degraded_count"] > 0:
        return "reroute"
    rate = summary["completion_rate"]
    if rate is None:
        return "insufficient"
    if rate < 0.8:
        return "reroute"
    if rate < 1.0 or summary["missing_count"] > 0:
        return "watch"
    return "accepted"


def decision_reasons(summary: dict[str, Any], gate: str) -> list[str]:
    reasons = [
        f"required execution packets: {summary['required_execution_count']}",
        f"complete execution packets: {summary['complete_count']}",
        f"completion rate: {summary['completion_rate']}",
        f"execution gate: {gate}",
    ]
    if summary["missing_count"] > 0:
        reasons.append("one or more packets are missing required execution evidence")
    if summary["blocked_count"] > 0:
        reasons.append("one or more packets contain blocked execution evidence")
    if summary["degraded_count"] > 0:
        reasons.append("one or more packets contain degraded execution evidence")
    if summary["invalid_count"] > 0:
        reasons.append("one or more packets contain invalid or inconsistent execution evidence")
    return reasons


def build_report(packet_refs: list[str], base_file: Path | None = None, route_group: str | None = None) -> dict[str, Any]:
    packet_summaries: list[dict[str, Any]] = []
    invalid_refs: list[dict[str, str]] = []

    for ref in packet_refs:
        path = resolve_ref(base_file, ref) if base_file is not None else Path(ref).resolve()
        if path is None:
            invalid_refs.append({"packet_ref": ref, "reason": "action packet ref is not local"})
            continue
        if not path.exists():
            invalid_refs.append({"packet_ref": ref, "reason": "action packet does not exist"})
            continue
        summary, errors = summarize_packet(ref, path)
        if errors:
            invalid_refs.extend({"packet_ref": ref, "reason": error} for error in errors)
            continue
        assert summary is not None
        packet_summaries.append(summary)

    groups = sorted({item["route_group"] for item in packet_summaries})
    if route_group is None:
        if len(groups) == 1:
            route_group = groups[0]
        elif len(groups) == 0:
            route_group = "unknown"
        else:
            raise ValueError("action packets span multiple route groups; pass --route-group")

    scoped_packets = [item for item in packet_summaries if item["route_group"] == route_group]
    out_of_scope = [item for item in packet_summaries if item["route_group"] != route_group]
    required_packets = [item for item in scoped_packets if item["execution_required"]]
    counts = {field: 0 for field in STATUS_FIELDS.values()}
    for item in scoped_packets:
        field = STATUS_FIELDS.get(item["execution_status"], "invalid_count")
        counts[field] += 1

    summary = {
        "packet_count": len(scoped_packets),
        "required_execution_count": len(required_packets),
        "complete_count": counts["complete_count"],
        "missing_count": counts["missing_count"],
        "blocked_count": counts["blocked_count"],
        "degraded_count": counts["degraded_count"],
        "invalid_count": counts["invalid_count"] + len(invalid_refs),
        "not_required_count": counts["not_required_count"],
        "completion_rate": completion_rate(counts["complete_count"], len(required_packets)),
    }
    gate = derive_gate(summary)

    return {
        "execution_report_version": CONTRACTS.ROUTE_EXECUTION_REPORT_VERSION,
        "route_group": route_group,
        "inputs": {
            "action_packet_refs": packet_refs,
        },
        **summary,
        "execution_gate": gate,
        "packet_summaries": scoped_packets,
        "invalid_packet_refs": invalid_refs,
        "out_of_scope_packet_refs": [item["packet_ref"] for item in out_of_scope],
        "decision_reasons": decision_reasons(summary, gate),
        "non_authorization": NON_AUTHORIZATION,
    }


def expected_report(report_path: Path, report: dict[str, Any]) -> dict[str, Any]:
    inputs = report.get("inputs", {})
    refs = inputs.get("action_packet_refs")
    if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
        raise ValueError("execution report inputs.action_packet_refs must be an array of strings")
    route_group = report.get("route_group")
    if not isinstance(route_group, str) or not route_group:
        raise ValueError("execution report route_group must be a non-empty string")
    return build_report(refs, base_file=report_path, route_group=route_group)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a HIGHBALL route execution report")
    parser.add_argument("action_packets", nargs="+", type=Path, help="Action Packet JSON files")
    parser.add_argument("--route-group", help="route group to summarize when inputs contain multiple groups")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    missing = [path for path in args.action_packets if not path.exists()]
    if missing:
        for path in missing:
            print(f"[HIGHBALL] ERROR: action packet does not exist: {path}", file=sys.stderr)
        return 2

    try:
        report = build_report([str(path.resolve()) for path in args.action_packets], route_group=args.route_group)
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    print(json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
