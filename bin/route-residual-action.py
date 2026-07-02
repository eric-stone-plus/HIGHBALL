#!/usr/bin/env python3
"""Choose the HIGHBALL evidence route for a residual-bearing action."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ACTION_BOUNDARIES = {"none", "reversible", "protected_write", "irreversible"}
CHANGE_CLASSES = {
    "claim",
    "code",
    "protocol",
    "architecture",
    "config",
    "credential",
    "deletion",
    "deployment",
    "financial",
    "legal",
}
RISKS = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "P0"}
TRACE_GATES = {"unknown", "pass", "review", "block"}
HUMAN_REVIEW_CLASSES = {"credential", "deletion", "deployment", "financial", "legal"}
QUINTE_CLASSES = {"protocol", "architecture"}
HIGH_RISKS = {"HIGH", "CRITICAL", "P0"}


def as_bool(value: Any) -> bool:
    return bool(value) if isinstance(value, bool) else False


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return 0


def validate_request(request: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(request.get("question"), str) or not request["question"].strip():
        errors.append("question must be a non-empty string")
    if request.get("action_boundary") not in ACTION_BOUNDARIES:
        errors.append("action_boundary is invalid")
    if request.get("change_class") not in CHANGE_CLASSES:
        errors.append("change_class is invalid")
    if not isinstance(request.get("affected_paths"), list) or not all(isinstance(item, str) for item in request["affected_paths"]):
        errors.append("affected_paths must be an array of strings")
    if "executable" in request and not isinstance(request.get("executable"), bool):
        errors.append("executable must be boolean when present")
    if request.get("risk") not in RISKS:
        errors.append("risk is invalid")
    if request.get("trace_quality_gate", "unknown") not in TRACE_GATES:
        errors.append("trace_quality_gate is invalid")
    if "open_high_risk_count" in request and not isinstance(request.get("open_high_risk_count"), int):
        errors.append("open_high_risk_count must be integer when present")
    if "user_authorized_push" in request and not isinstance(request.get("user_authorized_push"), bool):
        errors.append("user_authorized_push must be boolean when present")
    return errors


def route_request(request: dict[str, Any]) -> dict[str, Any]:
    action_boundary = request.get("action_boundary")
    change_class = request.get("change_class")
    executable = as_bool(request.get("executable"))
    risk = request.get("risk")
    trace_quality_gate = request.get("trace_quality_gate", "unknown")
    open_high_risk_count = as_int(request.get("open_high_risk_count"))

    route = "MAGI"
    reasons: list[str] = []
    required_artifacts: list[str] = []
    residual_trace_required = True
    kengen_authorization_required = False

    if trace_quality_gate == "block":
        route = "block"
        reasons.append("existing trace quality gate is block")
        required_artifacts.append("block record or corrected residual trace")
    elif open_high_risk_count > 0 and action_boundary in {"protected_write", "irreversible"}:
        route = "block"
        reasons.append("strict action boundary has open high-risk residuals")
        required_artifacts.append("closed, blocked, waived, or not-applicable high-risk residuals with evidence and scope")
    elif change_class in HUMAN_REVIEW_CLASSES:
        route = "human-review"
        reasons.append(f"{change_class} change requires human review")
        required_artifacts.append("scoped human decision, waiver, or block record")
    elif action_boundary == "irreversible":
        route = "QUINTE"
        reasons.append("irreversible boundary requires adversarial residual exposure")
        required_artifacts.append("QUINTE R3 residual trace")
        required_artifacts.append("QUINTE complete R1/R2/R3 dispatch ledgers")
    elif action_boundary == "protected_write":
        route = "QUINTE"
        reasons.append("protected write requires QUINTE residual trace before action")
        required_artifacts.append("QUINTE R3 residual trace")
        required_artifacts.append("QUINTE complete R1/R2/R3 dispatch ledgers")
    elif change_class in QUINTE_CLASSES:
        route = "QUINTE"
        reasons.append(f"{change_class} change requires adversarial review")
        required_artifacts.append("QUINTE R3 residual trace")
        required_artifacts.append("QUINTE complete R1/R2/R3 dispatch ledgers")
    elif executable and action_boundary in {"none", "reversible"}:
        route = "direct-evidence"
        reasons.append("claim is executable or source-verifiable")
        required_artifacts.append("file, command, runtime, source, or user evidence trace")
    elif risk in {"LOW", "MEDIUM"}:
        route = "MAGI"
        reasons.append("low or medium risk is suitable for triadic convergence/divergence review")
        required_artifacts.append("MAGI residual trace")
    elif risk in HIGH_RISKS:
        route = "QUINTE"
        reasons.append("high risk requires adversarial residual exposure")
        required_artifacts.append("QUINTE R3 residual trace")
        required_artifacts.append("QUINTE complete R1/R2/R3 dispatch ledgers")
    else:
        route = "MAGI"
        reasons.append("default independent stability review")
        required_artifacts.append("MAGI residual trace")

    if change_class in {"deletion", "deployment", "credential", "financial", "legal"}:
        kengen_authorization_required = True
    if action_boundary == "irreversible":
        kengen_authorization_required = True

    if route == "block":
        residual_trace_required = True
    elif route == "direct-evidence":
        residual_trace_required = True
    elif route == "human-review":
        residual_trace_required = True

    return {
        "route": route,
        "reason": reasons,
        "required_artifacts": required_artifacts,
        "residual_trace_required": residual_trace_required,
        "kengen_authorization_required": kengen_authorization_required,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Route a residual-bearing action")
    parser.add_argument("request_file", type=Path, help="JSON routing request")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        request = json.loads(args.request_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[HIGHBALL] ERROR: cannot read routing request: {exc}", file=sys.stderr)
        return 2

    if not isinstance(request, dict):
        print("[HIGHBALL] ERROR: routing request must be a JSON object", file=sys.stderr)
        return 2

    errors = validate_request(request)
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    result = route_request(request)
    indent = 2 if args.pretty else None
    print(json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
