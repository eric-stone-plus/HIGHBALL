#!/usr/bin/env python3
"""Build a non-authorizing route change proposal from a route policy report."""

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
POLICY_VALIDATOR = load_module("validate_route_policy_report", ROOT / "bin" / "validate-route-policy-report.py")


PROPOSED_CHANGES = {
    "keep_route_group",
    "watch_route_group",
    "reroute_route_group",
    "block_route_group",
    "collect_evidence",
}
PROPOSAL_STATUSES = {"draft", "proposed", "accepted", "rejected", "superseded"}
CHANGE_FIELDS = {"kind", "action", "target", "scope", "affected_paths", "rationale"}
SUBJECT_FIELDS = {"route_group", "action_boundary", "policy_recommendation", "proposed_change"}
INPUT_FIELDS = {"route_policy_report_ref"}
EVIDENCE_FIELDS = {
    "calibration_recommendation",
    "outcome_signal",
    "baseline_recommendation",
    "policy_recommendation",
}
TOP_LEVEL_FIELDS = {
    "proposal_version",
    "subject",
    "inputs",
    "evidence",
    "candidate_changes",
    "required_gates",
    "status",
    "non_authorization",
}


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


def route_boundary(route_group: str) -> str:
    parts = route_group.split(":")
    if len(parts) != 3:
        return "unknown"
    return parts[2]


def proposed_change(policy_recommendation: str) -> str:
    return {
        "keep": "keep_route_group",
        "watch": "watch_route_group",
        "reroute": "reroute_route_group",
        "block": "block_route_group",
        "insufficient": "collect_evidence",
    }[policy_recommendation]


def candidate_changes(route_group: str, policy_recommendation: str) -> list[dict[str, Any]]:
    change = proposed_change(policy_recommendation)
    boundary = route_boundary(route_group)
    scope = f"future {boundary} work matching route group {route_group}"

    if change == "block_route_group":
        return [
            {
                "kind": "routing_policy",
                "action": "block_default_use",
                "target": route_group,
                "scope": scope,
                "affected_paths": [
                    "specs/residual-routing.md",
                    "specs/shimei-routing.md",
                ],
                "rationale": "policy evidence recommends blocking this route group before similar protected use",
            }
        ]
    if change == "reroute_route_group":
        return [
            {
                "kind": "routing_policy",
                "action": "prefer_alternative_route",
                "target": route_group,
                "scope": scope,
                "affected_paths": [
                    "specs/residual-routing.md",
                ],
                "rationale": "policy evidence recommends a stronger, cheaper, or more direct route",
            }
        ]
    if change == "keep_route_group":
        return [
            {
                "kind": "routing_policy",
                "action": "record_keep_evidence",
                "target": route_group,
                "scope": scope,
                "affected_paths": [],
                "rationale": "policy evidence supports keeping the current route group under normal gates",
            }
        ]
    if change == "watch_route_group":
        return [
            {
                "kind": "observation",
                "action": "collect_more_outcomes",
                "target": route_group,
                "scope": scope,
                "affected_paths": [],
                "rationale": "policy evidence is useful but not strong enough for a route change",
            }
        ]
    return [
        {
            "kind": "observation",
            "action": "collect_more_calibration",
            "target": route_group,
            "scope": scope,
            "affected_paths": [],
            "rationale": "policy evidence is insufficient for a route change",
        }
    ]


def required_gates(policy_recommendation: str) -> list[str]:
    gates = [
        "validate evidence chain for the route policy report",
        "maintainer review of the proposed route change",
    ]
    if policy_recommendation in {"block", "reroute", "keep"}:
        gates.extend(
            [
                "update route documentation or host overlay only after review",
                "run HIGHBALL route and evidence-chain tests",
                "obtain KENGEN authorization before protected writes or push",
            ]
        )
    else:
        gates.append("collect more calibration traces or outcome ledger entries")
    return gates


def expected_proposal(policy: dict[str, Any], policy_ref: str) -> dict[str, Any]:
    route_group = policy["route_group"]
    recommendation = policy["policy_recommendation"]
    return {
        "proposal_version": "1.0",
        "subject": {
            "route_group": route_group,
            "action_boundary": route_boundary(route_group),
            "policy_recommendation": recommendation,
            "proposed_change": proposed_change(recommendation),
        },
        "inputs": {
            "route_policy_report_ref": policy_ref,
        },
        "evidence": {
            "calibration_recommendation": policy["calibration"]["recommendation"],
            "outcome_signal": policy["outcome"]["calibration_signal"],
            "baseline_recommendation": policy["baseline"]["recommendation"],
            "policy_recommendation": recommendation,
        },
        "candidate_changes": candidate_changes(route_group, recommendation),
        "required_gates": required_gates(recommendation),
        "status": "proposed",
        "non_authorization": "Route change proposals do not modify files, routing rules, authorization state, or SHIMEI bindings.",
    }


def build_report(policy_path: Path) -> dict[str, Any]:
    policy = load_json(policy_path)
    errors = POLICY_VALIDATOR.validate_report(policy)
    if errors:
        raise ValueError("; ".join(f"policy: {error}" for error in errors))
    return expected_proposal(policy, str(policy_path))


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


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


def validate_candidate_change(index: int, value: Any, errors: list[str]) -> dict[str, Any]:
    prefix = f"candidate_changes[{index}]"
    change = validate_fields(prefix, value, CHANGE_FIELDS, errors)
    if not change:
        return {}
    for field in ("kind", "action", "target", "scope", "rationale"):
        if not is_nonempty_string(change.get(field)):
            errors.append(f"{prefix}.{field} must be a non-empty string")
    paths = change.get("affected_paths")
    if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
        errors.append(f"{prefix}.affected_paths must be an array of strings")
    return change


def validate_report(report: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["report must be an object"]

    validate_fields("report", report, TOP_LEVEL_FIELDS, errors)
    if report.get("proposal_version") != "1.0":
        errors.append("proposal_version must be 1.0")

    subject = validate_fields("subject", report.get("subject"), SUBJECT_FIELDS, errors)
    if subject:
        if not is_nonempty_string(subject.get("route_group")):
            errors.append("subject.route_group must be a non-empty string")
        if not is_nonempty_string(subject.get("action_boundary")):
            errors.append("subject.action_boundary must be a non-empty string")
        if subject.get("policy_recommendation") not in POLICY_VALIDATOR.POLICY_RECOMMENDATIONS:
            errors.append("subject.policy_recommendation is invalid")
        if subject.get("proposed_change") not in PROPOSED_CHANGES:
            errors.append("subject.proposed_change is invalid")

    inputs = validate_fields("inputs", report.get("inputs"), INPUT_FIELDS, errors)
    if inputs and not is_nonempty_string(inputs.get("route_policy_report_ref")):
        errors.append("inputs.route_policy_report_ref must be a non-empty string")

    evidence = validate_fields("evidence", report.get("evidence"), EVIDENCE_FIELDS, errors)
    if evidence:
        if evidence.get("calibration_recommendation") not in POLICY_VALIDATOR.CALIBRATION_RECOMMENDATIONS:
            errors.append("evidence.calibration_recommendation is invalid")
        if evidence.get("outcome_signal") not in POLICY_VALIDATOR.OUTCOME_SIGNALS:
            errors.append("evidence.outcome_signal is invalid")
        if evidence.get("baseline_recommendation") not in POLICY_VALIDATOR.BASELINE_RECOMMENDATIONS:
            errors.append("evidence.baseline_recommendation is invalid")
        if evidence.get("policy_recommendation") not in POLICY_VALIDATOR.POLICY_RECOMMENDATIONS:
            errors.append("evidence.policy_recommendation is invalid")

    changes_value = report.get("candidate_changes")
    changes: list[dict[str, Any]] = []
    if not isinstance(changes_value, list) or len(changes_value) == 0:
        errors.append("candidate_changes must be a non-empty array")
    else:
        for index, item in enumerate(changes_value, start=1):
            change = validate_candidate_change(index, item, errors)
            if change:
                changes.append(change)

    if not is_string_list(report.get("required_gates"), min_items=1):
        errors.append("required_gates must be a non-empty array of strings")
    if report.get("status") not in PROPOSAL_STATUSES:
        errors.append("status is invalid")
    if not is_nonempty_string(report.get("non_authorization")):
        errors.append("non_authorization must be a non-empty string")

    if subject and evidence and changes:
        recommendation = subject.get("policy_recommendation")
        if evidence.get("policy_recommendation") != recommendation:
            errors.append("evidence.policy_recommendation differs from subject.policy_recommendation")
        expected_change = proposed_change(recommendation)
        if subject.get("proposed_change") != expected_change:
            errors.append(f"subject.proposed_change should be {expected_change}, got {subject.get('proposed_change')}")
        expected_changes = candidate_changes(subject.get("route_group"), recommendation)
        if report.get("candidate_changes") != expected_changes:
            errors.append("candidate_changes do not match derived route proposal")
        expected_gates = required_gates(recommendation)
        if report.get("required_gates") != expected_gates:
            errors.append("required_gates do not match derived route proposal")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a HIGHBALL route change proposal")
    parser.add_argument("route_policy_report", type=Path)
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    args = parser.parse_args()

    try:
        report = build_report(args.route_policy_report)
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    indent = 2 if args.pretty else None
    print(json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
