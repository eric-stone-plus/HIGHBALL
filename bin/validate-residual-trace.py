#!/usr/bin/env python3
"""Validate RASHOMON residual traces embedded in verdict markdown.

The validator intentionally uses only the Python standard library. It performs
the schema subset HIGHBALL needs at runtime and enforces protected-action
closure rules for high-risk residuals.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ALLOWED_TOP_LEVEL = {
    "trace_version",
    "question",
    "instrument",
    "residuals",
    "trial_manifest",
    "action_boundary",
    "highball_decision",
}
REQUIRED_TOP_LEVEL = {
    "question",
    "instrument",
    "residuals",
    "action_boundary",
    "highball_decision",
}
ALLOWED_INSTRUMENTS = {"MAGI", "QUINTE", "direct-evidence", "human"}
ALLOWED_ACTION_BOUNDARIES = {"none", "reversible", "protected_write", "irreversible"}
ALLOWED_HIGHBALL_DECISIONS = {"not_applicable", "pass", "review", "block", "escalate"}

ALLOWED_RESIDUAL_FIELDS = {
    "id",
    "severity",
    "type",
    "source",
    "finding",
    "affected_paths",
    "error_signature",
    "evidence",
    "disposition",
    "required_closure",
    "closure_state",
    "closure_evidence",
    "scope",
}
REQUIRED_RESIDUAL_FIELDS = ALLOWED_RESIDUAL_FIELDS
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "P0"}
HIGH_RISK_SEVERITIES = {"HIGH", "CRITICAL", "P0"}
ALLOWED_TYPES = {
    "contradiction",
    "omission",
    "evidence_gap",
    "confidence_mismatch",
    "drift",
    "execution_mismatch",
    "silent_collapse",
}
ALLOWED_DISPOSITIONS = {"verified", "falsified", "unresolved", "escalated", "discarded"}
ALLOWED_REQUIRED_CLOSURE = {
    "none",
    "edit",
    "test",
    "command",
    "block",
    "waiver",
    "human_review",
}
ALLOWED_CLOSURE_STATES = {"open", "closed", "blocked", "waived", "not_applicable"}
ALLOWED_BASE_MODEL_RELATIONS = {
    "unknown",
    "same_model",
    "same_family",
    "heterogeneous_models",
    "mixed",
    "human",
    "direct_evidence",
}
ALLOWED_TRIAL_MANIFEST_FIELDS = {
    "manifest_version",
    "base_model_relation",
    "perspective_count",
    "perspectives",
    "perturbation_axes",
    "independence_controls",
    "contamination_risks",
    "cost",
}
REQUIRED_TRIAL_MANIFEST_FIELDS = ALLOWED_TRIAL_MANIFEST_FIELDS
ALLOWED_PERSPECTIVE_FIELDS = {
    "id",
    "role",
    "route",
    "artifact",
    "prompt_hash",
    "independent_first_pass",
}
REQUIRED_PERSPECTIVE_FIELDS = ALLOWED_PERSPECTIVE_FIELDS
ALLOWED_COST_FIELDS = {
    "total_tokens",
    "wall_time_seconds",
    "tool_calls",
    "human_minutes",
}
REQUIRED_COST_FIELDS = ALLOWED_COST_FIELDS


class Finding:
    def __init__(self, severity: str, message: str) -> None:
        self.severity = severity
        self.message = message

    def __str__(self) -> str:
        return f"[{self.severity}] {self.message}"


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


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_string_array(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def is_nonempty_string_array(value: Any) -> bool:
    return isinstance(value, list) and all(is_nonempty_string(item) for item in value)


def is_closure_evidence_array(value: Any) -> bool:
    return isinstance(value, list) and all(item is None or isinstance(item, str) for item in value)


def has_closure_evidence(value: Any) -> bool:
    return (
        isinstance(value, list)
        and any(isinstance(item, str) and item.strip() for item in value)
    )


def validate_trial_manifest(manifest: Any, block_number: int) -> list[Finding]:
    findings: list[Finding] = []
    prefix = f"JSON block {block_number} trial_manifest"

    if not isinstance(manifest, dict):
        return [Finding("ERROR", f"{prefix} must be an object")]

    unknown = sorted(set(manifest) - ALLOWED_TRIAL_MANIFEST_FIELDS)
    if unknown:
        findings.append(Finding("ERROR", f"{prefix} has unknown fields: {', '.join(unknown)}"))

    missing = sorted(REQUIRED_TRIAL_MANIFEST_FIELDS - set(manifest))
    if missing:
        findings.append(Finding("ERROR", f"{prefix} is missing fields: {', '.join(missing)}"))

    if not is_nonempty_string(manifest.get("manifest_version")):
        findings.append(Finding("ERROR", f"{prefix} manifest_version must be a non-empty string"))

    if manifest.get("base_model_relation") not in ALLOWED_BASE_MODEL_RELATIONS:
        findings.append(Finding("ERROR", f"{prefix} base_model_relation is invalid"))

    perspective_count = manifest.get("perspective_count")
    if not isinstance(perspective_count, int) or perspective_count < 1:
        findings.append(Finding("ERROR", f"{prefix} perspective_count must be a positive integer"))

    perspectives = manifest.get("perspectives")
    if not isinstance(perspectives, list) or len(perspectives) < 1:
        findings.append(Finding("ERROR", f"{prefix} perspectives must be a non-empty array"))
    else:
        if isinstance(perspective_count, int) and perspective_count != len(perspectives):
            findings.append(Finding("ERROR", f"{prefix} perspective_count must match perspectives length"))
        seen_ids: set[str] = set()
        for index, perspective in enumerate(perspectives, start=1):
            perspective_prefix = f"{prefix} perspective {index}"
            if not isinstance(perspective, dict):
                findings.append(Finding("ERROR", f"{perspective_prefix} is not an object"))
                continue

            unknown_perspective = sorted(set(perspective) - ALLOWED_PERSPECTIVE_FIELDS)
            if unknown_perspective:
                findings.append(Finding("ERROR", f"{perspective_prefix} has unknown fields: {', '.join(unknown_perspective)}"))

            missing_perspective = sorted(REQUIRED_PERSPECTIVE_FIELDS - set(perspective))
            if missing_perspective:
                findings.append(Finding("ERROR", f"{perspective_prefix} is missing fields: {', '.join(missing_perspective)}"))

            perspective_id = perspective.get("id")
            if not is_nonempty_string(perspective_id):
                findings.append(Finding("ERROR", f"{perspective_prefix} id must be a non-empty string"))
            elif perspective_id in seen_ids:
                findings.append(Finding("ERROR", f"{perspective_prefix} has duplicate id {perspective_id}"))
            else:
                seen_ids.add(perspective_id)

            if not is_nonempty_string(perspective.get("role")):
                findings.append(Finding("ERROR", f"{perspective_prefix} role must be a non-empty string"))

            for field in ("route", "artifact", "prompt_hash"):
                value = perspective.get(field)
                if value is not None and not isinstance(value, str):
                    findings.append(Finding("ERROR", f"{perspective_prefix} {field} must be a string or null"))

            if not isinstance(perspective.get("independent_first_pass"), bool):
                findings.append(Finding("ERROR", f"{perspective_prefix} independent_first_pass must be boolean"))

    for field in ("perturbation_axes", "independence_controls", "contamination_risks"):
        if not is_nonempty_string_array(manifest.get(field)):
            findings.append(Finding("ERROR", f"{prefix} {field} must be an array of non-empty strings"))

    cost = manifest.get("cost")
    if not isinstance(cost, dict):
        findings.append(Finding("ERROR", f"{prefix} cost must be an object"))
    else:
        unknown_cost = sorted(set(cost) - ALLOWED_COST_FIELDS)
        if unknown_cost:
            findings.append(Finding("ERROR", f"{prefix} cost has unknown fields: {', '.join(unknown_cost)}"))

        missing_cost = sorted(REQUIRED_COST_FIELDS - set(cost))
        if missing_cost:
            findings.append(Finding("ERROR", f"{prefix} cost is missing fields: {', '.join(missing_cost)}"))

        for field in ("total_tokens", "wall_time_seconds", "tool_calls"):
            value = cost.get(field)
            if value is not None and (not isinstance(value, int) or value < 0):
                findings.append(Finding("ERROR", f"{prefix} cost.{field} must be a non-negative integer or null"))

        human_minutes = cost.get("human_minutes")
        if human_minutes is not None and (
            not isinstance(human_minutes, (int, float)) or human_minutes < 0
        ):
            findings.append(Finding("ERROR", f"{prefix} cost.human_minutes must be a non-negative number or null"))

    return findings


def validate_trace(trace: Any, block_number: int) -> list[Finding]:
    findings: list[Finding] = []

    if not isinstance(trace, dict):
        return [Finding("ERROR", f"JSON block {block_number} is not an object")]

    unknown = sorted(set(trace) - ALLOWED_TOP_LEVEL)
    if unknown:
        findings.append(Finding("ERROR", f"JSON block {block_number} has unknown top-level fields: {', '.join(unknown)}"))

    missing = sorted(REQUIRED_TOP_LEVEL - set(trace))
    if missing:
        findings.append(Finding("ERROR", f"JSON block {block_number} is missing top-level fields: {', '.join(missing)}"))

    if "trace_version" in trace and not isinstance(trace["trace_version"], str):
        findings.append(Finding("ERROR", f"JSON block {block_number} trace_version must be a string"))

    if not is_nonempty_string(trace.get("question")):
        findings.append(Finding("ERROR", f"JSON block {block_number} question must be a non-empty string"))

    if trace.get("instrument") not in ALLOWED_INSTRUMENTS:
        findings.append(Finding("ERROR", f"JSON block {block_number} instrument is invalid"))

    if trace.get("action_boundary") not in ALLOWED_ACTION_BOUNDARIES:
        findings.append(Finding("ERROR", f"JSON block {block_number} action_boundary is invalid"))

    if trace.get("highball_decision") not in ALLOWED_HIGHBALL_DECISIONS:
        findings.append(Finding("ERROR", f"JSON block {block_number} highball_decision is invalid"))

    if "trial_manifest" in trace:
        findings.extend(validate_trial_manifest(trace["trial_manifest"], block_number))

    action_boundary = trace.get("action_boundary")
    highball_decision = trace.get("highball_decision")
    residuals = trace.get("residuals")
    if not isinstance(residuals, list):
        findings.append(Finding("ERROR", f"JSON block {block_number} residuals must be an array"))
        return findings

    high_risk_open = False
    high_risk_unsupported = False
    seen_ids: set[str] = set()
    for index, residual in enumerate(residuals, start=1):
        prefix = f"JSON block {block_number} residual {index}"
        if not isinstance(residual, dict):
            findings.append(Finding("ERROR", f"{prefix} is not an object"))
            continue

        unknown_residual = sorted(set(residual) - ALLOWED_RESIDUAL_FIELDS)
        if unknown_residual:
            findings.append(Finding("ERROR", f"{prefix} has unknown fields: {', '.join(unknown_residual)}"))

        missing_residual = sorted(REQUIRED_RESIDUAL_FIELDS - set(residual))
        if missing_residual:
            findings.append(Finding("ERROR", f"{prefix} is missing fields: {', '.join(missing_residual)}"))

        residual_id = residual.get("id")
        if not is_nonempty_string(residual_id):
            findings.append(Finding("ERROR", f"{prefix} id must be a non-empty string"))
        elif residual_id in seen_ids:
            findings.append(Finding("ERROR", f"{prefix} has duplicate id {residual_id}"))
        else:
            seen_ids.add(residual_id)

        severity = residual.get("severity")
        if severity not in ALLOWED_SEVERITIES:
            findings.append(Finding("ERROR", f"{prefix} severity is invalid"))

        if residual.get("type") not in ALLOWED_TYPES:
            findings.append(Finding("ERROR", f"{prefix} type is invalid"))

        if not is_nonempty_string(residual.get("source")):
            findings.append(Finding("ERROR", f"{prefix} source must be a non-empty string"))

        if not is_nonempty_string(residual.get("finding")):
            findings.append(Finding("ERROR", f"{prefix} finding must be a non-empty string"))

        if not is_string_array(residual.get("affected_paths")):
            findings.append(Finding("ERROR", f"{prefix} affected_paths must be an array of strings"))

        if residual.get("error_signature") is not None and not isinstance(residual.get("error_signature"), str):
            findings.append(Finding("ERROR", f"{prefix} error_signature must be a string or null"))

        if residual.get("evidence") is not None and not isinstance(residual.get("evidence"), str):
            findings.append(Finding("ERROR", f"{prefix} evidence must be a string or null"))

        if residual.get("disposition") not in ALLOWED_DISPOSITIONS:
            findings.append(Finding("ERROR", f"{prefix} disposition is invalid"))

        if residual.get("required_closure") not in ALLOWED_REQUIRED_CLOSURE:
            findings.append(Finding("ERROR", f"{prefix} required_closure is invalid"))

        closure_state = residual.get("closure_state")
        if closure_state not in ALLOWED_CLOSURE_STATES:
            findings.append(Finding("ERROR", f"{prefix} closure_state is invalid"))

        closure_evidence = residual.get("closure_evidence")
        if not is_closure_evidence_array(closure_evidence):
            findings.append(Finding("ERROR", f"{prefix} closure_evidence must be an array of strings or nulls"))

        if not isinstance(residual.get("scope"), str):
            findings.append(Finding("ERROR", f"{prefix} scope must be a string"))

        if severity in HIGH_RISK_SEVERITIES:
            if closure_state == "open":
                high_risk_open = True
            elif closure_state in {"closed", "blocked", "not_applicable", "waived"}:
                if not has_closure_evidence(closure_evidence):
                    high_risk_unsupported = True
                if closure_state in {"closed", "blocked", "not_applicable", "waived"} and not is_nonempty_string(residual.get("scope")):
                    high_risk_unsupported = True

            if closure_state == "open":
                findings.append(Finding("BLOCK", f"{prefix} {residual_id or 'unknown'} is high-risk and open"))
            elif closure_state in {"closed", "blocked", "not_applicable"} and not has_closure_evidence(closure_evidence):
                findings.append(Finding("BLOCK", f"{prefix} {residual_id or 'unknown'} has {closure_state} without closure evidence"))
            elif closure_state == "waived":
                if not has_closure_evidence(closure_evidence):
                    findings.append(Finding("BLOCK", f"{prefix} {residual_id or 'unknown'} waiver lacks evidence"))
                if not is_nonempty_string(residual.get("scope")):
                    findings.append(Finding("BLOCK", f"{prefix} {residual_id or 'unknown'} waiver lacks scope"))
            elif closure_state in {"closed", "blocked", "not_applicable"} and not is_nonempty_string(residual.get("scope")):
                findings.append(Finding("BLOCK", f"{prefix} {residual_id or 'unknown'} has {closure_state} without scope"))

    if action_boundary in {"protected_write", "irreversible"}:
        if highball_decision == "pass" and high_risk_open:
            findings.append(Finding("BLOCK", f"JSON block {block_number} decision pass conflicts with open high-risk residuals"))
        if highball_decision == "pass" and high_risk_unsupported:
            findings.append(Finding("BLOCK", f"JSON block {block_number} decision pass conflicts with unsupported high-risk closure"))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate residual trace JSON blocks in a verdict file")
    parser.add_argument("verdict_file", type=Path)
    args = parser.parse_args()

    try:
        text = args.verdict_file.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[BANNIN] ERROR: cannot read verdict file: {exc}", file=sys.stderr)
        return 2

    blocks, raw_json_mode = candidate_blocks(text, args.verdict_file)
    if not blocks:
        print("[BANNIN] WARNING: verdict has no JSON residual closure ledger; closure cannot be verified", file=sys.stderr)
        return 0

    saw_trace = False
    all_findings: list[Finding] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            all_findings.append(Finding("ERROR", f"{label} is invalid JSON: {exc.msg}"))
            continue

        if isinstance(parsed, dict) and isinstance(parsed.get("residuals"), list):
            saw_trace = True
            all_findings.extend(validate_trace(parsed, block_number))

    if not saw_trace:
        if raw_json_mode:
            print("[BANNIN] ERROR: raw JSON file does not contain a residuals array", file=sys.stderr)
            return 2
        else:
            print("[BANNIN] WARNING: verdict JSON found but no residual closure ledger; closure cannot be verified", file=sys.stderr)
            return 0

    for finding in all_findings:
        print(f"[BANNIN] {finding}", file=sys.stderr)

    if any(finding.severity == "ERROR" for finding in all_findings):
        return 2
    if any(finding.severity == "BLOCK" for finding in all_findings):
        return 1

    print("[BANNIN] residual closure ledger verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
