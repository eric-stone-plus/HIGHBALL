#!/usr/bin/env python3
"""Validate HIGHBALL residual outcome ledgers."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


TOP_LEVEL_FIELDS = {
    "ledger_version",
    "subject",
    "observation_window",
    "entries",
    "summary",
}
SUBJECT_FIELDS = {"question", "action_boundary", "route_group"}
WINDOW_FIELDS = {"opened_at", "closed_at"}
ENTRY_FIELDS = {
    "id",
    "trace_ref",
    "action_packet_ref",
    "calibration_report_ref",
    "residual_ids",
    "route_group",
    "outcome",
    "evidence_type",
    "evidence",
    "observed_at",
    "impact",
    "notes",
}
SUMMARY_FIELDS = {
    "entry_count",
    "verified_positive_count",
    "verified_negative_count",
    "inconclusive_count",
    "regression_count",
    "calibration_signal",
}
ACTION_BOUNDARIES = {"none", "reversible", "protected_write", "irreversible"}
OUTCOMES = {"verified_positive", "verified_negative", "inconclusive", "regression"}
EVIDENCE_TYPES = {"command", "test", "runtime", "source", "human_review", "external_observation"}
IMPACTS = {"none", "low", "medium", "high", "critical"}
CALIBRATION_SIGNALS = {"supports_route", "weakens_route", "mixed", "insufficient"}


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


def is_nullable_string(value: Any) -> bool:
    return value is None or isinstance(value, str)


def is_string_list(value: Any, *, min_items: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(is_nonempty_string(item) for item in value)
    )


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def load_ledger(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    blocks, raw_json_mode = candidate_blocks(text, path)
    if not blocks:
        raise ValueError("no JSON outcome ledger found")

    ledgers: list[dict[str, Any]] = []
    errors: list[str] = []
    for block_number, block in blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            label = "raw JSON" if raw_json_mode else f"JSON block {block_number}"
            errors.append(f"{label} is invalid JSON: {exc.msg}")
            continue
        if isinstance(parsed, dict) and parsed.get("ledger_version") == "1.0":
            ledgers.append(parsed)

    if len(ledgers) != 1:
        detail = "; ".join(errors) if errors else f"found {len(ledgers)} outcome ledgers"
        raise ValueError(f"expected exactly one outcome ledger; {detail}")
    return ledgers[0]


def validate_object_fields(name: str, value: Any, fields: set[str], errors: list[str]) -> dict[str, Any]:
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


def validate_entry(index: int, entry: Any, seen_ids: set[str], errors: list[str]) -> dict[str, Any]:
    prefix = f"entries[{index}]"
    item = validate_object_fields(prefix, entry, ENTRY_FIELDS, errors)
    if not item:
        return {}

    entry_id = item.get("id")
    if not is_nonempty_string(entry_id):
        errors.append(f"{prefix}.id must be a non-empty string")
    elif entry_id in seen_ids:
        errors.append(f"{prefix}.id is duplicated")
    else:
        seen_ids.add(entry_id)

    refs = [
        item.get("trace_ref"),
        item.get("action_packet_ref"),
        item.get("calibration_report_ref"),
    ]
    if not any(is_nonempty_string(ref) for ref in refs):
        errors.append(f"{prefix} must reference a trace, Action Packet, or calibration report")

    for field in ("trace_ref", "action_packet_ref", "calibration_report_ref"):
        if not is_nullable_string(item.get(field)):
            errors.append(f"{prefix}.{field} must be a string or null")

    if not is_string_list(item.get("residual_ids")):
        errors.append(f"{prefix}.residual_ids must be an array of strings")
    if not is_nonempty_string(item.get("route_group")):
        errors.append(f"{prefix}.route_group must be a non-empty string")
    if item.get("outcome") not in OUTCOMES:
        errors.append(f"{prefix}.outcome is invalid")
    if item.get("evidence_type") not in EVIDENCE_TYPES:
        errors.append(f"{prefix}.evidence_type is invalid")
    if not is_string_list(item.get("evidence"), min_items=1):
        errors.append(f"{prefix}.evidence must be a non-empty array of strings")
    if not is_nonempty_string(item.get("observed_at")):
        errors.append(f"{prefix}.observed_at must be a non-empty string")
    if item.get("impact") not in IMPACTS:
        errors.append(f"{prefix}.impact is invalid")
    if not isinstance(item.get("notes"), str):
        errors.append(f"{prefix}.notes must be a string")

    return item


def derive_signal(counts: dict[str, int]) -> str:
    total = sum(counts.values())
    if total == 0:
        return "insufficient"
    if counts["regression"] > 0:
        return "weakens_route"
    if counts["verified_positive"] > 0 and counts["verified_negative"] > 0:
        return "mixed"
    if counts["verified_negative"] > 0 and counts["verified_positive"] == 0:
        return "weakens_route"
    if counts["verified_positive"] > 0 and counts["verified_negative"] == 0 and counts["inconclusive"] == 0:
        return "supports_route"
    return "insufficient"


def validate_ledger(ledger: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(ledger, dict):
        return ["ledger must be an object"]

    unknown = sorted(set(ledger) - TOP_LEVEL_FIELDS)
    if unknown:
        errors.append(f"ledger has unknown fields: {', '.join(unknown)}")
    missing = sorted(TOP_LEVEL_FIELDS - set(ledger))
    if missing:
        errors.append(f"ledger is missing fields: {', '.join(missing)}")

    if ledger.get("ledger_version") != "1.0":
        errors.append("ledger_version must be 1.0")

    subject = validate_object_fields("subject", ledger.get("subject"), SUBJECT_FIELDS, errors)
    if subject:
        if not is_nonempty_string(subject.get("question")):
            errors.append("subject.question must be a non-empty string")
        if subject.get("action_boundary") not in ACTION_BOUNDARIES:
            errors.append("subject.action_boundary is invalid")
        if not is_nullable_string(subject.get("route_group")):
            errors.append("subject.route_group must be a string or null")

    window = validate_object_fields("observation_window", ledger.get("observation_window"), WINDOW_FIELDS, errors)
    if window:
        if not is_nonempty_string(window.get("opened_at")):
            errors.append("observation_window.opened_at must be a non-empty string")
        closed_at = window.get("closed_at")
        if closed_at is not None and not is_nonempty_string(closed_at):
            errors.append("observation_window.closed_at must be a non-empty string or null")

    entries = ledger.get("entries")
    parsed_entries: list[dict[str, Any]] = []
    if not isinstance(entries, list) or len(entries) == 0:
        errors.append("entries must be a non-empty array")
    else:
        seen_ids: set[str] = set()
        for index, entry in enumerate(entries, start=1):
            parsed = validate_entry(index, entry, seen_ids, errors)
            if parsed:
                parsed_entries.append(parsed)

    summary = validate_object_fields("summary", ledger.get("summary"), SUMMARY_FIELDS, errors)
    if summary:
        for field in (
            "entry_count",
            "verified_positive_count",
            "verified_negative_count",
            "inconclusive_count",
            "regression_count",
        ):
            if not is_nonnegative_int(summary.get(field)):
                errors.append(f"summary.{field} must be a non-negative integer")
        if summary.get("calibration_signal") not in CALIBRATION_SIGNALS:
            errors.append("summary.calibration_signal is invalid")

    if parsed_entries and summary:
        counts = {
            "verified_positive": sum(1 for item in parsed_entries if item.get("outcome") == "verified_positive"),
            "verified_negative": sum(1 for item in parsed_entries if item.get("outcome") == "verified_negative"),
            "inconclusive": sum(1 for item in parsed_entries if item.get("outcome") == "inconclusive"),
            "regression": sum(1 for item in parsed_entries if item.get("outcome") == "regression"),
        }
        expected_summary = {
            "entry_count": len(parsed_entries),
            "verified_positive_count": counts["verified_positive"],
            "verified_negative_count": counts["verified_negative"],
            "inconclusive_count": counts["inconclusive"],
            "regression_count": counts["regression"],
            "calibration_signal": derive_signal(counts),
        }
        for field, expected in expected_summary.items():
            if summary.get(field) != expected:
                errors.append(f"summary.{field} should be {expected}, got {summary.get(field)}")

        subject_route = subject.get("route_group") if subject else None
        if is_nonempty_string(subject_route):
            for index, entry in enumerate(parsed_entries, start=1):
                if entry.get("route_group") != subject_route:
                    errors.append(f"entries[{index}].route_group differs from subject.route_group")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL residual outcome ledger")
    parser.add_argument("ledger_file", type=Path)
    args = parser.parse_args()

    try:
        ledger = load_ledger(args.ledger_file)
    except (OSError, ValueError) as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    errors = validate_ledger(ledger)
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    signal = ledger["summary"]["calibration_signal"]
    if signal == "weakens_route":
        print("[HIGHBALL] outcome ledger valid; calibration signal weakens route", file=sys.stderr)
        return 1

    print(f"[HIGHBALL] outcome ledger valid; calibration signal is {signal}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
