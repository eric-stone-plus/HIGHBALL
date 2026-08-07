#!/usr/bin/env python3
"""Verify QUINTE and MAGI product bundles against the active HIGHBALL contract."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import uuid
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

BRIEF_FIELDS = (
    "brief_version",
    "question",
    "context",
    "evidence_roots",
    "snapshot_ignore",
    "attachments",
    "action_scope",
    "affected_paths",
    "action_binding_sha256",
)
MANIFEST_FIELDS = {
    "manifest_version",
    "run_id",
    "created_at",
    "updated_at",
    "status",
    "brief_sha256",
    "policy_sha256",
    "snapshot_sha256",
    "runtime_sha256",
    "protocol_version",
    "effective_model",
    "seat_binding",
    "route_bindings",
    "sandbox_mode",
    "current_phase",
    "error",
    "r3_input_receipt",
    "primary_arbiter_challenge",
    "primary_arbiter_submission",
    "result_sha256",
}
RESULT_FIELDS = {
    "result_version",
    "run_id",
    "status",
    "brief_sha256",
    "question",
    "action_scope",
    "affected_paths",
    "action_binding_sha256",
    "seat_binding",
    "route_bindings",
    "summary",
    "recommendation",
    "dissent",
    "residuals",
    "trial_manifest",
}
RESIDUAL_FIELDS = {
    "id",
    "severity",
    "residual_type",
    "source",
    "finding",
    "evidence_refs",
    "disposition",
    "required_closure",
    "closure_state",
    "closure_evidence",
    "scope",
}
TRIAL_FIELDS = {
    "manifest_version",
    "base_model_relation",
    "perspective_count",
    "perspectives",
    "perturbation_axes",
    "independence_controls",
    "contamination_risks",
    "wall_time_seconds",
}
PERSPECTIVE_FIELDS = {
    "party_id",
    "route_id",
    "r1_artifact",
    "r2_artifact",
    "independent_first_pass",
}
PARTIES = [
    "Party A",
    "Party B",
    "Party C",
    "Party D",
    "Party E",
    "Counterpart Arbiter",
    "Primary Arbiter",
]
HOST_RECEIPT_FIELDS = {
    "host_receipt_version",
    "invocation_id",
    "receipt_path",
    "operation",
    "observed_at",
    "state_root",
    "state",
    "run_id",
    "preflight",
    "brief",
    "manifest",
    "result",
    "recovery",
}
HOST_STATE_FIELDS = {"code", "active_run_ids", "worker", "attempts", "blockers"}
HOST_STATE_CODES = {
    "ready",
    "preflight_failed",
    "active_run_present",
    "created",
    "started",
    "launch_failed",
    "observed",
    "terminal",
    "reconciled",
    "no_active_run",
    "ambiguous_active_runs",
}
HOST_MANIFEST_FIELDS = {
    "status",
    "manifest_version",
    "brief_sha256",
    "policy_sha256",
    "snapshot_sha256",
    "runtime_sha256",
    "worker_pid",
    "error",
    "result_sha256",
}
HOST_RESULT_FIELDS = {"verified", "actionable", "contract_version", "sha256", "path"}
HOST_RECOVERY_FIELDS = {"outcome", "launch_safe", "receipt_path"}
HOST_REQUIRED_MANIFEST_FIELDS = {
    "status",
    "manifest_version",
    "brief_sha256",
    "policy_sha256",
    "snapshot_sha256",
    "runtime_sha256",
    "result_sha256",
}
SEAT_BINDING_FIELDS = {"seat_id", "family", "provider", "text_model", "multimodal_model"}
ROUTE_BINDING_FIELDS = {
    "party_id",
    "route_id",
    "adapter",
    "executable",
    "family",
    "provider",
    "text_model",
    "multimodal_model",
    "perspective",
}
MAGI_SEAT_FIELDS = {
    "seat_id",
    "family",
    "provider",
    "text_model",
    "multimodal_model",
    "profile_sha256",
    "thesis_sha256",
    "dossier_ref",
    "dossier_sha256",
    "quinte_run_id",
    "quinte_manifest_sha256",
    "quinte_result_sha256",
    "assigned_evidence_refs",
    "evidence_mapping_ref",
    "evidence_mapping_sha256",
}
MAGI_REVIEW_FIELDS = {
    "artifact_ref",
    "sha256",
    "reviewer_seat_id",
    "reviewer_family",
    "reviewer_provider",
    "reviewer_text_model",
    "reviewer_multimodal_model",
    "reviewer_profile_id",
    "reviewer_profile_sha256",
    "reviewer_profile_source_sha256",
    "reviewer_agent_config_sha256",
    "methodology_trace_sha256",
    "reviewer_execution_receipt_ref",
    "reviewer_execution_receipt_sha256",
}
MAGI_FINAL_ADJUDICATOR_FIELDS = {
    "family",
    "provider",
    "text_model",
    "multimodal_model",
    "agent_config_sha256",
    "execution_mode",
    "execution_receipt_ref",
    "execution_receipt_sha256",
}
MAGI_EXECUTION_RECEIPT_FIELDS = {
    "receipt_version",
    "kind",
    "service",
    "seat_id",
    "image_digest",
    "profile_sha256",
    "agent_config_sha256",
    "input_packet_sha256",
    "output_artifact_sha256",
    "execution_mode",
}
MAGI_ASSIGNMENT_FIELDS = {
    "assignment_plan_version",
    "trial_id",
    "objective",
    "global_checks",
    "seats",
    "cross_review_obligations",
    "finale_condition",
    "limitations",
    "plan_binding_sha256",
}
MAGI_ASSIGNMENT_SEAT_FIELDS = {
    "seat_id",
    "family",
    "provider",
    "text_model",
    "multimodal_model",
    "profile_id",
    "profile_source_sha256",
    "container_service",
    "image_digest",
    "primary_focus",
    "mandatory_global_checks",
    "evidence_refs",
    "carrier_capabilities",
    "cost_rationale",
    "independence_class",
    "limitations",
}
MAGI_ASSIGNMENT_REVIEW_FIELDS = {
    "reviewer_seat_id",
    "subject_seat_id",
    "review_kind",
    "required_checks",
    "evidence_refs",
    "limitations",
}
MAGI_ASSIGNMENT_CARRIER_FIELDS = {
    "carrier_id",
    "snapshot_media_classes",
    "multimodal_media_types",
    "allow_sampled_video",
}
MAGI_ASSIGNMENT_FINALE_FIELDS = {
    "allowed_outcomes",
    "material_residual_states",
    "required_receipts",
    "stop_rule",
}
MAGI_EVIDENCE_MANIFEST_FIELDS = {
    "evidence_manifest_version",
    "original_brief_ref",
    "original_brief_sha256",
    "source_root",
    "staged_root_ref",
    "source_files",
    "derived_frames",
    "evidence_set_sha256",
    "limitations",
}
MAGI_EVIDENCE_SOURCE_FIELDS = {
    "id",
    "source_path",
    "source_relative_path",
    "staged_ref",
    "evidence_ref",
    "sha256",
    "size_bytes",
    "media_type",
    "media_class",
    "exposure_modes",
}
MAGI_EVIDENCE_FRAME_FIELDS = {
    "id",
    "source_id",
    "source_evidence_ref",
    "timestamp_ms",
    "staged_ref",
    "evidence_ref",
    "sha256",
    "size_bytes",
    "media_type",
    "media_class",
    "exposure_modes",
    "derivation_tool",
    "derivation_command",
    "derivation_command_sha256",
}
MAGI_EVIDENCE_COVERAGE_FIELDS = {
    "coverage_receipt_version",
    "coverage_status",
    "coverage_scope",
    "original_brief_sha256",
    "evidence_manifest_ref",
    "evidence_manifest_sha256",
    "artifacts",
    "exposed_evidence",
    "cited_evidence",
    "exposed_but_uncited",
    "unknown_citations",
    "unreviewed_media",
    "declared_limitations",
    "limitations",
    "receipt_binding_sha256",
}
MAGI_COVERAGE_ARTIFACT_FIELDS = {"artifact_ref", "sha256", "evidence_refs"}
MAGI_DOSSIER_FIELDS = {
    "dossier_version",
    "seat_id",
    "profile_id",
    "profile_ref",
    "profile_sha256",
    "reviewer_profile_ref",
    "reviewer_profile_sha256",
    "thesis_ref",
    "thesis_sha256",
    "perspective_input_ref",
    "perspective_input_sha256",
    "original_brief_sha256",
    "derived_quinte_brief_sha256",
    "quinte_run_ref",
    "quinte_manifest_sha256",
    "quinte_result_sha256",
    "assignment_plan_sha256",
    "assigned_evidence_refs",
    "evidence_mapping_ref",
    "evidence_mapping_sha256",
}
MAGI_REVIEW_ARTIFACT_FIELDS = {
    "review_version",
    "reviewer_alias",
    "subject_alias",
    "reviewer_profile_binding",
    "methodology_trace",
    "summary",
    "findings",
    "dissent",
}
MAGI_REVIEW_PROFILE_BINDING_FIELDS = {
    "profile_id",
    "profile_sha256",
    "profile_source_sha256",
    "thesis_sha256",
}
MAGI_FINAL_VERDICT_FIELDS = {
    "verdict_version",
    "decision",
    "summary",
    "recommendation",
    "findings",
    "dissent",
}
MAGI_RESIDUAL_TRACE_FIELDS = {
    "trace_version",
    "question",
    "instrument",
    "residuals",
    "trial_manifest",
    "action_boundary",
    "highball_decision",
    "action_binding_sha256",
}
MAGI_RESIDUAL_REDUCTION_FIELDS = {
    "receipt_version",
    "metric_scope",
    "baseline_scope",
    "seat_residual_source_refs",
    "cross_review_source_refs",
    "cross_review_novel_source_refs",
    "cross_review_linked_source_refs",
    "challenged_seat_source_refs",
    "final_represented_source_refs",
    "final_falsified_or_discarded_source_refs",
    "final_finding_ids",
    "final_unresolved_finding_ids",
    "counts",
    "limitations",
    "binding_sha256",
}
MAGI_RESIDUAL_REDUCTION_COUNT_FIELDS = {
    "seat_residuals",
    "cross_review_findings",
    "cross_review_novel_findings",
    "cross_review_linked_findings",
    "challenged_seat_residuals",
    "final_represented_sources",
    "final_falsified_or_discarded_sources",
    "final_findings",
    "final_unresolved_findings",
}

MAGI_PRODUCT_FIELDS = {
    "product_version",
    "product_sha256",
    "trial_id",
    "status",
    "runtime_sha256",
    "agent_config_sha256",
    "builder_config_sha256",
    "assignment_plan_ref",
    "assignment_plan_sha256",
    "evidence_manifest_ref",
    "evidence_manifest_sha256",
    "evidence_coverage_ref",
    "evidence_coverage_sha256",
    "original_brief_sha256",
    "action_binding_sha256",
    "question",
    "action_scope",
    "affected_paths",
    "final_decision",
    "final_dissent",
    "final_verdict_ref",
    "final_verdict_sha256",
    "residual_trace_ref",
    "residual_trace_sha256",
    "residual_reduction_ref",
    "residual_reduction_sha256",
    "seats",
    "cross_reviews",
    "final_adjudicator",
}


def trusted_runs_root() -> Path:
    state_root = os.environ.get("QUINTE_HOME")
    root = Path(state_root).expanduser() if state_root else Path.home() / ".quinte"
    return (root / "runs").resolve()


def is_canonical_uuid_v7(value: Any) -> bool:
    """Return whether *value* is QUINTE's canonical UUIDv7 spelling.

    Host receipt v1 binds filenames and run identities to the UUIDv7 values
    emitted by QUINTE.  Keep this stricter check local to the host contract;
    historical standalone Result validation intentionally retains its older
    canonical-UUID acceptance range.
    """
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return (
        parsed.version == 7
        and parsed.variant == uuid.RFC_4122
        and str(parsed) == value
    )


def active_quinte_binary() -> Path | None:
    configured = os.environ.get("HIGHBALL_QUINTE_BIN")
    if not configured:
        return None
    configured_path = Path(configured)
    if not configured_path.is_absolute():
        raise ValueError("HIGHBALL_QUINTE_BIN must be an absolute path")
    candidate = configured_path
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ValueError(
            "HIGHBALL_QUINTE_BIN must name an executable regular file"
        )
    return candidate.resolve()


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def string_list(value: Any, *, nonempty_items: bool = False) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, str) and (not nonempty_items or bool(item.strip()))
        for item in value
    )


def exact_fields(value: dict[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        errors.append(f"{label} has unknown fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"{label} is missing fields: {', '.join(missing)}")


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def validate_residual(value: Any, index: int, errors: list[str]) -> None:
    label = f"quinte result residuals[{index}]"
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return
    exact_fields(value, RESIDUAL_FIELDS, label, errors)
    if not nonempty(value.get("id")):
        errors.append(f"{label}.id must be a non-empty string")
    if value.get("severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "P0"}:
        errors.append(f"{label}.severity is invalid")
    for field in ("residual_type", "source", "finding", "required_closure", "scope"):
        if not nonempty(value.get(field)):
            errors.append(f"{label}.{field} must be a non-empty string")
    for field in ("evidence_refs", "closure_evidence"):
        if not string_list(value.get(field)):
            errors.append(f"{label}.{field} must be an array of strings")
    if value.get("disposition") not in {"verified", "falsified", "unresolved", "escalated", "discarded"}:
        errors.append(f"{label}.disposition is invalid")
    if value.get("closure_state") not in {"open", "closed", "blocked", "waived", "not_applicable"}:
        errors.append(f"{label}.closure_state is invalid")


def validate_trial_manifest(value: Any, route_bindings: Any, errors: list[str]) -> None:
    label = "quinte result trial_manifest"
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return
    exact_fields(value, TRIAL_FIELDS, label, errors)
    if value.get("manifest_version") != CONTRACTS.QUINTE_TRIAL_MANIFEST_VERSION:
        errors.append(f"{label}.manifest_version is unsupported")
    if value.get("base_model_relation") != "same_model":
        errors.append(f"{label}.base_model_relation must be same_model")
    perspectives = value.get("perspectives")
    if value.get("perspective_count") != 5 or not isinstance(perspectives, list) or len(perspectives) != 5:
        errors.append(f"{label} must contain exactly five perspectives")
        perspectives = perspectives if isinstance(perspectives, list) else []
    for index, perspective in enumerate(perspectives):
        item_label = f"{label}.perspectives[{index}]"
        if not isinstance(perspective, dict):
            errors.append(f"{item_label} must be an object")
            continue
        exact_fields(perspective, PERSPECTIVE_FIELDS, item_label, errors)
        expected_party = PARTIES[index] if index < 5 else None
        expected_route = (
            route_bindings[index].get("route_id")
            if isinstance(route_bindings, list)
            and index < len(route_bindings)
            and isinstance(route_bindings[index], dict)
            else None
        )
        if perspective.get("party_id") != expected_party or perspective.get("route_id") != expected_route:
            errors.append(f"{item_label} does not match the bound QUINTE route")
        if perspective.get("r1_artifact") != f"lanes/R1/{expected_route}/accepted.json":
            errors.append(f"{item_label}.r1_artifact is invalid")
        if perspective.get("r2_artifact") != f"lanes/R2/{expected_route}/accepted.json":
            errors.append(f"{item_label}.r2_artifact is invalid")
        if perspective.get("independent_first_pass") is not True:
            errors.append(f"{item_label}.independent_first_pass must be true")
    for field in ("perturbation_axes", "independence_controls", "contamination_risks"):
        if not string_list(value.get(field), nonempty_items=True):
            errors.append(f"{label}.{field} must be an array of non-empty strings")
    wall_time = value.get("wall_time_seconds")
    if wall_time is not None and (not isinstance(wall_time, int) or isinstance(wall_time, bool) or wall_time < 0):
        errors.append(f"{label}.wall_time_seconds must be a non-negative integer or null")


def validate_binding(value: Any, label: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return None
    exact_fields(value, SEAT_BINDING_FIELDS, label, errors)
    for field in SEAT_BINDING_FIELDS:
        if not nonempty(value.get(field)) or any(character.isspace() for character in value[field]):
            errors.append(f"{label}.{field} must be a non-empty identifier")
    return value


def validate_route_bindings(
    value: Any, seat: dict[str, Any] | None, label: str, errors: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 7:
        errors.append(f"{label} must contain exactly seven role bindings")
        return []
    routes: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{item_label} must be an object")
            continue
        exact_fields(item, ROUTE_BINDING_FIELDS, item_label, errors)
        if item.get("party_id") != PARTIES[index]:
            errors.append(f"{item_label}.party_id is out of order")
        if not nonempty(item.get("route_id")) or item.get("route_id") in seen_ids:
            errors.append(f"{item_label}.route_id must be a unique non-empty string")
        else:
            seen_ids.add(item["route_id"])
        for field in ("adapter", "executable", "family", "provider", "text_model", "multimodal_model"):
            if not nonempty(item.get(field)):
                errors.append(f"{item_label}.{field} must be a non-empty string")
        if not isinstance(item.get("perspective"), str):
            errors.append(f"{item_label}.perspective must be a string")
        if seat is not None:
            for field in ("family", "provider", "text_model", "multimodal_model"):
                if item.get(field) != seat.get(field):
                    errors.append(f"{item_label}.{field} violates the single-family seat binding")
        routes.append(item)
    return routes


def validate_result(result: dict[str, Any], errors: list[str]) -> None:
    exact_fields(result, RESULT_FIELDS, "quinte result", errors)
    if result.get("result_version") != CONTRACTS.QUINTE_RESULT_VERSION:
        errors.append(
            f"quinte result_version must be {CONTRACTS.QUINTE_RESULT_VERSION}; older results are archived-only"
        )
    try:
        if str(uuid.UUID(str(result.get("run_id")))) != result.get("run_id"):
            raise ValueError
    except (ValueError, AttributeError):
        errors.append("quinte result run_id must be a canonical UUID")
    if result.get("status") not in {"completed", "degraded"}:
        errors.append("quinte result status is invalid")
    if not CONTRACTS.is_digest(result.get("brief_sha256")):
        errors.append("quinte result brief_sha256 is invalid")
    if not nonempty(result.get("question")):
        errors.append("quinte result question must be a non-empty string")
    if result.get("action_scope") is not None and not isinstance(result.get("action_scope"), str):
        errors.append("quinte result action_scope must be a string or null")
    if not string_list(result.get("affected_paths")):
        errors.append("quinte result affected_paths must be an array of strings")
    if not CONTRACTS.is_digest(result.get("action_binding_sha256")):
        errors.append("quinte result action_binding_sha256 must be a sha256 digest")
    for field in ("summary", "recommendation"):
        if not nonempty(result.get(field)):
            errors.append(f"quinte result {field} must be a non-empty string")
    if not string_list(result.get("dissent")):
        errors.append("quinte result dissent must be an array of strings")
    residuals = result.get("residuals")
    if not isinstance(residuals, list):
        errors.append("quinte result residuals must be an array")
    else:
        seen_ids: set[str] = set()
        for index, residual in enumerate(residuals):
            validate_residual(residual, index, errors)
            if isinstance(residual, dict) and nonempty(residual.get("id")):
                if residual["id"] in seen_ids:
                    errors.append(f"quinte result residual id is duplicated: {residual['id']}")
                seen_ids.add(residual["id"])
    seat = validate_binding(result.get("seat_binding"), "quinte result seat_binding", errors)
    routes = validate_route_bindings(
        result.get("route_bindings"), seat, "quinte result route_bindings", errors
    )
    validate_trial_manifest(result.get("trial_manifest"), routes, errors)


def validate_brief(brief: dict[str, Any], errors: list[str]) -> None:
    exact_fields(brief, set(BRIEF_FIELDS), "quinte brief", errors)
    if brief.get("brief_version") != CONTRACTS.QUINTE_BRIEF_VERSION:
        errors.append(f"quinte brief_version must be {CONTRACTS.QUINTE_BRIEF_VERSION}")
    if not nonempty(brief.get("question")):
        errors.append("quinte brief question must be a non-empty string")
    if brief.get("context") is not None and not isinstance(brief.get("context"), str):
        errors.append("quinte brief context must be a string or null")
    for field in ("evidence_roots", "snapshot_ignore", "attachments", "affected_paths"):
        if not string_list(brief.get(field)):
            errors.append(f"quinte brief {field} must be an array of strings")
    if brief.get("action_scope") is not None and not isinstance(brief.get("action_scope"), str):
        errors.append("quinte brief action_scope must be a string or null")
    if not CONTRACTS.is_digest(brief.get("action_binding_sha256")):
        errors.append("quinte brief action_binding_sha256 must be a sha256 digest")


def canonical_brief_sha256(brief: dict[str, Any]) -> str:
    ordered = {field: brief.get(field) for field in BRIEF_FIELDS}
    encoded = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return CONTRACTS.sha256_bytes(encoded)


def resolve_ref(ref: str, base_dir: Path | None) -> Path:
    path = Path(ref)
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    return path.resolve()


def _path_is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def load_quinte_host_receipt(
    ref: str,
    request: dict[str, Any],
    *,
    base_dir: Path | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Read a durable receipt or a saved `host inspect --json` envelope.

    HIGHBALL intentionally performs no QUINTE command.  The receipt is an
    observation supplied by the caller; all product files are re-read and
    checked below before they can enter an Action Packet.
    """
    errors: list[str] = []
    supplied = resolve_ref(ref, base_dir)
    if not supplied.is_file():
        return None, [f"QUINTE host receipt does not exist: {ref}"]
    supplied_raw: bytes
    try:
        supplied_raw = supplied.read_bytes()
    except OSError as exc:
        return None, [f"QUINTE host receipt cannot be read: {exc}"]
    try:
        parsed = json.loads(supplied_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [f"QUINTE host receipt is not valid JSON: {exc}"]
    if not isinstance(parsed, dict):
        return None, ["QUINTE host receipt must be a JSON object"]

    # A captured CLI response is accepted only when its envelope is current;
    # the embedded durable receipt remains the authority and is re-read by
    # receipt_path.  A bare durable receipt is accepted directly.
    value = parsed
    envelope = any(field in parsed for field in ("cli_envelope_version", "ok", "data"))
    if envelope:
        unknown_envelope = sorted(set(parsed) - {"cli_envelope_version", "ok", "data"})
        missing_envelope = sorted({"cli_envelope_version", "ok", "data"} - set(parsed))
        if unknown_envelope:
            errors.append(
                "QUINTE host envelope has unknown fields: "
                + ", ".join(unknown_envelope)
            )
        if missing_envelope:
            errors.append(
                "QUINTE host envelope is missing fields: "
                + ", ".join(missing_envelope)
            )
        if parsed.get("cli_envelope_version") != CONTRACTS.QUINTE_CLI_ENVELOPE_VERSION:
            errors.append("QUINTE host envelope version is unsupported")
        if parsed.get("ok") is not True or not isinstance(parsed.get("data"), dict):
            errors.append("QUINTE host envelope is not a successful data envelope")
        value = parsed.get("data") if isinstance(parsed.get("data"), dict) else {}
    if errors:
        return None, errors

    unknown = sorted(set(value) - HOST_RECEIPT_FIELDS)
    missing = sorted({"host_receipt_version", "invocation_id", "receipt_path", "operation", "observed_at", "state_root", "state"} - set(value))
    if unknown:
        errors.append(f"QUINTE host receipt has unknown fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"QUINTE host receipt is missing fields: {', '.join(missing)}")
    if value.get("host_receipt_version") != CONTRACTS.QUINTE_HOST_RECEIPT_VERSION:
        errors.append("QUINTE host receipt version is unsupported")
    if value.get("operation") not in CONTRACTS.QUINTE_HOST_RECEIPT_OPERATIONS:
        errors.append("QUINTE host receipt operation must be inspect or reconcile")
    if CONTRACTS.parse_utc_timestamp(value.get("observed_at")) is None:
        errors.append("QUINTE host receipt observed_at must be an RFC 3339 UTC timestamp")
    invocation_id = value.get("invocation_id")
    if not nonempty(invocation_id):
        errors.append("QUINTE host receipt invocation_id must be a non-empty string")
    elif not is_canonical_uuid_v7(invocation_id):
        errors.append("QUINTE host receipt invocation_id must be a canonical UUIDv7")

    run_id = value.get("run_id")
    if run_id is not None:
        if not is_canonical_uuid_v7(run_id):
            errors.append("QUINTE host receipt run_id must be a canonical UUIDv7 when present")

    state_root_value = value.get("state_root")
    state_root: Path | None = None
    if not nonempty(state_root_value):
        errors.append("QUINTE host receipt state_root must be a non-empty string")
    else:
        state_root_candidate = Path(state_root_value).expanduser()
        if not state_root_candidate.is_absolute():
            errors.append("QUINTE host receipt state_root must be absolute")
        else:
            state_root = state_root_candidate.resolve()
            trusted_state_root = trusted_runs_root().parent.resolve()
            if state_root != trusted_state_root:
                errors.append(
                    "QUINTE host receipt state_root does not match the trusted QUINTE state root"
                )

    receipt_path_value = value.get("receipt_path")
    if not nonempty(receipt_path_value):
        errors.append("QUINTE host receipt receipt_path must be a non-empty string")
    else:
        durable_input = Path(receipt_path_value).expanduser()
        if durable_input.is_symlink():
            errors.append("QUINTE host receipt receipt_path must not be a symlink")
        durable = durable_input
        if not durable.is_absolute():
            errors.append("QUINTE host receipt receipt_path must be absolute")
        else:
            durable = durable.resolve()
            # A bare receipt must be the durable authority itself.  A saved
            # CLI envelope may live elsewhere, but its embedded receipt_path
            # must point at the authority that is re-read below.
            if not envelope and durable != supplied:
                errors.append("QUINTE host receipt receipt_path does not identify the supplied receipt")
            expected_durable = (
                state_root / "host" / "receipts" / f"{invocation_id}.json"
                if state_root is not None and nonempty(invocation_id)
                else None
            )
            if expected_durable is not None and durable != expected_durable:
                errors.append("QUINTE host receipt receipt_path is not bound to state_root")
            if nonempty(invocation_id) and durable.name != f"{invocation_id}.json":
                errors.append("QUINTE host receipt receipt_path is not bound to invocation_id")
            if durable.parent.name != "receipts" or durable.parent.parent.name != "host":
                errors.append("QUINTE host receipt receipt_path is outside the durable host receipts directory")
            if not durable.is_file():
                errors.append("QUINTE host receipt durable receipt_path does not exist")
            else:
                try:
                    durable_value = json.loads(durable.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    errors.append(f"QUINTE durable host receipt cannot be parsed: {exc}")
                else:
                    if durable_value != value:
                        errors.append("QUINTE host envelope does not match its durable receipt")
    state = value.get("state")
    if not isinstance(state, dict):
        errors.append("QUINTE host receipt state must be an object")
    else:
        unknown_state = sorted(set(state) - HOST_STATE_FIELDS)
        missing_state = sorted({"code", "active_run_ids"} - set(state))
        if unknown_state:
            errors.append(f"QUINTE host receipt state has unknown fields: {', '.join(unknown_state)}")
        if missing_state:
            errors.append(f"QUINTE host receipt state is missing fields: {', '.join(missing_state)}")
        if state.get("code") not in HOST_STATE_CODES:
            errors.append("QUINTE host receipt state.code is invalid")
        if not isinstance(state.get("active_run_ids"), list) or not all(
            isinstance(item, str) for item in state.get("active_run_ids", [])
        ):
            errors.append("QUINTE host receipt state.active_run_ids must be an array of strings")
        else:
            for active_run_id in state["active_run_ids"]:
                if not is_canonical_uuid_v7(active_run_id):
                    errors.append("QUINTE host receipt state.active_run_ids must contain canonical UUIDv7 values")
                    break
            if len(state["active_run_ids"]) != len(set(state["active_run_ids"])):
                errors.append("QUINTE host receipt state.active_run_ids must be unique")

    manifest = value.get("manifest")
    result_binding = value.get("result")
    recovery = value.get("recovery")
    if value.get("operation") == "reconcile":
        if not isinstance(recovery, dict):
            errors.append("QUINTE host reconcile receipt recovery must be an object")
        else:
            unknown_recovery = sorted(set(recovery) - HOST_RECOVERY_FIELDS)
            missing_recovery = sorted(HOST_RECOVERY_FIELDS - set(recovery))
            if unknown_recovery:
                errors.append(
                    f"QUINTE host receipt recovery has unknown fields: {', '.join(unknown_recovery)}"
                )
            if missing_recovery:
                errors.append(
                    f"QUINTE host receipt recovery is missing fields: {', '.join(missing_recovery)}"
                )
            if recovery.get("outcome") not in {
                "reconciled",
                "no_active_run",
                "ambiguous_active_runs",
            }:
                errors.append("QUINTE host receipt recovery.outcome is invalid")
            if not isinstance(recovery.get("launch_safe"), bool):
                errors.append("QUINTE host receipt recovery.launch_safe must be boolean")
            recovery_path = recovery.get("receipt_path")
            if not nonempty(recovery_path):
                errors.append("QUINTE host receipt recovery.receipt_path must be non-empty")
            elif nonempty(receipt_path_value) and Path(recovery_path).expanduser().resolve() != Path(receipt_path_value).expanduser().resolve():
                errors.append("QUINTE host receipt recovery.receipt_path is not bound to receipt_path")
            if recovery.get("outcome") != "reconciled":
                errors.append("QUINTE host reconcile receipt must bind a reconciled run")
            if not isinstance(state, dict) or state.get("code") != "reconciled":
                errors.append("QUINTE host reconcile receipt state.code must be reconciled")
            if isinstance(state, dict) and isinstance(recovery.get("launch_safe"), bool):
                expected_launch_safe = not state.get("active_run_ids")
                if recovery["launch_safe"] != expected_launch_safe:
                    errors.append(
                        "QUINTE host reconcile receipt recovery.launch_safe does not match active_run_ids"
                    )
    elif recovery is not None:
        errors.append("QUINTE host inspect receipt must not contain recovery")
    if value.get("operation") == "inspect" and isinstance(state, dict) and state.get("code") != "terminal":
        errors.append("QUINTE host inspect receipt state.code must be terminal")
    if value.get("operation") in {"inspect", "reconcile"} and not nonempty(run_id):
        errors.append("QUINTE host receipt run_id is required for inspect/reconcile")
    if not isinstance(manifest, dict):
        errors.append("QUINTE host receipt manifest must be an object")
    else:
        unknown_manifest = sorted(set(manifest) - HOST_MANIFEST_FIELDS)
        missing_manifest = sorted(HOST_REQUIRED_MANIFEST_FIELDS - set(manifest))
        if unknown_manifest:
            errors.append(f"QUINTE host receipt manifest has unknown fields: {', '.join(unknown_manifest)}")
        if missing_manifest:
            errors.append(f"QUINTE host receipt manifest is missing fields: {', '.join(missing_manifest)}")
        if not nonempty(manifest.get("manifest_version")):
            errors.append("QUINTE host receipt manifest manifest_version must be non-empty")
        for field in ("brief_sha256", "policy_sha256", "snapshot_sha256", "runtime_sha256"):
            if not CONTRACTS.is_digest(manifest.get(field)):
                errors.append(f"QUINTE host receipt manifest {field} is invalid")
        if not CONTRACTS.is_digest(manifest.get("result_sha256")):
            errors.append("QUINTE host receipt manifest result_sha256 is invalid")
        if manifest.get("status") not in {"completed", "degraded"}:
            errors.append("QUINTE host receipt manifest must be completed or degraded")
    if not isinstance(result_binding, dict):
        errors.append("QUINTE host receipt result must be an object")
    else:
        unknown_result = sorted(set(result_binding) - HOST_RESULT_FIELDS)
        if unknown_result:
            errors.append(f"QUINTE host receipt result has unknown fields: {', '.join(unknown_result)}")
        if result_binding.get("verified") is not True:
            errors.append("QUINTE host receipt result.verified must be true")
        if result_binding.get("actionable") is not True:
            errors.append("QUINTE host receipt result.actionable must be true for authorization")
        if result_binding.get("contract_version") != CONTRACTS.QUINTE_RESULT_VERSION:
            errors.append(
                "QUINTE host receipt result.contract_version does not match the active result contract"
            )
        if not CONTRACTS.is_digest(result_binding.get("sha256")):
            errors.append("QUINTE host receipt result.sha256 is invalid")
        if not nonempty(result_binding.get("path")):
            errors.append("QUINTE host receipt result.path must be non-empty")
        elif not Path(result_binding["path"]).expanduser().is_absolute():
            errors.append("QUINTE host receipt result.path must be absolute")
    if isinstance(manifest, dict) and isinstance(result_binding, dict):
        if manifest.get("result_sha256") != result_binding.get("sha256"):
            errors.append("QUINTE host receipt manifest/result digests differ")
    if isinstance(state, dict) and nonempty(run_id):
        active = state.get("active_run_ids", [])
        manifest_status = manifest.get("status") if isinstance(manifest, dict) else None
        if manifest_status in {"completed", "degraded"} and run_id in active:
            errors.append("terminal QUINTE host receipt still lists its run as active")

    if errors:
        return None, errors

    # Verify the receipt's result binding points to a canonical run artifact;
    # summarize() performs the full active QUINTE contract validation.
    result_input = Path(result_binding["path"]).expanduser()
    if result_input.is_symlink():
        errors.append("QUINTE host receipt result.path must not be a symlink")
    result_path = result_input.resolve()
    runs_root = trusted_runs_root()
    run_dir = result_path.parent
    if result_path.name != "result.json" or run_dir.parent != runs_root:
        errors.append("QUINTE host receipt result.path is outside the canonical runs root")
    if run_dir.name != run_id:
        errors.append("QUINTE host receipt result.path is not bound to run_id")
    if not _path_is_within(runs_root, result_path):
        errors.append("QUINTE host receipt result.path escapes the trusted runs root")
    if errors:
        return None, errors
    summary, product_errors = summarize(
        str(result_path), request, None, verify_cli=False
    )
    errors.extend(product_errors)
    if summary is None:
        return None, errors
    if summary["run_id"] != run_id:
        errors.append("QUINTE host receipt run_id does not match the verified result")
    if summary["result_sha256"] != result_binding["sha256"]:
        errors.append("QUINTE host receipt result digest does not match result.json")
    if summary["status"] != manifest["status"]:
        errors.append("QUINTE host receipt result status does not match manifest")
    if result_binding.get("contract_version") != summary["result_version"]:
        errors.append("QUINTE host receipt result contract version does not match result.json")
    try:
        canonical_manifest = load_json_object(run_dir / "manifest.json")
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"QUINTE canonical manifest cannot be re-read: {exc}")
    else:
        for field, projection in manifest.items():
            if canonical_manifest.get(field) != projection:
                errors.append(f"QUINTE host receipt manifest {field} does not match manifest.json")
    if errors:
        return None, errors
    return {
        **summary,
        "host_receipt_ref": str(supplied),
        "host_receipt_sha256": CONTRACTS.sha256_bytes(supplied_raw),
        "host_receipt_operation": value["operation"],
    }, []


def resolve_magi_artifact(trial: Path, ref: Any, label: str, errors: list[str]) -> Path | None:
    if not nonempty(ref):
        return None
    reference = Path(ref)
    if reference.is_absolute():
        errors.append(f"{label} must be a relative path")
        return None
    candidate = trial / reference
    current = trial
    for component in reference.parts:
        current = current / component
        if current.is_symlink():
            errors.append(f"{label} contains a symlink")
            return None
    path = candidate.resolve()
    if path == trial or trial not in path.parents:
        errors.append(f"{label} escapes the MAGI trial directory")
        return None
    return path


def verify_magi_artifact_digest(
    trial: Path,
    ref: Any,
    expected: Any,
    label: str,
    errors: list[str],
) -> tuple[Path | None, bytes | None]:
    path = resolve_magi_artifact(trial, ref, f"{label} ref", errors)
    if path is None:
        return None, None
    try:
        raw = path.read_bytes()
    except OSError as exc:
        errors.append(f"{label} cannot be read: {exc}")
        return path, None
    if CONTRACTS.sha256_bytes(raw) != expected:
        errors.append(f"{label} digest mismatch")
    return path, raw


def load_magi_json(raw: bytes | None, label: str, errors: list[str]) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"{label} must be a JSON object: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object")
        return None
    return value


def validate_magi_execution_receipt(
    value: dict[str, Any] | None,
    label: str,
    errors: list[str],
    *,
    expected_kind: str,
    expected_seat_id: str | None,
    expected_profile_sha256: str | None,
    expected_agent_config_sha256: str,
    expected_execution_mode: str | None,
    expected_output_sha256: str,
    expected_service: str | None = None,
    expected_image_digest: str | None = None,
) -> None:
    if value is None:
        return
    exact_fields(value, MAGI_EXECUTION_RECEIPT_FIELDS, label, errors)
    if value.get("receipt_version") != "1.0":
        errors.append(f"{label}.receipt_version is unsupported")
    for field in ("kind", "service", "execution_mode"):
        if not nonempty(value.get(field)):
            errors.append(f"{label}.{field} must be a non-empty string")
    if value.get("seat_id") is not None and not nonempty(value.get("seat_id")):
        errors.append(f"{label}.seat_id must be a non-empty string or null")
    if value.get("profile_sha256") is not None and not CONTRACTS.is_digest(
        value.get("profile_sha256")
    ):
        errors.append(f"{label}.profile_sha256 is invalid")
    for field in (
        "image_digest",
        "agent_config_sha256",
        "input_packet_sha256",
        "output_artifact_sha256",
    ):
        if not CONTRACTS.is_digest(value.get(field)):
            errors.append(f"{label}.{field} is invalid")
    for field, expected in (
        ("kind", expected_kind),
        ("seat_id", expected_seat_id),
        ("profile_sha256", expected_profile_sha256),
        ("agent_config_sha256", expected_agent_config_sha256),
        ("output_artifact_sha256", expected_output_sha256),
    ):
        if value.get(field) != expected:
            errors.append(f"{label}.{field} does not match the product summary")
    if expected_execution_mode is not None and value.get("execution_mode") != expected_execution_mode:
        errors.append(f"{label}.execution_mode does not match the product summary")
    if expected_service is not None and value.get("service") != expected_service:
        errors.append(f"{label}.service does not match the assignment plan")
    if expected_image_digest is not None and value.get("image_digest") != expected_image_digest:
        errors.append(f"{label}.image_digest does not match the assignment plan")


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return CONTRACTS.sha256_bytes(encoded)


def validate_magi_assignment_plan(
    value: dict[str, Any] | None,
    product: dict[str, Any],
    errors: list[str],
) -> tuple[dict[str, dict[str, Any]], set[tuple[str, str]]]:
    if value is None:
        return {}, set()
    label = "MAGI assignment plan"
    exact_fields(value, MAGI_ASSIGNMENT_FIELDS, label, errors)
    if value.get("assignment_plan_version") != "1.0":
        errors.append(f"{label}.assignment_plan_version is unsupported")
    if value.get("trial_id") != product.get("trial_id"):
        errors.append(f"{label}.trial_id does not match the product summary")
    identity = {key: item for key, item in value.items() if key != "plan_binding_sha256"}
    if value.get("plan_binding_sha256") != canonical_digest(identity):
        errors.append(f"{label}.plan_binding_sha256 does not match the frozen plan")
    raw_seats = value.get("seats")
    seats: dict[str, dict[str, Any]] = {}
    if not isinstance(raw_seats, list) or len(raw_seats) != 3:
        errors.append(f"{label}.seats must contain exactly three seats")
    else:
        for index, raw in enumerate(raw_seats):
            seat_label = f"{label}.seats[{index}]"
            if not isinstance(raw, dict):
                errors.append(f"{seat_label} must be an object")
                continue
            exact_fields(raw, MAGI_ASSIGNMENT_SEAT_FIELDS, seat_label, errors)
            seat_id = raw.get("seat_id")
            if not nonempty(seat_id):
                errors.append(f"{seat_label}.seat_id must be a non-empty string")
            elif seat_id in seats:
                errors.append(f"{label} contains a duplicate seat_id: {seat_id}")
            else:
                seats[seat_id] = raw
            for field in (
                "family",
                "provider",
                "text_model",
                "multimodal_model",
                "profile_id",
                "container_service",
            ):
                if not nonempty(raw.get(field)):
                    errors.append(f"{seat_label}.{field} must be a non-empty string")
            for field in ("profile_source_sha256", "image_digest"):
                if not CONTRACTS.is_digest(raw.get(field)):
                    errors.append(f"{seat_label}.{field} is invalid")
            carrier = raw.get("carrier_capabilities")
            if not isinstance(carrier, dict):
                errors.append(f"{seat_label}.carrier_capabilities must be an object")
            else:
                exact_fields(
                    carrier,
                    MAGI_ASSIGNMENT_CARRIER_FIELDS,
                    f"{seat_label}.carrier_capabilities",
                    errors,
                )
    obligations = value.get("cross_review_obligations")
    expected = {(left, right) for left in seats for right in seats if left != right}
    if not isinstance(obligations, list) or len(obligations) != 6:
        errors.append(f"{label}.cross_review_obligations must contain all six directed reviews")
    else:
        pairs: list[tuple[Any, Any]] = []
        for index, raw in enumerate(obligations):
            obligation_label = f"{label}.cross_review_obligations[{index}]"
            if not isinstance(raw, dict):
                errors.append(f"{obligation_label} must be an object")
                continue
            exact_fields(raw, MAGI_ASSIGNMENT_REVIEW_FIELDS, obligation_label, errors)
            reviewer = raw.get("reviewer_seat_id")
            subject = raw.get("subject_seat_id")
            if (
                not isinstance(reviewer, str)
                or not isinstance(subject, str)
                or reviewer not in seats
                or subject not in seats
                or reviewer == subject
            ):
                errors.append(f"{obligation_label} has an invalid directed seat pair")
            else:
                pairs.append((reviewer, subject))
        if len(pairs) != 6 or set(pairs) != expected:
            errors.append(f"{label} does not bind every directed review exactly once")
    finale = value.get("finale_condition")
    if not isinstance(finale, dict):
        errors.append(f"{label}.finale_condition must be an object")
    else:
        exact_fields(finale, MAGI_ASSIGNMENT_FINALE_FIELDS, f"{label}.finale_condition", errors)
    return seats, expected


def validate_magi_evidence_manifest(
    value: dict[str, Any] | None,
    product: dict[str, Any],
    trial: Path,
    errors: list[str],
) -> None:
    if value is None:
        return
    label = "MAGI evidence manifest"
    exact_fields(value, MAGI_EVIDENCE_MANIFEST_FIELDS, label, errors)
    if value.get("evidence_manifest_version") != "1.0":
        errors.append(f"{label}.evidence_manifest_version is unsupported")
    if value.get("original_brief_sha256") != product.get("original_brief_sha256"):
        errors.append(f"{label}.original_brief_sha256 does not match the product summary")
    verify_magi_artifact_digest(
        trial,
        value.get("original_brief_ref"),
        value.get("original_brief_sha256"),
        f"{label} original brief",
        errors,
    )
    if value.get("staged_root_ref") != "trial-private/evidence":
        errors.append(f"{label}.staged_root_ref is invalid")
    if not CONTRACTS.is_digest(value.get("evidence_set_sha256")):
        errors.append(f"{label}.evidence_set_sha256 is invalid")
    evidence_identity = {
        key: value.get(key)
        for key in (
            "evidence_manifest_version",
            "original_brief_ref",
            "original_brief_sha256",
            "source_root",
            "staged_root_ref",
            "source_files",
            "derived_frames",
            "limitations",
        )
    }
    if value.get("evidence_set_sha256") != canonical_digest(evidence_identity):
        errors.append(f"{label}.evidence_set_sha256 does not match the frozen evidence set")
    source_files = value.get("source_files")
    derived_frames = value.get("derived_frames")
    if not isinstance(source_files, list) or not isinstance(derived_frames, list):
        errors.append(f"{label}.source_files and derived_frames must be arrays")
        return
    if not source_files and (
        value.get("source_root") != "none://no-external-evidence" or derived_frames
    ):
        errors.append(f"{label} empty evidence must use the explicit no-evidence boundary")
    for collection, fields in (
        (source_files, MAGI_EVIDENCE_SOURCE_FIELDS),
        (derived_frames, MAGI_EVIDENCE_FRAME_FIELDS),
    ):
        for index, raw in enumerate(collection):
            item_label = f"{label} evidence[{index}]"
            if not isinstance(raw, dict):
                errors.append(f"{item_label} must be an object")
                continue
            exact_fields(raw, fields, item_label, errors)
            staged_ref = raw.get("staged_ref")
            staged_trial_ref = (
                f"trial-private/evidence/{staged_ref}" if nonempty(staged_ref) else staged_ref
            )
            path, artifact_raw = verify_magi_artifact_digest(
                trial,
                staged_trial_ref,
                raw.get("sha256"),
                f"{item_label} staged bytes",
                errors,
            )
            if artifact_raw is not None and raw.get("size_bytes") != len(artifact_raw):
                errors.append(f"{item_label}.size_bytes does not match staged bytes")


def validate_magi_residual_trace(
    value: dict[str, Any] | None,
    product: dict[str, Any],
    request: dict[str, Any],
    errors: list[str],
) -> None:
    if value is None:
        return
    label = "MAGI residual trace"
    exact_fields(value, MAGI_RESIDUAL_TRACE_FIELDS, label, errors)
    if value.get("trace_version") != "1.1":
        errors.append(f"{label}.trace_version is unsupported")
    if value.get("instrument") != "MAGI":
        errors.append(f"{label}.instrument must be MAGI")
    if value.get("question") != product.get("question"):
        errors.append(f"{label}.question does not match the product summary")
    if value.get("action_boundary") != request.get("action_boundary"):
        errors.append(f"{label}.action_boundary does not match the route request")
    if value.get("action_binding_sha256") != product.get("action_binding_sha256"):
        errors.append(f"{label}.action_binding_sha256 does not match the product summary")
    expected_decision = {"PASS": "pass", "BLOCK": "block", "ESCALATE": "escalate"}.get(
        product.get("final_decision")
    )
    if value.get("highball_decision") != expected_decision:
        errors.append(f"{label}.highball_decision does not match the final verdict")
    if not isinstance(value.get("residuals"), list) or not isinstance(
        value.get("trial_manifest"), dict
    ):
        errors.append(f"{label}.residuals/trial_manifest have invalid types")


def validate_magi_evidence_coverage(
    value: dict[str, Any] | None,
    product: dict[str, Any],
    trial: Path,
    errors: list[str],
) -> dict[str, str]:
    if value is None:
        return {}
    label = "MAGI evidence coverage receipt"
    exact_fields(value, MAGI_EVIDENCE_COVERAGE_FIELDS, label, errors)
    if value.get("coverage_receipt_version") != "1.0":
        errors.append(f"{label}.coverage_receipt_version is unsupported")
    if value.get("coverage_status") not in {"bounded", "limited"}:
        errors.append(f"{label}.coverage_status is invalid")
    if value.get("original_brief_sha256") != product.get("original_brief_sha256"):
        errors.append(f"{label}.original_brief_sha256 does not match the product summary")
    if value.get("evidence_manifest_ref") != product.get("evidence_manifest_ref"):
        errors.append(f"{label}.evidence_manifest_ref does not match the product summary")
    if value.get("evidence_manifest_sha256") != product.get("evidence_manifest_sha256"):
        errors.append(f"{label}.evidence_manifest_sha256 does not match the product summary")
    identity = {key: item for key, item in value.items() if key != "receipt_binding_sha256"}
    if value.get("receipt_binding_sha256") != canonical_digest(identity):
        errors.append(f"{label}.receipt_binding_sha256 does not match the receipt")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(f"{label}.artifacts must be a non-empty array")
        return {}
    refs: set[str] = set()
    bound: dict[str, str] = {}
    for index, raw in enumerate(artifacts):
        artifact_label = f"{label}.artifacts[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{artifact_label} must be an object")
            continue
        exact_fields(raw, MAGI_COVERAGE_ARTIFACT_FIELDS, artifact_label, errors)
        reference = raw.get("artifact_ref")
        if reference in refs:
            errors.append(f"{label} contains a duplicate artifact_ref: {reference}")
        elif nonempty(reference):
            refs.add(reference)
            if CONTRACTS.is_digest(raw.get("sha256")):
                bound[reference] = raw["sha256"]
        verify_magi_artifact_digest(
            trial,
            reference,
            raw.get("sha256"),
            f"{artifact_label} bound artifact",
            errors,
        )
    return bound


def validate_magi_residual_reduction(
    value: dict[str, Any] | None, errors: list[str]
) -> None:
    if value is None:
        return
    label = "MAGI residual-reduction receipt"
    exact_fields(value, MAGI_RESIDUAL_REDUCTION_FIELDS, label, errors)
    if value.get("receipt_version") != "1.0":
        errors.append(f"{label}.receipt_version is unsupported")
    identity = {key: item for key, item in value.items() if key != "binding_sha256"}
    if value.get("binding_sha256") != canonical_digest(identity):
        errors.append(f"{label}.binding_sha256 does not match the receipt")
    reference_fields = (
        "seat_residual_source_refs",
        "cross_review_source_refs",
        "cross_review_novel_source_refs",
        "cross_review_linked_source_refs",
        "challenged_seat_source_refs",
        "final_represented_source_refs",
        "final_falsified_or_discarded_source_refs",
        "final_finding_ids",
        "final_unresolved_finding_ids",
    )
    references: dict[str, list[str]] = {}
    for field in reference_fields:
        raw = value.get(field)
        if not string_list(raw, nonempty_items=True) or raw != sorted(set(raw)):
            errors.append(f"{label}.{field} must be a sorted unique string array")
            references[field] = []
        else:
            references[field] = raw
    counts = value.get("counts")
    if not isinstance(counts, dict):
        errors.append(f"{label}.counts must be an object")
        return
    exact_fields(counts, MAGI_RESIDUAL_REDUCTION_COUNT_FIELDS, f"{label}.counts", errors)
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counts.values()):
        errors.append(f"{label}.counts must contain non-negative integers")
        return
    expected_counts = {
        "seat_residuals": len(references["seat_residual_source_refs"]),
        "cross_review_findings": len(references["cross_review_source_refs"]),
        "cross_review_novel_findings": len(references["cross_review_novel_source_refs"]),
        "cross_review_linked_findings": len(references["cross_review_linked_source_refs"]),
        "challenged_seat_residuals": len(references["challenged_seat_source_refs"]),
        "final_represented_sources": len(references["final_represented_source_refs"]),
        "final_falsified_or_discarded_sources": len(
            references["final_falsified_or_discarded_source_refs"]
        ),
        "final_findings": len(references["final_finding_ids"]),
        "final_unresolved_findings": len(references["final_unresolved_finding_ids"]),
    }
    if counts != expected_counts:
        errors.append(f"{label}.counts do not match the receipt source lists")


def validate_magi_dossier_summary(
    value: dict[str, Any] | None,
    summary: dict[str, Any],
    product: dict[str, Any],
    assignment: dict[str, Any] | None,
    label: str,
    errors: list[str],
) -> None:
    if value is None:
        return
    exact_fields(value, MAGI_DOSSIER_FIELDS, f"{label} artifact", errors)
    if value.get("dossier_version") != "1.0":
        errors.append(f"{label} artifact.dossier_version is unsupported")
    for summary_field, dossier_field in (
        ("seat_id", "seat_id"),
        ("profile_sha256", "profile_sha256"),
        ("thesis_sha256", "thesis_sha256"),
        ("quinte_manifest_sha256", "quinte_manifest_sha256"),
        ("quinte_result_sha256", "quinte_result_sha256"),
    ):
        if summary.get(summary_field) != value.get(dossier_field):
            errors.append(f"{label}.{summary_field} does not match its dossier artifact")
    if value.get("original_brief_sha256") != product.get("original_brief_sha256"):
        errors.append(f"{label} dossier original_brief_sha256 does not match the product")
    if assignment is not None:
        if value.get("profile_id") != assignment.get("profile_id"):
            errors.append(f"{label} dossier profile_id does not match the assignment plan")
        if value.get("reviewer_profile_sha256") != assignment.get("profile_source_sha256"):
            errors.append(f"{label} reviewer profile digest does not match the assignment plan")
        if value.get("assigned_evidence_refs") != assignment.get("evidence_refs"):
            errors.append(f"{label} assigned_evidence_refs do not match the assignment plan")
    if summary.get("assigned_evidence_refs") != value.get("assigned_evidence_refs"):
        errors.append(f"{label}.assigned_evidence_refs do not match the dossier artifact")
    if summary.get("evidence_mapping_sha256") != value.get("evidence_mapping_sha256"):
        errors.append(f"{label}.evidence_mapping_sha256 does not match the dossier artifact")


def validate_magi_final_verdict(
    value: dict[str, Any] | None, product: dict[str, Any], errors: list[str]
) -> None:
    if value is None:
        return
    label = "MAGI final verdict"
    exact_fields(value, MAGI_FINAL_VERDICT_FIELDS, label, errors)
    if value.get("verdict_version") != "1.0":
        errors.append(f"{label}.verdict_version is unsupported")
    if value.get("decision") != product.get("final_decision"):
        errors.append(f"{label}.decision does not match the product summary")
    if value.get("dissent") != product.get("final_dissent"):
        errors.append(f"{label}.dissent does not match the product summary")


def summarize(
    ref: str,
    request: dict[str, Any],
    base_dir: Path | None = None,
    *,
    verify_cli: bool = True,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    path = resolve_ref(ref, base_dir)
    if not path.is_file():
        return None, [f"quinte result does not exist: {ref}"]
    if path.name != "result.json":
        errors.append("active QUINTE result must use the standard result.json filename")
    run_dir = path.parent
    runs_root = trusted_runs_root()
    try:
        run_dir.relative_to(runs_root)
    except ValueError:
        errors.append(f"active QUINTE result is outside the trusted runs root: {runs_root}")
    if run_dir.parent != runs_root:
        errors.append("active QUINTE result must be directly inside its canonical run directory")
    manifest_path = run_dir / "manifest.json"
    brief_path = run_dir / "input" / "brief.json"
    try:
        result_bytes = path.read_bytes()
        result = json.loads(result_bytes.decode("utf-8"))
        manifest = load_json_object(manifest_path)
        brief = load_json_object(brief_path)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return None, errors + [f"quinte product bundle cannot be read: {exc}"]
    if not isinstance(result, dict):
        return None, errors + ["quinte result must be a JSON object"]

    validate_result(result, errors)
    validate_brief(brief, errors)
    exact_fields(manifest, MANIFEST_FIELDS, "quinte manifest", errors)
    if manifest.get("manifest_version") != CONTRACTS.QUINTE_MANIFEST_VERSION:
        errors.append("quinte manifest_version is unsupported")
    if manifest.get("protocol_version") != CONTRACTS.QUINTE_PROTOCOL_VERSION:
        errors.append("quinte protocol_version is unsupported")
    manifest_seat = validate_binding(
        manifest.get("seat_binding"), "quinte manifest seat_binding", errors
    )
    validate_route_bindings(
        manifest.get("route_bindings"), manifest_seat, "quinte manifest route_bindings", errors
    )
    if manifest.get("seat_binding") != result.get("seat_binding"):
        errors.append("quinte manifest and result seat bindings differ")
    if manifest.get("route_bindings") != result.get("route_bindings"):
        errors.append("quinte manifest and result route bindings differ")
    if isinstance(manifest_seat, dict) and manifest.get("effective_model") != manifest_seat.get("text_model"):
        errors.append("quinte effective_model differs from the seat text model")
    for field in ("brief_sha256", "policy_sha256", "snapshot_sha256", "runtime_sha256", "result_sha256"):
        if not CONTRACTS.is_digest(manifest.get(field)):
            errors.append(f"quinte manifest {field} is invalid")
    if manifest.get("status") != "completed" or result.get("status") != "completed":
        errors.append("only a completed QUINTE run can authorize an action")
    if manifest.get("run_id") != result.get("run_id") or run_dir.name != result.get("run_id"):
        errors.append("quinte result run_id is not bound to its manifest and run directory")
    result_sha256 = CONTRACTS.sha256_bytes(result_bytes)
    if manifest.get("result_sha256") != result_sha256:
        errors.append("quinte result digest does not match its manifest")
    brief_sha256 = canonical_brief_sha256(brief)
    if manifest.get("brief_sha256") != brief_sha256 or result.get("brief_sha256") != brief_sha256:
        errors.append("quinte brief digest does not match the brief, manifest, and result")

    expected_binding = CONTRACTS.action_binding_sha256(request)
    for label, value in (
        ("brief", brief.get("action_binding_sha256")),
        ("result", result.get("action_binding_sha256")),
    ):
        if value != expected_binding:
            errors.append(f"quinte {label} action binding does not match the route request")
    for field in ("question", "action_scope", "affected_paths"):
        expected = request.get(field)
        if brief.get(field) != expected or result.get(field) != expected:
            errors.append(f"quinte brief/result {field} does not match the route request")

    if verify_cli:
        try:
            state_root_value = os.environ.get("QUINTE_HOME")
            if not state_root_value:
                raise ValueError(
                    "QUINTE_HOME must explicitly pin an absolute QUINTE state root"
                )
            if not Path(state_root_value).is_absolute():
                raise ValueError("QUINTE_HOME must be an absolute path")
            if not os.environ.get("HIGHBALL_QUINTE_BIN"):
                raise ValueError(
                    "HIGHBALL_QUINTE_BIN must explicitly pin an absolute QUINTE executable"
                )
            binary_value = os.environ["HIGHBALL_QUINTE_BIN"]
            if not Path(binary_value).is_absolute():
                raise ValueError("HIGHBALL_QUINTE_BIN must be an absolute path")
            quinte_binary = active_quinte_binary()
            runs_root_for_cli = trusted_runs_root()
            if quinte_binary is None:
                raise ValueError("HIGHBALL_QUINTE_BIN does not name an executable regular file")
        except ValueError as exc:
            errors.append(str(exc))
            quinte_binary = None
            runs_root_for_cli = None
        if quinte_binary is not None and runs_root_for_cli is not None:
            runtime_matches = False
            try:
                binary_sha256 = CONTRACTS.sha256_bytes(quinte_binary.read_bytes())
            except OSError as exc:
                errors.append(f"trusted quinte executable cannot be read: {exc}")
            else:
                if manifest.get("runtime_sha256") != binary_sha256:
                    errors.append("quinte manifest runtime digest does not match the pinned executable")
                else:
                    runtime_matches = True
            # Never execute a binary after its digest has drifted from the
            # runtime bound into the run manifest.  The direct result path is
            # legacy compatibility; receipt verification is subprocess-free.
            if runtime_matches:
                try:
                    completed = subprocess.run(
                        [str(quinte_binary), "inspect", str(result.get("run_id", "")), "--json"],
                        capture_output=True,
                        check=False,
                        text=True,
                        timeout=15,
                        env={**os.environ, "QUINTE_HOME": str(runs_root_for_cli.parent)},
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    errors.append(f"quinte CLI state inspection failed: {exc}")
                else:
                    if completed.returncode != 0:
                        errors.append("quinte CLI does not report the run as a completed valid product")
                    else:
                        try:
                            inspected = json.loads(completed.stdout)
                        except json.JSONDecodeError:
                            errors.append("quinte CLI state inspection did not return JSON")
                        else:
                            data = (
                                inspected.get("data")
                                if isinstance(inspected, dict)
                                and inspected.get("cli_envelope_version") == CONTRACTS.QUINTE_CLI_ENVELOPE_VERSION
                                and inspected.get("ok") is True
                                else None
                            )
                            inspected_manifest = data.get("manifest") if isinstance(data, dict) else None
                            inspected_result = data.get("result") if isinstance(data, dict) else None
                            if inspected_manifest != manifest or inspected_result != result:
                                errors.append("quinte CLI state differs from the bound manifest or result")

    outcome = {
        "result_ref": str(path),
        "run_id": result.get("run_id") if isinstance(result.get("run_id"), str) else "",
        "status": result.get("status") if isinstance(result.get("status"), str) else "",
        "result_version": result.get("result_version") if isinstance(result.get("result_version"), str) else "",
        "result_sha256": result_sha256,
        "brief_sha256": result.get("brief_sha256") if isinstance(result.get("brief_sha256"), str) else "",
        "question": result.get("question") if isinstance(result.get("question"), str) else "",
        "action_scope": result.get("action_scope") if isinstance(result.get("action_scope"), str) else None,
        "affected_paths": result.get("affected_paths") if string_list(result.get("affected_paths")) else [],
        "action_binding_sha256": (
            result.get("action_binding_sha256")
            if isinstance(result.get("action_binding_sha256"), str)
            else ""
        ),
    }
    return outcome, errors


def active_magi_binary() -> Path | None:
    configured = os.environ.get("HIGHBALL_MAGI_BIN")
    candidates = [Path(configured).expanduser()] if configured else []
    resolved = shutil.which("magi")
    if resolved:
        candidates.append(Path(resolved))
    candidates.extend([Path.home() / ".local" / "bin" / "magi", Path.home() / "bin" / "magi"])
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    return None


def summarize_magi(
    ref: str,
    request: dict[str, Any],
    base_dir: Path | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    trial = resolve_ref(ref, base_dir)
    if not trial.is_dir():
        return None, [f"MAGI trial directory does not exist: {ref}"]
    binary = active_magi_binary()
    if binary is None:
        return None, ["trusted magi executable is not available"]
    try:
        completed = subprocess.run(
            [str(binary), "verify-product", str(trial)],
            capture_output=True,
            check=False,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, [f"MAGI product verification failed: {exc}"]
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit {completed.returncode}"
        return None, [f"MAGI product verification failed: {detail}"]
    try:
        product = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return None, [f"MAGI product verification did not return JSON: {exc}"]
    if not isinstance(product, dict):
        return None, ["MAGI product summary must be an object"]
    exact_fields(product, MAGI_PRODUCT_FIELDS, "MAGI product summary", errors)
    if product.get("product_version") != CONTRACTS.MAGI_PRODUCT_VERSION:
        errors.append("MAGI product_version is unsupported")
    if product.get("status") != "completed":
        errors.append("MAGI product is not completed")
    if product.get("final_decision") not in {"PASS", "BLOCK", "ESCALATE"}:
        errors.append("MAGI final decision is invalid")
    if not string_list(product.get("final_dissent"), nonempty_items=True):
        errors.append("MAGI final dissent must be an array of non-empty strings")
    for field in (
        "trial_id",
        "question",
        "assignment_plan_ref",
        "evidence_manifest_ref",
        "evidence_coverage_ref",
        "final_verdict_ref",
        "residual_trace_ref",
        "residual_reduction_ref",
    ):
        if not nonempty(product.get(field)):
            errors.append(f"MAGI product {field} must be a non-empty string")
    if product.get("action_scope") is not None and not isinstance(product.get("action_scope"), str):
        errors.append("MAGI product action_scope must be a string or null")
    if not string_list(product.get("affected_paths"), nonempty_items=True):
        errors.append("MAGI product affected_paths must be an array of non-empty strings")
    identity = {key: value for key, value in product.items() if key != "product_sha256"}
    encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if product.get("product_sha256") != CONTRACTS.sha256_bytes(encoded):
        errors.append("MAGI product summary digest is invalid")
    for field in (
        "product_sha256",
        "runtime_sha256",
        "agent_config_sha256",
        "assignment_plan_sha256",
        "evidence_manifest_sha256",
        "evidence_coverage_sha256",
        "original_brief_sha256",
        "action_binding_sha256",
        "final_verdict_sha256",
        "residual_trace_sha256",
        "residual_reduction_sha256",
    ):
        if not CONTRACTS.is_digest(product.get(field)):
            errors.append(f"MAGI product {field} is invalid")
    if product.get("builder_config_sha256") is not None and not CONTRACTS.is_digest(
        product.get("builder_config_sha256")
    ):
        errors.append("MAGI product builder_config_sha256 is invalid")
    _, assignment_raw = verify_magi_artifact_digest(
        trial,
        product.get("assignment_plan_ref"),
        product.get("assignment_plan_sha256"),
        "MAGI assignment plan",
        errors,
    )
    assignment_seats, assignment_review_pairs = validate_magi_assignment_plan(
        load_magi_json(assignment_raw, "MAGI assignment plan", errors), product, errors
    )
    _, manifest_raw = verify_magi_artifact_digest(
        trial,
        product.get("evidence_manifest_ref"),
        product.get("evidence_manifest_sha256"),
        "MAGI evidence manifest",
        errors,
    )
    validate_magi_evidence_manifest(
        load_magi_json(manifest_raw, "MAGI evidence manifest", errors), product, trial, errors
    )
    _, coverage_raw = verify_magi_artifact_digest(
        trial,
        product.get("evidence_coverage_ref"),
        product.get("evidence_coverage_sha256"),
        "MAGI evidence coverage receipt",
        errors,
    )
    coverage_artifacts = validate_magi_evidence_coverage(
        load_magi_json(coverage_raw, "MAGI evidence coverage receipt", errors),
        product,
        trial,
        errors,
    )
    _, verdict_raw = verify_magi_artifact_digest(
        trial,
        product.get("final_verdict_ref"),
        product.get("final_verdict_sha256"),
        "MAGI final verdict",
        errors,
    )
    validate_magi_final_verdict(
        load_magi_json(verdict_raw, "MAGI final verdict", errors), product, errors
    )
    _, trace_raw = verify_magi_artifact_digest(
        trial,
        product.get("residual_trace_ref"),
        product.get("residual_trace_sha256"),
        "MAGI residual trace",
        errors,
    )
    validate_magi_residual_trace(
        load_magi_json(trace_raw, "MAGI residual trace", errors), product, request, errors
    )
    _, reduction_raw = verify_magi_artifact_digest(
        trial,
        product.get("residual_reduction_ref"),
        product.get("residual_reduction_sha256"),
        "MAGI residual-reduction receipt",
        errors,
    )
    validate_magi_residual_reduction(
        load_magi_json(reduction_raw, "MAGI residual-reduction receipt", errors), errors
    )
    if product.get("action_binding_sha256") != CONTRACTS.action_binding_sha256(request):
        errors.append("MAGI action binding does not match the route request")
    for field in ("question", "action_scope", "affected_paths"):
        if product.get(field) != request.get(field):
            errors.append(f"MAGI product {field} does not match the route request")
    final_adjudicator = product.get("final_adjudicator")
    if not isinstance(final_adjudicator, dict):
        errors.append("MAGI product final_adjudicator must be an object")
    else:
        exact_fields(
            final_adjudicator,
            MAGI_FINAL_ADJUDICATOR_FIELDS,
            "MAGI product final_adjudicator",
            errors,
        )
        for field in (
            "family",
            "provider",
            "text_model",
            "multimodal_model",
            "execution_mode",
            "execution_receipt_ref",
        ):
            if not nonempty(final_adjudicator.get(field)):
                errors.append(f"MAGI product final_adjudicator.{field} must be a non-empty string")
        for field in ("agent_config_sha256", "execution_receipt_sha256"):
            if not CONTRACTS.is_digest(final_adjudicator.get(field)):
                errors.append(f"MAGI product final_adjudicator.{field} is invalid")
    seats = product.get("seats")
    seats_by_id: dict[str, dict[str, Any]] = {}
    if not isinstance(seats, list) or len(seats) != 3:
        errors.append("MAGI product must contain exactly three seats")
    else:
        seat_ids: list[str] = []
        families: list[str] = []
        profiles: list[str] = []
        runs: list[str] = []
        dossier_refs: list[str] = []
        for index, item in enumerate(seats):
            label = f"MAGI product seats[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{label} must be an object")
                continue
            exact_fields(item, MAGI_SEAT_FIELDS, label, errors)
            for field in (
                "seat_id", "family", "provider", "text_model", "multimodal_model",
                "dossier_ref", "quinte_run_id",
            ):
                if not nonempty(item.get(field)):
                    errors.append(f"{label}.{field} must be a non-empty string")
            for field in (
                "profile_sha256", "thesis_sha256", "dossier_sha256",
                "quinte_manifest_sha256", "quinte_result_sha256",
            ):
                if not CONTRACTS.is_digest(item.get(field)):
                    errors.append(f"{label}.{field} is invalid")
            assigned_refs = item.get("assigned_evidence_refs")
            if not isinstance(assigned_refs, list) or not all(
                isinstance(value, str) and bool(value.strip()) for value in assigned_refs
            ):
                errors.append(f"{label}.assigned_evidence_refs must be a string array")
            mapping_ref = item.get("evidence_mapping_ref")
            mapping_sha = item.get("evidence_mapping_sha256")
            if mapping_ref is None and mapping_sha is None:
                if assigned_refs:
                    errors.append(f"{label} assigned evidence requires a mapping receipt")
            else:
                if not nonempty(mapping_ref):
                    errors.append(f"{label}.evidence_mapping_ref must be a non-empty string")
                if not CONTRACTS.is_digest(mapping_sha):
                    errors.append(f"{label}.evidence_mapping_sha256 is invalid")
                elif nonempty(mapping_ref):
                    verify_magi_artifact_digest(
                        trial,
                        mapping_ref,
                        mapping_sha,
                        f"{label} evidence mapping receipt",
                        errors,
                    )
            if nonempty(item.get("seat_id")):
                seat_ids.append(item["seat_id"])
                seats_by_id[item["seat_id"]] = item
                assigned = assignment_seats.get(item["seat_id"])
                if assigned is None:
                    errors.append(f"{label}.seat_id is not bound by the assignment plan")
                else:
                    for product_field, assignment_field in (
                        ("family", "family"),
                        ("provider", "provider"),
                        ("text_model", "text_model"),
                        ("multimodal_model", "multimodal_model"),
                    ):
                        if item.get(product_field) != assigned.get(assignment_field):
                            errors.append(
                                f"{label}.{product_field} does not match the assignment plan"
                            )
                    if item.get("profile_sha256") != assigned.get("profile_source_sha256"):
                        errors.append(f"{label}.profile_sha256 does not match the assignment plan")
                    if item.get("assigned_evidence_refs") != assigned.get("evidence_refs"):
                        errors.append(
                            f"{label}.assigned_evidence_refs do not match the assignment plan"
                        )
            if nonempty(item.get("family")):
                families.append(item["family"])
            if CONTRACTS.is_digest(item.get("profile_sha256")):
                profiles.append(item["profile_sha256"])
            if nonempty(item.get("quinte_run_id")):
                runs.append(item["quinte_run_id"])
            if nonempty(item.get("dossier_ref")):
                dossier_refs.append(item["dossier_ref"])
                _, dossier_raw = verify_magi_artifact_digest(
                    trial,
                    item.get("dossier_ref"),
                    item.get("dossier_sha256"),
                    f"{label} dossier",
                    errors,
                )
                validate_magi_dossier_summary(
                    load_magi_json(dossier_raw, f"{label} dossier", errors),
                    item,
                    product,
                    assignment_seats.get(item.get("seat_id")),
                    label,
                    errors,
                )
        if len(seat_ids) != 3 or len(set(seat_ids)) != 3:
            errors.append("MAGI product must contain three distinct seat IDs")
        if len(families) != 3 or len(set(families)) != 3:
            errors.append("MAGI product must contain three distinct model families")
        if len(profiles) != 3 or len(set(profiles)) != 3:
            errors.append("MAGI product must contain three distinct profile digests")
        if len(runs) != 3 or len(set(runs)) != 3:
            errors.append("MAGI product must contain three distinct QUINTE runs")
        if len(dossier_refs) != 3 or len(set(dossier_refs)) != 3:
            errors.append("MAGI product must contain three distinct dossier refs")
    reviews = product.get("cross_reviews")
    if not isinstance(reviews, list) or len(reviews) != 6:
        errors.append("MAGI product must contain all six directed cross-reviews")
    else:
        review_refs: list[str] = []
        execution_refs: list[str] = []
        reviewer_counts: dict[str, int] = {}
        reviewer_bindings: dict[str, tuple[Any, ...]] = {}
        artifact_review_pairs: set[tuple[str, str]] = set()
        for index, item in enumerate(reviews):
            label = f"MAGI product cross_reviews[{index}]"
            review_artifact: dict[str, Any] | None = None
            if not isinstance(item, dict):
                errors.append(f"{label} must be an object")
                continue
            exact_fields(item, MAGI_REVIEW_FIELDS, label, errors)
            if not nonempty(item.get("artifact_ref")):
                errors.append(f"{label}.artifact_ref must be a non-empty string")
            else:
                review_refs.append(item["artifact_ref"])
                _, review_raw = verify_magi_artifact_digest(
                    trial,
                    item.get("artifact_ref"),
                    item.get("sha256"),
                    f"{label} artifact",
                    errors,
                )
                review_artifact = load_magi_json(review_raw, f"{label} artifact", errors)
                if review_artifact is not None:
                    exact_fields(
                        review_artifact,
                        MAGI_REVIEW_ARTIFACT_FIELDS,
                        f"{label} artifact",
                        errors,
                    )
                    if review_artifact.get("review_version") != "1.1":
                        errors.append(f"{label} artifact.review_version is unsupported")
                    binding = review_artifact.get("reviewer_profile_binding")
                    if not isinstance(binding, dict):
                        errors.append(f"{label} artifact reviewer_profile_binding must be an object")
                    else:
                        exact_fields(
                            binding,
                            MAGI_REVIEW_PROFILE_BINDING_FIELDS,
                            f"{label} artifact reviewer_profile_binding",
                            errors,
                        )
                        for receipt_field, binding_field in (
                            ("reviewer_profile_id", "profile_id"),
                            ("reviewer_profile_sha256", "profile_sha256"),
                            ("reviewer_profile_source_sha256", "profile_source_sha256"),
                        ):
                            if item.get(receipt_field) != binding.get(binding_field):
                                errors.append(
                                    f"{label}.{receipt_field} does not match its review artifact"
                                )
                    methodology = review_artifact.get("methodology_trace")
                    methodology_bytes = json.dumps(
                        methodology,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    if item.get("methodology_trace_sha256") != CONTRACTS.sha256_bytes(
                        methodology_bytes
                    ):
                        errors.append(
                            f"{label}.methodology_trace_sha256 does not match its review artifact"
                        )
            for field in (
                "reviewer_seat_id",
                "reviewer_family",
                "reviewer_provider",
                "reviewer_text_model",
                "reviewer_multimodal_model",
                "reviewer_profile_id",
                "reviewer_execution_receipt_ref",
            ):
                if not nonempty(item.get(field)):
                    errors.append(f"{label}.{field} must be a non-empty string")
            if not CONTRACTS.is_digest(item.get("sha256")):
                errors.append(f"{label}.sha256 is invalid")
            for field in (
                "reviewer_profile_sha256",
                "reviewer_profile_source_sha256",
                "reviewer_agent_config_sha256",
                "methodology_trace_sha256",
                "reviewer_execution_receipt_sha256",
            ):
                if not CONTRACTS.is_digest(item.get(field)):
                    errors.append(f"{label}.{field} is invalid")
            if nonempty(item.get("reviewer_execution_receipt_ref")):
                execution_refs.append(item["reviewer_execution_receipt_ref"])
                _, receipt_raw = verify_magi_artifact_digest(
                    trial,
                    item.get("reviewer_execution_receipt_ref"),
                    item.get("reviewer_execution_receipt_sha256"),
                    f"{label} execution receipt",
                    errors,
                )
                validate_magi_execution_receipt(
                    load_magi_json(receipt_raw, f"{label} execution receipt", errors),
                    f"{label} execution receipt",
                    errors,
                    expected_kind="cross_review",
                    expected_seat_id=item.get("reviewer_seat_id"),
                    expected_profile_sha256=item.get("reviewer_profile_source_sha256"),
                    expected_agent_config_sha256=item.get("reviewer_agent_config_sha256"),
                    expected_execution_mode=None,
                    expected_output_sha256=item.get("sha256"),
                    expected_service=(
                        assignment_seats.get(item.get("reviewer_seat_id"), {}).get(
                            "container_service"
                        )
                    ),
                    expected_image_digest=(
                        assignment_seats.get(item.get("reviewer_seat_id"), {}).get(
                            "image_digest"
                        )
                    ),
                )
            reviewer_id = item.get("reviewer_seat_id")
            if nonempty(reviewer_id):
                reviewer_counts[reviewer_id] = reviewer_counts.get(reviewer_id, 0) + 1
                seat = seats_by_id.get(reviewer_id)
                if seat is None:
                    errors.append(f"{label}.reviewer_seat_id does not identify a product seat")
                else:
                    for receipt_field, seat_field in (
                        ("reviewer_family", "family"),
                        ("reviewer_provider", "provider"),
                        ("reviewer_text_model", "text_model"),
                        ("reviewer_multimodal_model", "multimodal_model"),
                        ("reviewer_profile_sha256", "profile_sha256"),
                    ):
                        if item.get(receipt_field) != seat.get(seat_field):
                            errors.append(f"{label}.{receipt_field} does not match its product seat")
                binding = tuple(
                    item.get(field)
                    for field in (
                        "reviewer_family",
                        "reviewer_provider",
                        "reviewer_text_model",
                        "reviewer_multimodal_model",
                        "reviewer_profile_id",
                        "reviewer_profile_sha256",
                        "reviewer_profile_source_sha256",
                        "reviewer_agent_config_sha256",
                    )
                )
                if reviewer_id in reviewer_bindings and reviewer_bindings[reviewer_id] != binding:
                    errors.append(f"{label} changes the frozen reviewer binding")
                reviewer_bindings[reviewer_id] = binding
                subject_alias = (
                    review_artifact.get("subject_alias")
                    if isinstance(review_artifact, dict)
                    else None
                )
                reviewer_alias = (
                    review_artifact.get("reviewer_alias")
                    if isinstance(review_artifact, dict)
                    else None
                )
                if reviewer_alias is not None and not nonempty(subject_alias):
                    errors.append(f"{label} artifact subject_alias must be a non-empty string")
                if nonempty(reviewer_alias) and nonempty(subject_alias):
                    artifact_review_pairs.add((reviewer_alias, subject_alias))
        if len(review_refs) != 6 or len(set(review_refs)) != 6:
            errors.append("MAGI product must contain six distinct cross-review refs")
        if len(execution_refs) != 6 or len(set(execution_refs)) != 6:
            errors.append("MAGI product must contain six distinct reviewer execution receipt refs")
        if set(reviewer_counts) != set(seats_by_id) or any(
            count != 2 for count in reviewer_counts.values()
        ):
            errors.append("MAGI product must contain exactly two cross-reviews from each seat")
        if assignment_review_pairs and len(artifact_review_pairs) != 6:
            errors.append("MAGI product review artifacts do not preserve six directed anonymous pairs")
    if isinstance(final_adjudicator, dict):
        _, receipt_raw = verify_magi_artifact_digest(
            trial,
            final_adjudicator.get("execution_receipt_ref"),
            final_adjudicator.get("execution_receipt_sha256"),
            "MAGI final adjudicator execution receipt",
            errors,
        )
        validate_magi_execution_receipt(
            load_magi_json(receipt_raw, "MAGI final adjudicator execution receipt", errors),
            "MAGI final adjudicator execution receipt",
            errors,
            expected_kind="final_adjudication",
            expected_seat_id=None,
            expected_profile_sha256=None,
            expected_agent_config_sha256=final_adjudicator.get("agent_config_sha256"),
            expected_execution_mode=final_adjudicator.get("execution_mode"),
            expected_output_sha256=product.get("final_verdict_sha256"),
        )
    outcome = {
        "product_ref": str(trial),
        "product_kind": "MAGI",
        "product_version": product.get("product_version", ""),
        "product_sha256": product.get("product_sha256", ""),
        "product_id": product.get("trial_id", ""),
        "status": product.get("status", ""),
        "decision": product.get("final_decision", ""),
        "question": product.get("question", ""),
        "action_scope": product.get("action_scope"),
        "affected_paths": product.get("affected_paths", []),
        "action_binding_sha256": product.get("action_binding_sha256", ""),
    }
    return outcome, errors


def build_product_evidence(
    request: dict[str, Any],
    route_decision: dict[str, Any],
    quinte_refs: list[str] | None = None,
    magi_refs: list[str] | None = None,
    *,
    base_dir: Path | None = None,
    quinte_receipt_refs: list[str] | None = None,
) -> dict[str, Any]:
    route = route_decision.get("route")
    qrefs = list(quinte_refs or [])
    qreceipt_refs = list(quinte_receipt_refs or [])
    mrefs = list(magi_refs or [])
    required = route in {"QUINTE", "MAGI"}
    expected = route if required else None
    errors: list[str] = []
    if qrefs and qreceipt_refs:
        errors.append("QUINTE result and host receipt cannot both be bound")
    if len(qrefs) + len(qreceipt_refs) + len(mrefs) > 1:
        errors.append("product binding accepts exactly one atomic product")
    quinte_sources = len(qrefs) + len(qreceipt_refs)
    if route == "QUINTE" and (quinte_sources != 1 or mrefs):
        errors.append("active QUINTE route requires exactly one QUINTE product or host receipt")
    elif route == "MAGI" and (len(mrefs) != 1 or qrefs or qreceipt_refs):
        errors.append("active MAGI route requires exactly one MAGI product")
    elif not required and (qrefs or qreceipt_refs or mrefs):
        errors.append("a product was supplied for a route that does not accept one")
    outcome = None
    if len(qrefs) == 1:
        summary, product_errors = summarize(qrefs[0], request, base_dir)
        errors.extend(product_errors)
        if summary is not None:
            outcome = {
                "product_ref": summary["result_ref"],
                "product_kind": "QUINTE",
                "product_version": summary["result_version"],
                "product_sha256": summary["result_sha256"],
                "product_id": summary["run_id"],
                "status": summary["status"],
                "decision": "PASS" if summary["status"] == "completed" else "BLOCK",
                "question": summary["question"],
                "action_scope": summary["action_scope"],
                "affected_paths": summary["affected_paths"],
                "action_binding_sha256": summary["action_binding_sha256"],
            }
    elif len(qreceipt_refs) == 1:
        summary, product_errors = load_quinte_host_receipt(
            qreceipt_refs[0], request, base_dir=base_dir
        )
        errors.extend(product_errors)
        if summary is not None:
            outcome = {
                "product_ref": summary["result_ref"],
                "product_kind": "QUINTE",
                "product_version": summary["result_version"],
                "product_sha256": summary["result_sha256"],
                "product_id": summary["run_id"],
                "status": summary["status"],
                "decision": "PASS" if summary["status"] == "completed" else "BLOCK",
                "question": summary["question"],
                "action_scope": summary["action_scope"],
                "affected_paths": summary["affected_paths"],
                "action_binding_sha256": summary["action_binding_sha256"],
                "host_receipt_ref": summary["host_receipt_ref"],
                "host_receipt_sha256": summary["host_receipt_sha256"],
                "host_receipt_operation": summary["host_receipt_operation"],
            }
    elif len(mrefs) == 1:
        outcome, product_errors = summarize_magi(mrefs[0], request, base_dir)
        errors.extend(product_errors)
    status = "invalid" if errors else "missing" if required and outcome is None else "not_required" if outcome is None else "complete"
    return {
        "required": required,
        "status": status,
        "binding": f"atomic_{expected.lower()}_product" if expected else "not_applicable",
        "product": outcome,
        "errors": errors,
    }
