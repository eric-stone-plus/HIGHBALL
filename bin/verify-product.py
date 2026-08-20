#!/usr/bin/env python3
"""Verify QUINTE product bundles against the active HIGHBALL contract."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
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
    else:
        observed_at = CONTRACTS.parse_utc_timestamp(value.get("observed_at"))
        # The receipt is an observation of a run, not the run itself, so a
        # fresh observation may describe an old run.  What must stay fresh
        # is the verification act: the docs promise stale products block.
        current = datetime.now(timezone.utc)
        if observed_at > current + timedelta(minutes=5):
            errors.append("QUINTE host receipt observed_at is in the future")
        if current - observed_at > timedelta(hours=24):
            errors.append("QUINTE host receipt is stale (observed more than twenty-four hours ago)")
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


def build_product_evidence(
    request: dict[str, Any],
    route_decision: dict[str, Any],
    quinte_refs: list[str] | None = None,
    *,
    base_dir: Path | None = None,
    quinte_receipt_refs: list[str] | None = None,
) -> dict[str, Any]:
    route = route_decision.get("route")
    qrefs = list(quinte_refs or [])
    qreceipt_refs = list(quinte_receipt_refs or [])
    required = route == "QUINTE"
    expected = route if required else None
    errors: list[str] = []
    if qrefs and qreceipt_refs:
        errors.append("QUINTE result and host receipt cannot both be bound")
    if len(qrefs) + len(qreceipt_refs) > 1:
        errors.append("product binding accepts exactly one atomic product")
    quinte_sources = len(qrefs) + len(qreceipt_refs)
    if route == "QUINTE" and quinte_sources != 1:
        errors.append("active QUINTE route requires exactly one QUINTE product or host receipt")
    elif not required and (qrefs or qreceipt_refs):
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
    status = "invalid" if errors else "missing" if required and outcome is None else "not_required" if outcome is None else "complete"
    return {
        "required": required,
        "status": status,
        "binding": f"atomic_{expected.lower()}_product" if expected else "not_applicable",
        "product": outcome,
        "errors": errors,
    }
