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
}
MAGI_REVIEW_FIELDS = {"artifact_ref", "sha256"}


def trusted_runs_root() -> Path:
    state_root = os.environ.get("QUINTE_HOME")
    root = Path(state_root).expanduser() if state_root else Path.home() / ".quinte"
    return (root / "runs").resolve()


def active_quinte_binary() -> Path | None:
    configured = os.environ.get("HIGHBALL_QUINTE_BIN")
    candidates = [Path(configured).expanduser()] if configured else []
    resolved = shutil.which("quinte")
    if resolved:
        candidates.append(Path(resolved))
    candidates.append(Path.home() / ".local" / "bin" / "quinte")
    if os.name == "nt":
        candidates.insert(0, Path.home() / "AppData" / "Local" / "Programs" / "quinte" / "bin" / "quinte.exe")
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    return None


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


def summarize(
    ref: str,
    request: dict[str, Any],
    base_dir: Path | None = None,
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

    quinte_binary = active_quinte_binary()
    if quinte_binary is None:
        errors.append("trusted quinte executable is not available on PATH")
    else:
        try:
            binary_sha256 = CONTRACTS.sha256_bytes(quinte_binary.read_bytes())
        except OSError as exc:
            errors.append(f"trusted quinte executable cannot be read: {exc}")
        else:
            if manifest.get("runtime_sha256") != binary_sha256:
                errors.append("quinte manifest runtime digest does not match the active executable")
        try:
            completed = subprocess.run(
                [str(quinte_binary), "inspect", str(result.get("run_id", "")), "--json"],
                capture_output=True,
                check=False,
                text=True,
                timeout=15,
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
    required = {
        "product_version", "product_sha256", "trial_id", "status", "runtime_sha256",
        "agent_config_sha256", "builder_config_sha256", "original_brief_sha256",
        "action_binding_sha256", "question", "action_scope", "affected_paths",
        "final_decision", "final_dissent", "final_verdict_ref", "final_verdict_sha256",
        "residual_trace_ref", "residual_trace_sha256", "seats", "cross_reviews",
    }
    exact_fields(product, required, "MAGI product summary", errors)
    if product.get("product_version") != CONTRACTS.MAGI_PRODUCT_VERSION:
        errors.append("MAGI product_version is unsupported")
    if product.get("status") != "completed":
        errors.append("MAGI product is not completed")
    if product.get("final_decision") not in {"PASS", "BLOCK", "ESCALATE"}:
        errors.append("MAGI final decision is invalid")
    if not string_list(product.get("final_dissent"), nonempty_items=True):
        errors.append("MAGI final dissent must be an array of non-empty strings")
    for field in ("trial_id", "question", "final_verdict_ref", "residual_trace_ref"):
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
        "product_sha256", "runtime_sha256", "agent_config_sha256",
        "original_brief_sha256", "action_binding_sha256", "final_verdict_sha256",
        "residual_trace_sha256",
    ):
        if not CONTRACTS.is_digest(product.get(field)):
            errors.append(f"MAGI product {field} is invalid")
    if product.get("builder_config_sha256") is not None and not CONTRACTS.is_digest(
        product.get("builder_config_sha256")
    ):
        errors.append("MAGI product builder_config_sha256 is invalid")
    if product.get("action_binding_sha256") != CONTRACTS.action_binding_sha256(request):
        errors.append("MAGI action binding does not match the route request")
    for field in ("question", "action_scope", "affected_paths"):
        if product.get(field) != request.get(field):
            errors.append(f"MAGI product {field} does not match the route request")
    seats = product.get("seats")
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
            if nonempty(item.get("seat_id")):
                seat_ids.append(item["seat_id"])
            if nonempty(item.get("family")):
                families.append(item["family"])
            if CONTRACTS.is_digest(item.get("profile_sha256")):
                profiles.append(item["profile_sha256"])
            if nonempty(item.get("quinte_run_id")):
                runs.append(item["quinte_run_id"])
            if nonempty(item.get("dossier_ref")):
                dossier_refs.append(item["dossier_ref"])
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
        for index, item in enumerate(reviews):
            label = f"MAGI product cross_reviews[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{label} must be an object")
                continue
            exact_fields(item, MAGI_REVIEW_FIELDS, label, errors)
            if not nonempty(item.get("artifact_ref")):
                errors.append(f"{label}.artifact_ref must be a non-empty string")
            else:
                review_refs.append(item["artifact_ref"])
            if not CONTRACTS.is_digest(item.get("sha256")):
                errors.append(f"{label}.sha256 is invalid")
        if len(review_refs) != 6 or len(set(review_refs)) != 6:
            errors.append("MAGI product must contain six distinct cross-review refs")
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
) -> dict[str, Any]:
    route = route_decision.get("route")
    qrefs = list(quinte_refs or [])
    mrefs = list(magi_refs or [])
    required = route in {"QUINTE", "MAGI"}
    expected = route if required else None
    errors: list[str] = []
    if len(qrefs) + len(mrefs) > 1:
        errors.append("product binding accepts exactly one atomic product")
    if route == "QUINTE" and (len(qrefs) != 1 or mrefs):
        errors.append("active QUINTE route requires exactly one QUINTE product")
    elif route == "MAGI" and (len(mrefs) != 1 or qrefs):
        errors.append("active MAGI route requires exactly one MAGI product")
    elif not required and (qrefs or mrefs):
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
