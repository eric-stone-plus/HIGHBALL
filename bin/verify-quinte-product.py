#!/usr/bin/env python3
"""Verify a QUINTE product bundle against the active HIGHBALL contract."""

from __future__ import annotations

import importlib.util
import json
import os
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
EXPECTED_ROUTES = [
    ("Party A", "codewhale"),
    ("Party B", "opencode"),
    ("Party C", "kilo"),
    ("Party D", "mimo"),
    ("Party E", "omp"),
]


def trusted_runs_root() -> Path:
    return (Path.home() / ".quinte" / "runs").resolve()


def active_quinte_binary() -> Path | None:
    candidates = [Path.home() / ".local" / "bin" / "quinte"]
    if os.name == "nt":
        candidates.insert(0, Path.home() / "AppData" / "Local" / "Programs" / "quinte" / "bin" / "quinte.exe")
    for candidate in candidates:
        if candidate.is_file():
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


def validate_trial_manifest(value: Any, errors: list[str]) -> None:
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
        expected = EXPECTED_ROUTES[index] if index < len(EXPECTED_ROUTES) else (None, None)
        if (perspective.get("party_id"), perspective.get("route_id")) != expected:
            errors.append(f"{item_label} does not match the fixed QUINTE route")
        if perspective.get("r1_artifact") != f"lanes/R1/{expected[1]}/accepted.json":
            errors.append(f"{item_label}.r1_artifact is invalid")
        if perspective.get("r2_artifact") != f"lanes/R2/{expected[1]}/accepted.json":
            errors.append(f"{item_label}.r2_artifact is invalid")
        if perspective.get("independent_first_pass") is not True:
            errors.append(f"{item_label}.independent_first_pass must be true")
    for field in ("perturbation_axes", "independence_controls", "contamination_risks"):
        if not string_list(value.get(field), nonempty_items=True):
            errors.append(f"{label}.{field} must be an array of non-empty strings")
    wall_time = value.get("wall_time_seconds")
    if wall_time is not None and (not isinstance(wall_time, int) or isinstance(wall_time, bool) or wall_time < 0):
        errors.append(f"{label}.wall_time_seconds must be a non-negative integer or null")


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
    validate_trial_manifest(result.get("trial_manifest"), errors)


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


def build_execution_evidence(
    request: dict[str, Any],
    route_decision: dict[str, Any],
    result_refs: list[str] | None = None,
    *,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    required = route_decision.get("route") == "QUINTE"
    refs = list(result_refs or [])
    errors: list[str] = []
    outcome = None
    if required and len(refs) != 1:
        errors.append("active QUINTE route requires exactly one atomic result.json")
    elif not required and refs:
        errors.append("QUINTE result was supplied for a route that does not authorize QUINTE execution")
    if len(refs) == 1:
        outcome, outcome_errors = summarize(refs[0], request, base_dir)
        errors.extend(outcome_errors)
    elif len(refs) > 1:
        errors.append("active QUINTE binding accepts exactly one product result")
    status = (
        "invalid"
        if errors
        else "missing"
        if required and outcome is None
        else "not_required"
        if outcome is None
        else "complete"
        if outcome.get("status") == "completed"
        else "blocked"
    )
    return {
        "required": required,
        "status": status,
        "binding": "atomic_quinte_outcome" if required or refs else "not_applicable",
        "quinte_outcome": outcome,
        "errors": errors,
    }
