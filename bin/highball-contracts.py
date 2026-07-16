#!/usr/bin/env python3
"""Shared HIGHBALL runtime contract identifiers and canonical bindings."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ACTION_PACKET_VERSION = "1.1"
RESIDUAL_TRACE_VERSION = "1.1"
QUINTE_BRIEF_VERSION = "1.1"
QUINTE_RESULT_VERSION = "2.0"
QUINTE_MANIFEST_VERSION = "1.0"
QUINTE_PROTOCOL_VERSION = "1.0"
QUINTE_TRIAL_MANIFEST_VERSION = "1.0"
QUINTE_CLI_ENVELOPE_VERSION = "1.0"
KENGEN_AUTHORIZATION_VERSION = "1.0"
KENGEN_CONSUMPTION_VERSION = "1.0"
ROUTE_EXECUTION_REPORT_VERSION = "1.1"
KENGEN_MAX_LIFETIME = timedelta(hours=8)

DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
ACTION_BINDING_FIELDS = (
    "question",
    "action_boundary",
    "change_class",
    "affected_paths",
)


def action_binding_payload(request: dict[str, Any]) -> dict[str, Any]:
    """Return the closed payload used to bind an action across products."""
    return {field: request.get(field) for field in ACTION_BINDING_FIELDS}


def canonical_action_binding_bytes(request: dict[str, Any]) -> bytes:
    """Encode the action binding as sorted, whitespace-free UTF-8 JSON."""
    return json.dumps(
        action_binding_payload(request),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def action_binding_sha256(request: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_action_binding_bytes(request)).hexdigest()
    return f"sha256:{digest}"


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def parse_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def validate_kengen_artifact(
    artifact: Any,
    request: dict[str, Any],
    *,
    now: datetime | None = None,
) -> list[str]:
    """Validate a short-lived, action-bound KENGEN user authorization."""
    if not isinstance(artifact, dict):
        return ["KENGEN authorization must be a JSON object"]
    fields = {
        "authorization_version",
        "authorization_id",
        "authorized_by",
        "decision",
        "action_binding_sha256",
        "action_scope",
        "issued_at",
        "expires_at",
    }
    errors: list[str] = []
    unknown = sorted(set(artifact) - fields)
    missing = sorted(fields - set(artifact))
    if unknown:
        errors.append(f"KENGEN authorization has unknown fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"KENGEN authorization is missing fields: {', '.join(missing)}")
    if artifact.get("authorization_version") != KENGEN_AUTHORIZATION_VERSION:
        errors.append("KENGEN authorization_version is unsupported")
    if not isinstance(artifact.get("authorization_id"), str) or not artifact["authorization_id"].strip():
        errors.append("KENGEN authorization_id must be a non-empty string")
    if artifact.get("authorized_by") != "user":
        errors.append("KENGEN authorized_by must be user")
    if artifact.get("decision") != "authorize":
        errors.append("KENGEN decision must be authorize")
    expected_binding = action_binding_sha256(request)
    if artifact.get("action_binding_sha256") != expected_binding:
        errors.append("KENGEN action binding does not match the route request")
    if artifact.get("action_scope") != request.get("action_scope"):
        errors.append("KENGEN action scope does not match the route request")
    issued_at = parse_utc_timestamp(artifact.get("issued_at"))
    expires_at = parse_utc_timestamp(artifact.get("expires_at"))
    if issued_at is None:
        errors.append("KENGEN issued_at must be an RFC 3339 UTC timestamp")
    if expires_at is None:
        errors.append("KENGEN expires_at must be an RFC 3339 UTC timestamp")
    if issued_at is not None and expires_at is not None:
        if expires_at <= issued_at:
            errors.append("KENGEN expires_at must be after issued_at")
        if expires_at - issued_at > KENGEN_MAX_LIFETIME:
            errors.append("KENGEN authorization lifetime exceeds eight hours")
        current = now or datetime.now(timezone.utc)
        if issued_at > current + timedelta(minutes=5):
            errors.append("KENGEN authorization is issued in the future")
        if expires_at <= current:
            errors.append("KENGEN authorization has expired")
    return errors


def summarize_kengen_artifact(
    ref: str | None,
    request: dict[str, Any],
    *,
    base_dir: Path | None = None,
    required: bool = False,
) -> dict[str, Any]:
    if ref is None:
        return {
            "required": required,
            "status": "missing" if required else "not_required",
            "artifact_ref": None,
            "artifact_sha256": None,
            "authorization_id": None,
            "action_binding_sha256": None,
            "action_scope": None,
            "issued_at": None,
            "expires_at": None,
            "errors": [],
        }
    path = Path(ref)
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    path = path.resolve()
    errors: list[str] = []
    artifact: dict[str, Any] | None = None
    raw = b""
    try:
        raw = path.read_bytes()
        parsed = json.loads(raw.decode("utf-8"))
        artifact = parsed if isinstance(parsed, dict) else None
        errors.extend(validate_kengen_artifact(parsed, request))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"KENGEN authorization cannot be read: {exc}")
    return {
        "required": required,
        "status": "invalid" if errors else "authorized",
        "artifact_ref": ref,
        "artifact_sha256": sha256_bytes(raw) if raw else None,
        "authorization_id": artifact.get("authorization_id") if artifact else None,
        "action_binding_sha256": artifact.get("action_binding_sha256") if artifact else None,
        "action_scope": artifact.get("action_scope") if artifact else None,
        "issued_at": artifact.get("issued_at") if artifact else None,
        "expires_at": artifact.get("expires_at") if artifact else None,
        "errors": errors,
    }
