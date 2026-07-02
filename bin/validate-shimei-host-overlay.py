#!/usr/bin/env python3
"""Validate a HIGHBALL SHIMEI host overlay."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any


NON_AUTHORIZATION = "SHIMEI host overlays do not authorize action, dispatch agents, or modify routing rules."

TOP_LEVEL_FIELDS = {
    "overlay_version",
    "profile_ref",
    "platform",
    "prompt_policy",
    "routes",
    "non_authorization",
}
PROMPT_POLICY_FIELDS = {
    "long_prompt_ref",
    "shell_expansion_allowed",
}
ROUTE_FIELDS = {
    "id",
    "role",
    "route_type",
    "route_id",
    "required",
    "command",
    "entrypoint",
    "artifact_policy",
}
ENTRYPOINT_FIELDS = {
    "kind",
    "executable",
    "verification_command",
    "verification_evidence",
    "is_custom_wrapper",
}
ARTIFACT_POLICY_FIELDS = {
    "separate_output_artifact",
    "requires_task_restatement",
}

PLATFORMS = {"macos", "windows", "linux", "unknown"}
ROUTE_TYPES = {
    "hm",
    "quinte_party",
    "quinte_auditor_b",
    "magi_perspective",
    "implementation_audit",
    "system_audit",
    "direct_evidence",
}
ENTRYPOINT_KINDS = {"host_session", "native_cli", "package_manager_shim"}
QUINTE_PARTIES = ["Party A", "Party B", "Party C", "Party D", "Party E"]
MAGI_PERSPECTIVES = ["Perspective A", "Perspective B", "Perspective C"]
WRAPPER_PATTERN = re.compile(r"(wrapper|delegate|dispatch-script|shim-wrapper)", re.IGNORECASE)


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


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def validate_command(name: str, value: Any, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) == 0:
        errors.append(f"{name} must be a non-empty array of command tokens")
        return []
    command: list[str] = []
    for index, item in enumerate(value):
        if not is_nonempty_string(item):
            errors.append(f"{name}[{index}] must be a non-empty string")
        else:
            command.append(item)
    return command


def command_executable(command: list[str]) -> str | None:
    return command[0] if command else None


def executable_matches(command: list[str], executable: str) -> bool:
    first = command_executable(command)
    if first is None:
        return False
    if first == executable:
        return True
    return Path(first).name == Path(executable).name


def looks_like_wrapper(value: str) -> bool:
    return WRAPPER_PATTERN.search(value) is not None


def validate_route(index: int, value: Any, errors: list[str]) -> dict[str, Any]:
    prefix = f"routes[{index}]"
    route = validate_fields(prefix, value, ROUTE_FIELDS, errors)
    if not route:
        return {}

    for field in ("id", "role", "route_id"):
        if not is_nonempty_string(route.get(field)):
            errors.append(f"{prefix}.{field} must be a non-empty string")
    if route.get("route_type") not in ROUTE_TYPES:
        errors.append(f"{prefix}.route_type is invalid")
    if route.get("required") is not True:
        errors.append(f"{prefix}.required must be true")

    command = validate_command(f"{prefix}.command", route.get("command"), errors)
    entrypoint = validate_fields(f"{prefix}.entrypoint", route.get("entrypoint"), ENTRYPOINT_FIELDS, errors)
    if entrypoint:
        if entrypoint.get("kind") not in ENTRYPOINT_KINDS:
            errors.append(f"{prefix}.entrypoint.kind is invalid")
        for field in ("executable", "verification_command", "verification_evidence"):
            if not is_nonempty_string(entrypoint.get(field)):
                errors.append(f"{prefix}.entrypoint.{field} must be a non-empty string")
        if entrypoint.get("is_custom_wrapper") is not False:
            errors.append(f"{prefix}.entrypoint.is_custom_wrapper must be false")
        executable = entrypoint.get("executable")
        if isinstance(executable, str) and command and not executable_matches(command, executable):
            errors.append(f"{prefix}.command[0] must match entrypoint.executable")
        for field in ("executable", "verification_command", "verification_evidence"):
            value = entrypoint.get(field)
            if isinstance(value, str) and looks_like_wrapper(value):
                errors.append(f"{prefix}.entrypoint.{field} looks like a wrapper dispatch path")
        if entrypoint.get("kind") == "host_session" and route.get("route_type") != "hm":
            errors.append(f"{prefix}.entrypoint.kind host_session is only valid for hm")
        if route.get("route_type") == "hm" and entrypoint.get("kind") != "host_session":
            errors.append(f"{prefix}.entrypoint.kind must be host_session for hm")
        if route.get("route_type") != "hm" and entrypoint.get("kind") == "host_session":
            errors.append(f"{prefix}.entrypoint.kind must not be host_session for dispatched routes")

    artifact = validate_fields(f"{prefix}.artifact_policy", route.get("artifact_policy"), ARTIFACT_POLICY_FIELDS, errors)
    if artifact:
        if artifact.get("separate_output_artifact") is not True:
            errors.append(f"{prefix}.artifact_policy.separate_output_artifact must be true")
        if route.get("route_type") in {"quinte_party", "quinte_auditor_b"}:
            if artifact.get("requires_task_restatement") is not True:
                errors.append(f"{prefix}.artifact_policy.requires_task_restatement must be true for QUINTE routes")
        elif not is_bool(artifact.get("requires_task_restatement")):
            errors.append(f"{prefix}.artifact_policy.requires_task_restatement must be boolean")

    return route


def validate_overlay(overlay: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(overlay, dict):
        return ["overlay must be an object"]

    validate_fields("overlay", overlay, TOP_LEVEL_FIELDS, errors)
    if overlay.get("overlay_version") != "1.0":
        errors.append("overlay_version must be 1.0")
    if not is_nonempty_string(overlay.get("profile_ref")):
        errors.append("profile_ref must be a non-empty string")
    if overlay.get("platform") not in PLATFORMS:
        errors.append("platform is invalid")
    if overlay.get("non_authorization") != NON_AUTHORIZATION:
        errors.append("non_authorization text is invalid")

    prompt_policy = validate_fields("prompt_policy", overlay.get("prompt_policy"), PROMPT_POLICY_FIELDS, errors)
    if prompt_policy:
        if not is_nonempty_string(prompt_policy.get("long_prompt_ref")):
            errors.append("prompt_policy.long_prompt_ref must be a non-empty string")
        if prompt_policy.get("shell_expansion_allowed") is not False:
            errors.append("prompt_policy.shell_expansion_allowed must be false")

    routes_value = overlay.get("routes")
    parsed_routes: list[dict[str, Any]] = []
    if not isinstance(routes_value, list) or len(routes_value) == 0:
        errors.append("routes must be a non-empty array")
    else:
        for index, route in enumerate(routes_value, start=1):
            parsed = validate_route(index, route, errors)
            if parsed:
                parsed_routes.append(parsed)

    if parsed_routes:
        ids = [route.get("id") for route in parsed_routes]
        route_ids = [route.get("route_id") for route in parsed_routes]
        if len(ids) != len(set(ids)):
            errors.append("routes.id values must be unique")
        if len(route_ids) != len(set(route_ids)):
            errors.append("routes.route_id values must be unique")

        quinte_parties = [route.get("role") for route in parsed_routes if route.get("route_type") == "quinte_party"]
        if quinte_parties and quinte_parties != QUINTE_PARTIES:
            errors.append("quinte_party routes must bind Party A through Party E in order")
        auditors = [route for route in parsed_routes if route.get("route_type") == "quinte_auditor_b"]
        if quinte_parties and len(auditors) != 1:
            errors.append("QUINTE host overlays with Party A-E must bind exactly one Auditor B")
        if auditors and auditors[0].get("role") != "Auditor B":
            errors.append("quinte_auditor_b route role must be Auditor B")

        magi = [route.get("role") for route in parsed_routes if route.get("route_type") == "magi_perspective"]
        if magi and magi != MAGI_PERSPECTIVES:
            errors.append("magi_perspective routes must bind Perspective A through Perspective C in order")

    return errors


def check_executables(overlay: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for index, route in enumerate(overlay.get("routes", []), start=1):
        if not isinstance(route, dict):
            continue
        entrypoint = route.get("entrypoint")
        if not isinstance(entrypoint, dict):
            continue
        if entrypoint.get("kind") == "host_session":
            continue
        executable = entrypoint.get("executable")
        if not isinstance(executable, str):
            continue
        if "/" in executable or "\\" in executable:
            path = Path(executable)
            if not path.exists():
                errors.append(f"routes[{index}] executable does not exist: {executable}")
            elif os.name != "nt" and not os.access(path, os.X_OK):
                errors.append(f"routes[{index}] executable is not executable: {executable}")
        elif shutil.which(executable) is None:
            errors.append(f"routes[{index}] executable is not on PATH: {executable}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL SHIMEI host overlay")
    parser.add_argument("overlay", type=Path)
    parser.add_argument("--check-executables", action="store_true", help="verify entrypoint executables exist on this host")
    args = parser.parse_args()

    try:
        overlay = load_json(args.overlay)
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    errors = validate_overlay(overlay)
    if args.check_executables and not errors:
        errors.extend(check_executables(overlay))
    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    print("[HIGHBALL] SHIMEI host overlay valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
