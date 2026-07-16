#!/usr/bin/env python3
"""Atomically consume one action-bound KENGEN authorization."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
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
CONTRACTS = load_module("highball_contracts", ROOT / "bin" / "highball-contracts.py")
ROUTER = load_module("route_residual_action", ROOT / "bin" / "route-residual-action.py")


def default_ledger() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home) / "highball" / "kengen-consumed"
    return Path.home() / ".local" / "state" / "highball" / "kengen-consumed"


def safe_component(value: str) -> str:
    if not value or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in value):
        raise ValueError("authorization_id must contain only A-Z, a-z, 0-9, dot, underscore, or hyphen")
    return value


def atomic_consume(ledger: Path, authorization_id: str, record: dict[str, Any]) -> Path:
    ledger.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        ledger.chmod(0o700)
    except OSError:
        pass
    claim = ledger / f"{safe_component(authorization_id)}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(claim, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        claim.unlink(missing_ok=True)
        raise
    return claim


def main() -> int:
    parser = argparse.ArgumentParser(description="Consume a KENGEN authorization exactly once")
    parser.add_argument("route_request", type=Path)
    parser.add_argument("authorization", type=Path)
    parser.add_argument("--ledger", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        request = json.loads(args.route_request.read_text(encoding="utf-8"))
        if not isinstance(request, dict):
            raise ValueError("route request must be a JSON object")
        request_errors = ROUTER.validate_request(request)
        if request_errors:
            raise ValueError("; ".join(request_errors))
        raw = args.authorization.read_bytes()
        artifact = json.loads(raw.decode("utf-8"))
        errors = CONTRACTS.validate_kengen_artifact(artifact, request)
        if errors:
            raise ValueError("; ".join(errors))
        record = {
            "consumption_version": CONTRACTS.KENGEN_CONSUMPTION_VERSION,
            "authorization_id": artifact["authorization_id"],
            "authorization_sha256": CONTRACTS.sha256_bytes(raw),
            "action_binding_sha256": CONTRACTS.action_binding_sha256(request),
        }
        ledger = args.ledger.resolve() if args.ledger is not None and os.environ.get("HIGHBALL_TESTING") == "1" else default_ledger().resolve()
        claim = atomic_consume(ledger, artifact["authorization_id"], record)
    except FileExistsError:
        print("[KENGEN] BLOCK: authorization was already consumed", file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"[KENGEN] ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"[KENGEN] authorization consumed: {claim}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
