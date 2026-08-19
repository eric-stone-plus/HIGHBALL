#!/usr/bin/env python3
"""Negative and product-binding tests for the HIGHBALL control plane.

Drives the shipped Rust `highball` binary. Fixture helpers below only
construct request/trace/trial trees; they are not the implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HIGHBALL = ROOT / "target" / "debug" / "highball"
if not HIGHBALL.is_file():
    HIGHBALL = ROOT / "target" / "release" / "highball"

ACTION_PACKET_VERSION = "2.0"
ROUTE_EXECUTION_REPORT_VERSION = "2.0"


def fixture_sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def fixture_action_binding_payload(request: dict[str, Any]) -> dict[str, Any]:
    return {field: request.get(field) for field in (
        "question", "action_boundary", "change_class", "affected_paths",
    )}


def fixture_canonical_action_binding_bytes(request: dict[str, Any]) -> bytes:
    return json.dumps(
        fixture_action_binding_payload(request),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def fixture_action_binding_sha256(request: dict[str, Any]) -> str:
    return fixture_sha256_bytes(fixture_canonical_action_binding_bytes(request))


def highball(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        [str(HIGHBALL), *args],
        capture_output=True,
        text=True,
        env=merged,
    )


def highball_json(*args: str, env: dict[str, str] | None = None) -> Any:
    completed = highball(*args, env=env)
    if not completed.stdout.strip():
        raise AssertionError(
            f"highball {' '.join(args)} produced no stdout\nstderr={completed.stderr}\nrc={completed.returncode}"
        )
    return json.loads(completed.stdout)


def validate_packet_errors(packet: dict[str, Any], base_dir: Path) -> list[str]:
    path = base_dir / "validate-packet.json"
    write(path, packet)
    completed = highball("validate-action-packet", str(path), "--base-dir", str(base_dir))
    if completed.returncode in (0, 1):
        return []
    return [
        line.split("ERROR: ", 1)[-1]
        for line in completed.stderr.splitlines()
        if "ERROR:" in line
    ]


def validate_report_errors(report: dict[str, Any], base_dir: Path) -> list[str]:
    path = base_dir / "validate-report.json"
    write(path, report)
    completed = highball("validate-route-execution-report", str(path))
    if completed.returncode in (0, 1):
        return []
    return [
        line.split("ERROR: ", 1)[-1]
        for line in completed.stderr.splitlines()
        if "ERROR:" in line
    ]


class ContractSchemaTests(unittest.TestCase):
    def test_host_uuid_helper_accepts_only_canonical_uuidv7(self) -> None:
        self.assertEqual(highball("uuid-v7", "018f47a2-4b5c-7d6e-8f90-123456789abc").returncode, 0)
        self.assertNotEqual(highball("uuid-v7", "018f47a2-4b5c-1d6e-8f90-123456789abc").returncode, 0)
        self.assertNotEqual(highball("uuid-v7", "018F47A2-4B5C-7D6E-8F90-123456789ABC").returncode, 0)

    def test_action_packet_schema_matches_active_product_decisions(self) -> None:
        schema = json.loads((ROOT / "schemas" / "action-packet.schema.json").read_text())
        self.assertEqual(schema["properties"]["packet_version"]["const"], ACTION_PACKET_VERSION)
        product = schema["$defs"]["productOutcome"]
        self.assertEqual(set(product["properties"]["decision"]["enum"]), {"PASS", "BLOCK", "ESCALATE"})
        self.assertEqual(product["properties"]["status"]["const"], "completed")
        conditional = product["allOf"][0]
        self.assertEqual(conditional["if"]["properties"]["product_kind"]["const"], "QUINTE")
        self.assertEqual(conditional["then"]["properties"]["decision"]["const"], "PASS")
        self.assertEqual(
            product["dependentRequired"],
            {
                "host_receipt_ref": ["host_receipt_sha256", "host_receipt_operation"],
                "host_receipt_sha256": ["host_receipt_ref", "host_receipt_operation"],
                "host_receipt_operation": ["host_receipt_ref", "host_receipt_sha256"],
            },
        )

        try:
            import jsonschema
        except ModuleNotFoundError:
            return
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_runtime_resolution_honors_explicit_state_and_binary_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "bin" / "quinte"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            resolved = highball_json(
                "resolve-runtime",
                env={
                    "QUINTE_HOME": str(root / "state"),
                    "HIGHBALL_QUINTE_BIN": str(binary),
                },
            )
            self.assertEqual(resolved["trusted_runs_root"], str((root / "state" / "runs").resolve()))
            self.assertEqual(resolved["active_quinte_binary"], str(binary.resolve()))

    def test_direct_quinte_verification_requires_explicit_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "bin" / "quinte"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            result_path = product(root / "state", request(), binary)
            req_path = root / "request.json"
            write(req_path, request())
            env = {k: v for k, v in os.environ.items() if k not in {"QUINTE_HOME", "HIGHBALL_QUINTE_BIN"}}
            out = highball_json(
                "summarize-quinte", str(result_path), str(req_path), "--verify-cli", env=env
            )
            self.assertTrue(any("QUINTE_HOME" in error for error in out["errors"]))

    def test_direct_quinte_verification_rejects_runtime_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state = root / "state"
            binary = root / "bin" / "quinte"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            result_path = product(state, request(), binary)
            binary.write_text("#!/bin/sh\n# replaced\nexit 0\n", encoding="utf-8")
            req_path = root / "request.json"
            write(req_path, request())
            out = highball_json(
                "summarize-quinte",
                str(result_path),
                str(req_path),
                "--verify-cli",
                env={"QUINTE_HOME": str(state), "HIGHBALL_QUINTE_BIN": str(binary)},
            )
            self.assertTrue(any("runtime digest" in error for error in out["errors"]), out["errors"])

    def test_direct_quinte_verification_rejects_relative_binary_pin(self) -> None:
        completed = highball(
            "resolve-runtime",
            env={"QUINTE_HOME": "/absolute/state", "HIGHBALL_QUINTE_BIN": "quinte"},
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("absolute path", completed.stderr)

    def test_direct_quinte_verification_accepts_matching_explicit_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state = root / "state"
            binary = root / "bin" / "quinte"
            binary.parent.mkdir()
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "run = pathlib.Path(os.environ['QUINTE_HOME']) / 'runs' / sys.argv[2]\n"
                "print(json.dumps({'cli_envelope_version': '1.0', 'ok': True, "
                "'data': {'manifest': json.loads((run/'manifest.json').read_text()), "
                "'result': json.loads((run/'result.json').read_text())}}))\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            result_path = product(state, request(), binary)
            req_path = root / "request.json"
            write(req_path, request())
            out = highball_json(
                "summarize-quinte",
                str(result_path),
                str(req_path),
                "--verify-cli",
                env={"QUINTE_HOME": str(state), "HIGHBALL_QUINTE_BIN": str(binary)},
            )
            self.assertIsNotNone(out["summary"])
            self.assertEqual(out["errors"], [])

    def test_route_execution_schema_matches_active_version(self) -> None:
        schema = json.loads((ROOT / "schemas" / "route-execution-report.schema.json").read_text())
        self.assertEqual(
            schema["properties"]["execution_report_version"]["const"],
            ROUTE_EXECUTION_REPORT_VERSION,
        )
        try:
            import jsonschema
        except ModuleNotFoundError:
            return
        jsonschema.Draft202012Validator.check_schema(schema)


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def digest_value(value: Any) -> str:
    return fixture_sha256_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    )


def write_digest(path: Path, value: Any) -> str:
    write(path, value)
    return fixture_sha256_bytes(path.read_bytes())


def request(**changes: Any) -> dict[str, Any]:
    value = {
        "question": "Should this protected change proceed?",
        "action_boundary": "protected_write",
        "change_class": "code",
        "affected_paths": ["HIGHBALL/bin/tool.py"],
        "action_scope": "Only HIGHBALL/bin/tool.py in this task.",
        "risk": "HIGH",
        "executable": False,
        "trace_quality_gate": "pass",
        "open_high_risk_count": 0,
    }
    value.update(changes)
    return value


def trace(req: dict[str, Any], **changes: Any) -> dict[str, Any]:
    value = {
        "trace_version": "1.1",
        "action_binding_sha256": fixture_action_binding_sha256(req),
        "question": req["question"],
        "instrument": "QUINTE",
        "residuals": [],
        "action_boundary": req["action_boundary"],
        "highball_decision": "pass",
        "trial_manifest": {
            "manifest_version": "1.0",
            "base_model_relation": "same_model",
            "perspective_count": 5,
            "perspectives": [
                {
                    "id": f"Party {letter}",
                    "role": "reviewer",
                    "route": route_id,
                    "artifact": f"lanes/R1/{route_id}/accepted.json",
                    "prompt_hash": None,
                    "independent_first_pass": True,
                }
                for letter, route_id in zip("ABCDE", ("codewhale", "opencode", "kilo", "mimo", "omp"))
            ],
            "perturbation_axes": ["role"],
            "independence_controls": ["independent first pass"],
            "contamination_risks": ["same model"],
            "cost": {"total_tokens": 1, "wall_time_seconds": 1, "tool_calls": 0, "human_minutes": 0},
        },
    }
    value.update(changes)
    return value


def product(home: Path, req: dict[str, Any], binary: Path, *, result_version: str = "2.1") -> Path:
    run_id = "018f47a2-4b5c-7d6e-8f90-123456789abc"
    run_dir = home / "runs" / run_id
    binding = fixture_action_binding_sha256(req)
    brief = {
        "brief_version": "1.1",
        "question": req["question"],
        "context": None,
        "evidence_roots": [],
        "snapshot_ignore": [],
        "attachments": [],
        "action_scope": req["action_scope"],
        "affected_paths": req["affected_paths"],
        "action_binding_sha256": binding,
    }
    brief_bytes = json.dumps(brief, ensure_ascii=False, separators=(",", ":")).encode()
    brief_sha = fixture_sha256_bytes(brief_bytes)
    perspectives = []
    for letter, route_id in zip("ABCDE", ("codewhale", "opencode", "kilo", "mimo", "omp")):
        perspectives.append({
            "party_id": f"Party {letter}",
            "route_id": route_id,
            "r1_artifact": f"lanes/R1/{route_id}/accepted.json",
            "r2_artifact": f"lanes/R2/{route_id}/accepted.json",
            "independent_first_pass": True,
        })
    result = {
        "result_version": result_version,
        "run_id": run_id,
        "status": "completed",
        "brief_sha256": brief_sha,
        "question": req["question"],
        "action_scope": req["action_scope"],
        "affected_paths": req["affected_paths"],
        "action_binding_sha256": binding,
        "seat_binding": {
            "seat_id": "seat-test",
            "family": "mimo",
            "provider": "xiaomi-token-plan-cn",
            "text_model": "mimo-v2.5-pro",
            "multimodal_model": "mimo-v2.5-pro",
        },
        "route_bindings": [],
        "summary": "Complete review.",
        "recommendation": "Proceed within scope.",
        "dissent": [],
        "residuals": [],
        "trial_manifest": {
            "manifest_version": "1.0",
            "base_model_relation": "same_model",
            "perspective_count": 5,
            "perspectives": perspectives,
            "perturbation_axes": ["role"],
            "independence_controls": ["independent first pass"],
            "contamination_risks": ["same model"],
            "wall_time_seconds": 1,
        },
    }
    parties = ["Party A", "Party B", "Party C", "Party D", "Party E", "Counterpart Arbiter", "Primary Arbiter"]
    route_ids = ["codewhale", "opencode", "kilo", "mimo", "omp", "cc", "pa"]
    result["route_bindings"] = [
        {
            "party_id": party,
            "route_id": route,
            "adapter": "omp",
            "executable": "omp",
            "family": "mimo",
            "provider": "xiaomi-token-plan-cn",
            "text_model": "mimo-v2.5-pro",
            "multimodal_model": "mimo-v2.5-pro",
            "perspective": "",
        }
        for party, route in zip(parties, route_ids)
    ]
    result_path = run_dir / "result.json"
    write(run_dir / "input" / "brief.json", brief)
    write(result_path, result)
    result_sha = fixture_sha256_bytes(result_path.read_bytes())
    manifest = {
        "manifest_version": "2.0",
        "run_id": run_id,
        "created_at": "2026-01-01T00:00:00.000Z",
        "updated_at": "2026-01-01T00:00:01.000Z",
        "status": "completed",
        "brief_sha256": brief_sha,
        "policy_sha256": "sha256:" + "1" * 64,
        "snapshot_sha256": "sha256:" + "2" * 64,
        "runtime_sha256": fixture_sha256_bytes(binary.read_bytes()),
        "protocol_version": "1.0",
        "effective_model": "mimo-v2.5-pro",
        "seat_binding": result["seat_binding"],
        "route_bindings": result["route_bindings"],
        "sandbox_mode": "process",
        "current_phase": None,
        "error": None,
        "r3_input_receipt": None,
        "primary_arbiter_challenge": None,
        "primary_arbiter_submission": None,
        "result_sha256": result_sha,
    }
    write(run_dir / "manifest.json", manifest)
    return result_path



class FailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_path = os.environ.get("PATH", "")
        self.binary = self.root / "bin" / "quinte"
        self.binary.parent.mkdir()
        self.binary.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            f"run = pathlib.Path({str(self.root / 'quinte')!r}) / 'runs' / sys.argv[2]\n"
            "print(json.dumps({'cli_envelope_version': '1.0', 'ok': True, 'data': "
            "{'manifest': json.loads((run/'manifest.json').read_text()), "
            "'result': json.loads((run/'result.json').read_text()), 'events': []}}))\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        os.environ["PATH"] = str(self.binary.parent) + os.pathsep + self.old_path
        self.env = {
            "QUINTE_HOME": str(self.root / "quinte"),
            "HIGHBALL_QUINTE_BIN": str(self.binary.resolve()),
        }
        self._old_pins = {
            key: os.environ.get(key)
            for key in ("QUINTE_HOME", "HIGHBALL_QUINTE_BIN")
        }
        os.environ.update(self.env)

    def tearDown(self) -> None:
        os.environ["PATH"] = self.old_path
        for key, value in self._old_pins.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp.cleanup()

    def build(
        self,
        req: dict[str, Any],
        tr: dict[str, Any],
        result: Path | None = None,
        auth: Path | None = None,
        receipt: Path | None = None,
    ) -> dict[str, Any]:
        req_path, trace_path = self.root / "request.json", self.root / "trace.json"
        write(req_path, req)
        write(trace_path, tr)
        args = ["build-action-packet", str(req_path), str(trace_path)]
        if result is not None:
            args.extend(["--quinte-result", str(result)])
        if receipt is not None:
            args.extend(["--quinte-receipt", str(receipt)])
        if auth is not None:
            args.extend(["--authorization", str(auth)])
        return highball_json(*args, env=self.env)

    def route(self, req: dict[str, Any]) -> dict[str, Any]:
        path = self.root / "route-request.json"
        write(path, req)
        return highball_json("route-residual-action", str(path), env=self.env)

    def route_errors(self, req: dict[str, Any]) -> list[str]:
        path = self.root / "route-request.json"
        write(path, req)
        completed = highball("route-residual-action", str(path), env=self.env)
        return [
            line.split("ERROR: ", 1)[-1]
            for line in completed.stderr.splitlines()
            if "ERROR:" in line
        ]

    def load_receipt(self, receipt_path: Path, req: dict[str, Any]) -> tuple[Any, list[str]]:
        req_path = self.root / "receipt-request.json"
        write(req_path, req)
        out = highball_json("load-host-receipt", str(receipt_path), str(req_path), env=self.env)
        return out["summary"], out["errors"]

    def execution_report(self, packet_path: Path) -> dict[str, Any]:
        return highball_json("build-route-execution-report", str(packet_path), env=self.env)

    def host_receipt(self, result_path: Path, *, operation: str = "inspect") -> Path:
        run_id = json.loads(result_path.read_text())["run_id"]
        run_dir = result_path.parent
        manifest = json.loads((run_dir / "manifest.json").read_text())
        state_root = self.root / "quinte"
        invocation_id = "019fd896-7769-7c62-a3c3-e4f34fbc09f3"
        receipt_path = state_root / "host" / "receipts" / f"{invocation_id}.json"
        receipt = {
            "host_receipt_version": "1.0",
            "invocation_id": invocation_id,
            "receipt_path": str(receipt_path),
            "operation": operation,
            "observed_at": "2026-08-07T00:00:00Z",
            "state_root": str(state_root),
            "state": {"code": "terminal", "active_run_ids": []},
            "run_id": run_id,
            "manifest": {
                "status": manifest["status"],
                "manifest_version": manifest["manifest_version"],
                "brief_sha256": manifest["brief_sha256"],
                "policy_sha256": manifest["policy_sha256"],
                "snapshot_sha256": manifest["snapshot_sha256"],
                "runtime_sha256": manifest["runtime_sha256"],
                "error": manifest["error"],
                "result_sha256": manifest["result_sha256"],
            },
            "result": {
                "verified": True,
                "actionable": True,
                "contract_version": "2.1",
                "sha256": manifest["result_sha256"],
                "path": str(result_path),
            },
        }
        if operation == "reconcile":
            receipt["state"]["code"] = "reconciled"
            receipt["recovery"] = {
                "outcome": "reconciled",
                "launch_safe": True,
                "receipt_path": str(receipt_path),
            }
        write(receipt_path, receipt)
        return receipt_path

    def test_action_binding_canonical_fixture(self) -> None:
        value = request(question="May this change proceed?", affected_paths=[r"HIGHBALL\bin\tool.py", "a/b.py"])
        req_path = self.root / "binding.json"
        write(req_path, value)
        completed = highball("action-binding", str(req_path))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = completed.stdout.strip().splitlines()
        self.assertEqual(
            lines[0],
            '{"action_boundary":"protected_write","affected_paths":["HIGHBALL\\\\bin\\\\tool.py","a/b.py"],"change_class":"code","question":"May this change proceed?"}',
        )
        self.assertEqual(lines[1], "sha256:05f2997ec8dfce94e74fb15b12a6901ac34b7265905cbca8ce5dc35cad110c9e")

    def test_strict_boundary_rejects_empty_or_duplicate_affected_paths(self) -> None:
        empty = request(affected_paths=[])
        duplicate = request(affected_paths=["HIGHBALL/bin/tool.py", "HIGHBALL/bin/tool.py"])
        self.assertTrue(any("at least one affected path" in error for error in self.route_errors(empty)))
        self.assertTrue(any("must not contain duplicates" in error for error in self.route_errors(duplicate)))

    def test_product_router_matrix_preserves_atomic_boundaries(self) -> None:
        cases = [
            (request(action_boundary="reversible", risk="LOW", executable=True), "direct-evidence", False),
            (request(action_boundary="protected_write", risk="MEDIUM"), "QUINTE", False),
            (request(action_boundary="protected_write", risk="HIGH"), "QUINTE", False),
            (request(action_boundary="none", change_class="protocol", risk="LOW"), "QUINTE", False),
            (request(action_boundary="none", change_class="architecture", risk="LOW"), "QUINTE", False),
            (request(action_boundary="reversible", change_class="credential", risk="LOW"), "human-review", True),
            (request(action_boundary="irreversible", risk="HIGH"), "QUINTE", True),
            (request(trace_quality_gate="block"), "block", False),
        ]
        for req, expected_route, expected_authorization in cases:
            with self.subTest(route=expected_route, request=req):
                decision = self.route(req)
                self.assertEqual(decision["route"], expected_route)
                self.assertEqual(decision["authorization_required"], expected_authorization)

    def test_route_trace_mismatch_blocks_without_result(self) -> None:
        req = request()
        packet = self.build(req, trace(req, instrument="QUINTE"))
        self.assertEqual(packet["action_decision"], "block")
        self.assertNotEqual(packet["product_evidence"]["status"], "complete")

    def test_fake_minimal_completed_result_is_rejected(self) -> None:
        req = request()
        fake = self.root / "fake" / "result.json"
        write(fake, {"run_id": "x", "status": "completed"})
        packet = self.build(req, trace(req), fake)
        self.assertEqual(packet["action_decision"], "block")
        self.assertEqual(packet["product_evidence"]["status"], "invalid")

    def test_host_receipt_binds_product_without_invoking_quinte(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        receipt_path = self.host_receipt(result_path)
        summary, errors = self.load_receipt(receipt_path, req)
        self.assertEqual(errors, [])
        self.assertIsNotNone(summary)
        packet = self.build(req, trace(req), receipt=receipt_path)
        self.assertEqual(packet["product_evidence"]["status"], "complete")
        outcome = packet["product_evidence"]["product"]
        self.assertEqual(outcome["host_receipt_operation"], "inspect")
        self.assertEqual(outcome["host_receipt_ref"], str(receipt_path.resolve()))
        self.assertFalse(validate_packet_errors(packet, self.root))

    def test_saved_host_envelope_reads_its_durable_receipt(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        receipt_path = self.host_receipt(result_path)
        durable = json.loads(receipt_path.read_text())
        envelope_path = self.root / "captured" / "inspect.json"
        write(
            envelope_path,
            {"cli_envelope_version": "1.0", "ok": True, "data": durable},
        )
        summary, errors = self.load_receipt(str(envelope_path), req)
        self.assertEqual(errors, [])
        self.assertIsNotNone(summary)
        self.assertEqual(summary["host_receipt_ref"], str(envelope_path.resolve()))

    def test_reconciled_host_receipt_binds_terminal_product(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        receipt_path = self.host_receipt(result_path, operation="reconcile")
        summary, errors = self.load_receipt(str(receipt_path), req)
        self.assertEqual(errors, [])
        self.assertIsNotNone(summary)
        self.assertEqual(summary["host_receipt_operation"], "reconcile")

        packet = self.build(req, trace(req), receipt=receipt_path)
        self.assertEqual(packet["product_evidence"]["status"], "complete")
        self.assertEqual(
            packet["product_evidence"]["product"]["host_receipt_operation"],
            "reconcile",
        )
        self.assertFalse(validate_packet_errors(packet, self.root))

    def test_reconcile_launch_safe_must_match_active_run_set(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        run_id = result_path.parent.name
        for name, active_run_ids, launch_safe in (
            ("active-but-safe", [run_id], True),
            ("empty-but-unsafe", [], False),
        ):
            with self.subTest(case=name):
                receipt_path = self.host_receipt(result_path, operation="reconcile")
                receipt = json.loads(receipt_path.read_text())
                receipt["state"]["active_run_ids"] = active_run_ids
                receipt["recovery"]["launch_safe"] = launch_safe
                write(receipt_path, receipt)
                summary, errors = self.load_receipt(
                    str(receipt_path), req
                )
                self.assertIsNone(summary)
                self.assertTrue(
                    any(
                        "recovery.launch_safe does not match active_run_ids" in item
                        for item in errors
                    )
                )

    def test_host_receipt_forbidden_operations_and_unverified_result_fail_closed(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        for operation in ("start", "preflight", "status"):
            with self.subTest(operation=operation):
                receipt_path = self.host_receipt(result_path, operation=operation)
                summary, errors = self.load_receipt(str(receipt_path), req)
                self.assertIsNone(summary)
                self.assertTrue(any("operation must be inspect or reconcile" in item for item in errors))

        receipt_path = self.host_receipt(result_path)
        receipt = json.loads(receipt_path.read_text())
        receipt["result"]["verified"] = False
        write(receipt_path, receipt)
        summary, errors = self.load_receipt(str(receipt_path), req)
        self.assertIsNone(summary)
        self.assertTrue(any("result.verified must be true" in item for item in errors))

    def test_host_receipt_state_root_binding_fails_closed(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        receipt_path = self.host_receipt(result_path)
        receipt = json.loads(receipt_path.read_text())
        receipt["state_root"] = str(self.root / "other-quinte")
        write(receipt_path, receipt)
        summary, errors = self.load_receipt(str(receipt_path), req)
        self.assertIsNone(summary)
        self.assertTrue(any("state_root does not match" in item for item in errors))

    def test_host_receipt_rejects_non_v7_and_noncanonical_ids(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        cases = (
            ("invocation_id", "019fd896-7769-1c62-a3c3-e4f34fbc09f3", "invocation_id must be a canonical UUIDv7"),
            ("invocation_id", "019FD896-7769-7C62-A3C3-E4F34FBC09F3", "invocation_id must be a canonical UUIDv7"),
            ("run_id", "019fd896-7769-1c62-a3c3-e4f34fbc09f2", "run_id must be a canonical UUIDv7"),
            ("active_run_ids", ["019fd896-7769-1c62-a3c3-e4f34fbc09f2"], "active_run_ids must contain canonical UUIDv7"),
        )
        for field, replacement, expected in cases:
            with self.subTest(field=field, replacement=replacement):
                receipt_path = self.host_receipt(result_path)
                receipt = json.loads(receipt_path.read_text())
                if field == "active_run_ids":
                    receipt["state"][field] = replacement
                else:
                    receipt[field] = replacement
                write(receipt_path, receipt)
                summary, errors = self.load_receipt(str(receipt_path), req)
                self.assertIsNone(summary)
                self.assertTrue(any(expected in item for item in errors), errors)

    def test_block_and_escalate_decisions_block_empty_residuals(self) -> None:
        req = request()
        for decision in ("block", "escalate"):
            with self.subTest(decision=decision):
                home = self.root / decision
                packet = self.build(req, trace(req, highball_decision=decision), product(home, req, self.binary))
                self.assertEqual(packet["action_decision"], "block")

    def test_old_result_contract_is_archived_only(self) -> None:
        req = request()
        home = self.root / "old"
        packet = self.build(req, trace(req), product(home, req, self.binary, result_version="1.0"))
        self.assertEqual(packet["product_evidence"]["status"], "invalid")

    def test_cross_task_result_replay_is_rejected(self) -> None:
        original = request()
        replay = request(question="A different task")
        home = self.root / "run"
        packet = self.build(replay, trace(replay), product(home, original, self.binary))
        self.assertEqual(packet["product_evidence"]["status"], "invalid")
        self.assertTrue(any("action binding" in error for error in packet["product_evidence"]["errors"]))

    def test_authorization_required_action_without_artifact_blocks(self) -> None:
        req = request(change_class="credential")
        packet = self.build(req, trace(req, instrument="human"))
        self.assertEqual(packet["authorization"]["status"], "missing")
        self.assertEqual(packet["action_decision"], "block")

    def test_authorization_consume_rejects_replay(self) -> None:
        req = request(change_class="credential")
        req_path, auth_path = self.root / "request.json", self.root / "auth.json"
        write(req_path, req)
        now = datetime.now(timezone.utc)
        write(auth_path, {
            "authorization_version": "1.0",
            "authorization_id": "auth-once",
            "authorized_by": "user",
            "decision": "authorize",
            "action_binding_sha256": fixture_action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        command = [str(HIGHBALL), "consume-authorization", str(req_path), str(auth_path), "--ledger", str(self.root / "ledger")]
        env = {**os.environ, "HIGHBALL_TESTING": "1"}
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 0)
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 1)

    def test_authorization_consume_rejects_packet_digest_drift(self) -> None:
        req = request(change_class="credential")
        req_path, auth_path = self.root / "request.json", self.root / "auth.json"
        write(req_path, req)
        now = datetime.now(timezone.utc)
        write(auth_path, {
            "authorization_version": "1.0",
            "authorization_id": "auth-digest-bound",
            "authorized_by": "user",
            "decision": "authorize",
            "action_binding_sha256": fixture_action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        command = [
            str(HIGHBALL),
            "consume-authorization",
            str(req_path),
            str(auth_path),
            "--expected-sha256",
            "sha256:" + "0" * 64,
            "--ledger",
            str(self.root / "ledger"),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            env={**os.environ, "HIGHBALL_TESTING": "1"},
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("authorization digest does not match", completed.stderr)
        self.assertFalse((self.root / "ledger").exists())

    def test_validator_recomputes_tampered_packet(self) -> None:
        req = request()
        home = self.root / "run"
        packet = self.build(req, trace(req), product(home, req, self.binary))
        packet["action_decision"] = "pass"
        packet["trace"]["highball_decision"] = "block"
        self.assertTrue(validate_packet_errors(packet, self.root))

    def test_route_execution_report_uses_atomic_binding(self) -> None:
        req = request()
        home = self.root / "run"
        packet = self.build(req, trace(req), product(home, req, self.binary))
        packet_path = self.root / "packet.json"
        write(packet_path, packet)
        report = self.execution_report(packet_path)
        self.assertEqual(report["execution_report_version"], "2.0")
        summary = report["packet_summaries"][0]
        self.assertEqual(summary["product_id"], packet["product_evidence"]["product"]["product_id"])
        self.assertEqual(
            set(summary),
            {
                "packet_ref", "route_group", "route", "trace_instrument",
                "action_boundary", "action_decision", "execution_required",
                "execution_status", "product_kind", "product_id", "product_sha256",
                "action_binding_sha256", "errors",
            },
        )
        self.assertFalse(validate_report_errors(report, self.root))

    def test_protected_write_guard_protects_bin_python_and_requires_packet(self) -> None:
        log = self.root / "session.log"
        log.write_text("write HIGHBALL/bin/tool.py\n", encoding="utf-8")
        command = ["bash", str(ROOT / "lib" / "protected-write-guard.sh"), "--check", str(log), "--action-packet", str(self.root / "missing.json")]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)

    def test_protected_write_guard_covers_product_source_and_container_files(self) -> None:
        command_base = [
            "bash", str(ROOT / "lib" / "protected-write-guard.sh"), "--check",
        ]
        for index, protected_path in enumerate(
            ("QUINTE/src/run.rs", "QUINTE/container/compose.yml")
        ):
            with self.subTest(path=protected_path):
                log = self.root / f"session-{index}.log"
                log.write_text(f"write {protected_path}\n", encoding="utf-8")
                command = [*command_base, str(log), "--action-packet", str(self.root / "missing.json")]
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)

    def test_protected_write_guard_consumes_authorization_before_pass_and_blocks_replay(self) -> None:
        req = request(action_boundary="reversible", change_class="credential", risk="LOW")
        tr = trace(req, instrument="human")
        tr.pop("trial_manifest")
        now = datetime.now(timezone.utc)
        auth = self.root / "authorization.json"
        write(auth, {
            "authorization_version": "1.0",
            "authorization_id": "protected-write-guard-single-use",
            "authorized_by": "user",
            "decision": "authorize",
            "action_binding_sha256": fixture_action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        packet = self.build(req, tr, auth=auth)
        self.assertEqual(packet["action_decision"], "pass")
        packet["authorization"]["artifact_ref"] = auth.name
        packet_path = self.root / "packet.json"
        write(packet_path, packet)
        log = self.root / "session.log"
        log.write_text("write HIGHBALL/bin/tool.py\n", encoding="utf-8")
        command = ["bash", str(ROOT / "lib" / "protected-write-guard.sh"), "--check", str(log), "--action-packet", str(packet_path)]
        env = {**os.environ, "HOME": str(self.root / "home")}
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 0)
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 1)

    def test_protected_write_guard_rejects_changed_authorization_bytes(self) -> None:
        req = request(action_boundary="reversible", change_class="credential", risk="LOW")
        tr = trace(req, instrument="human")
        tr.pop("trial_manifest")
        now = datetime.now(timezone.utc)
        auth = self.root / "authorization.json"
        write(auth, {
            "authorization_version": "1.0",
            "authorization_id": "protected-write-guard-drift",
            "authorized_by": "user",
            "decision": "authorize",
            "action_binding_sha256": fixture_action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        packet = self.build(req, tr, auth=auth)
        packet["authorization"]["artifact_ref"] = auth.name
        packet_path = self.root / "packet.json"
        write(packet_path, packet)
        auth.write_text(auth.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        log = self.root / "session.log"
        log.write_text("write HIGHBALL/bin/tool.py\n", encoding="utf-8")
        command = [
            "bash", str(ROOT / "lib" / "protected-write-guard.sh"), "--check", str(log),
            "--action-packet", str(packet_path),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            env={**os.environ, "HOME": str(self.root / "home")},
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("does not authorize", completed.stderr)

    def test_protected_write_guard_detects_repo_relative_write_targets(self) -> None:
        for index, line in enumerate((
            "Edit src/route.rs",
            "python3 -c open('src/main.rs','w')",
            "update schemas/action-packet.schema.json",
        )):
            with self.subTest(line=line):
                log = self.root / f"bare-session-{index}.log"
                log.write_text(line + "\n", encoding="utf-8")
                command = [
                    "bash", str(ROOT / "lib" / "protected-write-guard.sh"), "--check", str(log),
                    "--action-packet", str(self.root / "missing.json"),
                ]
                completed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
        clean = self.root / "clean-session.log"
        clean.write_text("discussed docs/notes.txt and /usr/bin/env only\n", encoding="utf-8")
        command = [
            "bash", str(ROOT / "lib" / "protected-write-guard.sh"), "--check", str(clean),
            "--action-packet", str(self.root / "missing.json"),
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("no protected engineering write", completed.stdout)

    def build_authorizing_human_packet(self, authorization_id: str) -> Path:
        req = request(action_boundary="reversible", change_class="credential", risk="LOW")
        tr = trace(req, instrument="human")
        tr.pop("trial_manifest")
        now = datetime.now(timezone.utc)
        auth = self.root / f"{authorization_id}.json"
        write(auth, {
            "authorization_version": "1.0",
            "authorization_id": authorization_id,
            "authorized_by": "user",
            "decision": "authorize",
            "action_binding_sha256": fixture_action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        packet = self.build(req, tr, auth=auth)
        self.assertEqual(packet["action_decision"], "pass")
        packet["authorization"]["artifact_ref"] = auth.name
        packet_path = self.root / f"packet-{authorization_id}.json"
        write(packet_path, packet)
        return packet_path

    def run_guard(self, log_text: str, packet_path: Path, home: Path) -> subprocess.CompletedProcess[str]:
        log = home / "session.log"
        log.write_text(log_text, encoding="utf-8")
        command = [
            "bash", str(ROOT / "lib" / "protected-write-guard.sh"), "--check", str(log),
            "--action-packet", str(packet_path),
        ]
        return subprocess.run(
            command,
            capture_output=True,
            env={**os.environ, "HOME": str(home)},
            text=True,
        )

    def test_protected_write_guard_passes_repo_relative_target_within_packet_scope(self) -> None:
        packet_path = self.build_authorizing_human_packet("guard-scope-repo-relative")
        home = self.root / "home-repo-relative"
        home.mkdir()
        completed = self.run_guard(
            "plan HIGHBALL/bin/tool.py\nwrite bin/tool.py\n",
            packet_path,
            home,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        replay = self.run_guard(
            "plan HIGHBALL/bin/tool.py\nwrite bin/tool.py\n",
            packet_path,
            home,
        )
        self.assertEqual(replay.returncode, 1, replay.stderr + replay.stdout)

    def test_protected_write_guard_blocks_write_outside_packet_scope(self) -> None:
        packet_path = self.build_authorizing_human_packet("guard-scope-outside")
        home = self.root / "home-outside"
        home.mkdir()
        completed = self.run_guard(
            "plan HIGHBALL/bin/tool.py\nwrite HIGHBALL/src/lib.rs\n",
            packet_path,
            home,
        )
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn("outside the Action Packet scope: HIGHBALL/src/lib.rs", completed.stderr)

        bare = self.run_guard(
            "plan HIGHBALL/bin/tool.py\nedit src/lib.rs\n",
            packet_path,
            home,
        )
        self.assertEqual(bare.returncode, 1, bare.stdout)
        self.assertIn("outside the Action Packet scope: src/lib.rs", bare.stderr)

    def test_python_validator_accepts_builder_block_packets_as_non_authorizing(self) -> None:
        req = request()
        tr = trace(req, instrument="QUINTE")
        packet = self.build(req, tr)
        self.assertEqual(packet["action_decision"], "block")
        self.assertTrue(any(
            reason.startswith("required atomic QUINTE product outcome is")
            for reason in packet["decision_reasons"]
        ), packet["decision_reasons"])
        req_path, trace_path = self.root / "request.json", self.root / "trace.json"
        write(req_path, req)
        write(trace_path, tr)
        py_builder = subprocess.run(
            ["python3", str(ROOT / "bin" / "build-action-packet.py"), str(req_path), str(trace_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(py_builder.returncode, 1, py_builder.stderr)
        for builder, packet_json in (
            ("rust", packet),
            ("python", json.loads(py_builder.stdout)),
        ):
            with self.subTest(builder=builder):
                packet_path = self.root / f"packet-{builder}.json"
                write(packet_path, packet_json)
                completed = subprocess.run(
                    ["python3", str(ROOT / "bin" / "validate-action-packet.py"), str(packet_path)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertIn("non-authorizing", completed.stderr)

    def test_measure_coverage_rounding_matches_across_implementations(self) -> None:
        residuals = [
            {
                "id": f"r-{index}",
                "severity": "LOW",
                "evidence": "evidence.md" if index == 0 else None,
                "closure_state": "closed",
            }
            for index in range(32)
        ]
        tr = {
            "trace_version": "1.1",
            "question": "Should this proceed?",
            "instrument": "QUINTE",
            "action_boundary": "none",
            "highball_decision": "pass",
            "residuals": residuals,
        }
        trace_path = self.root / "trace.json"
        write(trace_path, tr)
        rust = highball_json("measure-residual-trace", str(trace_path), env=self.env)
        py = subprocess.run(
            ["python3", str(ROOT / "bin" / "measure-residual-trace.py"), str(trace_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(py.returncode, 0, py.stderr)
        self.assertEqual(json.loads(py.stdout)["traces"][0], rust["traces"][0])
        # 1/32 is an exact rounding half: banker's rounding would yield 0.0312.
        self.assertEqual(rust["traces"][0]["evidence_coverage"], 0.0313)

    def test_router_rejects_boolean_open_high_risk_count(self) -> None:
        req = request(open_high_risk_count=True)
        self.assertTrue(any(
            "open_high_risk_count must be integer" in error for error in self.route_errors(req)
        ))
        path = self.root / "route-request.json"
        write(path, req)
        completed = subprocess.run(
            ["python3", str(ROOT / "bin" / "route-residual-action.py"), str(path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2, completed.stdout)
        self.assertIn("open_high_risk_count must be integer when present", completed.stderr)


if __name__ == "__main__":
    unittest.main()
