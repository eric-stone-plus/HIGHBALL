#!/usr/bin/env python3
"""Negative and product-binding tests for the HIGHBALL control plane."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACTS = load_module("test_contracts", ROOT / "bin" / "highball-contracts.py")
BUILDER = load_module("test_builder", ROOT / "bin" / "build-action-packet.py")
VALIDATOR = load_module("test_validator", ROOT / "bin" / "validate-action-packet.py")
PRODUCT = load_module("test_product", ROOT / "bin" / "verify-quinte-product.py")
EXECUTION_BUILDER = load_module("test_execution_builder", ROOT / "bin" / "build-route-execution-report.py")
EXECUTION_VALIDATOR = load_module("test_execution_validator", ROOT / "bin" / "validate-route-execution-report.py")


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
        "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
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


def product(home: Path, req: dict[str, Any], binary: Path, *, result_version: str = "2.0") -> Path:
    run_id = "018f47a2-4b5c-7d6e-8f90-123456789abc"
    run_dir = home / "runs" / run_id
    binding = CONTRACTS.action_binding_sha256(req)
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
    brief_sha = CONTRACTS.sha256_bytes(brief_bytes)
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
    result_path = run_dir / "result.json"
    write(run_dir / "input" / "brief.json", brief)
    write(result_path, result)
    result_sha = CONTRACTS.sha256_bytes(result_path.read_bytes())
    manifest = {
        "manifest_version": "1.0",
        "run_id": run_id,
        "created_at": "2026-01-01T00:00:00.000Z",
        "updated_at": "2026-01-01T00:00:01.000Z",
        "status": "completed",
        "brief_sha256": brief_sha,
        "policy_sha256": "sha256:" + "1" * 64,
        "snapshot_sha256": "sha256:" + "2" * 64,
        "runtime_sha256": CONTRACTS.sha256_bytes(binary.read_bytes()),
        "protocol_version": "1.0",
        "effective_model": "mimo-v2.5-pro",
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
        self.old_runs_root = PRODUCT.trusted_runs_root
        self.old_binary = PRODUCT.active_quinte_binary
        PRODUCT.trusted_runs_root = lambda: (self.root / "quinte" / "runs").resolve()
        PRODUCT.active_quinte_binary = lambda: self.binary.resolve()

    def tearDown(self) -> None:
        os.environ["PATH"] = self.old_path
        PRODUCT.trusted_runs_root = self.old_runs_root
        PRODUCT.active_quinte_binary = self.old_binary
        self.temp.cleanup()

    def build(self, req: dict[str, Any], tr: dict[str, Any], result: Path | None = None, auth: Path | None = None) -> dict[str, Any]:
        req_path, trace_path = self.root / "request.json", self.root / "trace.json"
        write(req_path, req)
        write(trace_path, tr)
        return BUILDER.build_packet(req_path, trace_path, [result] if result else [], auth)

    def test_action_binding_canonical_fixture(self) -> None:
        value = request(question="允许改动吗？", affected_paths=[r"HIGHBALL\bin\tool.py", "a/b.py"])
        self.assertEqual(
            CONTRACTS.canonical_action_binding_bytes(value).decode(),
            '{"action_boundary":"protected_write","affected_paths":["HIGHBALL\\\\bin\\\\tool.py","a/b.py"],"change_class":"code","question":"允许改动吗？"}',
        )
        self.assertEqual(CONTRACTS.action_binding_sha256(value), "sha256:7fe45882922fdb9c9dc748dabc2a23b2590187e017b29b73c35ae7f92c320a5e")

    def test_route_trace_mismatch_blocks_without_result(self) -> None:
        req = request()
        packet = self.build(req, trace(req, instrument="MAGI"))
        self.assertEqual(packet["action_decision"], "block")
        self.assertNotEqual(packet["execution_evidence"]["status"], "complete")

    def test_fake_minimal_completed_result_is_rejected(self) -> None:
        req = request()
        fake = self.root / "fake" / "result.json"
        write(fake, {"run_id": "x", "status": "completed"})
        packet = self.build(req, trace(req), fake)
        self.assertEqual(packet["action_decision"], "block")
        self.assertEqual(packet["execution_evidence"]["status"], "invalid")

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
        self.assertEqual(packet["execution_evidence"]["status"], "invalid")

    def test_cross_task_result_replay_is_rejected(self) -> None:
        original = request()
        replay = request(question="A different task")
        home = self.root / "run"
        packet = self.build(replay, trace(replay), product(home, original, self.binary))
        self.assertEqual(packet["execution_evidence"]["status"], "invalid")
        self.assertTrue(any("action binding" in error for error in packet["execution_evidence"]["errors"]))

    def test_kengen_required_action_without_artifact_blocks(self) -> None:
        req = request(change_class="credential")
        packet = self.build(req, trace(req, instrument="human"))
        self.assertEqual(packet["authorization"]["status"], "missing")
        self.assertEqual(packet["action_decision"], "block")

    def test_kengen_consume_rejects_replay(self) -> None:
        req = request(change_class="credential")
        req_path, auth_path = self.root / "request.json", self.root / "auth.json"
        write(req_path, req)
        now = datetime.now(timezone.utc)
        write(auth_path, {
            "authorization_version": "1.0",
            "authorization_id": "auth-once",
            "authorized_by": "user",
            "decision": "authorize",
            "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        command = [sys.executable, str(ROOT / "bin" / "consume-kengen-authorization.py"), str(req_path), str(auth_path), "--ledger", str(self.root / "ledger")]
        env = {**os.environ, "HIGHBALL_TESTING": "1"}
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 0)
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 1)

    def test_validator_recomputes_tampered_packet(self) -> None:
        req = request()
        home = self.root / "run"
        packet = self.build(req, trace(req), product(home, req, self.binary))
        packet["action_decision"] = "pass"
        packet["trace"]["highball_decision"] = "block"
        self.assertTrue(VALIDATOR.validate_packet(packet, base_dir=self.root))

    def test_route_execution_report_uses_atomic_binding(self) -> None:
        req = request()
        home = self.root / "run"
        packet = self.build(req, trace(req), product(home, req, self.binary))
        packet_path = self.root / "packet.json"
        write(packet_path, packet)
        report = EXECUTION_BUILDER.build_report([str(packet_path)])
        self.assertEqual(report["execution_report_version"], "1.1")
        summary = report["packet_summaries"][0]
        self.assertEqual(summary["quinte_run_id"], packet["execution_evidence"]["quinte_outcome"]["run_id"])
        self.assertEqual(
            set(summary),
            {
                "packet_ref", "route_group", "route", "trace_instrument",
                "action_boundary", "action_decision", "execution_required",
                "execution_status", "quinte_run_id", "quinte_result_sha256",
                "action_binding_sha256", "errors",
            },
        )
        self.assertFalse(EXECUTION_VALIDATOR.validate_report(report))

    def test_bannin_protects_bin_python_and_requires_packet(self) -> None:
        log = self.root / "session.log"
        log.write_text("write HIGHBALL/bin/tool.py\n", encoding="utf-8")
        command = ["bash", str(ROOT / "lib" / "bannin.sh"), "--check", str(log), "--action-packet", str(self.root / "missing.json")]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)

    def test_bannin_consumes_kengen_before_pass_and_blocks_replay(self) -> None:
        req = request(action_boundary="reversible", change_class="credential", risk="LOW")
        tr = trace(req, instrument="human")
        tr.pop("trial_manifest")
        now = datetime.now(timezone.utc)
        auth = self.root / "authorization.json"
        write(auth, {
            "authorization_version": "1.0",
            "authorization_id": "bannin-single-use",
            "authorized_by": "user",
            "decision": "authorize",
            "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
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
        command = ["bash", str(ROOT / "lib" / "bannin.sh"), "--check", str(log), "--action-packet", str(packet_path)]
        env = {**os.environ, "HOME": str(self.root / "home")}
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 0)
        self.assertEqual(subprocess.run(command, capture_output=True, env=env).returncode, 1)


if __name__ == "__main__":
    unittest.main()
