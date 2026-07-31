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
from unittest import mock


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
PRODUCT = load_module("test_product", ROOT / "bin" / "verify-product.py")
EXECUTION_BUILDER = load_module("test_execution_builder", ROOT / "bin" / "build-route-execution-report.py")
EXECUTION_VALIDATOR = load_module("test_execution_validator", ROOT / "bin" / "validate-route-execution-report.py")


class ContractSchemaTests(unittest.TestCase):
    def test_action_packet_schema_matches_active_product_decisions(self) -> None:
        schema = json.loads((ROOT / "schemas" / "action-packet.schema.json").read_text())
        self.assertEqual(schema["properties"]["packet_version"]["const"], CONTRACTS.ACTION_PACKET_VERSION)
        product = schema["$defs"]["productOutcome"]
        self.assertEqual(set(product["properties"]["decision"]["enum"]), {"PASS", "BLOCK", "ESCALATE"})
        self.assertEqual(product["properties"]["status"]["const"], "completed")
        conditional = product["allOf"][0]
        self.assertEqual(conditional["if"]["properties"]["product_kind"]["const"], "QUINTE")
        self.assertEqual(conditional["then"]["properties"]["decision"]["const"], "PASS")

        try:
            import jsonschema
        except ModuleNotFoundError:
            return
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_runtime_resolution_honors_explicit_state_and_binary_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "quinte"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {
                    "QUINTE_HOME": str(root / "state"),
                    "HIGHBALL_QUINTE_BIN": str(binary),
                },
                clear=False,
            ):
                self.assertEqual(PRODUCT.trusted_runs_root(), (root / "state" / "runs").resolve())
                self.assertEqual(PRODUCT.active_quinte_binary(), binary.resolve())

    def test_route_execution_schema_matches_active_version(self) -> None:
        schema = json.loads((ROOT / "schemas" / "route-execution-report.schema.json").read_text())
        self.assertEqual(
            schema["properties"]["execution_report_version"]["const"],
            CONTRACTS.ROUTE_EXECUTION_REPORT_VERSION,
        )
        try:
            import jsonschema
        except ModuleNotFoundError:
            return
        jsonschema.Draft202012Validator.check_schema(schema)


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


def product(home: Path, req: dict[str, Any], binary: Path, *, result_version: str = "2.1") -> Path:
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
    result_sha = CONTRACTS.sha256_bytes(result_path.read_bytes())
    manifest = {
        "manifest_version": "2.0",
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


def magi_product(root: Path, req: dict[str, Any], decision: str = "PASS") -> Path:
    trial = root / "magi-trial"
    trial.mkdir(parents=True)
    identity = {
        "product_version": "1.0",
        "trial_id": "trial-001",
        "status": "completed",
        "runtime_sha256": "sha256:" + "1" * 64,
        "agent_config_sha256": "sha256:" + "2" * 64,
        "builder_config_sha256": "sha256:" + "3" * 64,
        "original_brief_sha256": "sha256:" + "4" * 64,
        "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
        "question": req["question"],
        "action_scope": req["action_scope"],
        "affected_paths": req["affected_paths"],
        "final_decision": decision,
        "final_dissent": [],
        "final_verdict_ref": "final/verdict.json",
        "final_verdict_sha256": "sha256:" + "5" * 64,
        "residual_trace_ref": "final/residual-trace.json",
        "residual_trace_sha256": "sha256:" + "6" * 64,
        "seats": [
            {
                "seat_id": f"seat-{index}",
                "family": family,
                "provider": f"provider-{family}",
                "text_model": f"model-{family}",
                "multimodal_model": f"model-{family}",
                "profile_sha256": "sha256:" + str(index) * 64,
                "thesis_sha256": "sha256:" + str(index + 3) * 64,
                "dossier_ref": f"dossiers/seat-{index}.json",
                "dossier_sha256": "sha256:" + str(index + 6) * 64,
                "quinte_run_id": f"run-{index}",
                "quinte_manifest_sha256": "sha256:" + chr(96 + index) * 64,
                "quinte_result_sha256": "sha256:" + chr(99 + index) * 64,
            }
            for index, family in enumerate(("mimo", "deepseek", "openai"), start=1)
        ],
        "cross_reviews": [
            {"artifact_ref": f"reviews/{index}.json", "sha256": "sha256:" + format(index, "x") * 64}
            for index in range(1, 7)
        ],
    }
    encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    write(trial / "product-summary.json", {**identity, "product_sha256": CONTRACTS.sha256_bytes(encoded)})
    return trial


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
        self.magi_binary = self.root / "bin" / "magi"
        self.magi_binary.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "trial = pathlib.Path(sys.argv[-1])\n"
            "print((trial/'product-summary.json').read_text())\n",
            encoding="utf-8",
        )
        self.magi_binary.chmod(0o755)
        os.environ["PATH"] = str(self.binary.parent) + os.pathsep + self.old_path
        self.old_runs_root = PRODUCT.trusted_runs_root
        self.old_binary = PRODUCT.active_quinte_binary
        self.old_magi_binary = PRODUCT.active_magi_binary
        self.old_builder_magi_binary = BUILDER.PRODUCT.active_magi_binary
        self.old_validator_magi_binary = VALIDATOR.PRODUCT.active_magi_binary
        self.old_execution_magi_binary = EXECUTION_BUILDER.ACTION_PACKET.PRODUCT.active_magi_binary
        PRODUCT.trusted_runs_root = lambda: (self.root / "quinte" / "runs").resolve()
        PRODUCT.active_quinte_binary = lambda: self.binary.resolve()
        PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()
        BUILDER.PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()
        VALIDATOR.PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()
        EXECUTION_BUILDER.ACTION_PACKET.PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()

    def tearDown(self) -> None:
        os.environ["PATH"] = self.old_path
        PRODUCT.trusted_runs_root = self.old_runs_root
        PRODUCT.active_quinte_binary = self.old_binary
        PRODUCT.active_magi_binary = self.old_magi_binary
        BUILDER.PRODUCT.active_magi_binary = self.old_builder_magi_binary
        VALIDATOR.PRODUCT.active_magi_binary = self.old_validator_magi_binary
        EXECUTION_BUILDER.ACTION_PACKET.PRODUCT.active_magi_binary = self.old_execution_magi_binary
        self.temp.cleanup()

    def build(self, req: dict[str, Any], tr: dict[str, Any], result: Path | None = None, auth: Path | None = None, magi: Path | None = None) -> dict[str, Any]:
        req_path, trace_path = self.root / "request.json", self.root / "trace.json"
        write(req_path, req)
        write(trace_path, tr)
        return BUILDER.build_packet(req_path, trace_path, [result] if result else [], auth, [magi] if magi else [])

    def test_action_binding_canonical_fixture(self) -> None:
        value = request(question="允许改动吗？", affected_paths=[r"HIGHBALL\bin\tool.py", "a/b.py"])
        self.assertEqual(
            CONTRACTS.canonical_action_binding_bytes(value).decode(),
            '{"action_boundary":"protected_write","affected_paths":["HIGHBALL\\\\bin\\\\tool.py","a/b.py"],"change_class":"code","question":"允许改动吗？"}',
        )
        self.assertEqual(CONTRACTS.action_binding_sha256(value), "sha256:7fe45882922fdb9c9dc748dabc2a23b2590187e017b29b73c35ae7f92c320a5e")

    def test_strict_boundary_rejects_empty_or_duplicate_affected_paths(self) -> None:
        empty = request(affected_paths=[])
        duplicate = request(affected_paths=["HIGHBALL/bin/tool.py", "HIGHBALL/bin/tool.py"])
        self.assertTrue(any("at least one affected path" in error for error in BUILDER.ROUTER.validate_request(empty)))
        self.assertTrue(any("must not contain duplicates" in error for error in BUILDER.ROUTER.validate_request(duplicate)))

    def test_product_router_matrix_preserves_atomic_boundaries(self) -> None:
        cases = [
            (request(action_boundary="reversible", risk="LOW", executable=True), "direct-evidence", False),
            (request(action_boundary="protected_write", risk="MEDIUM"), "QUINTE", False),
            (request(action_boundary="protected_write", risk="HIGH"), "MAGI", False),
            (request(action_boundary="none", change_class="protocol", risk="LOW"), "QUINTE", False),
            (request(action_boundary="none", change_class="architecture", risk="LOW"), "MAGI", False),
            (request(action_boundary="reversible", change_class="credential", risk="LOW"), "human-review", True),
            (request(action_boundary="irreversible", risk="HIGH"), "MAGI", True),
            (request(trace_quality_gate="block"), "block", False),
        ]
        for req, expected_route, expected_authorization in cases:
            with self.subTest(route=expected_route, request=req):
                decision = BUILDER.ROUTER.route_request(req)
                self.assertEqual(decision["route"], expected_route)
                self.assertEqual(decision["authorization_required"], expected_authorization)

    def test_route_trace_mismatch_blocks_without_result(self) -> None:
        req = request()
        packet = self.build(req, trace(req, instrument="MAGI"))
        self.assertEqual(packet["action_decision"], "block")
        self.assertNotEqual(packet["product_evidence"]["status"], "complete")

    def test_fake_minimal_completed_result_is_rejected(self) -> None:
        req = request()
        fake = self.root / "fake" / "result.json"
        write(fake, {"run_id": "x", "status": "completed"})
        packet = self.build(req, trace(req), fake)
        self.assertEqual(packet["action_decision"], "block")
        self.assertEqual(packet["product_evidence"]["status"], "invalid")

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

    def test_magi_route_requires_verified_atomic_product(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        tr["trial_manifest"]["base_model_relation"] = "heterogeneous_models"
        tr["trial_manifest"]["perspective_count"] = 3
        tr["trial_manifest"]["perspectives"] = tr["trial_manifest"]["perspectives"][:3]
        packet = self.build(req, tr, magi=magi_product(self.root, req))
        self.assertEqual(packet["product_evidence"]["status"], "complete")
        self.assertEqual(packet["product_evidence"]["product"]["product_kind"], "MAGI")
        self.assertEqual(packet["action_decision"], "review")
        self.assertTrue(any("quality gate is review" in reason for reason in packet["decision_reasons"]))

    def test_magi_product_accepts_digest_bound_final_dissent(self) -> None:
        req = request(change_class="architecture")
        trial = magi_product(self.root, req)
        summary_path = trial / "product-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["final_dissent"] = ["material dissent preserved"]
        identity = {key: value for key, value in summary.items() if key != "product_sha256"}
        summary["product_sha256"] = CONTRACTS.sha256_bytes(
            json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        )
        write(summary_path, summary)
        tr = trace(req, instrument="MAGI")
        tr["trial_manifest"]["base_model_relation"] = "heterogeneous_models"
        tr["trial_manifest"]["perspective_count"] = 3
        tr["trial_manifest"]["perspectives"] = tr["trial_manifest"]["perspectives"][:3]
        packet = self.build(req, tr, magi=trial)
        self.assertEqual(packet["product_evidence"]["status"], "complete")
        self.assertEqual(packet["product_evidence"]["errors"], [])

    def test_completed_magi_block_and_escalate_are_valid_but_non_authorizing(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        tr["trial_manifest"]["base_model_relation"] = "heterogeneous_models"
        tr["trial_manifest"]["perspective_count"] = 3
        tr["trial_manifest"]["perspectives"] = tr["trial_manifest"]["perspectives"][:3]
        for decision in ("BLOCK", "ESCALATE"):
            with self.subTest(decision=decision):
                trial = magi_product(self.root / decision.lower(), req, decision)
                packet = self.build(req, tr, magi=trial)
                self.assertEqual(packet["product_evidence"]["status"], "complete")
                self.assertEqual(packet["product_evidence"]["errors"], [])
                self.assertEqual(packet["product_evidence"]["product"]["decision"], decision)
                self.assertEqual(packet["action_decision"], "block")
                self.assertTrue(any(f"MAGI product decision is {decision}" in reason for reason in packet["decision_reasons"]))
                self.assertFalse(VALIDATOR.validate_packet(packet, base_dir=self.root))

                packet_path = self.root / decision.lower() / "packet.json"
                write(packet_path, packet)
                report = EXECUTION_BUILDER.build_report([str(packet_path)])
                self.assertEqual(report["complete_count"], 1)
                self.assertEqual(report["execution_gate"], "accepted")
                self.assertEqual(report["packet_summaries"][0]["action_decision"], "block")
                self.assertFalse(EXECUTION_VALIDATOR.validate_report(report))

    def test_unknown_magi_decision_is_invalid(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        packet = self.build(req, tr, magi=magi_product(self.root, req, "REVIEW"))
        self.assertEqual(packet["product_evidence"]["status"], "invalid")
        self.assertEqual(packet["action_decision"], "block")

    def test_magi_trace_alone_cannot_authorize(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        tr["trial_manifest"]["base_model_relation"] = "heterogeneous_models"
        tr["trial_manifest"]["perspective_count"] = 3
        tr["trial_manifest"]["perspectives"] = tr["trial_manifest"]["perspectives"][:3]
        packet = self.build(req, tr)
        self.assertEqual(packet["product_evidence"]["status"], "invalid")
        self.assertEqual(packet["action_decision"], "block")

    def test_magi_same_family_disguise_is_rejected(self) -> None:
        req = request(change_class="architecture")
        trial = magi_product(self.root, req)
        summary_path = trial / "product-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["seats"][1]["family"] = summary["seats"][0]["family"]
        identity = {key: value for key, value in summary.items() if key != "product_sha256"}
        summary["product_sha256"] = CONTRACTS.sha256_bytes(
            json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        )
        write(summary_path, summary)
        tr = trace(req, instrument="MAGI")
        packet = self.build(req, tr, magi=trial)
        self.assertEqual(packet["product_evidence"]["status"], "invalid")
        self.assertTrue(any("distinct model families" in error for error in packet["product_evidence"]["errors"]))

    def test_magi_malformed_seat_and_review_bindings_are_rejected(self) -> None:
        req = request(change_class="architecture")
        trial = magi_product(self.root, req)
        summary_path = trial / "product-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["seats"][1]["seat_id"] = summary["seats"][0]["seat_id"]
        summary["seats"][2]["profile_sha256"] = "not-a-digest"
        summary["cross_reviews"][1]["artifact_ref"] = summary["cross_reviews"][0]["artifact_ref"]
        summary["cross_reviews"][2]["sha256"] = "not-a-digest"
        identity = {key: value for key, value in summary.items() if key != "product_sha256"}
        summary["product_sha256"] = CONTRACTS.sha256_bytes(
            json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        )
        write(summary_path, summary)
        tr = trace(req, instrument="MAGI")
        packet = self.build(req, tr, magi=trial)
        errors = packet["product_evidence"]["errors"]
        self.assertEqual(packet["product_evidence"]["status"], "invalid")
        self.assertTrue(any("distinct seat IDs" in error for error in errors))
        self.assertTrue(any("profile_sha256 is invalid" in error for error in errors))
        self.assertTrue(any("six distinct cross-review refs" in error for error in errors))
        self.assertTrue(any("cross_reviews[2].sha256 is invalid" in error for error in errors))

    def test_wrong_atomic_product_kind_is_rejected(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        packet = self.build(req, tr, result=product(self.root / "wrong-kind", req, self.binary))
        self.assertEqual(packet["product_evidence"]["status"], "invalid")

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
            "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        command = [sys.executable, str(ROOT / "bin" / "consume-authorization.py"), str(req_path), str(auth_path), "--ledger", str(self.root / "ledger")]
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
            "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
            "action_scope": req["action_scope"],
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        command = [
            sys.executable,
            str(ROOT / "bin" / "consume-authorization.py"),
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
        self.assertTrue(VALIDATOR.validate_packet(packet, base_dir=self.root))

    def test_route_execution_report_uses_atomic_binding(self) -> None:
        req = request()
        home = self.root / "run"
        packet = self.build(req, trace(req), product(home, req, self.binary))
        packet_path = self.root / "packet.json"
        write(packet_path, packet)
        report = EXECUTION_BUILDER.build_report([str(packet_path)])
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
        self.assertFalse(EXECUTION_VALIDATOR.validate_report(report))

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
            ("QUINTE/src/run.rs", "MAGI/magi/runtime.py", "MAGI/container/compose.yml")
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
            "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
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


if __name__ == "__main__":
    unittest.main()
