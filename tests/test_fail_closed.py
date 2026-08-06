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
    def test_host_uuid_helper_accepts_only_canonical_uuidv7(self) -> None:
        self.assertTrue(
            PRODUCT.is_canonical_uuid_v7("018f47a2-4b5c-7d6e-8f90-123456789abc")
        )
        self.assertFalse(
            PRODUCT.is_canonical_uuid_v7("018f47a2-4b5c-1d6e-8f90-123456789abc")
        )
        self.assertFalse(
            PRODUCT.is_canonical_uuid_v7("018F47A2-4B5C-7D6E-8F90-123456789ABC")
        )

    def test_action_packet_schema_matches_active_product_decisions(self) -> None:
        schema = json.loads((ROOT / "schemas" / "action-packet.schema.json").read_text())
        self.assertEqual(schema["properties"]["packet_version"]["const"], CONTRACTS.ACTION_PACKET_VERSION)
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


def digest_value(value: Any) -> str:
    return CONTRACTS.sha256_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    )


def write_digest(path: Path, value: Any) -> str:
    write(path, value)
    return CONTRACTS.sha256_bytes(path.read_bytes())


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
    trial_id = "trial-001"
    original_brief = {
        "question": req["question"],
        "action_scope": req["action_scope"],
        "affected_paths": req["affected_paths"],
        "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
    }
    original_brief_sha = write_digest(trial / "input" / "original-brief.json", original_brief)

    families = ("mimo", "deepseek", "openai")
    profile_ids = ("formalist", "empirical", "adversarial")
    assignment_seats = []
    product_seats = []
    for index, (family, profile_id) in enumerate(zip(families, profile_ids), start=1):
        seat_id = f"seat-{index}"
        profile_digest = "sha256:" + str(index) * 64
        assignment_seats.append(
            {
                "seat_id": seat_id,
                "family": family,
                "provider": f"provider-{family}",
                "text_model": f"model-{family}",
                "multimodal_model": f"model-{family}",
                "profile_id": profile_id,
                "profile_source_sha256": profile_digest,
                "container_service": seat_id,
                "image_digest": "sha256:" + str(index + 5) * 64,
                "primary_focus": [f"focus-{index}"],
                "mandatory_global_checks": ["citation", "contradiction"],
                "evidence_refs": [],
                "carrier_capabilities": {
                    "carrier_id": family,
                    "snapshot_media_classes": ["document"],
                    "multimodal_media_types": [],
                    "allow_sampled_video": False,
                },
                "cost_rationale": "Distinct review value.",
                "independence_class": "distinct_family_and_profile",
                "limitations": [],
            }
        )
        mapping = {
            "mapping_receipt_version": "1.0",
            "seat_id": seat_id,
            "evidence_manifest_sha256": "sha256:" + "e" * 64,
            "assignment_plan_sha256": "sha256:" + "f" * 64,
            "assigned_evidence_refs": [],
            "quinte_run_id": f"run-{index}",
            "quinte_snapshot_manifest_ref": "quinte-run/input/snapshot-manifest.json",
            "quinte_snapshot_manifest_sha256": "sha256:" + "0" * 64,
            "mappings": [],
            "unmapped_canonical_refs": [],
            "unmapped_quinte_local_refs": [],
            "limitations": [
                "Mapping joins staged digests to QUINTE snapshot/attachment entries; it does not prove model perception.",
                "Unmapped QUINTE-local refs are reported when the snapshot tree contains extra files.",
            ],
        }
        mapping_identity = {
            key: value for key, value in mapping.items() if key != "receipt_binding_sha256"
        }
        mapping["receipt_binding_sha256"] = digest_value(mapping_identity)
        mapping_ref = f"dossiers/{seat_id}-evidence-mapping-receipt.json"
        mapping_sha = write_digest(trial / mapping_ref, mapping)
        dossier = {
            "dossier_version": "1.0",
            "seat_id": seat_id,
            "profile_id": profile_id,
            "profile_ref": "profile.json",
            "profile_sha256": profile_digest,
            "reviewer_profile_ref": "reviewer-profile",
            "reviewer_profile_sha256": profile_digest,
            "thesis_ref": "thesis.json",
            "thesis_sha256": "sha256:" + str(index + 3) * 64,
            "perspective_input_ref": "perspective-input.json",
            "perspective_input_sha256": "sha256:" + str(index + 6) * 64,
            "original_brief_sha256": original_brief_sha,
            "derived_quinte_brief_sha256": "sha256:" + chr(96 + index) * 64,
            "quinte_run_ref": "quinte-run",
            "quinte_manifest_sha256": "sha256:" + chr(99 + index) * 64,
            "quinte_result_sha256": "sha256:" + str(index + 6) * 64,
            "assignment_plan_sha256": None,
            "assigned_evidence_refs": [],
            "evidence_mapping_ref": f"{seat_id}-evidence-mapping-receipt.json",
            "evidence_mapping_sha256": mapping_sha,
        }
        dossier_ref = f"dossiers/{seat_id}.json"
        dossier_sha = write_digest(trial / dossier_ref, dossier)
        product_seats.append(
            {
                "seat_id": seat_id,
                "family": family,
                "provider": f"provider-{family}",
                "text_model": f"model-{family}",
                "multimodal_model": f"model-{family}",
                "profile_sha256": profile_digest,
                "thesis_sha256": dossier["thesis_sha256"],
                "dossier_ref": dossier_ref,
                "dossier_sha256": dossier_sha,
                "quinte_run_id": f"run-{index}",
                "quinte_manifest_sha256": dossier["quinte_manifest_sha256"],
                "quinte_result_sha256": dossier["quinte_result_sha256"],
                "assigned_evidence_refs": [],
                "evidence_mapping_ref": mapping_ref,
                "evidence_mapping_sha256": mapping_sha,
            }
        )

    assignment_reviews = [
        {
            "reviewer_seat_id": reviewer,
            "subject_seat_id": subject,
            "review_kind": "artifact_review",
            "required_checks": ["challenge claims", "preserve dissent"],
            "evidence_refs": [],
            "limitations": ["Original evidence is not exposed."],
        }
        for reviewer in ("seat-1", "seat-2", "seat-3")
        for subject in ("seat-1", "seat-2", "seat-3")
        if reviewer != subject
    ]
    assignment_identity = {
        "assignment_plan_version": "1.0",
        "trial_id": trial_id,
        "objective": "Reduce decision-relevant residual uncertainty.",
        "global_checks": ["citation", "contradiction"],
        "seats": assignment_seats,
        "cross_review_obligations": assignment_reviews,
        "finale_condition": {
            "allowed_outcomes": ["BLOCK", "ESCALATE", "PASS"],
            "material_residual_states": ["bounded_escalation", "closed", "falsified"],
            "required_receipts": ["evidence coverage", "residual reduction"],
            "stop_rule": "Stop when further review is not decision-relevant.",
        },
        "limitations": ["One trial does not estimate a true error rate."],
    }
    assignment = {
        **assignment_identity,
        "plan_binding_sha256": digest_value(assignment_identity),
    }
    assignment_ref = "private/assignment-plan.json"
    assignment_sha = write_digest(trial / assignment_ref, assignment)

    manifest_identity = {
        "evidence_manifest_version": "1.0",
        "original_brief_ref": "input/original-brief.json",
        "original_brief_sha256": original_brief_sha,
        "source_root": "none://no-external-evidence",
        "staged_root_ref": "trial-private/evidence",
        "source_files": [],
        "derived_frames": [],
        "limitations": ["No external evidence was staged; conclusions are brief-only."],
    }
    manifest = {
        **manifest_identity,
        "evidence_set_sha256": digest_value(manifest_identity),
    }
    manifest_ref = "trial-private/evidence/evidence-manifest.json"
    manifest_sha = write_digest(trial / manifest_ref, manifest)

    final_verdict = {
        "verdict_version": "1.0",
        "decision": decision,
        "summary": "Final decision.",
        "recommendation": "Act only within the bound scope.",
        "findings": [],
        "dissent": [],
    }
    final_verdict_ref = "final/verdict.json"
    final_verdict_sha = write_digest(trial / final_verdict_ref, final_verdict)
    residual_trace_ref = "final/residual-trace.json"
    residual_trace_sha = write_digest(
        trial / residual_trace_ref,
        {
            "trace_version": "1.1",
            "question": req["question"],
            "instrument": "MAGI",
            "residuals": [],
            "trial_manifest": {
                "manifest_version": "1.0",
                "base_model_relation": "heterogeneous_models",
                "perspective_count": 3,
                "perspectives": [],
                "perturbation_axes": [],
                "independence_controls": [],
                "contamination_risks": [],
                "cost": {"total_tokens": None, "wall_time_seconds": None, "tool_calls": None, "human_minutes": None},
            },
            "action_boundary": req["action_boundary"],
            "highball_decision": {"PASS": "pass", "BLOCK": "block", "ESCALATE": "escalate"}.get(
                decision, "block"
            ),
            "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
        },
    )

    cross_reviews = []
    aliases = {"seat-1": "Perspective A", "seat-2": "Perspective B", "seat-3": "Perspective C"}
    for index, obligation in enumerate(assignment_reviews, start=1):
        reviewer = obligation["reviewer_seat_id"]
        subject = obligation["subject_seat_id"]
        seat_index = int(reviewer[-1])
        methodology = [
            {"kind": "method", "method": "structured challenge", "application": "Checked claims."},
            {"kind": "failure_check", "method": "omission scan", "application": "Checked omissions."},
        ]
        review = {
            "review_version": "1.1",
            "reviewer_alias": aliases[reviewer],
            "subject_alias": aliases[subject],
            "reviewer_profile_binding": {
                "profile_id": profile_ids[seat_index - 1],
                "profile_sha256": product_seats[seat_index - 1]["profile_sha256"],
                "profile_source_sha256": assignment_seats[seat_index - 1]["profile_source_sha256"],
                "thesis_sha256": product_seats[seat_index - 1]["thesis_sha256"],
            },
            "methodology_trace": methodology,
            "summary": "Review complete.",
            "findings": [],
            "dissent": [],
        }
        review_ref = f"reviews/{index}.json"
        review_sha = write_digest(trial / review_ref, review)
        agent_digest = CONTRACTS.sha256_bytes(f"reviewer-agent-config-{seat_index}".encode())
        execution = {
            "receipt_version": "1.0",
            "kind": "cross_review",
            "service": reviewer,
            "seat_id": reviewer,
            "image_digest": assignment_seats[seat_index - 1]["image_digest"],
            "profile_sha256": assignment_seats[seat_index - 1]["profile_source_sha256"],
            "agent_config_sha256": agent_digest,
            "input_packet_sha256": CONTRACTS.sha256_bytes(f"packet-{index}".encode()),
            "output_artifact_sha256": review_sha,
            "execution_mode": "container",
        }
        execution_ref = f"reviews/{index}-execution-receipt.json"
        execution_sha = write_digest(trial / execution_ref, execution)
        cross_reviews.append(
            {
                "artifact_ref": review_ref,
                "sha256": review_sha,
                "reviewer_seat_id": reviewer,
                "reviewer_family": families[seat_index - 1],
                "reviewer_provider": f"provider-{families[seat_index - 1]}",
                "reviewer_text_model": f"model-{families[seat_index - 1]}",
                "reviewer_multimodal_model": f"model-{families[seat_index - 1]}",
                "reviewer_profile_id": profile_ids[seat_index - 1],
                "reviewer_profile_sha256": product_seats[seat_index - 1]["profile_sha256"],
                "reviewer_profile_source_sha256": assignment_seats[seat_index - 1]["profile_source_sha256"],
                "reviewer_agent_config_sha256": agent_digest,
                "methodology_trace_sha256": digest_value(methodology),
                "reviewer_execution_receipt_ref": execution_ref,
                "reviewer_execution_receipt_sha256": execution_sha,
            }
        )

    adjudicator_agent_sha = CONTRACTS.sha256_bytes(b"final-adjudicator-agent")
    final_execution = {
        "receipt_version": "1.0",
        "kind": "final_adjudication",
        "service": "final-adjudicator",
        "seat_id": None,
        "image_digest": "sha256:" + "9" * 64,
        "profile_sha256": None,
        "agent_config_sha256": adjudicator_agent_sha,
        "input_packet_sha256": CONTRACTS.sha256_bytes(b"final-packet"),
        "output_artifact_sha256": final_verdict_sha,
        "execution_mode": "external_model",
    }
    final_execution_ref = "final/adjudicator-execution-receipt.json"
    final_execution_sha = write_digest(trial / final_execution_ref, final_execution)

    reduction_identity = {
        "receipt_version": "1.0",
        "metric_scope": "observable source coverage",
        "baseline_scope": "three seat dossiers",
        "seat_residual_source_refs": [],
        "cross_review_source_refs": [],
        "cross_review_novel_source_refs": [],
        "cross_review_linked_source_refs": [],
        "challenged_seat_source_refs": [],
        "final_represented_source_refs": [],
        "final_falsified_or_discarded_source_refs": [],
        "final_finding_ids": [],
        "final_unresolved_finding_ids": [],
        "counts": {field: 0 for field in PRODUCT.MAGI_RESIDUAL_REDUCTION_COUNT_FIELDS},
        "limitations": ["This receipt does not measure a true error rate."],
    }
    reduction = {**reduction_identity, "binding_sha256": digest_value(reduction_identity)}
    reduction_ref = "final/residual-reduction-receipt.json"
    reduction_sha = write_digest(trial / reduction_ref, reduction)

    coverage_artifact_refs = [
        *(seat["dossier_ref"] for seat in product_seats),
        *(review["artifact_ref"] for review in cross_reviews),
        final_verdict_ref,
        residual_trace_ref,
    ]
    coverage_artifacts = [
        {
            "artifact_ref": reference,
            "sha256": CONTRACTS.sha256_bytes((trial / reference).read_bytes()),
            "evidence_refs": [],
        }
        for reference in coverage_artifact_refs
    ]
    coverage_identity = {
        "coverage_receipt_version": "1.0",
        "coverage_status": "bounded",
        "coverage_scope": "artifact citation coverage; not proof of model perception or review",
        "original_brief_sha256": original_brief_sha,
        "evidence_manifest_ref": manifest_ref,
        "evidence_manifest_sha256": manifest_sha,
        "artifacts": coverage_artifacts,
        "exposed_evidence": [],
        "cited_evidence": [],
        "exposed_but_uncited": [],
        "unknown_citations": [],
        "unreviewed_media": [],
        "declared_limitations": ["No external evidence was staged."],
        "limitations": [
            "Mounted or exposed evidence is not equivalent to evidence read or reviewed.",
            "A citation is an artifact claim and does not attest semantic correctness.",
        ],
    }
    coverage = {
        **coverage_identity,
        "receipt_binding_sha256": digest_value(coverage_identity),
    }
    coverage_ref = "final/evidence-coverage-receipt.json"
    coverage_sha = write_digest(trial / coverage_ref, coverage)

    identity = {
        "product_version": "1.0",
        "trial_id": trial_id,
        "status": "completed",
        "runtime_sha256": "sha256:" + "1" * 64,
        "agent_config_sha256": "sha256:" + "2" * 64,
        "builder_config_sha256": "sha256:" + "3" * 64,
        "assignment_plan_ref": assignment_ref,
        "assignment_plan_sha256": assignment_sha,
        "evidence_manifest_ref": manifest_ref,
        "evidence_manifest_sha256": manifest_sha,
        "evidence_coverage_ref": coverage_ref,
        "evidence_coverage_sha256": coverage_sha,
        "original_brief_sha256": original_brief_sha,
        "action_binding_sha256": CONTRACTS.action_binding_sha256(req),
        "question": req["question"],
        "action_scope": req["action_scope"],
        "affected_paths": req["affected_paths"],
        "final_decision": decision,
        "final_dissent": [],
        "final_verdict_ref": final_verdict_ref,
        "final_verdict_sha256": final_verdict_sha,
        "residual_trace_ref": residual_trace_ref,
        "residual_trace_sha256": residual_trace_sha,
        "residual_reduction_ref": reduction_ref,
        "residual_reduction_sha256": reduction_sha,
        "final_adjudicator": {
            "family": "openai",
            "provider": "openai-api",
            "text_model": "gpt-5.6-sol",
            "multimodal_model": "gpt-5.6-sol",
            "agent_config_sha256": adjudicator_agent_sha,
            "execution_mode": "external_model",
            "execution_receipt_ref": final_execution_ref,
            "execution_receipt_sha256": final_execution_sha,
        },
        "seats": product_seats,
        "cross_reviews": cross_reviews,
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
        self.old_builder_runs_root = BUILDER.PRODUCT.trusted_runs_root
        self.old_validator_runs_root = VALIDATOR.PRODUCT.trusted_runs_root
        self.old_binary = PRODUCT.active_quinte_binary
        self.old_magi_binary = PRODUCT.active_magi_binary
        self.old_builder_magi_binary = BUILDER.PRODUCT.active_magi_binary
        self.old_validator_magi_binary = VALIDATOR.PRODUCT.active_magi_binary
        self.old_execution_magi_binary = EXECUTION_BUILDER.ACTION_PACKET.PRODUCT.active_magi_binary
        PRODUCT.trusted_runs_root = lambda: (self.root / "quinte" / "runs").resolve()
        BUILDER.PRODUCT.trusted_runs_root = lambda: (self.root / "quinte" / "runs").resolve()
        VALIDATOR.PRODUCT.trusted_runs_root = lambda: (self.root / "quinte" / "runs").resolve()
        PRODUCT.active_quinte_binary = lambda: self.binary.resolve()
        PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()
        BUILDER.PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()
        VALIDATOR.PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()
        EXECUTION_BUILDER.ACTION_PACKET.PRODUCT.active_magi_binary = lambda: self.magi_binary.resolve()

    def tearDown(self) -> None:
        os.environ["PATH"] = self.old_path
        PRODUCT.trusted_runs_root = self.old_runs_root
        BUILDER.PRODUCT.trusted_runs_root = self.old_builder_runs_root
        VALIDATOR.PRODUCT.trusted_runs_root = self.old_validator_runs_root
        PRODUCT.active_quinte_binary = self.old_binary
        PRODUCT.active_magi_binary = self.old_magi_binary
        BUILDER.PRODUCT.active_magi_binary = self.old_builder_magi_binary
        VALIDATOR.PRODUCT.active_magi_binary = self.old_validator_magi_binary
        EXECUTION_BUILDER.ACTION_PACKET.PRODUCT.active_magi_binary = self.old_execution_magi_binary
        self.temp.cleanup()

    def build(
        self,
        req: dict[str, Any],
        tr: dict[str, Any],
        result: Path | None = None,
        auth: Path | None = None,
        magi: Path | None = None,
        receipt: Path | None = None,
    ) -> dict[str, Any]:
        req_path, trace_path = self.root / "request.json", self.root / "trace.json"
        write(req_path, req)
        write(trace_path, tr)
        return BUILDER.build_packet(
            req_path,
            trace_path,
            [result] if result else [],
            auth,
            [magi] if magi else [],
            [receipt] if receipt else [],
        )

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

    def test_host_receipt_binds_product_without_invoking_quinte(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        receipt_path = self.host_receipt(result_path)
        old_binary = PRODUCT.active_quinte_binary
        def fail_if_called() -> Path:
            raise AssertionError("host receipt verification must not invoke quinte")
        PRODUCT.active_quinte_binary = fail_if_called
        try:
            summary, errors = PRODUCT.load_quinte_host_receipt(str(receipt_path), req)
        finally:
            PRODUCT.active_quinte_binary = old_binary
        self.assertEqual(errors, [])
        self.assertIsNotNone(summary)
        packet = self.build(req, trace(req), receipt=receipt_path)
        self.assertEqual(packet["product_evidence"]["status"], "complete")
        outcome = packet["product_evidence"]["product"]
        self.assertEqual(outcome["host_receipt_operation"], "inspect")
        self.assertEqual(outcome["host_receipt_ref"], str(receipt_path.resolve()))
        self.assertFalse(VALIDATOR.validate_packet(packet, base_dir=self.root))

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
        summary, errors = PRODUCT.load_quinte_host_receipt(str(envelope_path), req)
        self.assertEqual(errors, [])
        self.assertIsNotNone(summary)
        self.assertEqual(summary["host_receipt_ref"], str(envelope_path.resolve()))

    def test_reconciled_host_receipt_binds_terminal_product(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        receipt_path = self.host_receipt(result_path, operation="reconcile")
        summary, errors = PRODUCT.load_quinte_host_receipt(str(receipt_path), req)
        self.assertEqual(errors, [])
        self.assertIsNotNone(summary)
        self.assertEqual(summary["host_receipt_operation"], "reconcile")

        packet = self.build(req, trace(req), receipt=receipt_path)
        self.assertEqual(packet["product_evidence"]["status"], "complete")
        self.assertEqual(
            packet["product_evidence"]["product"]["host_receipt_operation"],
            "reconcile",
        )
        self.assertFalse(VALIDATOR.validate_packet(packet, base_dir=self.root))

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
                summary, errors = PRODUCT.load_quinte_host_receipt(
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
                summary, errors = PRODUCT.load_quinte_host_receipt(str(receipt_path), req)
                self.assertIsNone(summary)
                self.assertTrue(any("operation must be inspect or reconcile" in item for item in errors))

        receipt_path = self.host_receipt(result_path)
        receipt = json.loads(receipt_path.read_text())
        receipt["result"]["verified"] = False
        write(receipt_path, receipt)
        summary, errors = PRODUCT.load_quinte_host_receipt(str(receipt_path), req)
        self.assertIsNone(summary)
        self.assertTrue(any("result.verified must be true" in item for item in errors))

    def test_host_receipt_state_root_binding_fails_closed(self) -> None:
        req = request(risk="MEDIUM")
        result_path = product(self.root / "quinte", req, self.binary)
        receipt_path = self.host_receipt(result_path)
        receipt = json.loads(receipt_path.read_text())
        receipt["state_root"] = str(self.root / "other-quinte")
        write(receipt_path, receipt)
        summary, errors = PRODUCT.load_quinte_host_receipt(str(receipt_path), req)
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
                summary, errors = PRODUCT.load_quinte_host_receipt(str(receipt_path), req)
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
        verdict_path = trial / summary["final_verdict_ref"]
        verdict = json.loads(verdict_path.read_text())
        verdict["dissent"] = summary["final_dissent"]
        write(verdict_path, verdict)
        summary["final_verdict_sha256"] = CONTRACTS.sha256_bytes(verdict_path.read_bytes())
        execution_path = trial / summary["final_adjudicator"]["execution_receipt_ref"]
        execution = json.loads(execution_path.read_text())
        execution["output_artifact_sha256"] = summary["final_verdict_sha256"]
        write(execution_path, execution)
        summary["final_adjudicator"]["execution_receipt_sha256"] = CONTRACTS.sha256_bytes(
            execution_path.read_bytes()
        )
        coverage_path = trial / summary["evidence_coverage_ref"]
        coverage = json.loads(coverage_path.read_text())
        for artifact in coverage["artifacts"]:
            if artifact["artifact_ref"] == summary["final_verdict_ref"]:
                artifact["sha256"] = summary["final_verdict_sha256"]
        coverage_identity = {
            key: value for key, value in coverage.items() if key != "receipt_binding_sha256"
        }
        coverage["receipt_binding_sha256"] = digest_value(coverage_identity)
        write(coverage_path, coverage)
        summary["evidence_coverage_sha256"] = CONTRACTS.sha256_bytes(coverage_path.read_bytes())
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

    def test_magi_review_provenance_is_closed_and_digest_bound(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        fields = (
            "reviewer_profile_sha256",
            "reviewer_profile_source_sha256",
            "reviewer_agent_config_sha256",
            "methodology_trace_sha256",
            "reviewer_execution_receipt_sha256",
        )
        for index, field in enumerate(fields):
            with self.subTest(field=field):
                trial = magi_product(self.root / field, req)
                summary_path = trial / "product-summary.json"
                summary = json.loads(summary_path.read_text())
                summary["cross_reviews"][index][field] = "not-a-digest"
                identity = {key: value for key, value in summary.items() if key != "product_sha256"}
                summary["product_sha256"] = CONTRACTS.sha256_bytes(
                    json.dumps(
                        identity,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                )
                write(summary_path, summary)
                packet = self.build(req, tr, magi=trial)
                self.assertEqual(packet["product_evidence"]["status"], "invalid")
                self.assertTrue(
                    any(
                        f"cross_reviews[{index}].{field} is invalid" in error
                        for error in packet["product_evidence"]["errors"]
                    )
                )

        trial = magi_product(self.root / "unknown", req)
        summary_path = trial / "product-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["cross_reviews"][0]["unverified_provenance"] = "sha256:" + "f" * 64
        identity = {key: value for key, value in summary.items() if key != "product_sha256"}
        summary["product_sha256"] = CONTRACTS.sha256_bytes(
            json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        )
        write(summary_path, summary)
        packet = self.build(req, tr, magi=trial)
        self.assertEqual(packet["product_evidence"]["status"], "invalid")
        self.assertTrue(
            any(
                "cross_reviews[0] has unknown fields: unverified_provenance" in error
                for error in packet["product_evidence"]["errors"]
            )
        )

    def test_magi_review_receipts_bind_each_reviewer_to_its_frozen_seat(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        cases = (
            ("family", lambda summary: summary["cross_reviews"][0].__setitem__("reviewer_family", "deepseek"), "reviewer_family does not match"),
            ("profile", lambda summary: summary["cross_reviews"][0].__setitem__("reviewer_profile_sha256", "sha256:" + "f" * 64), "reviewer_profile_sha256 does not match"),
            ("drift", lambda summary: summary["cross_reviews"][1].__setitem__("reviewer_profile_id", "changed"), "changes the frozen reviewer binding"),
            ("count", lambda summary: summary["cross_reviews"][5].__setitem__("reviewer_seat_id", "seat-1"), "exactly two cross-reviews from each seat"),
            ("receipt", lambda summary: summary["cross_reviews"][1].__setitem__("reviewer_execution_receipt_ref", summary["cross_reviews"][0]["reviewer_execution_receipt_ref"]), "six distinct reviewer execution receipt refs"),
        )
        for name, mutate, expected in cases:
            with self.subTest(case=name):
                trial = magi_product(self.root / name, req)
                summary_path = trial / "product-summary.json"
                summary = json.loads(summary_path.read_text())
                mutate(summary)
                identity = {key: value for key, value in summary.items() if key != "product_sha256"}
                summary["product_sha256"] = CONTRACTS.sha256_bytes(
                    json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
                )
                write(summary_path, summary)
                packet = self.build(req, tr, magi=trial)
                self.assertEqual(packet["product_evidence"]["status"], "invalid")
                self.assertTrue(any(expected in error for error in packet["product_evidence"]["errors"]))

    def test_magi_final_adjudicator_provenance_is_closed_and_digest_bound(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        cases = (
            ("missing", lambda summary: summary.pop("final_adjudicator"), "missing fields: final_adjudicator"),
            ("digest", lambda summary: summary["final_adjudicator"].__setitem__("execution_receipt_sha256", "not-a-digest"), "execution_receipt_sha256 is invalid"),
            ("empty", lambda summary: summary["final_adjudicator"].__setitem__("provider", ""), "provider must be a non-empty string"),
            ("unknown", lambda summary: summary["final_adjudicator"].__setitem__("unverified", True), "has unknown fields: unverified"),
        )
        for name, mutate, expected in cases:
            with self.subTest(case=name):
                trial = magi_product(self.root / f"final-{name}", req)
                summary_path = trial / "product-summary.json"
                summary = json.loads(summary_path.read_text())
                mutate(summary)
                identity = {key: value for key, value in summary.items() if key != "product_sha256"}
                summary["product_sha256"] = CONTRACTS.sha256_bytes(
                    json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
                )
                write(summary_path, summary)
                packet = self.build(req, tr, magi=trial)
                self.assertEqual(packet["product_evidence"]["status"], "invalid")
                self.assertTrue(any(expected in error for error in packet["product_evidence"]["errors"]))

    def test_magi_bound_artifact_tampering_fails_closed(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        cases = (
            ("assignment", lambda trial, summary: trial / summary["assignment_plan_ref"], "assignment plan digest mismatch"),
            ("dossier", lambda trial, summary: trial / summary["seats"][0]["dossier_ref"], "dossier digest mismatch"),
            ("review", lambda trial, summary: trial / summary["cross_reviews"][0]["artifact_ref"], "artifact digest mismatch"),
            ("coverage", lambda trial, summary: trial / summary["evidence_coverage_ref"], "coverage receipt digest mismatch"),
            ("reduction", lambda trial, summary: trial / summary["residual_reduction_ref"], "residual-reduction receipt digest mismatch"),
            ("verdict", lambda trial, summary: trial / summary["final_verdict_ref"], "final verdict digest mismatch"),
        )
        for name, select, expected in cases:
            with self.subTest(artifact=name):
                trial = magi_product(self.root / f"tamper-{name}", req)
                summary = json.loads((trial / "product-summary.json").read_text())
                artifact = select(trial, summary)
                artifact.write_text(artifact.read_text() + "\n", encoding="utf-8")
                packet = self.build(req, tr, magi=trial)
                self.assertEqual(packet["product_evidence"]["status"], "invalid")
                self.assertTrue(any(expected in error for error in packet["product_evidence"]["errors"]))

    def test_magi_artifact_path_escape_fails_closed(self) -> None:
        req = request(change_class="architecture")
        trial = magi_product(self.root, req)
        summary_path = trial / "product-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["residual_reduction_ref"] = "../outside.json"
        summary["product_sha256"] = digest_value(
            {key: value for key, value in summary.items() if key != "product_sha256"}
        )
        write(summary_path, summary)
        packet = self.build(req, trace(req, instrument="MAGI"), magi=trial)
        self.assertEqual(packet["product_evidence"]["status"], "invalid")
        self.assertTrue(
            any("residual-reduction receipt ref escapes" in error for error in packet["product_evidence"]["errors"])
        )

    def test_magi_execution_receipt_output_and_assignment_drift_fail_closed(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        cases = (
            ("output", "output_artifact_sha256", "sha256:" + "f" * 64, "output_artifact_sha256 does not match"),
            ("service", "service", "wrong-seat", "service does not match the assignment plan"),
            ("image", "image_digest", "sha256:" + "f" * 64, "image_digest does not match the assignment plan"),
        )
        for name, field, value, expected in cases:
            with self.subTest(case=name):
                trial = magi_product(self.root / f"receipt-{name}", req)
                summary_path = trial / "product-summary.json"
                summary = json.loads(summary_path.read_text())
                receipt_path = trial / summary["cross_reviews"][0]["reviewer_execution_receipt_ref"]
                receipt = json.loads(receipt_path.read_text())
                receipt[field] = value
                write(receipt_path, receipt)
                summary["cross_reviews"][0]["reviewer_execution_receipt_sha256"] = CONTRACTS.sha256_bytes(
                    receipt_path.read_bytes()
                )
                summary["product_sha256"] = digest_value(
                    {key: item for key, item in summary.items() if key != "product_sha256"}
                )
                write(summary_path, summary)
                packet = self.build(req, tr, magi=trial)
                self.assertEqual(packet["product_evidence"]["status"], "invalid")
                self.assertTrue(any(expected in error for error in packet["product_evidence"]["errors"]))

    def test_magi_malformed_assignment_and_reduction_return_invalid_not_exception(self) -> None:
        req = request(change_class="architecture")
        tr = trace(req, instrument="MAGI")
        for name, reference_field, mutate, expected in (
            (
                "assignment",
                "assignment_plan_ref",
                lambda value: value.__setitem__("cross_review_obligations", []),
                "must contain all six directed reviews",
            ),
            (
                "reduction",
                "residual_reduction_ref",
                lambda value: value.__setitem__("seat_residual_source_refs", {"bad": True}),
                "must be a sorted unique string array",
            ),
        ):
            with self.subTest(case=name):
                trial = magi_product(self.root / f"malformed-{name}", req)
                summary_path = trial / "product-summary.json"
                summary = json.loads(summary_path.read_text())
                artifact = trial / summary[reference_field]
                value = json.loads(artifact.read_text())
                mutate(value)
                binding = "plan_binding_sha256" if name == "assignment" else "binding_sha256"
                value[binding] = digest_value(
                    {key: item for key, item in value.items() if key != binding}
                )
                write(artifact, value)
                digest_field = reference_field.removesuffix("_ref") + "_sha256"
                summary[digest_field] = CONTRACTS.sha256_bytes(artifact.read_bytes())
                summary["product_sha256"] = digest_value(
                    {key: item for key, item in summary.items() if key != "product_sha256"}
                )
                write(summary_path, summary)
                packet = self.build(req, tr, magi=trial)
                self.assertEqual(packet["product_evidence"]["status"], "invalid")
                self.assertTrue(any(expected in error for error in packet["product_evidence"]["errors"]))

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
