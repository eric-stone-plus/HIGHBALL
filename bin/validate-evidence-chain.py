#!/usr/bin/env python3
"""Validate references across HIGHBALL policy, baseline, outcome, packet, and trace artifacts."""

from __future__ import annotations

import argparse
import importlib.util
import json
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
POLICY_VALIDATOR = load_module("validate_route_policy_report", ROOT / "bin" / "validate-route-policy-report.py")
BASELINE_VALIDATOR = load_module("validate_route_baseline_report", ROOT / "bin" / "validate-route-baseline-report.py")
BASELINE_BUILDER = load_module("build_route_baseline_report", ROOT / "bin" / "build-route-baseline-report.py")
PROPOSAL_VALIDATOR = load_module("validate_route_change_proposal", ROOT / "bin" / "validate-route-change-proposal.py")
PROPOSAL_BUILDER = load_module("build_route_change_proposal", ROOT / "bin" / "build-route-change-proposal.py")
EXPERIMENT_REVIEW_VALIDATOR = load_module(
    "validate_route_experiment_review",
    ROOT / "bin" / "validate-route-experiment-review.py",
)
EXPERIMENT_REVIEW_BUILDER = load_module(
    "build_route_experiment_review",
    ROOT / "bin" / "build-route-experiment-review.py",
)
EXECUTION_VALIDATOR = load_module("validate_route_execution_report", ROOT / "bin" / "validate-route-execution-report.py")
EXECUTION_BUILDER = load_module("build_route_execution_report", ROOT / "bin" / "build-route-execution-report.py")
PAIRING_VALIDATOR = load_module("validate_route_pairing_report", ROOT / "bin" / "validate-route-pairing-report.py")
PAIRING_BUILDER = load_module("build_route_pairing_report", ROOT / "bin" / "build-route-pairing-report.py")
PAIR_MANIFEST_VALIDATOR = load_module("validate_route_pair_manifest", ROOT / "bin" / "validate-route-pair-manifest.py")
CALIBRATION_VALIDATOR = load_module("validate_route_calibration_report", ROOT / "bin" / "validate-route-calibration-report.py")
OUTCOME_VALIDATOR = load_module("validate_outcome_ledger", ROOT / "bin" / "validate-outcome-ledger.py")
ACTION_PACKET_VALIDATOR = load_module("validate_action_packet", ROOT / "bin" / "validate-action-packet.py")
TRACE_VALIDATOR = load_module("validate_residual_trace", ROOT / "bin" / "validate-residual-trace.py")


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


def resolve_ref(base_file: Path, ref: str | None) -> Path | None:
    if ref is None:
        return None
    ref_path = Path(ref)
    if ref_path.is_absolute():
        return ref_path.resolve()
    return (base_file.parent / ref_path).resolve()


def residual_ids(trace: dict[str, Any]) -> set[str]:
    ids = set()
    for residual in trace.get("residuals", []):
        if isinstance(residual, dict) and isinstance(residual.get("id"), str):
            ids.add(residual["id"])
    return ids


def validate_trace_object(trace: dict[str, Any], label: str, errors: list[str]) -> None:
    findings = TRACE_VALIDATOR.validate_trace(trace, 1)
    for finding in findings:
        if finding.severity == "ERROR":
            errors.append(f"{label}: {finding}")


def route_group_from_trace(trace: dict[str, Any]) -> str:
    manifest = trace.get("trial_manifest")
    relation = "unknown"
    if isinstance(manifest, dict) and isinstance(manifest.get("base_model_relation"), str):
        relation = manifest["base_model_relation"]
    instrument = trace.get("instrument") if isinstance(trace.get("instrument"), str) else "unknown"
    boundary = trace.get("action_boundary") if isinstance(trace.get("action_boundary"), str) else "unknown"
    return f"{instrument}:{relation}:{boundary}"


def empty_policy_baseline_summary() -> dict[str, Any]:
    return {
        "comparison_count": 0,
        "target_preferred_count": 0,
        "baseline_preferred_count": 0,
        "target_blocked_count": 0,
        "watch_count": 0,
        "insufficient_count": 0,
        "recommendation": "not_provided",
    }


def policy_baseline_summary_for_route(baseline: dict[str, Any] | None, route_group: str) -> dict[str, Any]:
    if baseline is None:
        return empty_policy_baseline_summary()
    comparisons = [
        comparison
        for comparison in baseline.get("comparisons", [])
        if isinstance(comparison, dict) and comparison.get("target_route_group") == route_group
    ]
    if not comparisons:
        summary = BASELINE_BUILDER.summarize([])
        summary["recommendation"] = "insufficient"
        return summary
    return BASELINE_BUILDER.summarize(comparisons)


def validate_policy_chain(policy_path: Path) -> list[str]:
    errors: list[str] = []
    policy = load_json(policy_path)
    errors.extend(f"policy: {error}" for error in POLICY_VALIDATOR.validate_report(policy))
    if errors:
        return errors

    calibration_path = resolve_ref(policy_path, policy["inputs"]["calibration_report_ref"])
    outcome_path = resolve_ref(policy_path, policy["inputs"]["outcome_ledger_ref"])
    baseline_path = resolve_ref(policy_path, policy["inputs"].get("baseline_report_ref"))
    experiment_review_path = resolve_ref(policy_path, policy["inputs"].get("experiment_review_ref"))
    execution_path = resolve_ref(policy_path, policy["inputs"].get("execution_report_ref"))
    assert calibration_path is not None
    assert outcome_path is not None

    if not calibration_path.exists():
        errors.append(f"calibration report does not exist: {calibration_path}")
        return errors
    if not outcome_path.exists():
        errors.append(f"outcome ledger does not exist: {outcome_path}")
        return errors
    if baseline_path is not None and not baseline_path.exists():
        errors.append(f"baseline report does not exist: {baseline_path}")
        return errors
    if experiment_review_path is not None and not experiment_review_path.exists():
        errors.append(f"experiment review does not exist: {experiment_review_path}")
        return errors
    if execution_path is not None and not execution_path.exists():
        errors.append(f"execution report does not exist: {execution_path}")
        return errors

    calibration = load_json(calibration_path)
    outcome = load_json(outcome_path)
    errors.extend(f"calibration: {error}" for error in CALIBRATION_VALIDATOR.validate_report(calibration))
    errors.extend(f"outcome: {error}" for error in OUTCOME_VALIDATOR.validate_ledger(outcome))
    baseline = None
    if baseline_path is not None:
        baseline = load_json(baseline_path)
        errors.extend(f"baseline: {error}" for error in BASELINE_VALIDATOR.validate_report(baseline))
    experiment_review = None
    if experiment_review_path is not None:
        experiment_review = load_json(experiment_review_path)
        errors.extend(f"experiment_review: {error}" for error in EXPERIMENT_REVIEW_VALIDATOR.validate_report(experiment_review))
    execution = None
    if execution_path is not None:
        execution = load_json(execution_path)
        errors.extend(f"execution: {error}" for error in EXECUTION_VALIDATOR.validate_report(execution))
    if errors:
        return errors

    route_group = policy["route_group"]
    if outcome["subject"].get("route_group") != route_group:
        errors.append("policy route_group differs from outcome subject route_group")
    if route_group not in calibration.get("route_groups", {}):
        errors.append("policy route_group is absent from calibration route_groups")

    if policy["calibration"]["recommendation"] != calibration["recommendation"]:
        errors.append("policy calibration recommendation differs from calibration report")
    if policy["calibration"]["trace_count"] != calibration["trace_count"]:
        errors.append("policy calibration trace_count differs from calibration report")
    if policy["calibration"]["invalid_trace_files"] != calibration["invalid_trace_files"]:
        errors.append("policy calibration invalid_trace_files differs from calibration report")
    if policy["outcome"]["calibration_signal"] != outcome["summary"]["calibration_signal"]:
        errors.append("policy outcome signal differs from outcome ledger")
    if policy["outcome"]["entry_count"] != outcome["summary"]["entry_count"]:
        errors.append("policy outcome entry_count differs from outcome ledger")
    expected_baseline_summary = policy_baseline_summary_for_route(baseline, route_group)
    if policy.get("baseline") != expected_baseline_summary:
        errors.append("policy baseline summary differs from baseline report")
    expected_experiment = {
        "review_ref": None,
        "review_verdict": "not_provided",
        "policy_gate": "not_provided",
        "required_before_policy_change": False,
    }
    if experiment_review is not None:
        expected_experiment = {
            "review_ref": policy["inputs"]["experiment_review_ref"],
            "review_verdict": experiment_review["review_verdict"],
            "policy_gate": {
                "supports_policy_review": "accepted",
                "needs_more_evidence": "watch",
                "stop_blocked": "block",
                "plan_violation": "insufficient",
            }[experiment_review["review_verdict"]],
            "required_before_policy_change": True,
        }
    if policy.get("experiment_review") != expected_experiment:
        errors.append("policy experiment review summary differs from experiment review report")
    expected_execution = {
        "report_ref": None,
        "execution_gate": "not_provided",
        "packet_count": 0,
        "required_execution_count": 0,
        "complete_count": 0,
        "missing_count": 0,
        "blocked_count": 0,
        "degraded_count": 0,
        "invalid_count": 0,
        "completion_rate": None,
    }
    if execution is not None:
        expected_execution = {
            "report_ref": policy["inputs"]["execution_report_ref"],
            "execution_gate": execution["execution_gate"],
            "packet_count": execution["packet_count"],
            "required_execution_count": execution["required_execution_count"],
            "complete_count": execution["complete_count"],
            "missing_count": execution["missing_count"],
            "blocked_count": execution["blocked_count"],
            "degraded_count": execution["degraded_count"],
            "invalid_count": execution["invalid_count"],
            "completion_rate": execution["completion_rate"],
        }
    if policy.get("execution") != expected_execution:
        errors.append("policy execution summary differs from execution report")
    if baseline is not None:
        baseline_inputs = baseline.get("inputs", {})
        baseline_calibration_path = resolve_ref(baseline_path, baseline_inputs.get("calibration_report_ref"))
        baseline_outcome_path = resolve_ref(baseline_path, baseline_inputs.get("outcome_ledger_ref"))
        if baseline_calibration_path != calibration_path:
            errors.append("policy baseline report calibration ref differs from policy calibration report")
        if baseline_outcome_path is not None and baseline_outcome_path != outcome_path:
            errors.append("policy baseline report outcome ref differs from policy outcome ledger")
    if experiment_review is not None:
        experiment_inputs = experiment_review.get("inputs", {})
        experiment_calibration_path = resolve_ref(experiment_review_path, experiment_inputs.get("calibration_report_ref"))
        experiment_outcome_path = resolve_ref(experiment_review_path, experiment_inputs.get("outcome_ledger_ref"))
        experiment_baseline_path = resolve_ref(experiment_review_path, experiment_inputs.get("baseline_report_ref"))
        if experiment_review.get("route_group") != route_group:
            errors.append("policy experiment review route_group differs from policy route_group")
        if experiment_calibration_path != calibration_path:
            errors.append("policy experiment review calibration ref differs from policy calibration report")
        if experiment_outcome_path is not None and experiment_outcome_path != outcome_path:
            errors.append("policy experiment review outcome ref differs from policy outcome ledger")
        if experiment_baseline_path is not None and experiment_baseline_path != baseline_path:
            errors.append("policy experiment review baseline ref differs from policy baseline report")
        errors.extend(validate_experiment_review_chain(experiment_review_path))
    if execution is not None:
        if execution.get("route_group") != route_group:
            errors.append("policy execution report route_group differs from policy route_group")
        errors.extend(validate_execution_chain(execution_path))

    calibration_sources = set()
    group = calibration.get("route_groups", {}).get(route_group)
    if isinstance(group, dict):
        for source in group.get("sources", []):
            if isinstance(source, str):
                source_path = resolve_ref(calibration_path, source)
                if source_path is not None:
                    calibration_sources.add(source_path)

    seen_trace_refs: set[Path] = set()
    for index, entry in enumerate(outcome.get("entries", []), start=1):
        prefix = f"outcome entries[{index}]"
        if not isinstance(entry, dict):
            continue
        if entry.get("route_group") != route_group:
            errors.append(f"{prefix} route_group differs from policy route_group")

        trace_path = resolve_ref(outcome_path, entry.get("trace_ref"))
        trace = None
        if trace_path is not None:
            if not trace_path.exists():
                errors.append(f"{prefix} trace_ref does not exist: {trace_path}")
            else:
                trace = load_json(trace_path)
                validate_trace_object(trace, f"{prefix} trace_ref", errors)
                seen_trace_refs.add(trace_path)
                if route_group_from_trace(trace) != route_group:
                    errors.append(f"{prefix} trace_ref route group differs from policy route_group")
                missing_ids = set(entry.get("residual_ids", [])) - residual_ids(trace)
                if missing_ids:
                    errors.append(f"{prefix} residual_ids missing from trace_ref: {', '.join(sorted(missing_ids))}")

        packet_path = resolve_ref(outcome_path, entry.get("action_packet_ref"))
        if packet_path is not None:
            if not packet_path.exists():
                errors.append(f"{prefix} action_packet_ref does not exist: {packet_path}")
            else:
                try:
                    packet = ACTION_PACKET_VALIDATOR.load_packet(packet_path)
                except ValueError as exc:
                    errors.append(f"{prefix} action_packet_ref cannot be loaded: {exc}")
                    packet = None
                if packet is not None:
                    packet_errors = ACTION_PACKET_VALIDATOR.validate_packet(packet, base_dir=packet_path.parent)
                    errors.extend(f"{prefix} action_packet_ref: {error}" for error in packet_errors)
                    packet_trace = packet.get("trace")
                    if isinstance(packet_trace, dict):
                        if route_group_from_trace(packet_trace) != route_group:
                            errors.append(f"{prefix} action_packet trace route group differs from policy route_group")
                        missing_ids = set(entry.get("residual_ids", [])) - residual_ids(packet_trace)
                        if missing_ids:
                            errors.append(f"{prefix} residual_ids missing from action packet trace: {', '.join(sorted(missing_ids))}")

        calibration_ref_path = resolve_ref(outcome_path, entry.get("calibration_report_ref"))
        if calibration_ref_path is not None and calibration_ref_path != calibration_path:
            errors.append(f"{prefix} calibration_report_ref differs from policy calibration report")

    if calibration_sources:
        missing_from_sources = seen_trace_refs - calibration_sources
        if missing_from_sources:
            missing = ", ".join(str(path) for path in sorted(missing_from_sources))
            errors.append(f"outcome trace refs are absent from calibration group sources: {missing}")

    return errors


def validate_baseline_chain(baseline_path: Path) -> list[str]:
    errors: list[str] = []
    report = load_json(baseline_path)
    errors.extend(f"baseline: {error}" for error in BASELINE_VALIDATOR.validate_report(report))
    if errors:
        return errors

    calibration_path = resolve_ref(baseline_path, report["inputs"]["calibration_report_ref"])
    outcome_path = resolve_ref(baseline_path, report["inputs"].get("outcome_ledger_ref"))
    assert calibration_path is not None

    if not calibration_path.exists():
        errors.append(f"calibration report does not exist: {calibration_path}")
        return errors

    calibration = load_json(calibration_path)
    errors.extend(f"calibration: {error}" for error in CALIBRATION_VALIDATOR.validate_report(calibration))

    outcome = None
    if outcome_path is not None:
        if not outcome_path.exists():
            errors.append(f"outcome ledger does not exist: {outcome_path}")
            return errors
        outcome = load_json(outcome_path)
        errors.extend(f"outcome: {error}" for error in OUTCOME_VALIDATOR.validate_ledger(outcome))
    if errors:
        return errors

    route_groups = calibration.get("route_groups", {})
    outcomes = BASELINE_BUILDER.outcome_counts(outcome)

    for index, comparison in enumerate(report.get("comparisons", []), start=1):
        prefix = f"baseline comparisons[{index}]"
        if not isinstance(comparison, dict):
            continue
        target_route = comparison.get("target_route_group")
        baseline_route = comparison.get("baseline_route_group")
        if target_route not in route_groups:
            errors.append(f"{prefix} target_route_group is absent from calibration report")
            continue
        if baseline_route not in route_groups:
            errors.append(f"{prefix} baseline_route_group is absent from calibration report")
            continue
        if BASELINE_BUILDER.route_boundary(target_route) != BASELINE_BUILDER.route_boundary(baseline_route):
            errors.append(f"{prefix} target and baseline action boundaries differ")

        expected_target = BASELINE_BUILDER.copy_group_summary(route_groups[target_route])
        expected_baseline = BASELINE_BUILDER.copy_group_summary(route_groups[baseline_route])
        if comparison.get("target") != expected_target:
            errors.append(f"{prefix} target summary differs from calibration report")
        if comparison.get("baseline") != expected_baseline:
            errors.append(f"{prefix} baseline summary differs from calibration report")

        outcome_block = comparison.get("outcomes")
        if isinstance(outcome_block, dict):
            expected_target_outcome = outcomes.get(target_route, BASELINE_BUILDER.empty_outcome())
            expected_baseline_outcome = outcomes.get(baseline_route, BASELINE_BUILDER.empty_outcome())
            if outcome_block.get("target") != expected_target_outcome:
                errors.append(f"{prefix} target outcome summary differs from outcome ledger")
            if outcome_block.get("baseline") != expected_baseline_outcome:
                errors.append(f"{prefix} baseline outcome summary differs from outcome ledger")

    return errors


def validate_pairing_chain(pairing_path: Path) -> list[str]:
    errors: list[str] = []
    report = load_json(pairing_path)
    errors.extend(f"pairing: {error}" for error in PAIRING_VALIDATOR.validate_report(report))
    if errors:
        return errors

    try:
        expected = PAIRING_BUILDER.expected_report(pairing_path, report)
    except ValueError as exc:
        return [f"pairing: {exc}"]
    if report != expected:
        errors.append("route pairing report differs from referenced pair manifest and traces")

    manifest_path = resolve_ref(pairing_path, report.get("inputs", {}).get("pair_manifest_ref"))
    if manifest_path is None:
        errors.append("pairing pair_manifest_ref must be a local file reference")
        return errors
    if not manifest_path.exists():
        errors.append(f"pair manifest does not exist: {manifest_path}")
        return errors

    manifest = load_json(manifest_path)
    errors.extend(f"pair_manifest: {error}" for error in PAIR_MANIFEST_VALIDATOR.BUILDER.validate_pair_manifest(manifest))
    if errors:
        return errors

    if manifest.get("experiment_id") != report.get("experiment_id"):
        errors.append("pairing report experiment_id differs from pair manifest")
    if manifest.get("route_group") != report.get("route_group"):
        errors.append("pairing report route_group differs from pair manifest")
    if manifest.get("baseline_route_group") != report.get("baseline_route_group"):
        errors.append("pairing report baseline_route_group differs from pair manifest")
    if manifest.get("action_boundary") != report.get("action_boundary"):
        errors.append("pairing report action_boundary differs from pair manifest")

    return errors


def validate_execution_chain(execution_path: Path) -> list[str]:
    errors: list[str] = []
    report = load_json(execution_path)
    errors.extend(f"execution: {error}" for error in EXECUTION_VALIDATOR.validate_report(report))
    if errors:
        return errors

    try:
        expected = EXECUTION_BUILDER.expected_report(execution_path, report)
    except ValueError as exc:
        return [f"execution: {exc}"]
    if report != expected:
        errors.append("route execution report differs from referenced Action Packets")

    for index, packet_summary in enumerate(report.get("packet_summaries", []), start=1):
        prefix = f"execution packet_summaries[{index}]"
        if not isinstance(packet_summary, dict):
            continue
        packet_path = resolve_ref(execution_path, packet_summary.get("packet_ref"))
        if packet_path is None or not packet_path.exists():
            errors.append(f"{prefix} packet_ref does not exist: {packet_summary.get('packet_ref')}")
            continue
        try:
            packet = ACTION_PACKET_VALIDATOR.load_packet(packet_path)
        except ValueError as exc:
            errors.append(f"{prefix} packet_ref cannot be loaded: {exc}")
            continue
        packet_errors = ACTION_PACKET_VALIDATOR.validate_packet(packet, base_dir=packet_path.parent)
        errors.extend(f"{prefix} packet_ref: {error}" for error in packet_errors)

    return errors


def validate_experiment_review_chain(review_path: Path) -> list[str]:
    errors: list[str] = []
    report = load_json(review_path)
    errors.extend(f"experiment_review: {error}" for error in EXPERIMENT_REVIEW_VALIDATOR.validate_report(report))
    if errors:
        return errors

    try:
        expected = EXPERIMENT_REVIEW_BUILDER.expected_review(review_path, report)
    except ValueError as exc:
        return [f"experiment_review: {exc}"]
    if report != expected:
        errors.append("route experiment review differs from referenced manifest and reports")

    inputs = report.get("inputs", {})
    calibration_path = resolve_ref(review_path, inputs.get("calibration_report_ref"))
    outcome_path = resolve_ref(review_path, inputs.get("outcome_ledger_ref"))
    baseline_path = resolve_ref(review_path, inputs.get("baseline_report_ref"))
    pairing_path = resolve_ref(review_path, inputs.get("pairing_report_ref"))
    if baseline_path is not None:
        errors.extend(validate_baseline_chain(baseline_path))
    if pairing_path is not None:
        errors.extend(validate_pairing_chain(pairing_path))
        if pairing_path.exists():
            pairing = load_json(pairing_path)
            if pairing.get("experiment_id") != report.get("experiment_id"):
                errors.append("experiment review pairing report experiment_id differs from review")
            if pairing.get("route_group") != report.get("route_group"):
                errors.append("experiment review pairing report route_group differs from review")
            if pairing.get("action_boundary") != report.get("action_boundary"):
                errors.append("experiment review pairing report action_boundary differs from review")
    if calibration_path is not None and calibration_path.exists():
        calibration = load_json(calibration_path)
        errors.extend(f"calibration: {error}" for error in CALIBRATION_VALIDATOR.validate_report(calibration))
    if outcome_path is not None and outcome_path.exists():
        outcome = load_json(outcome_path)
        errors.extend(f"outcome: {error}" for error in OUTCOME_VALIDATOR.validate_ledger(outcome))
    return errors


def validate_proposal_chain(proposal_path: Path) -> list[str]:
    errors: list[str] = []
    proposal = load_json(proposal_path)
    errors.extend(f"proposal: {error}" for error in PROPOSAL_VALIDATOR.validate_report(proposal))
    if errors:
        return errors

    policy_path = resolve_ref(proposal_path, proposal["inputs"]["route_policy_report_ref"])
    assert policy_path is not None
    if not policy_path.exists():
        errors.append(f"route policy report does not exist: {policy_path}")
        return errors

    policy = load_json(policy_path)
    policy_errors = POLICY_VALIDATOR.validate_report(policy)
    errors.extend(f"policy: {error}" for error in policy_errors)
    if errors:
        return errors

    expected = PROPOSAL_BUILDER.expected_proposal(policy, proposal["inputs"]["route_policy_report_ref"])
    if proposal != expected:
        errors.append("route change proposal differs from referenced route policy report")

    errors.extend(validate_policy_chain(policy_path))
    return errors


def validate_chain(path: Path) -> list[str]:
    artifact = load_json(path)
    if artifact.get("proposal_version") == "1.0":
        return validate_proposal_chain(path)
    if artifact.get("policy_report_version") == "1.0":
        return validate_policy_chain(path)
    if artifact.get("baseline_report_version") == "1.0":
        return validate_baseline_chain(path)
    if artifact.get("pairing_report_version") == "1.0":
        return validate_pairing_chain(path)
    if artifact.get("execution_report_version") == CONTRACTS.ROUTE_EXECUTION_REPORT_VERSION:
        return validate_execution_chain(path)
    if artifact.get("review_version") == "1.0":
        return validate_experiment_review_chain(path)
    return ["root artifact must be a route change proposal, route policy report, route baseline report, route pairing report, route execution report, or route experiment review"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a HIGHBALL evidence chain from a route proposal, policy, or baseline report")
    parser.add_argument("root_report", type=Path)
    args = parser.parse_args()

    try:
        errors = validate_chain(args.root_report.resolve())
    except ValueError as exc:
        print(f"[HIGHBALL] ERROR: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"[HIGHBALL] ERROR: {error}", file=sys.stderr)
        return 2

    print("[HIGHBALL] evidence chain valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
