//! Build and validate fail-closed HIGHBALL Action Packets.

use crate::contracts::{
    action_binding_sha256, is_digest, summarize_authorization_artifact, ACTION_PACKET_VERSION,
    QUINTE_HOST_RECEIPT_VERSION, RESIDUAL_TRACE_VERSION,
};
use crate::jsonutil::{candidate_blocks, is_string_list_min, load_object};
use crate::measure::{load_traces, measure_trace};
use crate::product::build_product_evidence;
use crate::route::{route_request, validate_request};
use crate::trace::validate_trace;
use serde_json::{json, Value};
use std::path::Path;

const TOP_LEVEL_FIELDS: &[&str] = &[
    "packet_version",
    "route_request",
    "route_decision",
    "trace",
    "validation",
    "quality",
    "product_evidence",
    "authorization",
    "action_decision",
    "decision_reasons",
    "required_next_steps",
];
const ROUTE_DECISION_FIELDS: &[&str] = &[
    "route",
    "reason",
    "required_artifacts",
    "residual_trace_required",
    "authorization_required",
];
const VALIDATION_FIELDS: &[&str] = &["status", "errors", "blocks"];
const QUALITY_FIELDS: &[&str] = &[
    "question",
    "instrument",
    "action_boundary",
    "highball_decision",
    "residual_count",
    "high_risk_count",
    "action_blocking_count",
    "open_high_risk_count",
    "unsupported_high_risk_closure_count",
    "silent_collapse_count",
    "unresolved_count",
    "decision_conflict_count",
    "evidence_coverage",
    "closure_evidence_coverage",
    "action_blocking_closure_coverage",
    "trial_manifest_present",
    "base_model_relation",
    "perspective_count",
    "independent_first_pass_count",
    "perturbation_axis_count",
    "independence_control_count",
    "contamination_risk_count",
    "same_model_flag",
    "cost_fields_present",
    "quality_gate",
    "warnings",
];
const PRODUCT_EVIDENCE_FIELDS: &[&str] = &["required", "status", "binding", "product", "errors"];
const AUTHORIZATION_FIELDS: &[&str] = &[
    "required",
    "status",
    "artifact_ref",
    "artifact_sha256",
    "authorization_id",
    "action_binding_sha256",
    "action_scope",
    "issued_at",
    "expires_at",
    "errors",
];
const PRODUCT_OUTCOME_FIELDS: &[&str] = &[
    "product_ref",
    "product_kind",
    "product_version",
    "product_sha256",
    "product_id",
    "status",
    "decision",
    "question",
    "action_scope",
    "affected_paths",
    "action_binding_sha256",
    "host_receipt_ref",
    "host_receipt_sha256",
    "host_receipt_operation",
];
const REQUIRED_PRODUCT_OUTCOME_FIELDS: &[&str] = &[
    "product_ref",
    "product_kind",
    "product_version",
    "product_sha256",
    "product_id",
    "status",
    "decision",
    "question",
    "action_scope",
    "affected_paths",
    "action_binding_sha256",
];
const ROUTES: &[&str] = &["direct-evidence", "QUINTE", "human-review", "block"];
const DECISIONS: &[&str] = &["pass", "review", "block"];
const VALIDATION_STATUSES: &[&str] = &["valid", "blocked", "invalid"];
const EXECUTION_STATUSES: &[&str] =
    &["not_required", "missing", "complete", "blocked", "degraded", "invalid"];
const BINDINGS: &[&str] = &["atomic_quinte_product", "not_applicable"];

fn route_instrument(route: &str) -> Option<&'static str> {
    match route {
        "direct-evidence" => Some("direct-evidence"),
        "QUINTE" => Some("QUINTE"),
        "human-review" => Some("human"),
        _ => None,
    }
}

pub fn validate_trace_status(trace: &Value) -> Value {
    let findings = validate_trace(trace, 1);
    let errors: Vec<String> = findings
        .iter()
        .filter(|f| f.severity == "ERROR")
        .map(|f| f.to_string())
        .collect();
    let blocks: Vec<String> = findings
        .iter()
        .filter(|f| f.severity == "BLOCK")
        .map(|f| f.to_string())
        .collect();
    let status = if !errors.is_empty() {
        "invalid"
    } else if !blocks.is_empty() {
        "blocked"
    } else {
        "valid"
    };
    json!({"status": status, "errors": errors, "blocks": blocks})
}

pub fn decide(
    request: &Value,
    route_decision: &Value,
    trace: &Value,
    validation: &Value,
    quality: &Value,
    product_evidence: &Value,
    authorization: &Value,
) -> (String, Vec<String>, Vec<String>) {
    let mut decision = "pass".to_string();
    let mut reasons = Vec::new();
    let mut next_steps = Vec::new();
    let apply_block = |decision: &mut String, reasons: &mut Vec<String>, next_steps: &mut Vec<String>, reason: String, step: String| {
        *decision = "block".into();
        reasons.push(reason);
        next_steps.push(step);
    };
    let apply_review = |decision: &mut String, reasons: &mut Vec<String>, next_steps: &mut Vec<String>, reason: String, step: String| {
        if decision.as_str() != "block" {
            *decision = "review".into();
        }
        reasons.push(reason);
        next_steps.push(step);
    };
    let route = route_decision.get("route").and_then(Value::as_str).unwrap_or("");
    match validation.get("status").and_then(Value::as_str) {
        Some("invalid") => apply_block(
            &mut decision, &mut reasons, &mut next_steps,
            "trace has structural validation errors".into(),
            "produce a schema-compatible residual trace".into(),
        ),
        Some("blocked") => apply_block(
            &mut decision, &mut reasons, &mut next_steps,
            "trace contains validator block findings".into(),
            "resolve the trace's blocking decision or residuals".into(),
        ),
        _ => {}
    }
    if route == "block" {
        apply_block(
            &mut decision, &mut reasons, &mut next_steps,
            "route decision is block".into(),
            "record the block or provide corrected evidence".into(),
        );
    }
    let execution_status = product_evidence.get("status").and_then(Value::as_str).unwrap_or("");
    if product_evidence.get("required") == Some(&Value::Bool(true)) && execution_status != "complete"
    {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            format!("required atomic {route} product outcome is {execution_status}"),
            format!("attach a current, completed, request-bound {route} product"),
        );
    } else if matches!(execution_status, "invalid" | "blocked" | "degraded") {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            format!("{route} product outcome is {execution_status}"),
            format!("repair or regenerate the bound {route} product outcome"),
        );
    }
    if execution_status == "complete" {
        if let Some(product) = product_evidence.get("product").filter(|p| p.is_object()) {
            let product_decision = product.get("decision").and_then(Value::as_str).unwrap_or("");
            if product_decision != "PASS" {
                apply_block(&mut decision, &mut reasons, &mut next_steps,
                    format!(
                        "{} product decision is {product_decision}",
                        product
                            .get("product_kind")
                            .and_then(Value::as_str)
                            .unwrap_or(route)
                    ),
                    "resolve the product's block or escalation before action".into(),
                );
            }
        }
    }
    if matches!(
        trace.get("highball_decision").and_then(Value::as_str),
        Some("block" | "escalate")
    ) {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            format!(
                "trace highball_decision is {}",
                trace.get("highball_decision").and_then(Value::as_str).unwrap()
            ),
            "resolve the upstream block or escalation before action".into(),
        );
    }
    match quality.get("quality_gate").and_then(Value::as_str) {
        Some("block") => apply_block(&mut decision, &mut reasons, &mut next_steps,
            "quality gate is block".into(),
            "resolve open or unsupported action-blocking residuals".into(),
        ),
        Some("review") => apply_review(&mut decision, &mut reasons, &mut next_steps,
            "quality gate is review".into(),
            "add evidence, closure evidence, scope, or human review".into(),
        ),
        _ => {}
    }
    if let Some(expected) = route_instrument(route) {
        if trace.get("instrument").and_then(Value::as_str) != Some(expected) {
            apply_block(&mut decision, &mut reasons, &mut next_steps,
                format!(
                    "route {route} expects trace instrument {expected}, got {}",
                    trace
                        .get("instrument")
                        .and_then(Value::as_str)
                        .unwrap_or("null")
                ),
                "produce a trace from the selected route or reroute the action".into(),
            );
        }
    }
    if request.get("question") != trace.get("question") {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            "route request question differs from trace question".into(),
            "produce a trace bound to this question".into(),
        );
    }
    if request.get("action_boundary") != trace.get("action_boundary") {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            "route request boundary differs from trace boundary".into(),
            "produce a trace scoped to the requested action boundary".into(),
        );
    }
    if trace.get("trace_version").and_then(Value::as_str) != Some(RESIDUAL_TRACE_VERSION) {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            "trace contract version is not active".into(),
            "produce an active residual trace contract".into(),
        );
    }
    if trace.get("action_binding_sha256").and_then(Value::as_str)
        != Some(action_binding_sha256(request).as_str())
    {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            "trace action binding differs from the route request".into(),
            "bind the trace to this action".into(),
        );
    }
    if route_decision.get("authorization_required") == Some(&Value::Bool(true))
        && authorization.get("status").and_then(Value::as_str) != Some("authorized")
    {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            format!(
                "required authorization is {}",
                authorization.get("status").and_then(Value::as_str).unwrap_or("null")
            ),
            "attach a current, user-issued, action-bound authorization artifact".into(),
        );
    } else if authorization.get("status").and_then(Value::as_str) == Some("invalid") {
        apply_block(&mut decision, &mut reasons, &mut next_steps,
            "authorization is invalid".into(),
            "replace the invalid authorization artifact".into(),
        );
    }
    if reasons.is_empty() {
        reasons.push("route, trace, product evidence, and authorization are consistent".into());
    }
    (decision, reasons, next_steps)
}

pub fn build_packet(
    request_path: &Path,
    trace_path: &Path,
    quinte_results: &[std::path::PathBuf],
    authorization: Option<&Path>,
    quinte_receipts: &[std::path::PathBuf],
) -> Result<Value, String> {
    let request = load_object(request_path)?;
    let errors = validate_request(&request);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let route_decision = route_request(&request);
    let traces = load_traces(trace_path)?;
    if traces.len() != 1 {
        return Err("action packet requires exactly one residual trace".into());
    }
    let trace = traces.into_iter().next().unwrap();
    let validation = validate_trace_status(&trace);
    let quality = measure_trace(&trace);
    let result_refs: Vec<String> = quinte_results
        .iter()
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()).display().to_string())
        .collect();
    let receipt_refs: Vec<String> = quinte_receipts
        .iter()
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()).display().to_string())
        .collect();
    let product_evidence = build_product_evidence(
        &request,
        &route_decision,
        &result_refs,
        None,
        &receipt_refs,
    );
    let auth = summarize_authorization_artifact(
        authorization.map(|p| {
            std::fs::canonicalize(p)
                .unwrap_or_else(|_| p.to_path_buf())
                .display()
                .to_string()
        })
        .as_deref(),
        &request,
        None,
        route_decision
            .get("authorization_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let (action_decision, reasons, next_steps) = decide(
        &request,
        &route_decision,
        &trace,
        &validation,
        &quality,
        &product_evidence,
        &auth,
    );
    Ok(json!({
        "packet_version": ACTION_PACKET_VERSION,
        "route_request": request,
        "route_decision": route_decision,
        "trace": trace,
        "validation": validation,
        "quality": quality,
        "product_evidence": product_evidence,
        "authorization": auth,
        "action_decision": action_decision,
        "decision_reasons": reasons,
        "required_next_steps": next_steps,
    }))
}

pub fn load_packet(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (blocks, raw_json_mode) = candidate_blocks(&text, path);
    if blocks.is_empty() {
        return Err("no JSON Action Packet found".into());
    }
    let mut packets = Vec::new();
    let mut errors = Vec::new();
    for (block_number, block) in blocks {
        match serde_json::from_str::<Value>(&block) {
            Ok(parsed)
                if parsed.get("packet_version").and_then(Value::as_str) == Some(ACTION_PACKET_VERSION) =>
            {
                packets.push(parsed);
            }
            Ok(_) => {}
            Err(exc) => {
                let label = if raw_json_mode {
                    "raw JSON".into()
                } else {
                    format!("JSON block {block_number}")
                };
                errors.push(format!("{label} is invalid JSON: {exc}"));
            }
        }
    }
    if packets.len() != 1 {
        let detail = if errors.is_empty() {
            format!("found {} Action Packets", packets.len())
        } else {
            errors.join("; ")
        };
        return Err(format!("expected exactly one Action Packet; {detail}"));
    }
    Ok(packets.remove(0))
}

fn field_errors(obj: &Value, allowed: &[&str], prefix: &str, errors: &mut Vec<String>) {
    let have: std::collections::BTreeSet<&str> = obj
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let allowed_set: std::collections::BTreeSet<&str> = allowed.iter().copied().collect();
    let unknown: Vec<_> = have.difference(&allowed_set).copied().collect();
    let missing: Vec<_> = allowed_set.difference(&have).copied().collect();
    if !unknown.is_empty() {
        errors.push(format!("{prefix} unknown fields: {}", unknown.join(", ")));
    }
    if !missing.is_empty() {
        errors.push(format!("{prefix} missing fields: {}", missing.join(", ")));
    }
}

pub fn validate_shape(packet: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if !packet.is_object() {
        return vec!["Action Packet must be a JSON object".into()];
    }
    let have: std::collections::BTreeSet<&str> = packet
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let allowed: std::collections::BTreeSet<&str> = TOP_LEVEL_FIELDS.iter().copied().collect();
    let unknown: Vec<_> = have.difference(&allowed).copied().collect();
    let missing: Vec<_> = allowed.difference(&have).copied().collect();
    if !unknown.is_empty() {
        errors.push(format!("unknown top-level fields: {}", unknown.join(", ")));
    }
    if !missing.is_empty() {
        errors.push(format!("missing top-level fields: {}", missing.join(", ")));
    }
    if packet.get("packet_version").and_then(Value::as_str) != Some(ACTION_PACKET_VERSION) {
        errors.push(format!("packet_version must be {ACTION_PACKET_VERSION}"));
    }
    match packet.get("route_request") {
        Some(req) if req.is_object() => {
            for e in validate_request(req) {
                errors.push(format!("route_request: {e}"));
            }
        }
        _ => errors.push("route_request must be an object".into()),
    }
    match packet.get("route_decision") {
        Some(rd) if rd.is_object() => {
            field_errors(rd, ROUTE_DECISION_FIELDS, "route_decision", &mut errors);
            if !ROUTES.contains(&rd.get("route").and_then(Value::as_str).unwrap_or("")) {
                errors.push("route_decision.route is invalid".into());
            }
            if !is_string_list_min(rd.get("reason"), 0) {
                errors.push("route_decision.reason must be an array of strings".into());
            }
            if !is_string_list_min(rd.get("required_artifacts"), 0) {
                errors.push("route_decision.required_artifacts must be an array of strings".into());
            }
            if !rd.get("residual_trace_required").map(Value::is_boolean).unwrap_or(false) {
                errors.push("route_decision.residual_trace_required must be boolean".into());
            }
            if !rd.get("authorization_required").map(Value::is_boolean).unwrap_or(false) {
                errors.push("route_decision.authorization_required must be boolean".into());
            }
        }
        _ => errors.push("route_decision must be an object".into()),
    }
    match packet.get("trace") {
        Some(tr) if tr.is_object() => {
            for item in validate_trace(tr, 1) {
                if item.severity == "ERROR" {
                    errors.push(format!("trace: {item}"));
                }
            }
        }
        _ => errors.push("trace must be an object".into()),
    }
    match packet.get("validation") {
        Some(v) if v.is_object() => {
            field_errors(v, VALIDATION_FIELDS, "validation", &mut errors);
            if !VALIDATION_STATUSES.contains(&v.get("status").and_then(Value::as_str).unwrap_or("")) {
                errors.push("validation.status is invalid".into());
            }
            if !is_string_list_min(v.get("errors"), 0) {
                errors.push("validation.errors must be an array of strings".into());
            }
            if !is_string_list_min(v.get("blocks"), 0) {
                errors.push("validation.blocks must be an array of strings".into());
            }
        }
        _ => errors.push("validation must be an object".into()),
    }
    match packet.get("quality") {
        Some(q) if q.is_object() => field_errors(q, QUALITY_FIELDS, "quality", &mut errors),
        _ => errors.push("quality must be an object".into()),
    }
    match packet.get("product_evidence") {
        Some(ex) if ex.is_object() => {
            field_errors(ex, PRODUCT_EVIDENCE_FIELDS, "product_evidence", &mut errors);
            if !ex.get("required").map(Value::is_boolean).unwrap_or(false) {
                errors.push("product_evidence.required must be boolean".into());
            }
            if !EXECUTION_STATUSES.contains(&ex.get("status").and_then(Value::as_str).unwrap_or("")) {
                errors.push("product_evidence.status is invalid".into());
            }
            if !BINDINGS.contains(&ex.get("binding").and_then(Value::as_str).unwrap_or("")) {
                errors.push("product_evidence.binding is invalid".into());
            }
            if let Some(outcome) = ex.get("product") {
                if !outcome.is_null() {
                    if !outcome.is_object() {
                        errors.push("product_evidence.product must be an object or null".into());
                    } else {
                        let have: std::collections::BTreeSet<&str> = outcome
                            .as_object()
                            .unwrap()
                            .keys()
                            .map(String::as_str)
                            .collect();
                        let allowed: std::collections::BTreeSet<&str> =
                            PRODUCT_OUTCOME_FIELDS.iter().copied().collect();
                        let required: std::collections::BTreeSet<&str> =
                            REQUIRED_PRODUCT_OUTCOME_FIELDS.iter().copied().collect();
                        let unknown: Vec<_> = have.difference(&allowed).copied().collect();
                        let missing: Vec<_> = required.difference(&have).copied().collect();
                        if !unknown.is_empty() {
                            errors.push(format!(
                                "product_evidence.product unknown fields: {}",
                                unknown.join(", ")
                            ));
                        }
                        if !missing.is_empty() {
                            errors.push(format!(
                                "product_evidence.product missing fields: {}",
                                missing.join(", ")
                            ));
                        }
                        for field in [
                            "product_ref",
                            "product_kind",
                            "product_version",
                            "product_id",
                            "status",
                            "decision",
                        ] {
                            if !matches!(outcome.get(field).and_then(Value::as_str), Some(s) if !s.trim().is_empty())
                            {
                                errors.push(format!(
                                    "product_evidence.product.{field} must be a non-empty string"
                                ));
                            }
                        }
                        match outcome.get("product_kind").and_then(Value::as_str) {
                            Some("QUINTE") => {
                                if outcome.get("decision").and_then(Value::as_str) != Some("PASS") {
                                    errors.push("QUINTE product decision must be PASS".into());
                                }
                            }
                            _ => errors.push("product_evidence.product.product_kind is invalid".into()),
                        }
                        for field in ["product_sha256", "action_binding_sha256"] {
                            if !is_digest(outcome.get(field)) {
                                errors.push(format!("product_evidence.product.{field} is invalid"));
                            }
                        }
                        let provenance = [
                            "host_receipt_ref",
                            "host_receipt_sha256",
                            "host_receipt_operation",
                        ];
                        let present: Vec<_> = provenance
                            .iter()
                            .filter(|f| outcome.get(**f).is_some())
                            .collect();
                        if !present.is_empty() && present.len() != provenance.len() {
                            errors.push(
                                "product_evidence.product host receipt provenance must be complete"
                                    .into(),
                            );
                        }
                        if outcome.get("product_kind").and_then(Value::as_str) != Some("QUINTE")
                            && !present.is_empty()
                        {
                            errors.push("host receipt provenance is only valid for a QUINTE product".into());
                        }
                        if outcome.get("host_receipt_ref").is_some()
                            && !matches!(
                                outcome.get("host_receipt_ref").and_then(Value::as_str),
                                Some(s) if !s.trim().is_empty()
                            )
                        {
                            errors.push("product_evidence.product.host_receipt_ref must be non-empty".into());
                        }
                        if outcome.get("host_receipt_sha256").is_some()
                            && !is_digest(outcome.get("host_receipt_sha256"))
                        {
                            errors.push("product_evidence.product.host_receipt_sha256 is invalid".into());
                        }
                        if outcome.get("host_receipt_operation").is_some()
                            && !matches!(
                                outcome.get("host_receipt_operation").and_then(Value::as_str),
                                Some("inspect" | "reconcile")
                            )
                        {
                            errors.push(
                                "product_evidence.product.host_receipt_operation must be inspect or reconcile"
                                    .into(),
                            );
                        }
                        if !matches!(
                            outcome.get("question").and_then(Value::as_str),
                            Some(s) if !s.trim().is_empty()
                        ) {
                            errors.push(
                                "product_evidence.product.question must be a non-empty string".into(),
                            );
                        }
                        if let Some(s) = outcome.get("action_scope") {
                            if !s.is_null() && !s.is_string() {
                                errors.push(
                                    "product_evidence.product.action_scope must be a string or null"
                                        .into(),
                                );
                            }
                        }
                        if !is_string_list_min(outcome.get("affected_paths"), 0) {
                            errors.push(
                                "product_evidence.product.affected_paths must be an array of strings"
                                    .into(),
                            );
                        }
                    }
                }
            }
            if !is_string_list_min(ex.get("errors"), 0) {
                errors.push("product_evidence.errors must be an array of strings".into());
            }
        }
        _ => errors.push("product_evidence must be an object".into()),
    }
    match packet.get("authorization") {
        Some(a) if a.is_object() => {
            field_errors(a, AUTHORIZATION_FIELDS, "authorization", &mut errors);
            if !a.get("required").map(Value::is_boolean).unwrap_or(false) {
                errors.push("authorization.required must be boolean".into());
            }
            if !matches!(
                a.get("status").and_then(Value::as_str),
                Some("not_required" | "missing" | "authorized" | "invalid")
            ) {
                errors.push("authorization.status is invalid".into());
            }
            for field in [
                "artifact_ref",
                "artifact_sha256",
                "authorization_id",
                "action_binding_sha256",
                "action_scope",
                "issued_at",
                "expires_at",
            ] {
                if let Some(v) = a.get(field) {
                    if !v.is_null() && !v.is_string() {
                        errors.push(format!("authorization.{field} must be a string or null"));
                    }
                }
            }
            if !is_string_list_min(a.get("errors"), 0) {
                errors.push("authorization.errors must be an array of strings".into());
            }
        }
        _ => errors.push("authorization must be an object".into()),
    }
    if !DECISIONS.contains(&packet.get("action_decision").and_then(Value::as_str).unwrap_or("")) {
        errors.push("action_decision is invalid".into());
    }
    if !is_string_list_min(packet.get("decision_reasons"), 1) {
        errors.push("decision_reasons must be a non-empty array of strings".into());
    }
    if !is_string_list_min(packet.get("required_next_steps"), 0) {
        errors.push("required_next_steps must be an array of strings".into());
    }
    let _ = QUINTE_HOST_RECEIPT_VERSION;
    errors
}

pub fn validate_consistency(packet: &Value, base_dir: Option<&Path>) -> Vec<String> {
    let mut errors = Vec::new();
    let request = &packet["route_request"];
    let route_decision = &packet["route_decision"];
    let trace = &packet["trace"];
    let validation = &packet["validation"];
    let quality = &packet["quality"];
    let product_evidence = &packet["product_evidence"];
    let authorization = &packet["authorization"];
    let expected_route = route_request(request);
    if route_decision != &expected_route {
        errors.push("route_decision does not match route_request".into());
    }
    let expected_validation = validate_trace_status(trace);
    if validation != &expected_validation {
        errors.push("validation does not match derived trace validation".into());
    }
    let expected_quality = measure_trace(trace);
    if quality != &expected_quality {
        errors.push("quality does not match derived residual trace metrics".into());
    }
    let mut result_refs = Vec::new();
    let mut receipt_refs = Vec::new();
    if let Some(outcome) = product_evidence.get("product").filter(|p| p.is_object()) {
        if let Some(r#ref) = outcome.get("product_ref").and_then(Value::as_str) {
            match outcome.get("product_kind").and_then(Value::as_str) {
                Some("QUINTE") => {
                    if let Some(rr) = outcome.get("host_receipt_ref").and_then(Value::as_str) {
                        if !rr.is_empty() {
                            receipt_refs.push(rr.to_string());
                        } else {
                            result_refs.push(r#ref.to_string());
                        }
                    } else {
                        result_refs.push(r#ref.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let expected_execution = build_product_evidence(
        request,
        route_decision,
        &result_refs,
        base_dir,
        &receipt_refs,
    );
    if product_evidence != &expected_execution {
        errors.push("product_evidence does not match derived product evidence".into());
    }
    let expected_auth = summarize_authorization_artifact(
        authorization.get("artifact_ref").and_then(Value::as_str),
        request,
        base_dir,
        route_decision
            .get("authorization_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    if authorization != &expected_auth {
        errors.push("authorization does not match the bound authorization artifact".into());
    }
    let (action_decision, decision_reasons, required_next_steps) = decide(
        request,
        route_decision,
        trace,
        validation,
        quality,
        product_evidence,
        authorization,
    );
    if packet.get("action_decision").and_then(Value::as_str) != Some(action_decision.as_str()) {
        errors.push("action_decision does not match derived packet decision".into());
    }
    let reasons_v = json!(decision_reasons);
    if packet.get("decision_reasons") != Some(&reasons_v) {
        errors.push("decision_reasons do not match derived packet reasons".into());
    }
    let steps_v = json!(required_next_steps);
    if packet.get("required_next_steps") != Some(&steps_v) {
        errors.push("required_next_steps do not match derived packet next steps".into());
    }
    errors
}

pub fn validate_packet(packet: &Value, base_dir: Option<&Path>) -> Vec<String> {
    let shape = validate_shape(packet);
    if !shape.is_empty() {
        return shape;
    }
    validate_consistency(packet, base_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decide_blocks_missing_required_product() {
        let request = json!({"question":"q","action_boundary":"none"});
        let route = json!({"route":"QUINTE","authorization_required":false});
        let trace = json!({
            "question":"q",
            "action_boundary":"none",
            "instrument":"QUINTE",
            "trace_version":"1.1",
            "action_binding_sha256": crate::contracts::action_binding_sha256(&json!({
                "question":"q","action_boundary":"none","change_class":null,"affected_paths":null
            })),
            "highball_decision":"pass",
        });
        let validation = json!({"status":"valid","errors":[],"blocks":[]});
        let quality = json!({"quality_gate":"pass"});
        let product = json!({"required":true,"status":"missing","product":null});
        let auth = json!({"status":"not_required"});
        let (d, reasons, _) = decide(&request, &route, &trace, &validation, &quality, &product, &auth);
        assert_eq!(d, "block");
        assert!(reasons.iter().any(|r| r.contains("required atomic QUINTE")));
    }
}
