//! Build and validate route execution reports from Action Packets.

use crate::contracts::ROUTE_EXECUTION_REPORT_VERSION;
use crate::jsonutil::{candidate_blocks, is_string_list_min};
use crate::packet::{load_packet, validate_packet};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const NON_AUTHORIZATION: &str =
    "Route execution reports do not authorize action, dispatch agents, or modify routing rules.";

const TOP_LEVEL_FIELDS: &[&str] = &[
    "execution_report_version",
    "route_group",
    "inputs",
    "packet_count",
    "required_execution_count",
    "complete_count",
    "missing_count",
    "blocked_count",
    "degraded_count",
    "invalid_count",
    "not_required_count",
    "completion_rate",
    "execution_gate",
    "packet_summaries",
    "invalid_packet_refs",
    "out_of_scope_packet_refs",
    "decision_reasons",
    "non_authorization",
];
const PACKET_SUMMARY_FIELDS: &[&str] = &[
    "packet_ref",
    "route_group",
    "route",
    "trace_instrument",
    "action_boundary",
    "action_decision",
    "execution_required",
    "execution_status",
    "product_kind",
    "product_id",
    "product_sha256",
    "action_binding_sha256",
    "errors",
];
const INVALID_REF_FIELDS: &[&str] = &["packet_ref", "reason"];
const EXECUTION_STATUSES: &[&str] =
    &["not_required", "missing", "complete", "blocked", "degraded", "invalid"];
const EXECUTION_GATES: &[&str] = &["accepted", "watch", "reroute", "block", "insufficient"];

fn resolve_ref(base_file: Option<&Path>, r#ref: &str) -> Option<PathBuf> {
    if r#ref.contains("://") {
        return None;
    }
    let path = PathBuf::from(r#ref);
    if path.is_absolute() {
        return Some(std::fs::canonicalize(&path).unwrap_or(path));
    }
    base_file.map(|b| std::fs::canonicalize(b.parent().unwrap_or(Path::new(".")).join(&path)).unwrap_or_else(|_| b.parent().unwrap_or(Path::new(".")).join(&path)))
}

fn route_group_from_trace(trace: &Value) -> String {
    let relation = trace
        .get("trial_manifest")
        .and_then(|m| m.get("base_model_relation"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let instrument = trace.get("instrument").and_then(Value::as_str).unwrap_or("unknown");
    let boundary = trace.get("action_boundary").and_then(Value::as_str).unwrap_or("unknown");
    format!("{instrument}:{relation}:{boundary}")
}

pub fn completion_rate(complete_count: i64, required_count: i64) -> Value {
    if required_count == 0 {
        Value::Null
    } else {
        json!(((complete_count as f64) / (required_count as f64) * 10000.0).round() / 10000.0)
    }
}

fn summarize_packet(packet_ref: &str, packet_path: &Path) -> Result<Value, Vec<String>> {
    let packet = load_packet(packet_path).map_err(|e| vec![format!("action packet cannot be loaded: {packet_ref}: {e}")])?;
    let packet_errors = validate_packet(&packet, Some(packet_path.parent().unwrap_or(Path::new("."))));
    let trace = packet.get("trace").filter(|t| t.is_object()).cloned().unwrap_or(json!({}));
    let route_decision = packet
        .get("route_decision")
        .filter(|t| t.is_object())
        .cloned()
        .unwrap_or(json!({}));
    let execution = packet
        .get("product_evidence")
        .filter(|t| t.is_object())
        .cloned()
        .unwrap_or(json!({}));
    let mut status = execution
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("invalid")
        .to_string();
    if !packet_errors.is_empty() {
        status = "invalid".into();
    }
    let outcome = execution
        .get("product")
        .filter(|p| p.is_object())
        .cloned()
        .unwrap_or(json!({}));
    let mut all_errors = packet_errors;
    if let Some(arr) = execution.get("errors").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                all_errors.push(s.to_string());
            }
        }
    }
    Ok(json!({
        "packet_ref": packet_ref,
        "route_group": route_group_from_trace(&trace),
        "route": route_decision.get("route").and_then(Value::as_str).unwrap_or("unknown"),
        "trace_instrument": trace.get("instrument").and_then(Value::as_str).unwrap_or("unknown"),
        "action_boundary": trace.get("action_boundary").and_then(Value::as_str).unwrap_or("unknown"),
        "action_decision": packet.get("action_decision").and_then(Value::as_str).unwrap_or("unknown"),
        "execution_required": execution.get("required") == Some(&Value::Bool(true)),
        "execution_status": status,
        "product_kind": outcome.get("product_kind").and_then(Value::as_str),
        "product_id": outcome.get("product_id").and_then(Value::as_str),
        "product_sha256": outcome.get("product_sha256").and_then(Value::as_str),
        "action_binding_sha256": outcome.get("action_binding_sha256").and_then(Value::as_str),
        "errors": all_errors,
    }))
}

pub fn derive_gate(summary: &Value) -> &'static str {
    let required_count = summary["required_execution_count"].as_i64().unwrap_or(0);
    if summary["packet_count"].as_i64().unwrap_or(0) == 0 || required_count == 0 {
        return "insufficient";
    }
    if summary["invalid_count"].as_i64().unwrap_or(0) > 0
        || summary["blocked_count"].as_i64().unwrap_or(0) > 0
    {
        return "block";
    }
    if summary["degraded_count"].as_i64().unwrap_or(0) > 0 {
        return "reroute";
    }
    match summary.get("completion_rate") {
        Some(Value::Null) | None => "insufficient",
        Some(v) => {
            let rate = v.as_f64().unwrap_or(0.0);
            if rate < 0.8 {
                "reroute"
            } else if rate < 1.0 || summary["missing_count"].as_i64().unwrap_or(0) > 0 {
                "watch"
            } else {
                "accepted"
            }
        }
    }
}

fn decision_reasons(summary: &Value, gate: &str) -> Vec<String> {
    let mut reasons = vec![
        format!(
            "required execution packets: {}",
            summary["required_execution_count"]
        ),
        format!("complete execution packets: {}", summary["complete_count"]),
        format!("completion rate: {}", summary["completion_rate"]),
        format!("execution gate: {gate}"),
    ];
    if summary["missing_count"].as_i64().unwrap_or(0) > 0 {
        reasons.push("one or more packets are missing required execution evidence".into());
    }
    if summary["blocked_count"].as_i64().unwrap_or(0) > 0 {
        reasons.push("one or more packets contain blocked execution evidence".into());
    }
    if summary["degraded_count"].as_i64().unwrap_or(0) > 0 {
        reasons.push("one or more packets contain degraded execution evidence".into());
    }
    if summary["invalid_count"].as_i64().unwrap_or(0) > 0 {
        reasons.push("one or more packets contain invalid or inconsistent execution evidence".into());
    }
    reasons
}

pub fn build_report(
    packet_refs: &[String],
    base_file: Option<&Path>,
    route_group: Option<&str>,
) -> Result<Value, String> {
    let mut packet_summaries = Vec::new();
    let mut invalid_refs = Vec::new();
    for r#ref in packet_refs {
        let Some(path) = resolve_ref(base_file, r#ref) else {
            invalid_refs.push(json!({"packet_ref": r#ref, "reason": "action packet ref is not local"}));
            continue;
        };
        if !path.exists() {
            invalid_refs.push(json!({"packet_ref": r#ref, "reason": "action packet does not exist"}));
            continue;
        }
        match summarize_packet(r#ref, &path) {
            Ok(s) => packet_summaries.push(s),
            Err(errs) => {
                for e in errs {
                    invalid_refs.push(json!({"packet_ref": r#ref, "reason": e}));
                }
            }
        }
    }
    let mut groups: Vec<String> = packet_summaries
        .iter()
        .filter_map(|s| s.get("route_group").and_then(Value::as_str).map(str::to_string))
        .collect();
    groups.sort();
    groups.dedup();
    let route_group = match route_group {
        Some(g) => g.to_string(),
        None if groups.len() == 1 => groups[0].clone(),
        None if groups.is_empty() => "unknown".into(),
        None => return Err("action packets span multiple route groups; pass --route-group".into()),
    };
    let scoped: Vec<Value> = packet_summaries
        .iter()
        .filter(|s| s.get("route_group").and_then(Value::as_str) == Some(route_group.as_str()))
        .cloned()
        .collect();
    let out_of_scope: Vec<String> = packet_summaries
        .iter()
        .filter(|s| s.get("route_group").and_then(Value::as_str) != Some(route_group.as_str()))
        .filter_map(|s| s.get("packet_ref").and_then(Value::as_str).map(str::to_string))
        .collect();
    let required_count = scoped
        .iter()
        .filter(|s| s.get("execution_required") == Some(&Value::Bool(true)))
        .count() as i64;
    let mut counts = serde_json::Map::from_iter([
        ("complete_count".into(), json!(0)),
        ("missing_count".into(), json!(0)),
        ("blocked_count".into(), json!(0)),
        ("degraded_count".into(), json!(0)),
        ("invalid_count".into(), json!(0)),
        ("not_required_count".into(), json!(0)),
    ]);
    for item in &scoped {
        let field = match item.get("execution_status").and_then(Value::as_str) {
            Some("complete") => "complete_count",
            Some("missing") => "missing_count",
            Some("blocked") => "blocked_count",
            Some("degraded") => "degraded_count",
            Some("not_required") => "not_required_count",
            _ => "invalid_count",
        };
        let n = counts[field].as_i64().unwrap_or(0) + 1;
        counts.insert(field.into(), json!(n));
    }
    counts.insert(
        "invalid_count".into(),
        json!(counts["invalid_count"].as_i64().unwrap_or(0) + invalid_refs.len() as i64),
    );
    let complete = counts["complete_count"].as_i64().unwrap_or(0);
    let summary = json!({
        "packet_count": scoped.len(),
        "required_execution_count": required_count,
        "complete_count": complete,
        "missing_count": counts["missing_count"],
        "blocked_count": counts["blocked_count"],
        "degraded_count": counts["degraded_count"],
        "invalid_count": counts["invalid_count"],
        "not_required_count": counts["not_required_count"],
        "completion_rate": completion_rate(complete, required_count),
    });
    let gate = derive_gate(&summary);
    Ok(json!({
        "execution_report_version": ROUTE_EXECUTION_REPORT_VERSION,
        "route_group": route_group,
        "inputs": {"action_packet_refs": packet_refs},
        "packet_count": summary["packet_count"],
        "required_execution_count": summary["required_execution_count"],
        "complete_count": summary["complete_count"],
        "missing_count": summary["missing_count"],
        "blocked_count": summary["blocked_count"],
        "degraded_count": summary["degraded_count"],
        "invalid_count": summary["invalid_count"],
        "not_required_count": summary["not_required_count"],
        "completion_rate": summary["completion_rate"],
        "execution_gate": gate,
        "packet_summaries": scoped,
        "invalid_packet_refs": invalid_refs,
        "out_of_scope_packet_refs": out_of_scope,
        "decision_reasons": decision_reasons(&summary, gate),
        "non_authorization": NON_AUTHORIZATION,
    }))
}

pub fn expected_report(report_path: &Path, report: &Value) -> Result<Value, String> {
    let refs = report
        .pointer("/inputs/action_packet_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "execution report inputs.action_packet_refs must be an array of strings".to_string())?;
    if !refs.iter().all(Value::is_string) {
        return Err("execution report inputs.action_packet_refs must be an array of strings".into());
    }
    let refs: Vec<String> = refs.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let route_group = report
        .get("route_group")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "execution report route_group must be a non-empty string".to_string())?;
    build_report(&refs, Some(report_path), Some(route_group))
}

pub fn load_report(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (blocks, raw_json_mode) = candidate_blocks(&text, path);
    if blocks.is_empty() {
        return Err("no JSON route execution report found".into());
    }
    let mut reports = Vec::new();
    let mut errors = Vec::new();
    for (n, block) in blocks {
        match serde_json::from_str::<Value>(&block) {
            Ok(parsed)
                if parsed.get("execution_report_version").and_then(Value::as_str)
                    == Some(ROUTE_EXECUTION_REPORT_VERSION) =>
            {
                reports.push(parsed);
            }
            Ok(_) => {}
            Err(e) => {
                let label = if raw_json_mode {
                    "raw JSON".into()
                } else {
                    format!("JSON block {n}")
                };
                errors.push(format!("{label} is invalid JSON: {e}"));
            }
        }
    }
    if reports.len() != 1 {
        let detail = if errors.is_empty() {
            format!("found {} route execution reports", reports.len())
        } else {
            errors.join("; ")
        };
        return Err(format!("expected exactly one route execution report; {detail}"));
    }
    Ok(reports.remove(0))
}

pub fn validate_report(report: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if !report.is_object() {
        return vec!["report must be an object".into()];
    }
    let have: std::collections::BTreeSet<&str> = report
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let allowed: std::collections::BTreeSet<&str> = TOP_LEVEL_FIELDS.iter().copied().collect();
    let unknown: Vec<_> = have.difference(&allowed).copied().collect();
    let missing: Vec<_> = allowed.difference(&have).copied().collect();
    if !unknown.is_empty() {
        errors.push(format!("report has unknown fields: {}", unknown.join(", ")));
    }
    if !missing.is_empty() {
        errors.push(format!("report is missing fields: {}", missing.join(", ")));
    }
    if report.get("execution_report_version").and_then(Value::as_str)
        != Some(ROUTE_EXECUTION_REPORT_VERSION)
    {
        errors.push(format!(
            "execution_report_version must be {ROUTE_EXECUTION_REPORT_VERSION}"
        ));
    }
    if !matches!(report.get("route_group").and_then(Value::as_str), Some(s) if !s.trim().is_empty()) {
        errors.push("route_group must be a non-empty string".into());
    }
    match report.get("inputs") {
        Some(inputs) if inputs.is_object() => {
            let ih: std::collections::BTreeSet<&str> = inputs
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            let ia: std::collections::BTreeSet<&str> = ["action_packet_refs"].into_iter().collect();
            let unk: Vec<_> = ih.difference(&ia).copied().collect();
            let miss: Vec<_> = ia.difference(&ih).copied().collect();
            if !unk.is_empty() {
                errors.push(format!("inputs has unknown fields: {}", unk.join(", ")));
            }
            if !miss.is_empty() {
                errors.push(format!("inputs is missing fields: {}", miss.join(", ")));
            }
            if !is_string_list_min(inputs.get("action_packet_refs"), 1) {
                errors.push("inputs.action_packet_refs must be a non-empty array of strings".into());
            }
        }
        _ => errors.push("inputs must be an object".into()),
    }
    for field in [
        "packet_count",
        "required_execution_count",
        "complete_count",
        "missing_count",
        "blocked_count",
        "degraded_count",
        "invalid_count",
        "not_required_count",
    ] {
        if !matches!(report.get(field), Some(v) if v.is_i64() && v.as_i64().unwrap() >= 0 && !v.is_boolean())
        {
            errors.push(format!("{field} must be a non-negative integer"));
        }
    }
    match report.get("completion_rate") {
        Some(Value::Null) | None => {}
        Some(v) if v.as_f64().map(|n| (0.0..=1.0).contains(&n) && !v.is_boolean()).unwrap_or(false) => {}
        _ => errors.push("completion_rate must be a number between 0 and 1 or null".into()),
    }
    if !EXECUTION_GATES.contains(&report.get("execution_gate").and_then(Value::as_str).unwrap_or("")) {
        errors.push("execution_gate is invalid".into());
    }
    let mut parsed_summaries = Vec::new();
    match report.get("packet_summaries") {
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                if !item.is_object() {
                    errors.push(format!("packet_summaries[{}] must be an object", i + 1));
                    continue;
                }
                let have: std::collections::BTreeSet<&str> =
                    item.as_object().unwrap().keys().map(String::as_str).collect();
                let allowed: std::collections::BTreeSet<&str> =
                    PACKET_SUMMARY_FIELDS.iter().copied().collect();
                let unk: Vec<_> = have.difference(&allowed).copied().collect();
                let miss: Vec<_> = allowed.difference(&have).copied().collect();
                let pfx = format!("packet_summaries[{}]", i + 1);
                if !unk.is_empty() {
                    errors.push(format!("{pfx} has unknown fields: {}", unk.join(", ")));
                }
                if !miss.is_empty() {
                    errors.push(format!("{pfx} is missing fields: {}", miss.join(", ")));
                }
                for field in [
                    "packet_ref",
                    "route_group",
                    "route",
                    "trace_instrument",
                    "action_boundary",
                    "action_decision",
                ] {
                    if !matches!(item.get(field).and_then(Value::as_str), Some(s) if !s.trim().is_empty())
                    {
                        errors.push(format!("{pfx}.{field} must be a non-empty string"));
                    }
                }
                if !item.get("execution_required").map(Value::is_boolean).unwrap_or(false) {
                    errors.push(format!("{pfx}.execution_required must be boolean"));
                }
                if !EXECUTION_STATUSES
                    .contains(&item.get("execution_status").and_then(Value::as_str).unwrap_or(""))
                {
                    errors.push(format!("{pfx}.execution_status is invalid"));
                }
                for field in ["product_kind", "product_id", "product_sha256", "action_binding_sha256"] {
                    if let Some(v) = item.get(field) {
                        if !v.is_null() && !matches!(v.as_str(), Some(s) if !s.trim().is_empty()) {
                            errors.push(format!("{pfx}.{field} must be a non-empty string or null"));
                        }
                    }
                }
                if !is_string_list_min(item.get("errors"), 0) {
                    errors.push(format!("{pfx}.errors must be an array of strings"));
                }
                parsed_summaries.push(item.clone());
            }
        }
        _ => errors.push("packet_summaries must be an array".into()),
    }
    match report.get("invalid_packet_refs") {
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                let pfx = format!("invalid_packet_refs[{}]", i + 1);
                if !item.is_object() {
                    errors.push(format!("{pfx} must be an object"));
                    continue;
                }
                let have: std::collections::BTreeSet<&str> =
                    item.as_object().unwrap().keys().map(String::as_str).collect();
                let allowed: std::collections::BTreeSet<&str> =
                    INVALID_REF_FIELDS.iter().copied().collect();
                let unk: Vec<_> = have.difference(&allowed).copied().collect();
                let miss: Vec<_> = allowed.difference(&have).copied().collect();
                if !unk.is_empty() {
                    errors.push(format!("{pfx} has unknown fields: {}", unk.join(", ")));
                }
                if !miss.is_empty() {
                    errors.push(format!("{pfx} is missing fields: {}", miss.join(", ")));
                }
                for field in ["packet_ref", "reason"] {
                    if !matches!(item.get(field).and_then(Value::as_str), Some(s) if !s.trim().is_empty())
                    {
                        errors.push(format!("{pfx}.{field} must be a non-empty string"));
                    }
                }
            }
        }
        _ => errors.push("invalid_packet_refs must be an array".into()),
    }
    if !is_string_list_min(report.get("out_of_scope_packet_refs"), 0) {
        errors.push("out_of_scope_packet_refs must be an array of strings".into());
    }
    if !is_string_list_min(report.get("decision_reasons"), 1) {
        errors.push("decision_reasons must be a non-empty array of strings".into());
    }
    if report.get("non_authorization").and_then(Value::as_str) != Some(NON_AUTHORIZATION) {
        errors.push("non_authorization text is invalid".into());
    }
    if !parsed_summaries.is_empty() {
        let route_group = report.get("route_group").and_then(Value::as_str);
        if parsed_summaries
            .iter()
            .any(|s| s.get("route_group").and_then(Value::as_str) != route_group)
        {
            errors.push("packet_summaries must all match route_group".into());
        }
        let invalid_len = report
            .get("invalid_packet_refs")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let status_counts = json!({
            "complete_count": parsed_summaries.iter().filter(|s| s.get("execution_status").and_then(Value::as_str)==Some("complete")).count(),
            "missing_count": parsed_summaries.iter().filter(|s| s.get("execution_status").and_then(Value::as_str)==Some("missing")).count(),
            "blocked_count": parsed_summaries.iter().filter(|s| s.get("execution_status").and_then(Value::as_str)==Some("blocked")).count(),
            "degraded_count": parsed_summaries.iter().filter(|s| s.get("execution_status").and_then(Value::as_str)==Some("degraded")).count(),
            "invalid_count": parsed_summaries.iter().filter(|s| s.get("execution_status").and_then(Value::as_str)==Some("invalid")).count() + invalid_len,
            "not_required_count": parsed_summaries.iter().filter(|s| s.get("execution_status").and_then(Value::as_str)==Some("not_required")).count(),
            "required_execution_count": parsed_summaries.iter().filter(|s| s.get("execution_required")==Some(&Value::Bool(true))).count(),
            "packet_count": parsed_summaries.len(),
        });
        for field in [
            "complete_count",
            "missing_count",
            "blocked_count",
            "degraded_count",
            "invalid_count",
            "not_required_count",
            "required_execution_count",
            "packet_count",
        ] {
            if report.get(field) != status_counts.get(field) {
                errors.push(format!(
                    "{field} should be {}, got {}",
                    status_counts[field],
                    report.get(field).cloned().unwrap_or(Value::Null)
                ));
            }
        }
        let expected_completion = completion_rate(
            status_counts["complete_count"].as_i64().unwrap_or(0),
            status_counts["required_execution_count"].as_i64().unwrap_or(0),
        );
        if report.get("completion_rate") != Some(&expected_completion) {
            errors.push(format!(
                "completion_rate should be {expected_completion}, got {}",
                report.get("completion_rate").cloned().unwrap_or(Value::Null)
            ));
        }
        let mut gate_input = status_counts.clone();
        if let Some(obj) = gate_input.as_object_mut() {
            obj.insert("completion_rate".into(), expected_completion);
        }
        let expected_gate = derive_gate(&gate_input);
        if report.get("execution_gate").and_then(Value::as_str) != Some(expected_gate) {
            errors.push(format!(
                "execution_gate should be {expected_gate}, got {}",
                report.get("execution_gate").cloned().unwrap_or(Value::Null)
            ));
        }
    }
    errors
}

pub fn validate_recomputable(report_path: &Path, report: &Value) -> Vec<String> {
    match expected_report(report_path, report) {
        Ok(expected) if &expected == report => Vec::new(),
        Ok(_) => vec!["route execution report differs from referenced Action Packets".into()],
        Err(e) => vec![e],
    }
}
