//! Measure residual trace quality without asserting correctness probability.

use crate::jsonutil::candidate_blocks;
use serde_json::{json, Map, Value};
use std::path::Path;

const HIGH_RISK_SEVERITIES: &[&str] = &["HIGH", "CRITICAL", "P0"];
const SUPPORTING_STATES: &[&str] = &["closed", "blocked", "waived", "not_applicable"];
const STRICT_BOUNDARIES: &[&str] = &["protected_write", "irreversible"];
const WEAK_MODEL_RELATIONS: &[&str] = &["same_model", "same_family"];

fn nonempty_string(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_str), Some(s) if !s.trim().is_empty())
}

fn nonempty_list_string(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .any(|item| matches!(item.as_str(), Some(s) if !s.trim().is_empty())),
        _ => false,
    }
}

fn ratio(numerator: usize, denominator: usize) -> Value {
    if denominator == 0 {
        Value::Null
    } else {
        let v = ((numerator as f64) / (denominator as f64) * 10000.0).round() / 10000.0;
        json!(v)
    }
}

fn is_high_risk(residual: &Value) -> bool {
    HIGH_RISK_SEVERITIES.contains(&residual.get("severity").and_then(Value::as_str).unwrap_or(""))
}

fn is_action_blocking(residual: &Value) -> bool {
    is_high_risk(residual)
        || !matches!(
            residual.get("required_closure").and_then(Value::as_str),
            None | Some("none")
        )
        || residual.get("disposition").and_then(Value::as_str) == Some("escalated")
}

fn has_supported_closure(residual: &Value) -> bool {
    let state = residual.get("closure_state").and_then(Value::as_str).unwrap_or("");
    if !SUPPORTING_STATES.contains(&state) {
        return false;
    }
    nonempty_list_string(residual.get("closure_evidence")) && nonempty_string(residual.get("scope"))
}

fn measure_manifest(trace: &Value) -> Map<String, Value> {
    let manifest = trace.get("trial_manifest");
    if !matches!(manifest, Some(Value::Object(_))) {
        return json!({
            "trial_manifest_present": false,
            "base_model_relation": null,
            "perspective_count": 0,
            "independent_first_pass_count": 0,
            "perturbation_axis_count": 0,
            "independence_control_count": 0,
            "contamination_risk_count": 0,
            "same_model_flag": false,
            "cost_fields_present": false,
        })
        .as_object()
        .unwrap()
        .clone();
    }
    let manifest = manifest.unwrap();
    let perspectives: Vec<&Value> = manifest
        .get("perspectives")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter(|i| i.is_object()).collect())
        .unwrap_or_default();
    let cost = manifest.get("cost");
    let cost_fields_present = matches!(cost, Some(Value::Object(m)) if
        ["total_tokens", "wall_time_seconds", "tool_calls", "human_minutes"]
            .iter()
            .all(|f| m.contains_key(*f))
    );
    let base_model_relation = manifest.get("base_model_relation").cloned().unwrap_or(Value::Null);
    let perspective_count = manifest
        .get("perspective_count")
        .and_then(Value::as_i64)
        .unwrap_or(perspectives.len() as i64);
    json!({
        "trial_manifest_present": true,
        "base_model_relation": base_model_relation,
        "perspective_count": perspective_count,
        "independent_first_pass_count": perspectives.iter().filter(|i| i.get("independent_first_pass") == Some(&Value::Bool(true))).count(),
        "perturbation_axis_count": manifest.get("perturbation_axes").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
        "independence_control_count": manifest.get("independence_controls").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
        "contamination_risk_count": manifest.get("contamination_risks").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
        "same_model_flag": WEAK_MODEL_RELATIONS.contains(&base_model_relation.as_str().unwrap_or("")),
        "cost_fields_present": cost_fields_present,
    })
    .as_object()
    .unwrap()
    .clone()
}

pub fn measure_trace(trace: &Value) -> Value {
    let residuals: Vec<&Value> = trace
        .get("residuals")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter(|i| i.is_object()).collect())
        .unwrap_or_default();
    let action_boundary = trace.get("action_boundary").cloned().unwrap_or(Value::Null);
    let highball_decision = trace.get("highball_decision").cloned().unwrap_or(Value::Null);
    let manifest_metrics = measure_manifest(trace);

    let residual_count = residuals.len();
    let evidence_count = residuals
        .iter()
        .filter(|i| nonempty_string(i.get("evidence")))
        .count();
    let closure_evidence_count = residuals
        .iter()
        .filter(|i| nonempty_list_string(i.get("closure_evidence")))
        .count();
    let high_risk: Vec<&&Value> = residuals.iter().filter(|i| is_high_risk(i)).collect();
    let action_blocking: Vec<&&Value> = residuals.iter().filter(|i| is_action_blocking(i)).collect();
    let open_high_risk: Vec<&&&Value> = high_risk
        .iter()
        .filter(|i| i.get("closure_state").and_then(Value::as_str) == Some("open"))
        .collect();
    let unsupported_high_risk: Vec<&&&Value> = high_risk
        .iter()
        .filter(|i| {
            SUPPORTING_STATES.contains(&i.get("closure_state").and_then(Value::as_str).unwrap_or(""))
                && !has_supported_closure(i)
        })
        .collect();
    let action_blocking_supported = action_blocking
        .iter()
        .filter(|i| has_supported_closure(i))
        .count();
    let silent_collapse = residuals
        .iter()
        .filter(|i| i.get("type").and_then(Value::as_str) == Some("silent_collapse"))
        .count();
    let unresolved = residuals
        .iter()
        .filter(|i| {
            matches!(
                i.get("disposition").and_then(Value::as_str),
                Some("unresolved" | "escalated")
            ) || i.get("closure_state").and_then(Value::as_str) == Some("open")
        })
        .count();

    let mut decision_conflicts = 0i64;
    let boundary = action_boundary.as_str().unwrap_or("");
    if STRICT_BOUNDARIES.contains(&boundary) && highball_decision.as_str() == Some("pass") {
        if !open_high_risk.is_empty() {
            decision_conflicts += 1;
        }
        if !unsupported_high_risk.is_empty() {
            decision_conflicts += 1;
        }
    }

    let mut warnings: Vec<String> = Vec::new();
    if STRICT_BOUNDARIES.contains(&boundary) && residual_count == 0 {
        warnings.push("strict action boundary has an empty residual set".into());
    }
    if residual_count > 0 && evidence_count < residual_count {
        warnings.push("one or more residuals lack evidence".into());
    }
    if !action_blocking.is_empty() && action_blocking_supported < action_blocking.len() {
        warnings.push("one or more action-blocking residuals lack supported closure".into());
    }
    if silent_collapse > 0 {
        warnings.push("silent-collapse residuals require external anchoring or review".into());
    }
    if STRICT_BOUNDARIES.contains(&boundary)
        && manifest_metrics["trial_manifest_present"] != Value::Bool(true)
    {
        warnings.push("strict action boundary lacks trial manifest".into());
    }
    if manifest_metrics["trial_manifest_present"] == Value::Bool(true) {
        if manifest_metrics["perspective_count"] != manifest_metrics["independent_first_pass_count"]
        {
            warnings.push("one or more perspectives lack independent first pass".into());
        }
        if manifest_metrics["perturbation_axis_count"] == json!(0) {
            warnings.push("trial manifest has no perturbation axes".into());
        }
        if manifest_metrics["same_model_flag"] == Value::Bool(true) {
            warnings.push(
                "same-model or same-family trace is stability evidence, not independent confirmation"
                    .into(),
            );
        }
        if manifest_metrics["cost_fields_present"] != Value::Bool(true) {
            warnings.push("trial manifest lacks complete cost fields".into());
        }
    }

    let mut quality_gate = "pass";
    if STRICT_BOUNDARIES.contains(&boundary)
        && (!open_high_risk.is_empty() || !unsupported_high_risk.is_empty() || decision_conflicts > 0)
    {
        quality_gate = "block";
    } else if !warnings.is_empty() || unresolved > 0 {
        quality_gate = "review";
    }

    let mut out = json!({
        "question": trace.get("question").cloned().unwrap_or(Value::Null),
        "instrument": trace.get("instrument").cloned().unwrap_or(Value::Null),
        "action_boundary": action_boundary,
        "highball_decision": highball_decision,
        "residual_count": residual_count,
        "high_risk_count": high_risk.len(),
        "action_blocking_count": action_blocking.len(),
        "open_high_risk_count": open_high_risk.len(),
        "unsupported_high_risk_closure_count": unsupported_high_risk.len(),
        "silent_collapse_count": silent_collapse,
        "unresolved_count": unresolved,
        "decision_conflict_count": decision_conflicts,
        "evidence_coverage": ratio(evidence_count, residual_count),
        "closure_evidence_coverage": ratio(closure_evidence_count, residual_count),
        "action_blocking_closure_coverage": ratio(action_blocking_supported, action_blocking.len()),
        "quality_gate": quality_gate,
        "warnings": warnings,
    });
    if let Some(obj) = out.as_object_mut() {
        for (k, v) in manifest_metrics {
            obj.insert(k, v);
        }
    }
    out
}

pub fn combine(measurements: &[Value]) -> Value {
    let gates: Vec<&str> = measurements
        .iter()
        .filter_map(|m| m.get("quality_gate").and_then(Value::as_str))
        .collect();
    let aggregate_gate = if gates.contains(&"block") {
        "block"
    } else if gates.contains(&"review") {
        "review"
    } else {
        "pass"
    };
    json!({
        "trace_count": measurements.len(),
        "residual_count": measurements.iter().map(|m| m["residual_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "high_risk_count": measurements.iter().map(|m| m["high_risk_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "action_blocking_count": measurements.iter().map(|m| m["action_blocking_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "open_high_risk_count": measurements.iter().map(|m| m["open_high_risk_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "unsupported_high_risk_closure_count": measurements.iter().map(|m| m["unsupported_high_risk_closure_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "silent_collapse_count": measurements.iter().map(|m| m["silent_collapse_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "unresolved_count": measurements.iter().map(|m| m["unresolved_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "decision_conflict_count": measurements.iter().map(|m| m["decision_conflict_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        "traces_with_manifest": measurements.iter().filter(|m| m["trial_manifest_present"] == Value::Bool(true)).count(),
        "same_model_trace_count": measurements.iter().filter(|m| m["same_model_flag"] == Value::Bool(true)).count(),
        "quality_gate": aggregate_gate,
        "traces": measurements,
    })
}

pub fn load_traces(path: &Path) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (blocks, raw_json_mode) = candidate_blocks(&text, path);
    if blocks.is_empty() {
        return Err("no JSON residual trace block found".into());
    }
    let mut traces = Vec::new();
    let mut errors = Vec::new();
    for (block_number, block) in blocks {
        match serde_json::from_str::<Value>(&block) {
            Ok(parsed) if parsed.get("residuals").map(Value::is_array).unwrap_or(false) => {
                traces.push(parsed);
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
    if traces.is_empty() {
        let detail = if errors.is_empty() {
            "no residuals array found".into()
        } else {
            errors.join("; ")
        };
        return Err(detail);
    }
    Ok(traces)
}
