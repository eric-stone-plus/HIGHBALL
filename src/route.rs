//! Choose the HIGHBALL evidence route for a residual-bearing action.

use serde_json::{json, Value};
use std::collections::BTreeSet;

const ACTION_BOUNDARIES: &[&str] = &["none", "reversible", "protected_write", "irreversible"];
const CHANGE_CLASSES: &[&str] = &[
    "claim",
    "code",
    "protocol",
    "architecture",
    "config",
    "credential",
    "deletion",
    "deployment",
    "financial",
    "legal",
];
const RISKS: &[&str] = &["LOW", "MEDIUM", "HIGH", "CRITICAL", "P0"];
const TRACE_GATES: &[&str] = &["unknown", "pass", "review", "block"];
const HUMAN_REVIEW_CLASSES: &[&str] = &["credential", "deletion", "deployment", "financial", "legal"];
const QUINTE_CLASSES: &[&str] = &["protocol", "architecture"];
const HIGH_RISKS: &[&str] = &["HIGH", "CRITICAL", "P0"];
const REQUEST_FIELDS: &[&str] = &[
    "question",
    "action_boundary",
    "change_class",
    "affected_paths",
    "action_scope",
    "risk",
    "executable",
    "trace_quality_gate",
    "open_high_risk_count",
];

fn as_bool(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

fn as_int(value: Option<&Value>) -> i64 {
    value.and_then(Value::as_i64).unwrap_or(0)
}

pub fn validate_request(request: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(obj) = request.as_object() else {
        return vec!["route request must be a JSON object".into()];
    };
    let have: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let allowed: BTreeSet<&str> = REQUEST_FIELDS.iter().copied().collect();
    let unknown: Vec<_> = have.difference(&allowed).copied().collect();
    if !unknown.is_empty() {
        errors.push(format!(
            "route request has unknown fields: {}",
            unknown.join(", ")
        ));
    }
    if !matches!(request.get("question").and_then(Value::as_str), Some(s) if !s.trim().is_empty()) {
        errors.push("question must be a non-empty string".into());
    }
    if !ACTION_BOUNDARIES.contains(&request.get("action_boundary").and_then(Value::as_str).unwrap_or(""))
    {
        errors.push("action_boundary is invalid".into());
    }
    if !CHANGE_CLASSES.contains(&request.get("change_class").and_then(Value::as_str).unwrap_or("")) {
        errors.push("change_class is invalid".into());
    }
    match request.get("affected_paths") {
        Some(Value::Array(items))
            if items
                .iter()
                .all(|i| matches!(i.as_str(), Some(s) if !s.trim().is_empty())) =>
        {
            let paths: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
            let boundary = request.get("action_boundary").and_then(Value::as_str);
            if matches!(boundary, Some("protected_write" | "irreversible")) && paths.is_empty() {
                errors.push("strict action boundaries require at least one affected path".into());
            } else {
                let set: BTreeSet<&str> = paths.iter().copied().collect();
                if set.len() != paths.len() {
                    errors.push("affected_paths must not contain duplicates".into());
                }
            }
        }
        _ => errors.push("affected_paths must be an array of non-empty strings".into()),
    }
    if !request.as_object().unwrap().contains_key("action_scope")
        || !(request.get("action_scope").map(|v| v.is_null() || v.is_string()).unwrap_or(false))
    {
        errors.push("action_scope must be a string or null".into());
    }
    if request.get("executable").is_some() && !request.get("executable").unwrap().is_boolean() {
        errors.push("executable must be boolean when present".into());
    }
    if !RISKS.contains(&request.get("risk").and_then(Value::as_str).unwrap_or("")) {
        errors.push("risk is invalid".into());
    }
    let gate = request
        .get("trace_quality_gate")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if !TRACE_GATES.contains(&gate) {
        errors.push("trace_quality_gate is invalid".into());
    }
    if request.get("open_high_risk_count").is_some()
        && !request.get("open_high_risk_count").unwrap().is_i64()
        && !request.get("open_high_risk_count").unwrap().is_u64()
    {
        errors.push("open_high_risk_count must be integer when present".into());
    }
    errors
}

pub fn route_request(request: &Value) -> Value {
    let action_boundary = request.get("action_boundary").and_then(Value::as_str);
    let change_class = request.get("change_class").and_then(Value::as_str).unwrap_or("");
    let executable = as_bool(request.get("executable"));
    let risk = request.get("risk").and_then(Value::as_str).unwrap_or("");
    let trace_quality_gate = request
        .get("trace_quality_gate")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let open_high_risk_count = as_int(request.get("open_high_risk_count"));

    let mut route;
    let mut reasons: Vec<String> = Vec::new();
    let mut required_artifacts: Vec<String> = Vec::new();
    let mut residual_trace_required = true;
    let mut authorization_required = false;

    if trace_quality_gate == "block" {
        route = "block";
        reasons.push("existing trace quality gate is block".into());
        required_artifacts.push("block record or corrected residual trace".into());
    } else if open_high_risk_count > 0
        && matches!(action_boundary, Some("protected_write" | "irreversible"))
    {
        route = "block";
        reasons.push("strict action boundary has open high-risk residuals".into());
        required_artifacts.push(
            "closed, blocked, waived, or not-applicable high-risk residuals with evidence and scope"
                .into(),
        );
    } else if HUMAN_REVIEW_CLASSES.contains(&change_class) {
        route = "human-review";
        reasons.push(format!("{change_class} change requires human review"));
        required_artifacts.push("scoped human decision, waiver, or block record".into());
    } else if action_boundary == Some("irreversible") {
        route = "QUINTE";
        reasons.push(
            "irreversible boundary requires five-school adversarial review and final adjudication"
                .into(),
        );
        required_artifacts.push("QUINTE residual closure trace".into());
        required_artifacts.push("completed atomic QUINTE product outcome".into());
    } else if action_boundary == Some("protected_write") && HIGH_RISKS.contains(&risk) {
        route = "QUINTE";
        reasons.push(
            "high-risk protected write requires five-school adversarial review and final adjudication"
                .into(),
        );
        required_artifacts.push("QUINTE residual closure trace".into());
        required_artifacts.push("completed atomic QUINTE product outcome".into());
    } else if action_boundary == Some("protected_write") {
        route = "QUINTE";
        reasons.push("bounded protected write requires single-family adversarial review".into());
        required_artifacts.push("QUINTE residual closure trace".into());
        required_artifacts.push("completed atomic QUINTE product outcome".into());
    } else if QUINTE_CLASSES.contains(&change_class) {
        route = "QUINTE";
        reasons.push(format!("{change_class} change requires adversarial review"));
        required_artifacts.push("QUINTE residual closure trace".into());
        required_artifacts.push("completed atomic QUINTE product outcome".into());
    } else if executable && matches!(action_boundary, Some("none" | "reversible")) {
        route = "direct-evidence";
        reasons.push("claim is executable or source-verifiable".into());
        required_artifacts.push("file, command, runtime, source, or user evidence trace".into());
    } else if matches!(risk, "LOW" | "MEDIUM") {
        route = "QUINTE";
        reasons.push("non-executable judgment requires bounded adversarial review".into());
        required_artifacts.push("QUINTE residual closure trace".into());
        required_artifacts.push("completed atomic QUINTE product outcome".into());
    } else if HIGH_RISKS.contains(&risk) {
        route = "QUINTE";
        reasons.push("high risk requires five-school adversarial review and final adjudication".into());
        required_artifacts.push("QUINTE residual closure trace".into());
        required_artifacts.push("completed atomic QUINTE product outcome".into());
    } else {
        route = "QUINTE";
        reasons.push("default independent stability review".into());
        required_artifacts.push("QUINTE residual closure trace".into());
        required_artifacts.push("completed atomic QUINTE product outcome".into());
    }

    if route == "QUINTE"
        && !matches!(
            request.get("action_scope").and_then(Value::as_str),
            Some(s) if !s.trim().is_empty()
        )
    {
        let scoped = route;
        route = "block";
        reasons.push(format!("{scoped} execution requires a non-empty action scope"));
        required_artifacts.push(format!(
            "explicit action scope bound into the {scoped} product"
        ));
    }

    if matches!(
        change_class,
        "deletion" | "deployment" | "credential" | "financial" | "legal"
    ) {
        authorization_required = true;
    }
    if action_boundary == Some("irreversible") {
        authorization_required = true;
    }

    if matches!(route, "block" | "direct-evidence" | "human-review") {
        residual_trace_required = true;
    }

    json!({
        "route": route,
        "reason": reasons,
        "required_artifacts": required_artifacts,
        "residual_trace_required": residual_trace_required,
        "authorization_required": authorization_required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(changes: Value) -> Value {
        let mut base = json!({
            "question": "Should this protected change proceed?",
            "action_boundary": "protected_write",
            "change_class": "code",
            "affected_paths": ["HIGHBALL/bin/tool.py"],
            "action_scope": "Only HIGHBALL/bin/tool.py in this task.",
            "risk": "HIGH",
            "executable": false,
            "trace_quality_gate": "pass",
            "open_high_risk_count": 0,
        });
        if let (Some(obj), Some(ch)) = (base.as_object_mut(), changes.as_object()) {
            for (k, v) in ch {
                obj.insert(k.clone(), v.clone());
            }
        }
        base
    }

    #[test]
    fn router_matrix_preserves_atomic_boundaries() {
        let cases = [
            (req(json!({"action_boundary":"reversible","risk":"LOW","executable":true})), "direct-evidence", false),
            (req(json!({"action_boundary":"protected_write","risk":"MEDIUM"})), "QUINTE", false),
            (req(json!({"action_boundary":"protected_write","risk":"HIGH"})), "QUINTE", false),
            (req(json!({"action_boundary":"none","change_class":"protocol","risk":"LOW"})), "QUINTE", false),
            (req(json!({"action_boundary":"none","change_class":"architecture","risk":"LOW"})), "QUINTE", false),
            (req(json!({"action_boundary":"reversible","change_class":"credential","risk":"LOW"})), "human-review", true),
            (req(json!({"action_boundary":"irreversible","risk":"HIGH"})), "QUINTE", true),
            (req(json!({"trace_quality_gate":"block"})), "block", false),
        ];
        for (request, expected_route, expected_auth) in cases {
            let decision = route_request(&request);
            assert_eq!(decision["route"], expected_route, "{request}");
            assert_eq!(decision["authorization_required"], expected_auth, "{request}");
        }
    }

    #[test]
    fn strict_boundary_rejects_empty_or_duplicate_paths() {
        let empty = req(json!({"affected_paths": []}));
        let dup = req(json!({"affected_paths": ["HIGHBALL/bin/tool.py", "HIGHBALL/bin/tool.py"]}));
        assert!(validate_request(&empty)
            .iter()
            .any(|e| e.contains("at least one affected path")));
        assert!(validate_request(&dup)
            .iter()
            .any(|e| e.contains("must not contain duplicates")));
    }
}
