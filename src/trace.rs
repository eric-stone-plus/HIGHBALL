//! Validate residual-trace 1.1 compatibility artifacts.

use crate::contracts::{is_digest_str, RESIDUAL_TRACE_VERSION};
use crate::jsonutil::candidate_blocks;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const ALLOWED_TOP_LEVEL: &[&str] = &[
    "trace_version",
    "question",
    "instrument",
    "residuals",
    "trial_manifest",
    "action_boundary",
    "highball_decision",
    "action_binding_sha256",
];
const REQUIRED_TOP_LEVEL: &[&str] = &[
    "trace_version",
    "question",
    "instrument",
    "residuals",
    "action_boundary",
    "highball_decision",
    "action_binding_sha256",
];
const ALLOWED_INSTRUMENTS: &[&str] = &["QUINTE", "direct-evidence", "human"];
const ALLOWED_ACTION_BOUNDARIES: &[&str] = &["none", "reversible", "protected_write", "irreversible"];
const ALLOWED_HIGHBALL_DECISIONS: &[&str] = &["not_applicable", "pass", "review", "block", "escalate"];
const ALLOWED_RESIDUAL_FIELDS: &[&str] = &[
    "id",
    "severity",
    "type",
    "source",
    "finding",
    "affected_paths",
    "error_signature",
    "evidence",
    "disposition",
    "required_closure",
    "closure_state",
    "closure_evidence",
    "scope",
];
const ALLOWED_SEVERITIES: &[&str] = &["LOW", "MEDIUM", "HIGH", "CRITICAL", "P0"];
const HIGH_RISK_SEVERITIES: &[&str] = &["HIGH", "CRITICAL", "P0"];
const ALLOWED_TYPES: &[&str] = &[
    "contradiction",
    "omission",
    "evidence_gap",
    "confidence_mismatch",
    "drift",
    "execution_mismatch",
    "silent_collapse",
];
const ALLOWED_DISPOSITIONS: &[&str] = &["verified", "falsified", "unresolved", "escalated", "discarded"];
const ALLOWED_REQUIRED_CLOSURE: &[&str] =
    &["none", "edit", "test", "command", "block", "waiver", "human_review"];
const ALLOWED_CLOSURE_STATES: &[&str] = &["open", "closed", "blocked", "waived", "not_applicable"];
const ALLOWED_BASE_MODEL_RELATIONS: &[&str] = &[
    "unknown",
    "same_model",
    "same_family",
    "heterogeneous_models",
    "mixed",
    "human",
    "direct_evidence",
];
const ALLOWED_TRIAL_MANIFEST_FIELDS: &[&str] = &[
    "manifest_version",
    "base_model_relation",
    "perspective_count",
    "perspectives",
    "perturbation_axes",
    "independence_controls",
    "contamination_risks",
    "cost",
];
const ALLOWED_PERSPECTIVE_FIELDS: &[&str] =
    &["id", "role", "route", "artifact", "prompt_hash", "independent_first_pass"];
const ALLOWED_COST_FIELDS: &[&str] =
    &["total_tokens", "wall_time_seconds", "tool_calls", "human_minutes"];

#[derive(Clone, Debug)]
pub struct Finding {
    pub severity: &'static str,
    pub message: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.severity, self.message)
    }
}

fn is_nonempty_string(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_str), Some(s) if !s.trim().is_empty())
}

fn is_string_array(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if items.iter().all(Value::is_string))
}

fn is_nonempty_string_array(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if items.iter().all(|i| matches!(i.as_str(), Some(s) if !s.trim().is_empty())))
}

fn is_closure_evidence_array(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if items.iter().all(|i| i.is_null() || i.is_string()))
}

fn has_closure_evidence(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if items.iter().any(|i| matches!(i.as_str(), Some(s) if !s.trim().is_empty())))
}

fn field_diff(have: &Value, allowed: &[&str]) -> (Vec<String>, Vec<String>) {
    let have: BTreeSet<&str> = have
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    let unknown: Vec<String> = have.difference(&allowed).map(|s| (*s).to_string()).collect();
    let missing: Vec<String> = allowed.difference(&have).map(|s| (*s).to_string()).collect();
    (unknown, missing)
}

fn validate_trial_manifest(manifest: &Value, block_number: usize) -> Vec<Finding> {
    let prefix = format!("JSON block {block_number} trial_manifest");
    let Some(obj) = manifest.as_object() else {
        return vec![Finding {
            severity: "ERROR",
            message: format!("{prefix} must be an object"),
        }];
    };
    let _ = obj;
    let mut findings = Vec::new();
    let (unknown, missing) = field_diff(manifest, ALLOWED_TRIAL_MANIFEST_FIELDS);
    if !unknown.is_empty() {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("{prefix} has unknown fields: {}", unknown.join(", ")),
        });
    }
    if !missing.is_empty() {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("{prefix} is missing fields: {}", missing.join(", ")),
        });
    }
    if !is_nonempty_string(manifest.get("manifest_version")) {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("{prefix} manifest_version must be a non-empty string"),
        });
    }
    if !ALLOWED_BASE_MODEL_RELATIONS
        .contains(&manifest.get("base_model_relation").and_then(Value::as_str).unwrap_or(""))
    {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("{prefix} base_model_relation is invalid"),
        });
    }
    let perspective_count = manifest.get("perspective_count").and_then(Value::as_i64);
    if !matches!(perspective_count, Some(n) if n >= 1) {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("{prefix} perspective_count must be a positive integer"),
        });
    }
    match manifest.get("perspectives") {
        Some(Value::Array(perspectives)) if !perspectives.is_empty() => {
            if let Some(n) = perspective_count {
                if n as usize != perspectives.len() {
                    findings.push(Finding {
                        severity: "ERROR",
                        message: format!("{prefix} perspective_count must match perspectives length"),
                    });
                }
            }
            let mut seen_ids: BTreeSet<String> = BTreeSet::new();
            for (index, perspective) in perspectives.iter().enumerate() {
                let pfx = format!("{prefix} perspective {}", index + 1);
                if !perspective.is_object() {
                    findings.push(Finding {
                        severity: "ERROR",
                        message: format!("{pfx} is not an object"),
                    });
                    continue;
                }
                let (unk, miss) = field_diff(perspective, ALLOWED_PERSPECTIVE_FIELDS);
                if !unk.is_empty() {
                    findings.push(Finding {
                        severity: "ERROR",
                        message: format!("{pfx} has unknown fields: {}", unk.join(", ")),
                    });
                }
                if !miss.is_empty() {
                    findings.push(Finding {
                        severity: "ERROR",
                        message: format!("{pfx} is missing fields: {}", miss.join(", ")),
                    });
                }
                match perspective.get("id").and_then(Value::as_str) {
                    Some(id) if !id.trim().is_empty() => {
                        if !seen_ids.insert(id.to_string()) {
                            findings.push(Finding {
                                severity: "ERROR",
                                message: format!("{pfx} has duplicate id {id}"),
                            });
                        }
                    }
                    _ => findings.push(Finding {
                        severity: "ERROR",
                        message: format!("{pfx} id must be a non-empty string"),
                    }),
                }
                if !is_nonempty_string(perspective.get("role")) {
                    findings.push(Finding {
                        severity: "ERROR",
                        message: format!("{pfx} role must be a non-empty string"),
                    });
                }
                for field in ["route", "artifact", "prompt_hash"] {
                    if let Some(v) = perspective.get(field) {
                        if !v.is_null() && !v.is_string() {
                            findings.push(Finding {
                                severity: "ERROR",
                                message: format!("{pfx} {field} must be a string or null"),
                            });
                        }
                    }
                }
                if !perspective.get("independent_first_pass").map(Value::is_boolean).unwrap_or(false)
                {
                    findings.push(Finding {
                        severity: "ERROR",
                        message: format!("{pfx} independent_first_pass must be boolean"),
                    });
                }
            }
        }
        _ => findings.push(Finding {
            severity: "ERROR",
            message: format!("{prefix} perspectives must be a non-empty array"),
        }),
    }
    for field in ["perturbation_axes", "independence_controls", "contamination_risks"] {
        if !is_nonempty_string_array(manifest.get(field)) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} {field} must be an array of non-empty strings"),
            });
        }
    }
    match manifest.get("cost") {
        Some(cost) if cost.is_object() => {
            let (unk, miss) = field_diff(cost, ALLOWED_COST_FIELDS);
            if !unk.is_empty() {
                findings.push(Finding {
                    severity: "ERROR",
                    message: format!("{prefix} cost has unknown fields: {}", unk.join(", ")),
                });
            }
            if !miss.is_empty() {
                findings.push(Finding {
                    severity: "ERROR",
                    message: format!("{prefix} cost is missing fields: {}", miss.join(", ")),
                });
            }
            for field in ["total_tokens", "wall_time_seconds", "tool_calls"] {
                if let Some(v) = cost.get(field) {
                    if !v.is_null() && !(v.is_i64() && v.as_i64().unwrap() >= 0) && !(v.is_u64()) {
                        findings.push(Finding {
                            severity: "ERROR",
                            message: format!(
                                "{prefix} cost.{field} must be a non-negative integer or null"
                            ),
                        });
                    }
                }
            }
            if let Some(hm) = cost.get("human_minutes") {
                if !hm.is_null()
                    && !(hm.as_f64().map(|n| n >= 0.0).unwrap_or(false) && !hm.is_boolean())
                {
                    findings.push(Finding {
                        severity: "ERROR",
                        message: format!(
                            "{prefix} cost.human_minutes must be a non-negative number or null"
                        ),
                    });
                }
            }
        }
        _ => findings.push(Finding {
            severity: "ERROR",
            message: format!("{prefix} cost must be an object"),
        }),
    }
    findings
}

pub fn validate_trace(trace: &Value, block_number: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !trace.is_object() {
        return vec![Finding {
            severity: "ERROR",
            message: format!("JSON block {block_number} is not an object"),
        }];
    }
    let (unknown, _) = field_diff(trace, ALLOWED_TOP_LEVEL);
    if !unknown.is_empty() {
        findings.push(Finding {
            severity: "ERROR",
            message: format!(
                "JSON block {block_number} has unknown top-level fields: {}",
                unknown.join(", ")
            ),
        });
    }
    let required: BTreeSet<&str> = REQUIRED_TOP_LEVEL.iter().copied().collect();
    let have: BTreeSet<&str> = trace
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let miss: Vec<_> = required.difference(&have).copied().collect();
    if !miss.is_empty() {
        findings.push(Finding {
            severity: "ERROR",
            message: format!(
                "JSON block {block_number} is missing top-level fields: {}",
                miss.join(", ")
            ),
        });
    }
    if trace.get("trace_version").and_then(Value::as_str) != Some(RESIDUAL_TRACE_VERSION) {
        findings.push(Finding {
            severity: "ERROR",
            message: format!(
                "JSON block {block_number} trace_version must be {RESIDUAL_TRACE_VERSION}"
            ),
        });
    }
    match trace.get("action_binding_sha256").and_then(Value::as_str) {
        Some(b) if is_digest_str(b) => {}
        _ => findings.push(Finding {
            severity: "ERROR",
            message: format!("JSON block {block_number} action_binding_sha256 is invalid"),
        }),
    }
    if !is_nonempty_string(trace.get("question")) {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("JSON block {block_number} question must be a non-empty string"),
        });
    }
    if !ALLOWED_INSTRUMENTS.contains(&trace.get("instrument").and_then(Value::as_str).unwrap_or("")) {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("JSON block {block_number} instrument is invalid"),
        });
    }
    if !ALLOWED_ACTION_BOUNDARIES
        .contains(&trace.get("action_boundary").and_then(Value::as_str).unwrap_or(""))
    {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("JSON block {block_number} action_boundary is invalid"),
        });
    }
    if !ALLOWED_HIGHBALL_DECISIONS
        .contains(&trace.get("highball_decision").and_then(Value::as_str).unwrap_or(""))
    {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("JSON block {block_number} highball_decision is invalid"),
        });
    }
    if trace.get("trial_manifest").is_some() {
        findings.extend(validate_trial_manifest(&trace["trial_manifest"], block_number));
    }
    let action_boundary = trace.get("action_boundary").and_then(Value::as_str);
    let highball_decision = trace.get("highball_decision").and_then(Value::as_str);
    let Some(residuals) = trace.get("residuals").and_then(Value::as_array) else {
        findings.push(Finding {
            severity: "ERROR",
            message: format!("JSON block {block_number} residuals must be an array"),
        });
        return findings;
    };
    let mut high_risk_open = false;
    let mut high_risk_unsupported = false;
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    for (index, residual) in residuals.iter().enumerate() {
        let prefix = format!("JSON block {block_number} residual {}", index + 1);
        if !residual.is_object() {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} is not an object"),
            });
            continue;
        }
        let (unk, miss) = field_diff(residual, ALLOWED_RESIDUAL_FIELDS);
        if !unk.is_empty() {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} has unknown fields: {}", unk.join(", ")),
            });
        }
        if !miss.is_empty() {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} is missing fields: {}", miss.join(", ")),
            });
        }
        let residual_id = residual.get("id").and_then(Value::as_str).unwrap_or("");
        if residual_id.trim().is_empty() {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} id must be a non-empty string"),
            });
        } else if !seen_ids.insert(residual_id.to_string()) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} has duplicate id {residual_id}"),
            });
        }
        let severity = residual.get("severity").and_then(Value::as_str).unwrap_or("");
        if !ALLOWED_SEVERITIES.contains(&severity) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} severity is invalid"),
            });
        }
        if !ALLOWED_TYPES.contains(&residual.get("type").and_then(Value::as_str).unwrap_or("")) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} type is invalid"),
            });
        }
        if !is_nonempty_string(residual.get("source")) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} source must be a non-empty string"),
            });
        }
        if !is_nonempty_string(residual.get("finding")) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} finding must be a non-empty string"),
            });
        }
        if !is_string_array(residual.get("affected_paths")) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} affected_paths must be an array of strings"),
            });
        }
        if let Some(v) = residual.get("error_signature") {
            if !v.is_null() && !v.is_string() {
                findings.push(Finding {
                    severity: "ERROR",
                    message: format!("{prefix} error_signature must be a string or null"),
                });
            }
        }
        if let Some(v) = residual.get("evidence") {
            if !v.is_null() && !v.is_string() {
                findings.push(Finding {
                    severity: "ERROR",
                    message: format!("{prefix} evidence must be a string or null"),
                });
            }
        }
        if !ALLOWED_DISPOSITIONS
            .contains(&residual.get("disposition").and_then(Value::as_str).unwrap_or(""))
        {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} disposition is invalid"),
            });
        }
        if !ALLOWED_REQUIRED_CLOSURE
            .contains(&residual.get("required_closure").and_then(Value::as_str).unwrap_or(""))
        {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} required_closure is invalid"),
            });
        }
        let closure_state = residual.get("closure_state").and_then(Value::as_str).unwrap_or("");
        if !ALLOWED_CLOSURE_STATES.contains(&closure_state) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} closure_state is invalid"),
            });
        }
        if !is_closure_evidence_array(residual.get("closure_evidence")) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} closure_evidence must be an array of strings or nulls"),
            });
        }
        if !residual.get("scope").map(Value::is_string).unwrap_or(false) {
            findings.push(Finding {
                severity: "ERROR",
                message: format!("{prefix} scope must be a string"),
            });
        }
        if HIGH_RISK_SEVERITIES.contains(&severity) {
            if closure_state == "open" {
                high_risk_open = true;
            } else if matches!(closure_state, "closed" | "blocked" | "not_applicable" | "waived") {
                if !has_closure_evidence(residual.get("closure_evidence")) {
                    high_risk_unsupported = true;
                }
                if !is_nonempty_string(residual.get("scope")) {
                    high_risk_unsupported = true;
                }
            }
            let rid = if residual_id.is_empty() {
                "unknown"
            } else {
                residual_id
            };
            if closure_state == "open" {
                findings.push(Finding {
                    severity: "BLOCK",
                    message: format!("{prefix} {rid} is high-risk and open"),
                });
            } else if matches!(closure_state, "closed" | "blocked" | "not_applicable")
                && !has_closure_evidence(residual.get("closure_evidence"))
            {
                findings.push(Finding {
                    severity: "BLOCK",
                    message: format!("{prefix} {rid} has {closure_state} without closure evidence"),
                });
            } else if closure_state == "waived" {
                if !has_closure_evidence(residual.get("closure_evidence")) {
                    findings.push(Finding {
                        severity: "BLOCK",
                        message: format!("{prefix} {rid} waiver lacks evidence"),
                    });
                }
                if !is_nonempty_string(residual.get("scope")) {
                    findings.push(Finding {
                        severity: "BLOCK",
                        message: format!("{prefix} {rid} waiver lacks scope"),
                    });
                }
            } else if matches!(closure_state, "closed" | "blocked" | "not_applicable")
                && !is_nonempty_string(residual.get("scope"))
            {
                findings.push(Finding {
                    severity: "BLOCK",
                    message: format!("{prefix} {rid} has {closure_state} without scope"),
                });
            }
        }
    }
    if matches!(action_boundary, Some("protected_write" | "irreversible")) {
        if matches!(highball_decision, Some("block" | "escalate")) {
            findings.push(Finding {
                severity: "BLOCK",
                message: format!(
                    "JSON block {block_number} decision {} blocks the action boundary",
                    highball_decision.unwrap()
                ),
            });
        }
        if highball_decision == Some("pass") && high_risk_open {
            findings.push(Finding {
                severity: "BLOCK",
                message: format!(
                    "JSON block {block_number} decision pass conflicts with open high-risk residuals"
                ),
            });
        }
        if highball_decision == Some("pass") && high_risk_unsupported {
            findings.push(Finding {
                severity: "BLOCK",
                message: format!(
                    "JSON block {block_number} decision pass conflicts with unsupported high-risk closure"
                ),
            });
        }
    }
    findings
}

pub fn validate_file(path: &Path) -> Result<(Vec<Finding>, bool), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read verdict file: {e}"))?;
    let (blocks, raw_json_mode) = candidate_blocks(&text, path);
    if blocks.is_empty() {
        return Err("verdict has no JSON residual closure ledger".into());
    }
    let mut saw_trace = false;
    let mut all = Vec::new();
    for (block_number, block) in blocks {
        match serde_json::from_str::<Value>(&block) {
            Ok(parsed) if parsed.get("residuals").map(Value::is_array).unwrap_or(false) => {
                saw_trace = true;
                all.extend(validate_trace(&parsed, block_number));
            }
            Ok(_) => {}
            Err(exc) => {
                let label = if raw_json_mode {
                    "raw JSON".into()
                } else {
                    format!("JSON block {block_number}")
                };
                all.push(Finding {
                    severity: "ERROR",
                    message: format!("{label} is invalid JSON: {exc}"),
                });
            }
        }
    }
    if !saw_trace {
        return Err(if raw_json_mode {
            "raw JSON file does not contain a residuals array".into()
        } else {
            "verdict JSON found but no residual closure ledger".into()
        });
    }
    Ok((all, true))
}
