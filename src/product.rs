//! Verify QUINTE product bundles against the active HIGHBALL contract.

use crate::contracts::{
    action_binding_sha256, is_digest, parse_utc_timestamp, sha256_bytes, QUINTE_BRIEF_VERSION,
    QUINTE_CLI_ENVELOPE_VERSION, QUINTE_HOST_RECEIPT_VERSION, QUINTE_MANIFEST_VERSION,
    QUINTE_PROTOCOL_VERSION, QUINTE_RESULT_VERSION, QUINTE_TRIAL_MANIFEST_VERSION,
};
use chrono::{Duration, Utc};
use crate::jsonutil::{exact_fields, load_object, nonempty, path_is_within, resolve_ref, string_list};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

const BRIEF_FIELDS: &[&str] = &[
    "brief_version",
    "question",
    "context",
    "evidence_roots",
    "snapshot_ignore",
    "attachments",
    "action_scope",
    "affected_paths",
    "action_binding_sha256",
];
const MANIFEST_FIELDS: &[&str] = &[
    "manifest_version",
    "run_id",
    "created_at",
    "updated_at",
    "status",
    "brief_sha256",
    "policy_sha256",
    "snapshot_sha256",
    "runtime_sha256",
    "protocol_version",
    "effective_model",
    "seat_binding",
    "route_bindings",
    "sandbox_mode",
    "current_phase",
    "error",
    "r3_input_receipt",
    "primary_arbiter_challenge",
    "primary_arbiter_submission",
    "result_sha256",
];
const RESULT_FIELDS: &[&str] = &[
    "result_version",
    "run_id",
    "status",
    "brief_sha256",
    "question",
    "action_scope",
    "affected_paths",
    "action_binding_sha256",
    "seat_binding",
    "route_bindings",
    "summary",
    "recommendation",
    "dissent",
    "residuals",
    "trial_manifest",
];
const RESIDUAL_FIELDS: &[&str] = &[
    "id",
    "severity",
    "residual_type",
    "source",
    "finding",
    "evidence_refs",
    "disposition",
    "required_closure",
    "closure_state",
    "closure_evidence",
    "scope",
];
const TRIAL_FIELDS: &[&str] = &[
    "manifest_version",
    "base_model_relation",
    "perspective_count",
    "perspectives",
    "perturbation_axes",
    "independence_controls",
    "contamination_risks",
    "wall_time_seconds",
];
const PERSPECTIVE_FIELDS: &[&str] = &[
    "party_id",
    "route_id",
    "r1_artifact",
    "r2_artifact",
    "independent_first_pass",
];
const PARTIES: &[&str] = &[
    "Party A",
    "Party B",
    "Party C",
    "Party D",
    "Party E",
    "Counterpart Arbiter",
    "Primary Arbiter",
];
const HOST_RECEIPT_FIELDS: &[&str] = &[
    "host_receipt_version",
    "invocation_id",
    "receipt_path",
    "operation",
    "observed_at",
    "state_root",
    "state",
    "run_id",
    "preflight",
    "brief",
    "manifest",
    "result",
    "recovery",
];
const HOST_STATE_FIELDS: &[&str] = &["code", "active_run_ids", "worker", "attempts", "blockers"];
const HOST_STATE_CODES: &[&str] = &[
    "ready",
    "preflight_failed",
    "active_run_present",
    "created",
    "started",
    "launch_failed",
    "observed",
    "terminal",
    "reconciled",
    "no_active_run",
    "ambiguous_active_runs",
];
const HOST_MANIFEST_FIELDS: &[&str] = &[
    "status",
    "manifest_version",
    "brief_sha256",
    "policy_sha256",
    "snapshot_sha256",
    "runtime_sha256",
    "worker_pid",
    "error",
    "result_sha256",
];
const HOST_RESULT_FIELDS: &[&str] = &["verified", "actionable", "contract_version", "sha256", "path"];
const HOST_RECOVERY_FIELDS: &[&str] = &["outcome", "launch_safe", "receipt_path"];
const HOST_REQUIRED_MANIFEST_FIELDS: &[&str] = &[
    "status",
    "manifest_version",
    "brief_sha256",
    "policy_sha256",
    "snapshot_sha256",
    "runtime_sha256",
    "result_sha256",
];
const SEAT_BINDING_FIELDS: &[&str] = &["seat_id", "family", "provider", "text_model", "multimodal_model"];
const ROUTE_BINDING_FIELDS: &[&str] = &[
    "party_id",
    "route_id",
    "adapter",
    "executable",
    "family",
    "provider",
    "text_model",
    "multimodal_model",
    "perspective",
];

pub fn trusted_runs_root() -> PathBuf {
    let root = std::env::var("QUINTE_HOME")
        .ok()
        .map(|s| {
            let p = PathBuf::from(s);
            if p.starts_with("~") {
                if let Some(home) = home_dir() {
                    return home.join(p.strip_prefix("~").unwrap_or(&p));
                }
            }
            p
        })
        .unwrap_or_else(|| home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".quinte"));
    std::fs::canonicalize(root.join("runs")).unwrap_or_else(|_| root.join("runs"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

pub fn is_canonical_uuid_v7(value: &str) -> bool {
    match Uuid::parse_str(value) {
        Ok(parsed) => {
            parsed.get_version_num() == 7
                && parsed.get_variant() == uuid::Variant::RFC4122
                && parsed.to_string() == value
        }
        Err(_) => false,
    }
}

pub fn is_canonical_uuid(value: &str) -> bool {
    match Uuid::parse_str(value) {
        Ok(parsed) => parsed.to_string() == value,
        Err(_) => false,
    }
}

pub fn active_quinte_binary() -> Result<Option<PathBuf>, String> {
    let Some(configured) = std::env::var("HIGHBALL_QUINTE_BIN").ok() else {
        return Ok(None);
    };
    let configured_path = PathBuf::from(&configured);
    if !configured_path.is_absolute() {
        return Err("HIGHBALL_QUINTE_BIN must be an absolute path".into());
    }
    if !configured_path.is_file() {
        return Err("HIGHBALL_QUINTE_BIN must name an executable regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&configured_path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err("HIGHBALL_QUINTE_BIN must name an executable regular file".into());
        }
    }
    Ok(Some(
        std::fs::canonicalize(&configured_path).unwrap_or(configured_path),
    ))
}

fn validate_residual(value: &Value, index: usize, errors: &mut Vec<String>) {
    let label = format!("quinte result residuals[{index}]");
    if !value.is_object() {
        errors.push(format!("{label} must be an object"));
        return;
    }
    exact_fields(value, RESIDUAL_FIELDS, &label, errors);
    if !nonempty(value.get("id")) {
        errors.push(format!("{label}.id must be a non-empty string"));
    }
    if !["LOW", "MEDIUM", "HIGH", "CRITICAL", "P0"]
        .contains(&value.get("severity").and_then(Value::as_str).unwrap_or(""))
    {
        errors.push(format!("{label}.severity is invalid"));
    }
    for field in ["residual_type", "source", "finding", "required_closure", "scope"] {
        if !nonempty(value.get(field)) {
            errors.push(format!("{label}.{field} must be a non-empty string"));
        }
    }
    for field in ["evidence_refs", "closure_evidence"] {
        if !string_list(value.get(field), false) {
            errors.push(format!("{label}.{field} must be an array of strings"));
        }
    }
    if !["verified", "falsified", "unresolved", "escalated", "discarded"]
        .contains(&value.get("disposition").and_then(Value::as_str).unwrap_or(""))
    {
        errors.push(format!("{label}.disposition is invalid"));
    }
    if !["open", "closed", "blocked", "waived", "not_applicable"]
        .contains(&value.get("closure_state").and_then(Value::as_str).unwrap_or(""))
    {
        errors.push(format!("{label}.closure_state is invalid"));
    }
}

fn validate_trial_manifest(value: &Value, route_bindings: &Value, errors: &mut Vec<String>) {
    let label = "quinte result trial_manifest";
    if !value.is_object() {
        errors.push(format!("{label} must be an object"));
        return;
    }
    exact_fields(value, TRIAL_FIELDS, label, errors);
    if value.get("manifest_version").and_then(Value::as_str) != Some(QUINTE_TRIAL_MANIFEST_VERSION) {
        errors.push(format!("{label}.manifest_version is unsupported"));
    }
    if value.get("base_model_relation").and_then(Value::as_str) != Some("same_model") {
        errors.push(format!("{label}.base_model_relation must be same_model"));
    }
    let perspectives = value.get("perspectives").and_then(Value::as_array);
    if value.get("perspective_count").and_then(Value::as_i64) != Some(5)
        || !matches!(perspectives, Some(p) if p.len() == 5)
    {
        errors.push(format!("{label} must contain exactly five perspectives"));
    }
    let perspectives = perspectives.cloned().unwrap_or_default();
    let routes = route_bindings.as_array().cloned().unwrap_or_default();
    for (index, perspective) in perspectives.iter().enumerate() {
        let item_label = format!("{label}.perspectives[{index}]");
        if !perspective.is_object() {
            errors.push(format!("{item_label} must be an object"));
            continue;
        }
        exact_fields(perspective, PERSPECTIVE_FIELDS, &item_label, errors);
        let expected_party = PARTIES.get(index).copied();
        let expected_route = routes.get(index).and_then(|r| r.get("route_id")).and_then(Value::as_str);
        if perspective.get("party_id").and_then(Value::as_str) != expected_party
            || perspective.get("route_id").and_then(Value::as_str) != expected_route
        {
            errors.push(format!("{item_label} does not match the bound QUINTE route"));
        }
        let expected_r1 = expected_route.map(|r| format!("lanes/R1/{r}/accepted.json"));
        let expected_r2 = expected_route.map(|r| format!("lanes/R2/{r}/accepted.json"));
        if perspective.get("r1_artifact").and_then(Value::as_str) != expected_r1.as_deref() {
            errors.push(format!("{item_label}.r1_artifact is invalid"));
        }
        if perspective.get("r2_artifact").and_then(Value::as_str) != expected_r2.as_deref() {
            errors.push(format!("{item_label}.r2_artifact is invalid"));
        }
        if perspective.get("independent_first_pass") != Some(&Value::Bool(true)) {
            errors.push(format!("{item_label}.independent_first_pass must be true"));
        }
    }
    for field in ["perturbation_axes", "independence_controls", "contamination_risks"] {
        if !string_list(value.get(field), true) {
            errors.push(format!("{label}.{field} must be an array of non-empty strings"));
        }
    }
    if let Some(wall) = value.get("wall_time_seconds") {
        if !wall.is_null() && !(wall.is_i64() && !wall.is_boolean() && wall.as_i64().unwrap() >= 0) {
            errors.push(format!("{label}.wall_time_seconds must be a non-negative integer or null"));
        }
    }
}

fn validate_binding(value: &Value, label: &str, errors: &mut Vec<String>) -> Option<Value> {
    if !value.is_object() {
        errors.push(format!("{label} must be an object"));
        return None;
    }
    exact_fields(value, SEAT_BINDING_FIELDS, label, errors);
    for field in SEAT_BINDING_FIELDS {
        match value.get(*field).and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() && !s.chars().any(char::is_whitespace) => {}
            _ => errors.push(format!("{label}.{field} must be a non-empty identifier")),
        }
    }
    Some(value.clone())
}

fn validate_route_bindings(
    value: &Value,
    seat: Option<&Value>,
    label: &str,
    errors: &mut Vec<String>,
) -> Vec<Value> {
    let Some(arr) = value.as_array() else {
        errors.push(format!("{label} must contain exactly seven role bindings"));
        return Vec::new();
    };
    if arr.len() != 7 {
        errors.push(format!("{label} must contain exactly seven role bindings"));
        return Vec::new();
    }
    let mut routes = Vec::new();
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    for (index, item) in arr.iter().enumerate() {
        let item_label = format!("{label}[{index}]");
        if !item.is_object() {
            errors.push(format!("{item_label} must be an object"));
            continue;
        }
        exact_fields(item, ROUTE_BINDING_FIELDS, &item_label, errors);
        if item.get("party_id").and_then(Value::as_str) != Some(PARTIES[index]) {
            errors.push(format!("{item_label}.party_id is out of order"));
        }
        match item.get("route_id").and_then(Value::as_str) {
            Some(id) if !id.trim().is_empty() && seen_ids.insert(id.to_string()) => {}
            _ => errors.push(format!("{item_label}.route_id must be a unique non-empty string")),
        }
        for field in ["adapter", "executable", "family", "provider", "text_model", "multimodal_model"] {
            if !nonempty(item.get(field)) {
                errors.push(format!("{item_label}.{field} must be a non-empty string"));
            }
        }
        if !item.get("perspective").map(Value::is_string).unwrap_or(false) {
            errors.push(format!("{item_label}.perspective must be a string"));
        }
        if let Some(seat) = seat {
            for field in ["family", "provider", "text_model", "multimodal_model"] {
                if item.get(field) != seat.get(field) {
                    errors.push(format!(
                        "{item_label}.{field} violates the single-family seat binding"
                    ));
                }
            }
        }
        routes.push(item.clone());
    }
    routes
}

fn validate_result(result: &Value, errors: &mut Vec<String>) {
    exact_fields(result, RESULT_FIELDS, "quinte result", errors);
    if result.get("result_version").and_then(Value::as_str) != Some(QUINTE_RESULT_VERSION) {
        errors.push(format!(
            "quinte result_version must be {QUINTE_RESULT_VERSION}; older results are archived-only"
        ));
    }
    match result.get("run_id").and_then(Value::as_str) {
        Some(id) if is_canonical_uuid(id) => {}
        _ => errors.push("quinte result run_id must be a canonical UUID".into()),
    }
    if !matches!(
        result.get("status").and_then(Value::as_str),
        Some("completed" | "degraded")
    ) {
        errors.push("quinte result status is invalid".into());
    }
    if !is_digest(result.get("brief_sha256")) {
        errors.push("quinte result brief_sha256 is invalid".into());
    }
    if !nonempty(result.get("question")) {
        errors.push("quinte result question must be a non-empty string".into());
    }
    if let Some(scope) = result.get("action_scope") {
        if !scope.is_null() && !scope.is_string() {
            errors.push("quinte result action_scope must be a string or null".into());
        }
    }
    if !string_list(result.get("affected_paths"), false) {
        errors.push("quinte result affected_paths must be an array of strings".into());
    }
    if !is_digest(result.get("action_binding_sha256")) {
        errors.push("quinte result action_binding_sha256 must be a sha256 digest".into());
    }
    for field in ["summary", "recommendation"] {
        if !nonempty(result.get(field)) {
            errors.push(format!("quinte result {field} must be a non-empty string"));
        }
    }
    if !string_list(result.get("dissent"), false) {
        errors.push("quinte result dissent must be an array of strings".into());
    }
    match result.get("residuals") {
        Some(Value::Array(residuals)) => {
            let mut seen = BTreeSet::new();
            for (index, residual) in residuals.iter().enumerate() {
                validate_residual(residual, index, errors);
                if let Some(id) = residual.get("id").and_then(Value::as_str) {
                    if nonempty(residual.get("id")) && !seen.insert(id.to_string()) {
                        errors.push(format!("quinte result residual id is duplicated: {id}"));
                    }
                }
            }
        }
        _ => errors.push("quinte result residuals must be an array".into()),
    }
    let seat = result
        .get("seat_binding")
        .and_then(|v| validate_binding(v, "quinte result seat_binding", errors));
    let routes = result.get("route_bindings").cloned().unwrap_or(Value::Null);
    let routes = validate_route_bindings(&routes, seat.as_ref(), "quinte result route_bindings", errors);
    let routes_v = Value::Array(routes);
    if let Some(tm) = result.get("trial_manifest") {
        validate_trial_manifest(tm, &routes_v, errors);
    } else {
        validate_trial_manifest(&Value::Null, &routes_v, errors);
    }
}

fn validate_brief(brief: &Value, errors: &mut Vec<String>) {
    exact_fields(brief, BRIEF_FIELDS, "quinte brief", errors);
    if brief.get("brief_version").and_then(Value::as_str) != Some(QUINTE_BRIEF_VERSION) {
        errors.push(format!("quinte brief_version must be {QUINTE_BRIEF_VERSION}"));
    }
    if !nonempty(brief.get("question")) {
        errors.push("quinte brief question must be a non-empty string".into());
    }
    if let Some(ctx) = brief.get("context") {
        if !ctx.is_null() && !ctx.is_string() {
            errors.push("quinte brief context must be a string or null".into());
        }
    }
    for field in ["evidence_roots", "snapshot_ignore", "attachments", "affected_paths"] {
        if !string_list(brief.get(field), false) {
            errors.push(format!("quinte brief {field} must be an array of strings"));
        }
    }
    if let Some(scope) = brief.get("action_scope") {
        if !scope.is_null() && !scope.is_string() {
            errors.push("quinte brief action_scope must be a string or null".into());
        }
    }
    if !is_digest(brief.get("action_binding_sha256")) {
        errors.push("quinte brief action_binding_sha256 must be a sha256 digest".into());
    }
}

fn canonical_brief_sha256(brief: &Value) -> String {
    sha256_bytes(&crate::jsonutil::canonical_bytes_fields(brief, BRIEF_FIELDS))
}

pub fn summarize(
    r#ref: &str,
    request: &Value,
    base_dir: Option<&Path>,
    verify_cli: bool,
) -> (Option<Value>, Vec<String>) {
    let mut errors = Vec::new();
    let path = resolve_ref(r#ref, base_dir);
    if !path.is_file() {
        return (None, vec![format!("quinte result does not exist: {ref}")]);
    }
    if path.file_name().and_then(|s| s.to_str()) != Some("result.json") {
        errors.push("active QUINTE result must use the standard result.json filename".into());
    }
    let run_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let runs_root = trusted_runs_root();
    if !path_is_within(&runs_root, &run_dir) {
        errors.push(format!(
            "active QUINTE result is outside the trusted runs root: {}",
            runs_root.display()
        ));
    }
    if run_dir.parent() != Some(runs_root.as_path()) {
        errors.push("active QUINTE result must be directly inside its canonical run directory".into());
    }
    let result_bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => return (None, {
            errors.push(format!("quinte product bundle cannot be read: {e}"));
            errors
        }),
    };
    let result: Value = match serde_json::from_slice(&result_bytes) {
        Ok(v) => v,
        Err(e) => return (None, {
            errors.push(format!("quinte product bundle cannot be read: {e}"));
            errors
        }),
    };
    let manifest = match load_object(&run_dir.join("manifest.json")) {
        Ok(v) => v,
        Err(e) => return (None, {
            errors.push(format!("quinte product bundle cannot be read: {e}"));
            errors
        }),
    };
    let brief = match load_object(&run_dir.join("input").join("brief.json")) {
        Ok(v) => v,
        Err(e) => return (None, {
            errors.push(format!("quinte product bundle cannot be read: {e}"));
            errors
        }),
    };
    if !result.is_object() {
        errors.push("quinte result must be a JSON object".into());
        return (None, errors);
    }
    validate_result(&result, &mut errors);
    validate_brief(&brief, &mut errors);
    exact_fields(&manifest, MANIFEST_FIELDS, "quinte manifest", &mut errors);
    if manifest.get("manifest_version").and_then(Value::as_str) != Some(QUINTE_MANIFEST_VERSION) {
        errors.push("quinte manifest_version is unsupported".into());
    }
    if manifest.get("protocol_version").and_then(Value::as_str) != Some(QUINTE_PROTOCOL_VERSION) {
        errors.push("quinte protocol_version is unsupported".into());
    }
    let manifest_seat = manifest
        .get("seat_binding")
        .and_then(|v| validate_binding(v, "quinte manifest seat_binding", &mut errors));
    if let Some(rb) = manifest.get("route_bindings") {
        validate_route_bindings(rb, manifest_seat.as_ref(), "quinte manifest route_bindings", &mut errors);
    } else {
        validate_route_bindings(&Value::Null, manifest_seat.as_ref(), "quinte manifest route_bindings", &mut errors);
    }
    if manifest.get("seat_binding") != result.get("seat_binding") {
        errors.push("quinte manifest and result seat bindings differ".into());
    }
    if manifest.get("route_bindings") != result.get("route_bindings") {
        errors.push("quinte manifest and result route bindings differ".into());
    }
    if let Some(seat) = &manifest_seat {
        if manifest.get("effective_model") != seat.get("text_model") {
            errors.push("quinte effective_model differs from the seat text model".into());
        }
    }
    for field in ["brief_sha256", "policy_sha256", "snapshot_sha256", "runtime_sha256", "result_sha256"] {
        if !is_digest(manifest.get(field)) {
            errors.push(format!("quinte manifest {field} is invalid"));
        }
    }
    if manifest.get("status").and_then(Value::as_str) != Some("completed")
        || result.get("status").and_then(Value::as_str) != Some("completed")
    {
        errors.push("only a completed QUINTE run can authorize an action".into());
    }
    let run_id = result.get("run_id").and_then(Value::as_str);
    if manifest.get("run_id").and_then(Value::as_str) != run_id
        || run_dir.file_name().and_then(|s| s.to_str()) != run_id
    {
        errors.push("quinte result run_id is not bound to its manifest and run directory".into());
    }
    let result_sha256 = sha256_bytes(&result_bytes);
    if manifest.get("result_sha256").and_then(Value::as_str) != Some(result_sha256.as_str()) {
        errors.push("quinte result digest does not match its manifest".into());
    }
    let brief_sha256 = canonical_brief_sha256(&brief);
    if manifest.get("brief_sha256").and_then(Value::as_str) != Some(brief_sha256.as_str())
        || result.get("brief_sha256").and_then(Value::as_str) != Some(brief_sha256.as_str())
    {
        errors.push("quinte brief digest does not match the brief, manifest, and result".into());
    }
    let expected_binding = action_binding_sha256(request);
    for (label, value) in [
        ("brief", brief.get("action_binding_sha256")),
        ("result", result.get("action_binding_sha256")),
    ] {
        if value.and_then(Value::as_str) != Some(expected_binding.as_str()) {
            errors.push(format!("quinte {label} action binding does not match the route request"));
        }
    }
    for field in ["question", "action_scope", "affected_paths"] {
        let expected = request.get(field);
        if brief.get(field) != expected || result.get(field) != expected {
            errors.push(format!("quinte brief/result {field} does not match the route request"));
        }
    }
    if verify_cli {
        verify_quinte_cli(&result, &manifest, &mut errors);
    }
    let outcome = json!({
        "result_ref": path.display().to_string(),
        "run_id": result.get("run_id").and_then(Value::as_str).unwrap_or(""),
        "status": result.get("status").and_then(Value::as_str).unwrap_or(""),
        "result_version": result.get("result_version").and_then(Value::as_str).unwrap_or(""),
        "result_sha256": result_sha256,
        "brief_sha256": result.get("brief_sha256").and_then(Value::as_str).unwrap_or(""),
        "question": result.get("question").and_then(Value::as_str).unwrap_or(""),
        "action_scope": result.get("action_scope").cloned().unwrap_or(Value::Null),
        "affected_paths": if string_list(result.get("affected_paths"), false) {
            result.get("affected_paths").cloned().unwrap()
        } else {
            json!([])
        },
        "action_binding_sha256": result.get("action_binding_sha256").and_then(Value::as_str).unwrap_or(""),
    });
    (Some(outcome), errors)
}

fn verify_quinte_cli(result: &Value, manifest: &Value, errors: &mut Vec<String>) {
    let state_root_value = std::env::var("QUINTE_HOME").ok();
    if state_root_value.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
        errors.push("QUINTE_HOME must explicitly pin an absolute QUINTE state root".into());
        return;
    }
    let state_root_value = state_root_value.unwrap();
    if !Path::new(&state_root_value).is_absolute() {
        errors.push("QUINTE_HOME must be an absolute path".into());
        return;
    }
    if std::env::var("HIGHBALL_QUINTE_BIN").ok().filter(|s| !s.is_empty()).is_none() {
        errors.push("HIGHBALL_QUINTE_BIN must explicitly pin an absolute QUINTE executable".into());
        return;
    }
    let binary_value = std::env::var("HIGHBALL_QUINTE_BIN").unwrap();
    if !Path::new(&binary_value).is_absolute() {
        errors.push("HIGHBALL_QUINTE_BIN must be an absolute path".into());
        return;
    }
    let quinte_binary = match active_quinte_binary() {
        Ok(Some(p)) => p,
        Ok(None) => {
            errors.push("HIGHBALL_QUINTE_BIN does not name an executable regular file".into());
            return;
        }
        Err(e) => {
            errors.push(e);
            return;
        }
    };
    let runs_root_for_cli = trusted_runs_root();
    let binary_sha256 = match std::fs::read(&quinte_binary) {
        Ok(b) => sha256_bytes(&b),
        Err(e) => {
            errors.push(format!("trusted quinte executable cannot be read: {e}"));
            return;
        }
    };
    if manifest.get("runtime_sha256").and_then(Value::as_str) != Some(binary_sha256.as_str()) {
        errors.push("quinte manifest runtime digest does not match the pinned executable".into());
        return;
    }
    let run_id = result.get("run_id").and_then(Value::as_str).unwrap_or("");
    let state_root = runs_root_for_cli.parent().unwrap_or(Path::new("."));
    match run_quinte_inspect(&quinte_binary, run_id, state_root, QUINTE_CLI_INSPECT_TIMEOUT) {
        Err(e) => errors.push(e),
        Ok(inspected) => {
            let data = if inspected.get("cli_envelope_version").and_then(Value::as_str)
                == Some(QUINTE_CLI_ENVELOPE_VERSION)
                && inspected.get("ok") == Some(&Value::Bool(true))
            {
                inspected.get("data")
            } else {
                None
            };
            let inspected_manifest = data.and_then(|d| d.get("manifest"));
            let inspected_result = data.and_then(|d| d.get("result"));
            if inspected_manifest != Some(manifest) || inspected_result != Some(result) {
                errors.push("quinte CLI state differs from the bound manifest or result".into());
            }
        }
    }
}

/// The Python verifier fails closed after 15 seconds when the pinned QUINTE
/// binary hangs (lock wait, blocked input). The Rust cross-check keeps the
/// same bound so a wedged executable cannot block packet builds, validation,
/// or the protected-write guard forever.
const QUINTE_CLI_INSPECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn run_quinte_inspect(
    quinte_binary: &Path,
    run_id: &str,
    state_root: &Path,
    timeout: std::time::Duration,
) -> Result<Value, String> {
    use std::io::Read;
    use std::process::Stdio;

    let mut child = Command::new(quinte_binary)
        .args(["inspect", run_id, "--json"])
        .env("QUINTE_HOME", state_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("quinte CLI state inspection failed: {e}"))?;
    let mut stdout_pipe = child.stdout.take().expect("piped child stdout");
    let reader = std::thread::spawn(move || {
        let mut stdout = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut stdout);
        stdout
    });
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = reader.join().unwrap_or_default();
                if !status.success() {
                    return Err(
                        "quinte CLI does not report the run as a completed valid product".into(),
                    );
                }
                return serde_json::from_slice(&stdout)
                    .map_err(|_| "quinte CLI state inspection did not return JSON".to_string());
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "quinte CLI state inspection failed: timed out after {}s",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => return Err(format!("quinte CLI state inspection failed: {e}")),
        }
    }
}

pub fn load_quinte_host_receipt(
    r#ref: &str,
    request: &Value,
    base_dir: Option<&Path>,
) -> (Option<Value>, Vec<String>) {
    let mut errors = Vec::new();
    let supplied = resolve_ref(r#ref, base_dir);
    if !supplied.is_file() {
        return (None, vec![format!("QUINTE host receipt does not exist: {ref}")]);
    }
    let supplied_raw = match std::fs::read(&supplied) {
        Ok(b) => b,
        Err(e) => return (None, vec![format!("QUINTE host receipt cannot be read: {e}")]),
    };
    let parsed: Value = match serde_json::from_slice(&supplied_raw) {
        Ok(v) => v,
        Err(e) => return (None, vec![format!("QUINTE host receipt is not valid JSON: {e}")]),
    };
    if !parsed.is_object() {
        return (None, vec!["QUINTE host receipt must be a JSON object".into()]);
    }
    let envelope = ["cli_envelope_version", "ok", "data"]
        .iter()
        .any(|f| parsed.get(*f).is_some());
    let mut value = parsed.clone();
    if envelope {
        let have: BTreeSet<&str> = parsed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let allowed: BTreeSet<&str> = ["cli_envelope_version", "ok", "data"].into_iter().collect();
        let unknown: Vec<_> = have.difference(&allowed).copied().collect();
        let missing: Vec<_> = allowed.difference(&have).copied().collect();
        if !unknown.is_empty() {
            errors.push(format!(
                "QUINTE host envelope has unknown fields: {}",
                unknown.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "QUINTE host envelope is missing fields: {}",
                missing.join(", ")
            ));
        }
        if parsed.get("cli_envelope_version").and_then(Value::as_str) != Some(QUINTE_CLI_ENVELOPE_VERSION)
        {
            errors.push("QUINTE host envelope version is unsupported".into());
        }
        if parsed.get("ok") != Some(&Value::Bool(true))
            || !parsed.get("data").map(Value::is_object).unwrap_or(false)
        {
            errors.push("QUINTE host envelope is not a successful data envelope".into());
        }
        value = parsed.get("data").cloned().unwrap_or(json!({}));
    }
    if !errors.is_empty() {
        return (None, errors);
    }
    let have: BTreeSet<&str> = value
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let allowed: BTreeSet<&str> = HOST_RECEIPT_FIELDS.iter().copied().collect();
    let unknown: Vec<_> = have.difference(&allowed).copied().collect();
    let required: BTreeSet<&str> = [
        "host_receipt_version",
        "invocation_id",
        "receipt_path",
        "operation",
        "observed_at",
        "state_root",
        "state",
    ]
    .into_iter()
    .collect();
    let missing: Vec<_> = required.difference(&have).copied().collect();
    if !unknown.is_empty() {
        errors.push(format!(
            "QUINTE host receipt has unknown fields: {}",
            unknown.join(", ")
        ));
    }
    if !missing.is_empty() {
        errors.push(format!(
            "QUINTE host receipt is missing fields: {}",
            missing.join(", ")
        ));
    }
    if value.get("host_receipt_version").and_then(Value::as_str) != Some(QUINTE_HOST_RECEIPT_VERSION) {
        errors.push("QUINTE host receipt version is unsupported".into());
    }
    if !matches!(
        value.get("operation").and_then(Value::as_str),
        Some("inspect" | "reconcile")
    ) {
        errors.push("QUINTE host receipt operation must be inspect or reconcile".into());
    }
    if parse_utc_timestamp(value.get("observed_at")).is_none() {
        errors.push("QUINTE host receipt observed_at must be an RFC 3339 UTC timestamp".into());
    } else if let Some(observed) =
        parse_utc_timestamp(value.get("observed_at")).map(|t| t.with_timezone(&Utc))
    {
        // The receipt is an observation of a run, not the run itself, so a
        // fresh observation may describe an old run.  What must stay fresh
        // is the verification act: the docs promise stale products block.
        let current = Utc::now();
        if observed > current + Duration::minutes(5) {
            errors.push("QUINTE host receipt observed_at is in the future".into());
        }
        if current.signed_duration_since(observed) > Duration::hours(24) {
            errors.push(
                "QUINTE host receipt is stale (observed more than twenty-four hours ago)".into(),
            );
        }
    }
    let invocation_id = value.get("invocation_id").and_then(Value::as_str);
    if !nonempty(value.get("invocation_id")) {
        errors.push("QUINTE host receipt invocation_id must be a non-empty string".into());
    } else if !is_canonical_uuid_v7(invocation_id.unwrap()) {
        errors.push("QUINTE host receipt invocation_id must be a canonical UUIDv7".into());
    }
    let run_id = value.get("run_id").and_then(Value::as_str);
    if let Some(rid) = run_id {
        if !is_canonical_uuid_v7(rid) {
            errors.push("QUINTE host receipt run_id must be a canonical UUIDv7 when present".into());
        }
    }
    let mut state_root: Option<PathBuf> = None;
    match value.get("state_root").and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => {
            let candidate = PathBuf::from(s);
            if !candidate.is_absolute() {
                errors.push("QUINTE host receipt state_root must be absolute".into());
            } else {
                let resolved = std::fs::canonicalize(&candidate).unwrap_or(candidate);
                let trusted = trusted_runs_root()
                    .parent()
                    .map(|p| std::fs::canonicalize(p).unwrap_or(p.to_path_buf()));
                if trusted.as_ref() != Some(&resolved) {
                    errors.push(
                        "QUINTE host receipt state_root does not match the trusted QUINTE state root"
                            .into(),
                    );
                }
                state_root = Some(resolved);
            }
        }
        _ => errors.push("QUINTE host receipt state_root must be a non-empty string".into()),
    }
    let receipt_path_value = value.get("receipt_path").and_then(Value::as_str);
    if !nonempty(value.get("receipt_path")) {
        errors.push("QUINTE host receipt receipt_path must be a non-empty string".into());
    } else {
        let durable_input = PathBuf::from(receipt_path_value.unwrap());
        if durable_input.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            errors.push("QUINTE host receipt receipt_path must not be a symlink".into());
        }
        if !durable_input.is_absolute() {
            errors.push("QUINTE host receipt receipt_path must be absolute".into());
        } else {
            let durable = std::fs::canonicalize(&durable_input).unwrap_or(durable_input.clone());
            let supplied_c = std::fs::canonicalize(&supplied).unwrap_or(supplied.clone());
            if !envelope && durable != supplied_c {
                errors.push(
                    "QUINTE host receipt receipt_path does not identify the supplied receipt".into(),
                );
            }
            if let (Some(sr), Some(iid)) = (&state_root, invocation_id) {
                let expected = sr.join("host").join("receipts").join(format!("{iid}.json"));
                let expected = std::fs::canonicalize(&expected).unwrap_or(expected);
                if durable != expected {
                    errors.push("QUINTE host receipt receipt_path is not bound to state_root".into());
                }
            }
            if let Some(iid) = invocation_id {
                if durable.file_name().and_then(|s| s.to_str()) != Some(&format!("{iid}.json")) {
                    errors.push("QUINTE host receipt receipt_path is not bound to invocation_id".into());
                }
            }
            if durable.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()) != Some("receipts")
                || durable
                    .parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                    != Some("host")
            {
                errors.push(
                    "QUINTE host receipt receipt_path is outside the durable host receipts directory"
                        .into(),
                );
            }
            if !durable.is_file() {
                errors.push("QUINTE host receipt durable receipt_path does not exist".into());
            } else if let Ok(text) = std::fs::read_to_string(&durable) {
                match serde_json::from_str::<Value>(&text) {
                    Ok(durable_value) => {
                        if durable_value != value {
                            errors.push("QUINTE host envelope does not match its durable receipt".into());
                        }
                    }
                    Err(e) => errors.push(format!("QUINTE durable host receipt cannot be parsed: {e}")),
                }
            }
        }
    }
    let state = value.get("state");
    if !matches!(state, Some(s) if s.is_object()) {
        errors.push("QUINTE host receipt state must be an object".into());
    } else if let Some(state) = state {
        let have: BTreeSet<&str> = state.as_object().unwrap().keys().map(String::as_str).collect();
        let allowed: BTreeSet<&str> = HOST_STATE_FIELDS.iter().copied().collect();
        let unknown: Vec<_> = have.difference(&allowed).copied().collect();
        let required: BTreeSet<&str> = ["code", "active_run_ids"].into_iter().collect();
        let missing: Vec<_> = required.difference(&have).copied().collect();
        if !unknown.is_empty() {
            errors.push(format!(
                "QUINTE host receipt state has unknown fields: {}",
                unknown.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "QUINTE host receipt state is missing fields: {}",
                missing.join(", ")
            ));
        }
        if !HOST_STATE_CODES.contains(&state.get("code").and_then(Value::as_str).unwrap_or("")) {
            errors.push("QUINTE host receipt state.code is invalid".into());
        }
        match state.get("active_run_ids") {
            Some(Value::Array(ids)) if ids.iter().all(Value::is_string) => {
                for id in ids {
                    if !is_canonical_uuid_v7(id.as_str().unwrap()) {
                        errors.push(
                            "QUINTE host receipt state.active_run_ids must contain canonical UUIDv7 values"
                                .into(),
                        );
                        break;
                    }
                }
                let set: BTreeSet<&str> = ids.iter().filter_map(Value::as_str).collect();
                if set.len() != ids.len() {
                    errors.push("QUINTE host receipt state.active_run_ids must be unique".into());
                }
            }
            _ => errors.push(
                "QUINTE host receipt state.active_run_ids must be an array of strings".into(),
            ),
        }
    }
    let recovery = value.get("recovery");
    if value.get("operation").and_then(Value::as_str) == Some("reconcile") {
        match recovery {
            Some(rec) if rec.is_object() => {
                let have: BTreeSet<&str> = rec.as_object().unwrap().keys().map(String::as_str).collect();
                let allowed: BTreeSet<&str> = HOST_RECOVERY_FIELDS.iter().copied().collect();
                let unknown: Vec<_> = have.difference(&allowed).copied().collect();
                let missing: Vec<_> = allowed.difference(&have).copied().collect();
                if !unknown.is_empty() {
                    errors.push(format!(
                        "QUINTE host receipt recovery has unknown fields: {}",
                        unknown.join(", ")
                    ));
                }
                if !missing.is_empty() {
                    errors.push(format!(
                        "QUINTE host receipt recovery is missing fields: {}",
                        missing.join(", ")
                    ));
                }
                if !matches!(
                    rec.get("outcome").and_then(Value::as_str),
                    Some("reconciled" | "no_active_run" | "ambiguous_active_runs")
                ) {
                    errors.push("QUINTE host receipt recovery.outcome is invalid".into());
                }
                if !rec.get("launch_safe").map(Value::is_boolean).unwrap_or(false) {
                    errors.push("QUINTE host receipt recovery.launch_safe must be boolean".into());
                }
                if !nonempty(rec.get("receipt_path")) {
                    errors.push("QUINTE host receipt recovery.receipt_path must be non-empty".into());
                } else if let (Some(rp), Some(sp)) = (
                    rec.get("receipt_path").and_then(Value::as_str),
                    receipt_path_value,
                ) {
                    let a = std::fs::canonicalize(rp).unwrap_or_else(|_| PathBuf::from(rp));
                    let b = std::fs::canonicalize(sp).unwrap_or_else(|_| PathBuf::from(sp));
                    if a != b {
                        errors.push(
                            "QUINTE host receipt recovery.receipt_path is not bound to receipt_path"
                                .into(),
                        );
                    }
                }
                if rec.get("outcome").and_then(Value::as_str) != Some("reconciled") {
                    errors.push("QUINTE host reconcile receipt must bind a reconciled run".into());
                }
                if state.and_then(|s| s.get("code")).and_then(Value::as_str) != Some("reconciled") {
                    errors.push("QUINTE host reconcile receipt state.code must be reconciled".into());
                }
                if let (Some(st), Some(ls)) = (
                    state.and_then(|s| s.get("active_run_ids")),
                    rec.get("launch_safe").and_then(Value::as_bool),
                ) {
                    let expected = st.as_array().map(|a| a.is_empty()).unwrap_or(false);
                    if ls != expected {
                        errors.push(
                            "QUINTE host reconcile receipt recovery.launch_safe does not match active_run_ids"
                                .into(),
                        );
                    }
                }
            }
            _ => errors.push("QUINTE host reconcile receipt recovery must be an object".into()),
        }
    } else if recovery.is_some() {
        errors.push("QUINTE host inspect receipt must not contain recovery".into());
    }
    if value.get("operation").and_then(Value::as_str) == Some("inspect")
        && state.and_then(|s| s.get("code")).and_then(Value::as_str) != Some("terminal")
    {
        errors.push("QUINTE host inspect receipt state.code must be terminal".into());
    }
    if matches!(
        value.get("operation").and_then(Value::as_str),
        Some("inspect" | "reconcile")
    ) && !nonempty(value.get("run_id"))
    {
        errors.push("QUINTE host receipt run_id is required for inspect/reconcile".into());
    }
    let manifest = value.get("manifest");
    if !matches!(manifest, Some(m) if m.is_object()) {
        errors.push("QUINTE host receipt manifest must be an object".into());
    } else if let Some(manifest) = manifest {
        let have: BTreeSet<&str> = manifest.as_object().unwrap().keys().map(String::as_str).collect();
        let allowed: BTreeSet<&str> = HOST_MANIFEST_FIELDS.iter().copied().collect();
        let required: BTreeSet<&str> = HOST_REQUIRED_MANIFEST_FIELDS.iter().copied().collect();
        let unknown: Vec<_> = have.difference(&allowed).copied().collect();
        let missing: Vec<_> = required.difference(&have).copied().collect();
        if !unknown.is_empty() {
            errors.push(format!(
                "QUINTE host receipt manifest has unknown fields: {}",
                unknown.join(", ")
            ));
        }
        if !missing.is_empty() {
            errors.push(format!(
                "QUINTE host receipt manifest is missing fields: {}",
                missing.join(", ")
            ));
        }
        if !nonempty(manifest.get("manifest_version")) {
            errors.push("QUINTE host receipt manifest manifest_version must be non-empty".into());
        }
        for field in ["brief_sha256", "policy_sha256", "snapshot_sha256", "runtime_sha256"] {
            if !is_digest(manifest.get(field)) {
                errors.push(format!("QUINTE host receipt manifest {field} is invalid"));
            }
        }
        if !is_digest(manifest.get("result_sha256")) {
            errors.push("QUINTE host receipt manifest result_sha256 is invalid".into());
        }
        if !matches!(
            manifest.get("status").and_then(Value::as_str),
            Some("completed" | "degraded")
        ) {
            errors.push("QUINTE host receipt manifest must be completed or degraded".into());
        }
    }
    let result_binding = value.get("result");
    if !matches!(result_binding, Some(r) if r.is_object()) {
        errors.push("QUINTE host receipt result must be an object".into());
    } else if let Some(rb) = result_binding {
        let have: BTreeSet<&str> = rb.as_object().unwrap().keys().map(String::as_str).collect();
        let allowed: BTreeSet<&str> = HOST_RESULT_FIELDS.iter().copied().collect();
        let unknown: Vec<_> = have.difference(&allowed).copied().collect();
        if !unknown.is_empty() {
            errors.push(format!(
                "QUINTE host receipt result has unknown fields: {}",
                unknown.join(", ")
            ));
        }
        if rb.get("verified") != Some(&Value::Bool(true)) {
            errors.push("QUINTE host receipt result.verified must be true".into());
        }
        if rb.get("actionable") != Some(&Value::Bool(true)) {
            errors.push("QUINTE host receipt result.actionable must be true for authorization".into());
        }
        if rb.get("contract_version").and_then(Value::as_str) != Some(QUINTE_RESULT_VERSION) {
            errors.push(
                "QUINTE host receipt result.contract_version does not match the active result contract"
                    .into(),
            );
        }
        if !is_digest(rb.get("sha256")) {
            errors.push("QUINTE host receipt result.sha256 is invalid".into());
        }
        if !nonempty(rb.get("path")) {
            errors.push("QUINTE host receipt result.path must be non-empty".into());
        } else if !Path::new(rb.get("path").and_then(Value::as_str).unwrap()).is_absolute() {
            errors.push("QUINTE host receipt result.path must be absolute".into());
        }
    }
    if let (Some(m), Some(rb)) = (manifest, result_binding) {
        if m.get("result_sha256") != rb.get("sha256") {
            errors.push("QUINTE host receipt manifest/result digests differ".into());
        }
    }
    if let (Some(st), Some(rid)) = (state, run_id) {
        if let Some(active) = st.get("active_run_ids").and_then(Value::as_array) {
            let manifest_status = manifest.and_then(|m| m.get("status")).and_then(Value::as_str);
            if matches!(manifest_status, Some("completed" | "degraded"))
                && active.iter().any(|v| v.as_str() == Some(rid))
            {
                errors.push("terminal QUINTE host receipt still lists its run as active".into());
            }
        }
    }
    if !errors.is_empty() {
        return (None, errors);
    }
    let result_input = PathBuf::from(result_binding.unwrap().get("path").and_then(Value::as_str).unwrap());
    if result_input.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        errors.push("QUINTE host receipt result.path must not be a symlink".into());
    }
    let result_path = std::fs::canonicalize(&result_input).unwrap_or(result_input);
    let runs_root = trusted_runs_root();
    let run_dir = result_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    if result_path.file_name().and_then(|s| s.to_str()) != Some("result.json")
        || run_dir.parent() != Some(runs_root.as_path())
    {
        errors.push("QUINTE host receipt result.path is outside the canonical runs root".into());
    }
    if run_dir.file_name().and_then(|s| s.to_str()) != run_id {
        errors.push("QUINTE host receipt result.path is not bound to run_id".into());
    }
    if !path_is_within(&runs_root, &result_path) {
        errors.push("QUINTE host receipt result.path escapes the trusted runs root".into());
    }
    if !errors.is_empty() {
        return (None, errors);
    }
    let (summary, product_errors) = summarize(&result_path.display().to_string(), request, None, false);
    errors.extend(product_errors);
    let Some(summary) = summary else {
        return (None, errors);
    };
    if summary.get("run_id").and_then(Value::as_str) != run_id {
        errors.push("QUINTE host receipt run_id does not match the verified result".into());
    }
    if summary.get("result_sha256") != result_binding.and_then(|r| r.get("sha256")) {
        errors.push("QUINTE host receipt result digest does not match result.json".into());
    }
    if summary.get("status") != manifest.and_then(|m| m.get("status")) {
        errors.push("QUINTE host receipt result status does not match manifest".into());
    }
    if result_binding.and_then(|r| r.get("contract_version")) != summary.get("result_version") {
        errors.push("QUINTE host receipt result contract version does not match result.json".into());
    }
    match load_object(&run_dir.join("manifest.json")) {
        Ok(canonical) => {
            if let Some(proj) = manifest.and_then(Value::as_object) {
                for (field, projection) in proj {
                    if canonical.get(field) != Some(projection) {
                        errors.push(format!(
                            "QUINTE host receipt manifest {field} does not match manifest.json"
                        ));
                    }
                }
            }
        }
        Err(e) => errors.push(format!("QUINTE canonical manifest cannot be re-read: {e}")),
    }
    if !errors.is_empty() {
        return (None, errors);
    }
    let mut out = summary;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "host_receipt_ref".into(),
            json!(supplied.display().to_string()),
        );
        obj.insert("host_receipt_sha256".into(), json!(sha256_bytes(&supplied_raw)));
        obj.insert(
            "host_receipt_operation".into(),
            json!(value.get("operation").and_then(Value::as_str).unwrap_or("")),
        );
    }
    (Some(out), Vec::new())
}

pub fn build_product_evidence(
    request: &Value,
    route_decision: &Value,
    quinte_refs: &[String],
    base_dir: Option<&Path>,
    quinte_receipt_refs: &[String],
) -> Value {
    let route = route_decision.get("route").and_then(Value::as_str);
    let required = matches!(route, Some("QUINTE"));
    let expected = if required { route } else { None };
    let mut errors = Vec::new();
    if !quinte_refs.is_empty() && !quinte_receipt_refs.is_empty() {
        errors.push("QUINTE result and host receipt cannot both be bound".into());
    }
    if quinte_refs.len() + quinte_receipt_refs.len() > 1 {
        errors.push("product binding accepts exactly one atomic product".into());
    }
    let quinte_sources = quinte_refs.len() + quinte_receipt_refs.len();
    if route == Some("QUINTE") && quinte_sources != 1 {
        errors.push("active QUINTE route requires exactly one QUINTE product or host receipt".into());
    } else if !required && (!quinte_refs.is_empty() || !quinte_receipt_refs.is_empty()) {
        errors.push("a product was supplied for a route that does not accept one".into());
    }
    let mut outcome = None;
    if quinte_refs.len() == 1 {
        let (summary, product_errors) = summarize(&quinte_refs[0], request, base_dir, true);
        errors.extend(product_errors);
        if let Some(summary) = summary {
            outcome = Some(json!({
                "product_ref": summary["result_ref"],
                "product_kind": "QUINTE",
                "product_version": summary["result_version"],
                "product_sha256": summary["result_sha256"],
                "product_id": summary["run_id"],
                "status": summary["status"],
                "decision": if summary["status"] == "completed" { "PASS" } else { "BLOCK" },
                "question": summary["question"],
                "action_scope": summary["action_scope"],
                "affected_paths": summary["affected_paths"],
                "action_binding_sha256": summary["action_binding_sha256"],
            }));
        }
    } else if quinte_receipt_refs.len() == 1 {
        let (summary, product_errors) =
            load_quinte_host_receipt(&quinte_receipt_refs[0], request, base_dir);
        errors.extend(product_errors);
        if let Some(summary) = summary {
            outcome = Some(json!({
                "product_ref": summary["result_ref"],
                "product_kind": "QUINTE",
                "product_version": summary["result_version"],
                "product_sha256": summary["result_sha256"],
                "product_id": summary["run_id"],
                "status": summary["status"],
                "decision": if summary["status"] == "completed" { "PASS" } else { "BLOCK" },
                "question": summary["question"],
                "action_scope": summary["action_scope"],
                "affected_paths": summary["affected_paths"],
                "action_binding_sha256": summary["action_binding_sha256"],
                "host_receipt_ref": summary["host_receipt_ref"],
                "host_receipt_sha256": summary["host_receipt_sha256"],
                "host_receipt_operation": summary["host_receipt_operation"],
            }));
        }
    }
    let status = if !errors.is_empty() {
        "invalid"
    } else if required && outcome.is_none() {
        "missing"
    } else if outcome.is_none() {
        "not_required"
    } else {
        "complete"
    };
    let binding = expected
        .map(|e| format!("atomic_{}_product", e.to_lowercase()))
        .unwrap_or_else(|| "not_applicable".into());
    json!({
        "required": required,
        "status": status,
        "binding": binding,
        "product": outcome,
        "errors": errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn quinte_cli_inspect_times_out_fail_closed() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("highball-inspect-timeout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("quinte-hang");
        let mut handle = std::fs::File::create(&script).unwrap();
        writeln!(handle, "#!/bin/sh\nsleep 5").unwrap();
        drop(handle);
        std::fs::set_permissions(&script, PermissionsExt::from_mode(0o755)).unwrap();
        let started = std::time::Instant::now();
        let outcome = run_quinte_inspect(
            &script,
            "run",
            Path::new("/nonexistent"),
            std::time::Duration::from_millis(250),
        );
        let _ = std::fs::remove_file(&script);
        let _ = std::fs::remove_dir(&dir);
        let message = outcome.err().unwrap_or_default();
        assert!(message.contains("timed out"), "unexpected outcome: {message}");
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
    }
}
