//! Shared HIGHBALL runtime contract identifiers and canonical bindings.

use crate::jsonutil::{canonical_bytes, load_bytes_object, nonempty};
use chrono::{DateTime, Duration, FixedOffset, Utc};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const ACTION_PACKET_VERSION: &str = "2.0";
pub const RESIDUAL_TRACE_VERSION: &str = "1.1";
pub const QUINTE_BRIEF_VERSION: &str = "1.1";
pub const QUINTE_RESULT_VERSION: &str = "2.1";
pub const QUINTE_MANIFEST_VERSION: &str = "2.0";
pub const QUINTE_PROTOCOL_VERSION: &str = "1.0";
pub const QUINTE_TRIAL_MANIFEST_VERSION: &str = "1.0";
pub const QUINTE_CLI_ENVELOPE_VERSION: &str = "1.0";
pub const QUINTE_HOST_RECEIPT_VERSION: &str = "1.0";
pub const AUTHORIZATION_VERSION: &str = "1.0";
pub const AUTHORIZATION_CONSUMPTION_VERSION: &str = "1.0";
pub const ROUTE_EXECUTION_REPORT_VERSION: &str = "2.0";

pub const ACTION_BINDING_FIELDS: [&str; 4] =
    ["question", "action_boundary", "change_class", "affected_paths"];

pub fn digest_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap())
}

pub fn action_binding_payload(request: &Value) -> Value {
    let mut obj = serde_json::Map::new();
    for field in ACTION_BINDING_FIELDS {
        obj.insert(field.to_string(), request.get(field).cloned().unwrap_or(Value::Null));
    }
    Value::Object(obj)
}

pub fn canonical_action_binding_bytes(request: &Value) -> Vec<u8> {
    canonical_bytes(&action_binding_payload(request))
}

pub fn sha256_bytes(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

pub fn action_binding_sha256(request: &Value) -> String {
    sha256_bytes(&canonical_action_binding_bytes(request))
}

pub fn is_digest(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_str), Some(s) if digest_re().is_match(s))
}

pub fn is_digest_str(value: &str) -> bool {
    digest_re().is_match(value)
}

pub fn parse_utc_timestamp(value: Option<&Value>) -> Option<DateTime<FixedOffset>> {
    let s = value.and_then(Value::as_str)?;
    if !s.ends_with('Z') {
        return None;
    }
    let rewritten = format!("{}+00:00", &s[..s.len() - 1]);
    DateTime::parse_from_rfc3339(&rewritten).ok()
}

pub fn validate_authorization_artifact(
    artifact: &Value,
    request: &Value,
    now: Option<DateTime<Utc>>,
) -> Vec<String> {
    let Some(obj) = artifact.as_object() else {
        return vec!["authorization must be a JSON object".into()];
    };
    let fields: std::collections::BTreeSet<&str> = [
        "authorization_version",
        "authorization_id",
        "authorized_by",
        "decision",
        "action_binding_sha256",
        "action_scope",
        "issued_at",
        "expires_at",
    ]
    .into_iter()
    .collect();
    let have: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let mut errors = Vec::new();
    let unknown: Vec<_> = have.difference(&fields).copied().collect();
    let missing: Vec<_> = fields.difference(&have).copied().collect();
    if !unknown.is_empty() {
        errors.push(format!(
            "authorization has unknown fields: {}",
            unknown.join(", ")
        ));
    }
    if !missing.is_empty() {
        errors.push(format!(
            "authorization is missing fields: {}",
            missing.join(", ")
        ));
    }
    if artifact.get("authorization_version").and_then(Value::as_str) != Some(AUTHORIZATION_VERSION)
    {
        errors.push("authorization_version is unsupported".into());
    }
    if !nonempty(artifact.get("authorization_id")) {
        errors.push("authorization_id must be a non-empty string".into());
    }
    if artifact.get("authorized_by").and_then(Value::as_str) != Some("user") {
        errors.push("authorized_by must be user".into());
    }
    if artifact.get("decision").and_then(Value::as_str) != Some("authorize") {
        errors.push("authorization decision must be authorize".into());
    }
    let expected_binding = action_binding_sha256(request);
    if artifact.get("action_binding_sha256").and_then(Value::as_str) != Some(expected_binding.as_str())
    {
        errors.push("authorization action binding does not match the route request".into());
    }
    if artifact.get("action_scope") != request.get("action_scope") {
        errors.push("authorization action scope does not match the route request".into());
    }
    let issued_at = parse_utc_timestamp(artifact.get("issued_at"));
    let expires_at = parse_utc_timestamp(artifact.get("expires_at"));
    if issued_at.is_none() {
        errors.push("issued_at must be an RFC 3339 UTC timestamp".into());
    }
    if expires_at.is_none() {
        errors.push("expires_at must be an RFC 3339 UTC timestamp".into());
    }
    if let (Some(issued), Some(expires)) = (issued_at, expires_at) {
        if expires <= issued {
            errors.push("expires_at must be after issued_at".into());
        }
        if expires - issued > Duration::hours(8) {
            errors.push("authorization lifetime exceeds eight hours".into());
        }
        let current = now.unwrap_or_else(Utc::now);
        if issued > current + Duration::minutes(5) {
            errors.push("authorization is issued in the future".into());
        }
        if expires <= current {
            errors.push("authorization has expired".into());
        }
    }
    errors
}

pub fn summarize_authorization_artifact(
    r#ref: Option<&str>,
    request: &Value,
    base_dir: Option<&Path>,
    required: bool,
) -> Value {
    let Some(r#ref) = r#ref else {
        return json!({
            "required": required,
            "status": if required { "missing" } else { "not_required" },
            "artifact_ref": null,
            "artifact_sha256": null,
            "authorization_id": null,
            "action_binding_sha256": null,
            "action_scope": null,
            "issued_at": null,
            "expires_at": null,
            "errors": []
        });
    };
    let mut path = PathBuf::from(r#ref);
    if !path.is_absolute() {
        if let Some(base) = base_dir {
            path = base.join(&path);
        }
    }
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    let mut errors = Vec::new();
    let mut artifact: Option<Value> = None;
    let mut raw = Vec::new();
    match std::fs::read(&path) {
        Ok(bytes) => {
            raw = bytes;
            match load_bytes_object(&raw) {
                Ok(parsed) => {
                    errors.extend(validate_authorization_artifact(&parsed, request, None));
                    artifact = Some(parsed);
                }
                Err(e) => errors.push(format!("authorization cannot be read: {e}")),
            }
        }
        Err(e) => errors.push(format!("authorization cannot be read: {e}")),
    }
    let status = if errors.is_empty() {
        "authorized"
    } else {
        "invalid"
    };
    json!({
        "required": required,
        "status": status,
        "artifact_ref": r#ref,
        "artifact_sha256": if raw.is_empty() { Value::Null } else { json!(sha256_bytes(&raw)) },
        "authorization_id": artifact.as_ref().and_then(|a| a.get("authorization_id").cloned()).unwrap_or(Value::Null),
        "action_binding_sha256": artifact.as_ref().and_then(|a| a.get("action_binding_sha256").cloned()).unwrap_or(Value::Null),
        "action_scope": artifact.as_ref().and_then(|a| a.get("action_scope").cloned()).unwrap_or(Value::Null),
        "issued_at": artifact.as_ref().and_then(|a| a.get("issued_at").cloned()).unwrap_or(Value::Null),
        "expires_at": artifact.as_ref().and_then(|a| a.get("expires_at").cloned()).unwrap_or(Value::Null),
        "errors": errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn action_binding_matches_python_fixture() {
        let value = json!({
            "question": "May this change proceed?",
            "action_boundary": "protected_write",
            "change_class": "code",
            "affected_paths": ["HIGHBALL\\bin\\tool.py", "a/b.py"],
        });
        let bytes = canonical_action_binding_bytes(&value);
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"action_boundary":"protected_write","affected_paths":["HIGHBALL\\bin\\tool.py","a/b.py"],"change_class":"code","question":"May this change proceed?"}"#
        );
        assert_eq!(
            action_binding_sha256(&value),
            "sha256:05f2997ec8dfce94e74fb15b12a6901ac34b7265905cbca8ce5dc35cad110c9e"
        );
    }
}
