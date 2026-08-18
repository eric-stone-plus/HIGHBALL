//! Atomically consume one action-bound user authorization.

use crate::contracts::{
    action_binding_sha256, is_digest_str, sha256_bytes, validate_authorization_artifact,
    AUTHORIZATION_CONSUMPTION_VERSION,
};
use crate::jsonutil::dump_sorted;
use crate::route::validate_request;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub fn default_ledger() -> PathBuf {
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        if !state.is_empty() {
            return PathBuf::from(state).join("highball").join("authorization-consumed");
        }
    }
    dirs_fallback_home().join(".local/state/highball/authorization-consumed")
}

fn dirs_fallback_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn safe_component(value: &str) -> Result<&str, String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(
            "authorization_id must contain only A-Z, a-z, 0-9, dot, underscore, or hyphen".into(),
        );
    }
    Ok(value)
}

pub fn atomic_consume(ledger: &Path, authorization_id: &str, record: &Value) -> Result<PathBuf, String> {
    fs::create_dir_all(ledger).map_err(|e| e.to_string())?;
    let _ = fs::set_permissions(ledger, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let claim = ledger.join(format!("{}.json", safe_component(authorization_id)?));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut handle = match opts.open(&claim) {
        Ok(h) => h,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err("ALREADY_CONSUMED".into());
        }
        Err(e) => return Err(e.to_string()),
    };
    let payload = format!("{}\n", dump_sorted(record));
    if let Err(e) = handle.write_all(payload.as_bytes()).and_then(|_| handle.flush()) {
        let _ = fs::remove_file(&claim);
        return Err(e.to_string());
    }
    let _ = handle.sync_all();
    Ok(claim)
}

pub fn consume(
    request: &Value,
    authorization_raw: &[u8],
    expected_sha256: Option<&str>,
    ledger: &Path,
) -> Result<PathBuf, String> {
    let request_errors = validate_request(request);
    if !request_errors.is_empty() {
        return Err(request_errors.join("; "));
    }
    let actual = sha256_bytes(authorization_raw);
    if let Some(expected) = expected_sha256 {
        if !is_digest_str(expected) {
            return Err("expected authorization digest is invalid".into());
        }
        if actual != expected {
            return Err("authorization digest does not match the Action Packet".into());
        }
    }
    let artifact: Value = serde_json::from_slice(authorization_raw)
        .map_err(|e| format!("authorization cannot be read: {e}"))?;
    let errors = validate_authorization_artifact(&artifact, request, None);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let record = json!({
        "consumption_version": AUTHORIZATION_CONSUMPTION_VERSION,
        "authorization_id": artifact["authorization_id"],
        "authorization_sha256": actual,
        "action_binding_sha256": action_binding_sha256(request),
    });
    let id = artifact
        .get("authorization_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "authorization_id must be a non-empty string".to_string())?;
    atomic_consume(ledger, id, &record)
}
