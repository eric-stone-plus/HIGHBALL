//! Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` bytes.

use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

pub fn canonical_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(&mut out, value);
    out
}

fn write_canonical(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            out.extend_from_slice(serde_json::to_string(s).expect("string json").as_bytes())
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(out, item);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(serde_json::to_string(*key).expect("key json").as_bytes());
                out.push(b':');
                write_canonical(out, &map[*key]);
            }
            out.push(b'}');
        }
    }
}

pub fn dump_sorted(value: &Value) -> String {
    String::from_utf8(canonical_bytes(value)).expect("canonical json is utf-8")
}

/// Python `json.dumps(obj, ensure_ascii=False, separators=(",", ":"))` for a
/// closed field list — insertion order, not sorted keys.
pub fn canonical_bytes_fields(value: &Value, fields: &[&str]) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(serde_json::to_string(*field).expect("key").as_bytes());
        out.push(b':');
        write_canonical(&mut out, value.get(*field).unwrap_or(&Value::Null));
    }
    out.push(b'}');
    out
}

pub fn load_object(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}", path = path.display()))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}", path = path.display()))?;
    if !value.is_object() {
        return Err(format!("{} must contain a JSON object", path.display()));
    }
    Ok(value)
}

pub fn load_bytes_object(raw: &[u8]) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("must be a JSON object".into());
    }
    Ok(value)
}

pub fn as_str(value: &Value) -> Option<&str> {
    value.as_str()
}

pub fn nonempty(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_str), Some(s) if !s.trim().is_empty())
}

pub fn string_list(value: Option<&Value>, nonempty_items: bool) -> bool {
    match value {
        Some(Value::Array(items)) => items.iter().all(|item| match item.as_str() {
            Some(s) => !nonempty_items || !s.trim().is_empty(),
            None => false,
        }),
        _ => false,
    }
}

pub fn exact_fields(value: &Value, expected: &[&str], label: &str, errors: &mut Vec<String>) {
    let Some(obj) = value.as_object() else {
        errors.push(format!("{label} must be an object"));
        return;
    };
    let expected: std::collections::BTreeSet<&str> = expected.iter().copied().collect();
    let have: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let unknown: Vec<&str> = have.difference(&expected).copied().collect();
    let missing: Vec<&str> = expected.difference(&have).copied().collect();
    if !unknown.is_empty() {
        errors.push(format!(
            "{label} has unknown fields: {}",
            unknown.join(", ")
        ));
    }
    if !missing.is_empty() {
        errors.push(format!(
            "{label} is missing fields: {}",
            missing.join(", ")
        ));
    }
}

pub fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

pub fn without_key(value: &Value, key: &str) -> Value {
    let mut obj = value.as_object().cloned().unwrap_or_default();
    obj.remove(key);
    Value::Object(obj)
}

pub fn extract_json_blocks(text: &str) -> Vec<(usize, String)> {
    let re = regex::Regex::new(r"(?ms)^```json[ \t]*\n(.*?)^```[ \t]*$").unwrap();
    re.captures_iter(text)
        .enumerate()
        .map(|(i, c)| (i + 1, c.get(1).unwrap().as_str().to_string()))
        .collect()
}

pub fn candidate_blocks(text: &str, path: &Path) -> (Vec<(usize, String)>, bool) {
    let blocks = extract_json_blocks(text);
    if !blocks.is_empty() {
        return (blocks, false);
    }
    let stripped = text.trim();
    let suffix = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .eq_ignore_ascii_case("json");
    if suffix || stripped.starts_with('{') {
        return (vec![(1, stripped.to_string())], true);
    }
    (Vec::new(), false)
}

pub fn resolve_ref(r#ref: &str, base_dir: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(r#ref);
    if !path.is_absolute() {
        if let Some(base) = base_dir {
            return base.join(path);
        }
    }
    path
}

pub fn path_is_within(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

pub fn obj_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key)
}

pub fn map_clone(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

pub fn is_string_list_min(value: Option<&Value>, min_items: usize) -> bool {
    match value {
        Some(Value::Array(items)) => {
            items.len() >= min_items && items.iter().all(|i| i.is_string())
        }
        _ => false,
    }
}
