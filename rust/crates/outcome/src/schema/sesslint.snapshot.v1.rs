//! RX-SCH-sesslint.snapshot.v1: optional input envelope, not report metadata.
//!
//! Pin: 02694d537104659df66cdd084354739f3cccc440. Python consumes this
//! schema and has no envelope producer. No producer-byte parity is claimed.
//! Validation follows the schema, independently of load_snapshot semantics:
//! observed_at is only a suffix pattern, unavailable may carry records, and
//! absent/null metadata are preserved without applying loader defaults.
//! Text parsing reuses strict JSON's binary64, Unicode scalar, depth128 and
//! 4300-digit integer domain; duplicate keys are refused. Errors are content-free.
//! As in Python, exponent overflow is accepted inside unconstrained record data.

use crate::contract::{parse_strict_json, Json, Mapping, Scalar};
use crate::snapshot::{COMPLETENESS, MAX_RECORDS, ORIGINS, SNAPSHOT_SCHEMA_VERSION};
use std::fmt;

/// Exact pinned schema bytes, including final LF.
pub const SNAPSHOT_SCHEMA_JSON: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.snapshot.v1.json",
  "title": "SessLint OutcomeGuard Snapshot Envelope",
  "description": "Optional JSON envelope for one source or target observation. Plain CSV, JSON arrays and JSONL are also accepted. Metadata is never inferred: completeness defaults to unknown and origin to user_file.",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version"],
  "properties": {
    "schema_version": {"const": "sesslint.snapshot/v1"},
    "observed_at": {"anyOf": [{"type": "null"}, {"type": "string", "pattern": "(Z|z|[+-][0-9]{2}:?[0-9]{2})$"}]},
    "completeness": {"anyOf": [{"type": "null"}, {"enum": ["complete", "partial", "unknown", "unavailable"]}]},
    "origin": {"anyOf": [{"type": "null"}, {"enum": ["target_system", "workflow_log", "user_file", "manual"]}]},
    "demo": {"type": "boolean"},
    "records": {"type": "array", "maxItems": 1000000, "items": {"type": "object"}}
  }
}
"##;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    StrictJson,
    Reject {
        keyword: &'static str,
        field: &'static str,
    },
}
impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StrictJson => f.write_str("snapshot schema strict JSON rejected"),
            Self::Reject { keyword, field } => write!(f, "snapshot schema {keyword} at {field}"),
        }
    }
}
impl std::error::Error for SchemaError {}
fn reject(keyword: &'static str, field: &'static str) -> SchemaError {
    SchemaError::Reject { keyword, field }
}

/// Validated borrowed fields. None means absent; Some(None) means explicit null.
/// Nested record values are preserved, not scalarized or included in diagnostics.
#[derive(Clone, PartialEq)]
pub struct Envelope<'a> {
    pub schema_version: &'a str,
    pub observed_at: Option<Option<&'a str>>,
    pub completeness: Option<Option<&'a str>>,
    pub origin: Option<Option<&'a str>>,
    pub demo: Option<bool>,
    pub records: Option<&'a [Json]>,
}
impl fmt::Debug for Envelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Envelope(..)")
    }
}

fn nullable<'a>(
    raw: &'a Mapping,
    key: &'static str,
) -> Result<Option<Option<&'a str>>, SchemaError> {
    match raw.get(key) {
        None => Ok(None),
        Some(Json::Scalar(Scalar::Null)) => Ok(Some(None)),
        Some(Json::Scalar(Scalar::String(value))) => Ok(Some(Some(value))),
        _ => Err(reject("anyOf", key)),
    }
}

/// Python/jsonschema regex search: (Z|z|[+-][0-9]{2}:?[0-9]{2})$.
/// `$` also matches before one terminal LF; no calendar/time validation occurs.
fn observed_pattern(text: &str) -> bool {
    let text = text.strip_suffix('\n').unwrap_or(text).as_bytes();
    if matches!(text.last(), Some(b'Z' | b'z')) {
        return true;
    }
    [5, 6].into_iter().any(|length| {
        let Some(tail) = text.get(text.len().saturating_sub(length)..) else {
            return false;
        };
        tail.len() == length
            && matches!(tail[0], b'+' | b'-')
            && tail[1..3].iter().all(u8::is_ascii_digit)
            && (length == 5 || tail[3] == b':')
            && tail[length - 2..].iter().all(u8::is_ascii_digit)
    })
}

impl<'a> Envelope<'a> {
    pub fn from_json(value: &'a Json) -> Result<Self, SchemaError> {
        let Json::Object(raw) = value else {
            return Err(reject("type", "$"));
        };
        const KEYS: &[&str] = &[
            "schema_version",
            "observed_at",
            "completeness",
            "origin",
            "demo",
            "records",
        ];
        if raw.keys().any(|key| !KEYS.contains(&key.as_str())) {
            return Err(reject("additionalProperties", "$"));
        }
        let version = raw
            .get("schema_version")
            .ok_or_else(|| reject("required", "schema_version"))?;
        if version.as_str() != Some(SNAPSHOT_SCHEMA_VERSION) {
            return Err(reject("const", "schema_version"));
        }
        let observed_at = nullable(raw, "observed_at")?;
        if observed_at.flatten().is_some_and(|v| !observed_pattern(v)) {
            return Err(reject("pattern", "observed_at"));
        }
        let completeness = nullable(raw, "completeness")?;
        if completeness
            .flatten()
            .is_some_and(|v| !COMPLETENESS.contains(&v))
        {
            return Err(reject("enum", "completeness"));
        }
        let origin = nullable(raw, "origin")?;
        if origin.flatten().is_some_and(|v| !ORIGINS.contains(&v)) {
            return Err(reject("enum", "origin"));
        }
        let demo = match raw.get("demo") {
            None => None,
            Some(Json::Scalar(Scalar::Bool(b))) => Some(*b),
            _ => return Err(reject("type", "demo")),
        };
        let records = match raw.get("records") {
            None => None,
            Some(Json::Array(rows)) => {
                if rows.len() > MAX_RECORDS {
                    return Err(reject("maxItems", "records"));
                }
                if rows.iter().any(|row| !matches!(row, Json::Object(_))) {
                    return Err(reject("type", "records.items"));
                }
                Some(rows.as_slice())
            }
            _ => return Err(reject("type", "records")),
        };
        Ok(Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            observed_at,
            completeness,
            origin,
            demo,
            records,
        })
    }
}

/// Validates text without producing or echoing observation payloads.
pub fn validate(text: &str) -> Result<(), SchemaError> {
    let value = parse_strict_json(text).map_err(|_| SchemaError::StrictJson)?;
    Envelope::from_json(&value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_blob_and_independent_schema_vectors() {
        let blob = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../parity/schemas/sesslint.snapshot.v1/schema.json"
        ));
        assert_eq!(SNAPSHOT_SCHEMA_JSON.as_bytes(), blob.as_bytes());
        let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../parity/schemas/sesslint.snapshot.v1/vectors.json"
        )))
        .unwrap();
        let rows = data["vectors"].as_array().unwrap();
        assert_eq!(rows.len(), data["count"].as_u64().unwrap() as usize);
        assert!(rows.len() > 200);
        for row in rows {
            let input = row["input"].as_str().unwrap();
            let valid = row["valid"].as_bool().unwrap();
            assert_eq!(validate(input).is_ok(), valid, "{}", row["id"]);
        }
        for row in data["boundaries"].as_array().unwrap() {
            let count = row["count"].as_u64().unwrap() as usize;
            let raw = Json::Object(Mapping::from([
                (
                    "schema_version".into(),
                    Json::Scalar(Scalar::String(SNAPSHOT_SCHEMA_VERSION.into())),
                ),
                (
                    "records".into(),
                    Json::Array(vec![Json::Object(Mapping::new()); count]),
                ),
            ]));
            assert_eq!(
                Envelope::from_json(&raw).is_ok(),
                row["valid"].as_bool().unwrap(),
                "count={count}"
            );
        }
    }

    #[test]
    fn presence_and_nested_values_are_preserved() {
        let raw = parse_strict_json(r#"{"schema_version":"sesslint.snapshot/v1","observed_at":null,"origin":"manual","demo":false,"records":[{"x":[true,{"n":2}]}]}"#).unwrap();
        let env = Envelope::from_json(&raw).unwrap();
        assert_eq!(env.observed_at, Some(None));
        assert_eq!(env.completeness, None);
        assert_eq!(env.origin, Some(Some("manual")));
        assert_eq!(env.demo, Some(false));
        assert_eq!(env.records.unwrap().len(), 1);
        let Json::Object(obj) = &env.records.unwrap()[0] else {
            panic!()
        };
        assert!(matches!(&obj["x"], Json::Array(items) if items.len() == 2));
        assert_eq!(format!("{env:?}"), "Envelope(..)");
    }

    #[test]
    fn schema_acceptance_does_not_imply_loader_acceptance() {
        for time in ["garbageZ", "z", "+9999", "\n+99:99\n"] {
            assert!(observed_pattern(time));
            assert!(
                crate::snapshot::parse_instant(&Json::Scalar(Scalar::String(time.into())))
                    .is_none()
            );
        }
        assert!(validate(r#"{"schema_version":"sesslint.snapshot/v1","completeness":"unavailable","records":[{}]}"#).is_ok());
    }

    #[test]
    fn parser_boundary_diagnostics_are_content_free() {
        let duplicate = r#"{"private sentinel":1,"private sentinel":2}"#;
        assert_eq!(validate(duplicate), Err(SchemaError::StrictJson));
        assert!(!validate(duplicate)
            .unwrap_err()
            .to_string()
            .contains("private sentinel"));
        for text in [
            r#"{"schema_version":"sesslint.snapshot/v1","records":[{"x":NaN}]}"#,
            r#"{"schema_version":"sesslint.snapshot/v1","records":[{"x":"\ud800"}]}"#,
        ] {
            assert!(validate(text).is_err());
        }
        assert!(
            validate(r#"{"schema_version":"sesslint.snapshot/v1","records":[{"x":1e400}]}"#)
                .is_ok()
        );
    }
}
