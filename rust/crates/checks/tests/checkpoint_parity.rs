//! Module-surface parity for `sesslint.checks.checkpoint` against pinned Python vectors.
//!
//! Exercises checkpoint checks on cases that are silent on both sides (empty finding lists).

use checks::checkpoint::{
    check_checkpoint, compute_checkpoint_fingerprint, CheckpointItem, ALL, KIND_CHECKPOINT,
    KIND_COMPACTION, KIND_RUN_START, MAX_CHECKPOINT_FINDINGS, TOOL_KINDS,
};
use checks::context::CheckContext;
use model::canonical::{Payload, SessionEvent};
use model::codes::SL201;
use model::events::{EventField, EventMapping, EventValue};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/checks.checkpoint/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/checks.checkpoint/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/checks.checkpoint/PROVENANCE.json";
const EXPECTED_VECTOR_COUNT: usize = 10;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.checks.checkpoint";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CHECKPOINT_RS_SHA256: &str =
    "324c7354ce6378e05881735cea87d68887ab65fc8ebff73141ab06be180be7da";
const EXPECTED_VECTORS_SHA256: &str =
    "d61f4794951694693418e7fb1e22b238c4f38a0a0e4f147d15567b99370c6a86";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

#[test]
fn checkpoint_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE.json");
    assert!(!bool_field(&provenance, "contains_real_data").expect("contains_real_data"),);

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest_normalized = manifest_raw.replace("\r\n", "\n");
    let manifest = parse_object_only(&manifest_normalized).expect("parse manifest.json");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
        "vectors_sha256 must match generator output"
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT,
        "manifest vector_count"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);

    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );

    for case in &doc.cases {
        assert_case(case);
    }
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(
        string_field(meta, "schema").expect("schema"),
        EXPECTED_SCHEMA
    );
    assert_eq!(
        string_field(meta, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "checks_checkpoint_rs_sha256").expect("checks_checkpoint_rs_sha256"),
        EXPECTED_CHECKPOINT_RS_SHA256
    );

    let py_all = array_field(meta, "python_all").expect("python_all");
    assert_eq!(py_all.len(), ALL.len(), "python_all length");
    for (idx, item) in py_all.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{idx}] must be string");
        };
        assert_eq!(name.as_str(), ALL[idx], "python_all[{idx}]");
    }

    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    let gap_markers = [
        "FINGERPRINT_CODEC_UNAVAILABLE",
        "combined list",
        "overflow",
        "Unicode Nd",
        "Python repr",
    ];
    for marker in gap_markers {
        assert!(
            gaps.iter()
                .any(|item| matches!(item, JsonValue::Str(s) if s.contains(marker))),
            "expected known_parity_gaps to mention {marker:?}"
        );
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "check_checkpoint_events" => {
            let source_path = string_field(&case.construct, "source_path").expect("source_path");
            let events = decode_event_value_list(&case.construct, "events").expect("events");
            let max_findings = optional_i64_field(&case.construct, "max_findings_per_family")
                .expect("max_findings_per_family");
            let sensitivity = optional_string_field(&case.construct, "checkpoint_sensitivity")
                .expect("checkpoint_sensitivity");
            let context = optional_check_context(&case.construct).expect("context");

            if let Ok(expected_len) = usize_field(&case.expected, "check_checkpoint_len") {
                let findings = check_checkpoint(
                    &events,
                    Some(source_path.as_str()),
                    max_findings,
                    sensitivity.as_deref(),
                    context.as_ref(),
                    None,
                )
                .unwrap_or_else(|err| panic!("{}: check_checkpoint: {err}", case.id));
                assert_eq!(
                    findings.len(),
                    expected_len,
                    "{}: check_checkpoint_len",
                    case.id
                );
            }

            if case.id == "constants_and_all" {
                assert_eq!(
                    i64_field(&case.expected, "max_checkpoint_findings")
                        .expect("max_checkpoint_findings"),
                    MAX_CHECKPOINT_FINDINGS,
                    "{}",
                    case.id
                );
                assert_eq!(
                    string_field(&case.expected, "kind_checkpoint").expect("kind_checkpoint"),
                    KIND_CHECKPOINT,
                    "{}",
                    case.id
                );
                assert_eq!(
                    string_field(&case.expected, "kind_compaction").expect("kind_compaction"),
                    KIND_COMPACTION,
                    "{}",
                    case.id
                );

                let run_list =
                    string_array_sorted(&case.expected, "kind_run_start").expect("kind_run_start");
                let mut rust_run: Vec<String> =
                    KIND_RUN_START.iter().map(|s| (*s).to_owned()).collect();
                rust_run.sort();
                assert_eq!(run_list, rust_run, "{}", case.id);

                let tool_list =
                    string_array_sorted(&case.expected, "tool_kinds").expect("tool_kinds");
                let mut rust_tool: Vec<String> =
                    TOOL_KINDS.iter().map(|s| (*s).to_owned()).collect();
                rust_tool.sort();
                assert_eq!(tool_list, rust_tool, "{}", case.id);

                let py_all_expected =
                    string_array_ordered(&case.expected, "python_all").expect("python_all");
                assert_eq!(
                    py_all_expected,
                    ALL.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                    "{}",
                    case.id
                );
            }
        }
        "fingerprint_items" => {
            let code = string_field(&case.construct, "code").expect("code");
            let items_json = array_field(&case.construct, "items").expect("items");
            let mut items: Vec<CheckpointItem> = Vec::new();
            for item in items_json {
                let JsonValue::Str(s) = item else {
                    panic!("{}: fingerprint item must be string", case.id);
                };
                items.push(CheckpointItem::from(s.as_str()));
            }
            let digest = compute_checkpoint_fingerprint(&code, items);
            assert_eq!(
                digest,
                string_field(&case.expected, "digest").expect("digest"),
                "{}",
                case.id
            );
            assert_eq!(code, SL201, "{}: fingerprint case uses SL201", case.id);
        }
        other => panic!("{}: unknown construct type {other}", case.id),
    }
}

fn string_array_sorted(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let arr = array_field(obj, key)?;
    let mut out: Vec<String> = arr
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
            }),
        })
        .collect::<Result<_, _>>()?;
    out.sort();
    Ok(out)
}

fn string_array_ordered(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let arr = array_field(obj, key)?;
    arr.iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
            }),
        })
        .collect()
}

fn optional_check_context(
    construct: &[(String, JsonValue)],
) -> Result<Option<CheckContext>, ParseError> {
    let Some(raw) = construct
        .iter()
        .find(|(k, _)| k == "context")
        .map(|(_, v)| v)
    else {
        return Ok(None);
    };
    let ctx = as_object(raw, "context")?;
    let adapter_id = string_field(ctx, "adapter_id")?;
    let adapter_version = string_field(ctx, "adapter_version")?;
    let profile_id = string_field(ctx, "profile_id")?;
    let profile_version = string_field(ctx, "profile_version")?;
    let timestamp_skew_ms =
        i64_field(ctx, "timestamp_skew_ms").unwrap_or(DEFAULT_TIMESTAMP_SKEW_MS);
    let source_metadata = optional_source_metadata(ctx)?;
    Ok(Some(CheckContext::new(
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        source_metadata,
        timestamp_skew_ms,
    )))
}

const DEFAULT_TIMESTAMP_SKEW_MS: i64 = 2000;

fn optional_source_metadata(
    ctx: &[(String, JsonValue)],
) -> Result<Option<BTreeMap<String, serde_json::Value>>, ParseError> {
    match ctx.iter().find(|(k, _)| k == "source_metadata") {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Object(entries))) => {
            let mut out = BTreeMap::new();
            for (key, value) in entries {
                out.insert(key.clone(), hand_json_to_serde(value)?);
            }
            Ok(Some(out))
        }
        Some(_) => Err(ParseError {
            message: "source_metadata must be null or object".into(),
        }),
    }
}

fn hand_json_to_serde(value: &JsonValue) -> Result<serde_json::Value, ParseError> {
    Ok(match value {
        JsonValue::Null => serde_json::Value::Null,
        JsonValue::Bool(flag) => serde_json::Value::Bool(*flag),
        JsonValue::Str(text) => serde_json::Value::String(text.clone()),
        JsonValue::Number(n) => serde_json::Value::Number((*n).into()),
        JsonValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .ok_or_else(|| ParseError {
                message: "non-finite float in JSON".into(),
            })?,
        JsonValue::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.push(hand_json_to_serde(item)?);
            }
            serde_json::Value::Array(out)
        }
        JsonValue::Object(entries) => {
            let mut map = serde_json::Map::new();
            for (key, val) in entries {
                map.insert(key.clone(), hand_json_to_serde(val)?);
            }
            serde_json::Value::Object(map)
        }
    })
}

fn decode_event_value_list(
    construct: &[(String, JsonValue)],
    key: &str,
) -> Result<Vec<EventValue>, ParseError> {
    let items = array_field(construct, key)?;
    items
        .iter()
        .map(|item| {
            let wrapped = as_object(item, "event element")?;
            decode_event_value(wrapped)
        })
        .collect()
}

fn decode_event_value(wrapped: &[(String, JsonValue)]) -> Result<EventValue, ParseError> {
    let format = string_field(wrapped, "format")?;
    match format.as_str() {
        "session" => {
            let entries = array_field(wrapped, "entries")?;
            let event = decode_session_event_inner(&entries)?;
            Ok(EventValue::from_session(event))
        }
        "mapping" => {
            let entries = array_field(wrapped, "entries")?;
            mapping_entries_to_event_value(&entries)
        }
        other => Err(ParseError {
            message: format!("unknown event format {other}"),
        }),
    }
}

fn mapping_entries_to_event_value(entries: &[JsonValue]) -> Result<EventValue, ParseError> {
    let mut pairs = Vec::new();
    for pair in entries {
        let JsonValue::Array(two) = pair else {
            return Err(ParseError {
                message: "mapping pair must be array".into(),
            });
        };
        if two.len() != 2 {
            return Err(ParseError {
                message: "mapping pair must have length 2".into(),
            });
        }
        let JsonValue::Str(key) = &two[0] else {
            return Err(ParseError {
                message: "mapping key must be string".into(),
            });
        };
        let field = json_to_event_field(&two[1])?;
        pairs.push((key.clone(), field));
    }
    Ok(EventValue::Mapping(EventMapping::new(pairs)))
}

fn decode_session_event_inner(entries: &[JsonValue]) -> Result<SessionEvent, ParseError> {
    let id = tagged_string_in_mapping(entries, "id")?;
    let seq = tagged_i64_in_mapping(entries, "seq")?;
    let kind_json = lookup_mapping_value(entries, "kind").ok_or_else(|| ParseError {
        message: "missing kind".into(),
    })?;
    let kind_obj = as_object(kind_json, "kind")?;
    let kind_tag = string_field(kind_obj, "t")?;
    if kind_tag != "str" {
        return Err(ParseError {
            message: "kind.t must be str in vectors".into(),
        });
    }
    let kind = string_field(kind_obj, "v")?;
    let extra_value = lookup_mapping_value(entries, "extra_fields").ok_or_else(|| ParseError {
        message: "missing extra_fields".into(),
    })?;

    let mut parent_id: Option<String> = None;
    if let Some(pid_val) = lookup_mapping_value(entries, "parent_id") {
        let obj = as_object(pid_val, "parent_id")?;
        let tag = string_field(obj, "t")?;
        parent_id = match tag.as_str() {
            "null" => None,
            "str" => Some(string_field(obj, "v")?),
            _ => {
                return Err(ParseError {
                    message: "parent_id must be null or str in vectors".into(),
                });
            }
        };
    }

    let mut event = SessionEvent::new(
        id,
        parent_id,
        seq,
        "2024-02-29T00:00:00Z",
        "assistant",
        kind,
    );
    event.extra_fields = json_to_payload(extra_value)?;
    if let Some(corr_val) = lookup_mapping_value(entries, "correlation_id") {
        let obj = as_object(corr_val, "correlation_id")?;
        let tag = string_field(obj, "t")?;
        event.correlation_id = match tag.as_str() {
            "null" => None,
            "str" => Some(string_field(obj, "v")?),
            _ => {
                return Err(ParseError {
                    message: "correlation_id must be null or str in vectors".into(),
                });
            }
        };
    }
    if let Some(bid_val) = lookup_mapping_value(entries, "branch_id") {
        let obj = as_object(bid_val, "branch_id")?;
        let tag = string_field(obj, "t")?;
        event.branch_id = match tag.as_str() {
            "null" => None,
            "str" => Some(string_field(obj, "v")?),
            _ => {
                return Err(ParseError {
                    message: "branch_id must be null or str in vectors".into(),
                });
            }
        };
    }
    if let Some(sl_val) = lookup_mapping_value(entries, "source_line") {
        let obj = as_object(sl_val, "source_line")?;
        let tag = string_field(obj, "t")?;
        event.source_line = match tag.as_str() {
            "null" => None,
            "int" => Some(i64_field(obj, "v")?),
            _ => {
                return Err(ParseError {
                    message: "source_line must be null or int in vectors".into(),
                });
            }
        };
    }
    if let Some(payload_val) = lookup_mapping_value(entries, "payload") {
        event.payload = json_to_payload(payload_val)?;
    }
    Ok(event)
}

fn lookup_mapping_value<'a>(entries: &'a [JsonValue], key: &str) -> Option<&'a JsonValue> {
    for pair in entries {
        let JsonValue::Array(two) = pair else {
            continue;
        };
        if two.len() != 2 {
            continue;
        }
        let JsonValue::Str(k) = &two[0] else {
            continue;
        };
        if k == key {
            return Some(&two[1]);
        }
    }
    None
}

fn tagged_string_in_mapping(entries: &[JsonValue], key: &str) -> Result<String, ParseError> {
    let value = lookup_mapping_value(entries, key).ok_or_else(|| ParseError {
        message: format!("missing key {key}"),
    })?;
    let obj = as_object(value, key)?;
    let tag = string_field(obj, "t")?;
    if tag != "str" {
        return Err(ParseError {
            message: format!("{key}.t must be str"),
        });
    }
    string_field(obj, "v")
}

fn tagged_i64_in_mapping(entries: &[JsonValue], key: &str) -> Result<i64, ParseError> {
    let value = lookup_mapping_value(entries, key).ok_or_else(|| ParseError {
        message: format!("missing key {key}"),
    })?;
    let obj = as_object(value, key)?;
    let tag = string_field(obj, "t")?;
    if tag != "int" {
        return Err(ParseError {
            message: format!("{key}.t must be int"),
        });
    }
    i64_field(obj, "v")
}

fn json_to_event_field(value: &JsonValue) -> Result<EventField, ParseError> {
    let obj = as_object(value, "tagged field")?;
    let tag = string_field(obj, "t")?;
    match tag.as_str() {
        "null" => Ok(EventField::Null),
        "bool" => Ok(EventField::Bool(bool_field(obj, "v")?)),
        "int" => Ok(EventField::Int(i64_field(obj, "v")?)),
        "float" => Ok(EventField::Float(f64_field(obj, "v")?)),
        "str" => Ok(EventField::Str(string_field(obj, "v")?)),
        "map" => {
            let nested = array_field(obj, "entries")?;
            Ok(EventField::Mapping(mapping_array_to_event_mapping(
                &nested,
            )?))
        }
        "list" => {
            let items = array_field(obj, "items")?;
            let mut out = Vec::new();
            for item in items {
                out.push(json_to_event_field(&item)?);
            }
            Ok(EventField::List(out))
        }
        other => Err(ParseError {
            message: format!("unknown field tag {other}"),
        }),
    }
}

fn mapping_array_to_event_mapping(arr: &[JsonValue]) -> Result<EventMapping, ParseError> {
    let mut out = Vec::new();
    for pair in arr {
        let JsonValue::Array(two) = pair else {
            return Err(ParseError {
                message: "mapping pair must be array".into(),
            });
        };
        if two.len() != 2 {
            return Err(ParseError {
                message: "mapping pair must have length 2".into(),
            });
        }
        let JsonValue::Str(key) = &two[0] else {
            return Err(ParseError {
                message: "mapping key must be string".into(),
            });
        };
        let field = json_to_event_field(&two[1])?;
        out.push((key.clone(), field));
    }
    Ok(EventMapping::new(out))
}

fn json_to_payload(value: &JsonValue) -> Result<Payload, ParseError> {
    let obj = as_object(value, "payload")?;
    let tag = string_field(obj, "t")?;
    match tag.as_str() {
        "null" => Ok(Payload::null()),
        "bool" => Ok(Payload::bool_value(bool_field(obj, "v")?)),
        "int" => Ok(Payload::int(i64_field(obj, "v")?)),
        "float" => Ok(Payload::float(f64_field(obj, "v")?)),
        "str" => Ok(Payload::string(string_field(obj, "v")?)),
        "map" => {
            let nested = array_field(obj, "entries")?;
            let mut pairs = Vec::new();
            for pair in nested {
                let JsonValue::Array(two) = pair else {
                    return Err(ParseError {
                        message: "map entry must be array".into(),
                    });
                };
                if two.len() != 2 {
                    return Err(ParseError {
                        message: "map entry must have length 2".into(),
                    });
                }
                let JsonValue::Str(key) = &two[0] else {
                    return Err(ParseError {
                        message: "map key must be string".into(),
                    });
                };
                pairs.push((Payload::string(key.clone()), json_to_payload(&two[1])?));
            }
            Ok(Payload::map(pairs))
        }
        "list" => {
            let items = array_field(obj, "items")?;
            let mut out = Vec::new();
            for item in items {
                out.push(json_to_payload(&item)?);
            }
            Ok(Payload::list(out))
        }
        "tuple" => {
            let items = array_field(obj, "items")?;
            let mut out = Vec::new();
            for item in items {
                out.push(json_to_payload(&item)?);
            }
            Ok(Payload::tuple(out))
        }
        other => Err(ParseError {
            message: format!("unknown payload tag {other}"),
        }),
    }
}

// --- minimal JSON (vectors.json) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Float(f64),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    Ok(as_object(&value, "root")?.to_vec())
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let JsonValue::Object(root) = value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let vectors = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    let cases: Result<Vec<VectorCase>, _> = items.iter().map(parse_vector_case).collect();
    Ok(ParsedDocument {
        meta: root.clone(),
        cases: cases?,
    })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        Some(_) => Err(ParseError {
            message: format!("{key} must be string or absent"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<i64>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Number(n))) => Ok(Some(*n)),
        Some(_) => Err(ParseError {
            message: format!("{key} must be number or absent"),
        }),
    }
}

fn f64_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Float(f))) => Ok(*f),
        _ => Err(ParseError {
            message: format!("{key} must be float"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    let first = input.as_bytes()[0];
    match first {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_numeric_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_numeric_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        idx += 1;
    }
    if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let start_digits = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
            return Err(ParseError {
                message: "invalid float".into(),
            });
        }
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let slice = &input[..idx];
        let value: f64 = slice.parse().map_err(|_| ParseError {
            message: "float overflow".into(),
        })?;
        let parsed = if negative { -value } else { value };
        return Ok((JsonValue::Float(parsed), &input[idx..]));
    }
    let digits = &input[start_digits..idx];
    let magnitude: i64 = digits.parse().map_err(|_| ParseError {
        message: "number overflow".into(),
    })?;
    let value = if negative { -magnitude } else { magnitude };
    Ok((JsonValue::Number(value), &input[idx..]))
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), stripped));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), stripped));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        if !rest.starts_with(':') {
            return Err(ParseError {
                message: "expected : in object".into(),
            });
        }
        rest = rest[1..].trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or } in object".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, c)| c).collect();
                        if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad \\u escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode scalar".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
