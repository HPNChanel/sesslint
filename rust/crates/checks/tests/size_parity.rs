//! Module-surface parity for `sesslint.checks.size` against pinned Python vectors.
//!
//! Exercises [`check_size_anomaly`], [`check_sl011`], and [`ALL`] on cases that are
//! silent on Python (empty finding list).

use checks::size::{
    check_size_anomaly, check_sl011, ALL, SIZE_FLOOR_BYTES, SIZE_MIN_RECORDS, SIZE_RATIO_K,
};
use checks::context::CheckContext;
use model::events::EventValue;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/checks.size/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/checks.size/manifest.json";
const EXPECTED_VECTOR_COUNT: usize = 8;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.checks.size";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CHECKS_SIZE_RS_SHA256: &str =
    "a20813bedab53701d557a78e88e6786a7300e02f63aac3c7fb61cd1b217b08fb";
const EXPECTED_VECTORS_SHA256: &str =
    "b5a6b3d98c8c61e8cbfe34e2aa01abf8008528847a0a03324c27719be4d1dd49";

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

#[test]
fn size_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

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
        string_field(meta, "checks_size_rs_sha256").expect("checks_size_rs_sha256"),
        EXPECTED_CHECKS_SIZE_RS_SHA256
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
        "PYTHON_INT_UNBOUNDED",
        "2^53",
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
        "size_check" => {
            let source_path = string_field(&case.construct, "source_path").expect("source_path");
            let events: &[EventValue] = &[];
            let context = lookup_construct_value(&case.construct, "context")
                .map(|value| build_check_context_from_tagged(value).expect("decode context"));
            let ctx_ref = context.as_ref();

            let check_findings_len =
                usize_field(&case.expected, "check_findings_len").expect("check_findings_len");
            let findings_size = check_size_anomaly(events, &source_path, ctx_ref)
                .unwrap_or_else(|err| panic!("{}: check_size_anomaly: {err}", case.id));
            assert_eq!(findings_size.len(), check_findings_len, "{}", case.id);
            let findings_sl = check_sl011(events, &source_path, ctx_ref)
                .unwrap_or_else(|err| panic!("{}: check_sl011: {err}", case.id));
            assert_eq!(findings_sl.len(), check_findings_len, "{}", case.id);

            if case.id == "constants_and_all" {
                assert_eq!(
                    i64_field(&case.expected, "SIZE_FLOOR_BYTES").expect("SIZE_FLOOR_BYTES"),
                    SIZE_FLOOR_BYTES,
                    "{}",
                    case.id
                );
                assert_eq!(
                    i64_field(&case.expected, "SIZE_MIN_RECORDS").expect("SIZE_MIN_RECORDS"),
                    SIZE_MIN_RECORDS,
                    "{}",
                    case.id
                );
                assert_eq!(
                    i64_field(&case.expected, "SIZE_RATIO_K").expect("SIZE_RATIO_K"),
                    SIZE_RATIO_K,
                    "{}",
                    case.id
                );
            }
        }
        other => panic!("{}: unknown construct type {other}", case.id),
    }
}

fn lookup_construct_value<'a>(
    construct: &'a [(String, JsonValue)],
    key: &str,
) -> Option<&'a JsonValue> {
    construct
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

fn build_check_context_from_tagged(value: &JsonValue) -> Result<CheckContext, ParseError> {
    let serde_val = json_tagged_to_serde(value)?;
    let obj = serde_val.as_object().ok_or_else(|| ParseError {
        message: "context must decode to object".into(),
    })?;
    let adapter_id = obj
        .get("adapter_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError {
            message: "adapter_id".into(),
        })?
        .to_owned();
    let adapter_version = obj
        .get("adapter_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError {
            message: "adapter_version".into(),
        })?
        .to_owned();
    let profile_id = obj
        .get("profile_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError {
            message: "profile_id".into(),
        })?
        .to_owned();
    let profile_version = obj
        .get("profile_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ParseError {
            message: "profile_version".into(),
        })?
        .to_owned();
    let timestamp_skew_ms = obj
        .get("timestamp_skew_ms")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ParseError {
            message: "timestamp_skew_ms".into(),
        })?;
    let source_metadata = match obj.get("source_metadata") {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(k.clone(), v.clone());
            }
            Some(out)
        }
        _ => {
            return Err(ParseError {
                message: "source_metadata must be object or null".into(),
            });
        }
    };
    Ok(CheckContext::new(
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        source_metadata,
        timestamp_skew_ms,
    ))
}

fn json_tagged_to_serde(value: &JsonValue) -> Result<Value, ParseError> {
    let obj = as_object(value, "tagged value")?;
    let tag = string_field(obj, "t")?;
    Ok(match tag.as_str() {
        "null" => Value::Null,
        "bool" => Value::Bool(bool_field(obj, "v")?),
        "int" => Value::from(i64_field(obj, "v")?),
        "float" => {
            let f = f64_field(obj, "v")?;
            let num =
                serde_json::Number::from_f64(f).ok_or_else(|| ParseError {
                    message: "non-finite float".into(),
                })?;
            Value::Number(num)
        }
        "str" => Value::String(string_field(obj, "v")?),
        "list" => {
            let items = array_field(obj, "items")?;
            let mut out = Vec::new();
            for item in items {
                out.push(json_tagged_to_serde(&item)?);
            }
            Value::Array(out)
        }
        "map" => {
            let entries = array_field(obj, "entries")?;
            let mut map = serde_json::Map::new();
            for pair in entries {
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
                map.insert(key.clone(), json_tagged_to_serde(&two[1])?);
            }
            Value::Object(map)
        }
        "tuple" => {
            let items = array_field(obj, "items")?;
            let mut out = Vec::new();
            for item in items {
                out.push(json_tagged_to_serde(&item)?);
            }
            Value::Array(out)
        }
        other => {
            return Err(ParseError {
                message: format!("unknown tagged type {other}"),
            });
        }
    })
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
