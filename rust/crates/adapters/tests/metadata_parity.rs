//! Parity for `sesslint.adapters.metadata` against pinned Python vectors.
//!
//! Compares [`SEMANTIC_KEYS`], [`has_semantic_fields`], and [`UnknownMetadataTracker`]
//! flush modes. Pin snapshots of private `_groups` rows stay in the vector and are
//! not asserted.

use adapters::metadata::{
    has_semantic_fields, MetadataKey, MetadataValue, UnknownMetadataTracker, SEMANTIC_KEYS,
};
use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.metadata/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 123;
const EXPECTED_VECTORS_SHA256: &str =
    "51aca752f54821f04f7e7800d182125e4f57d4125d7cf7d434ab039238352ae9";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.adapters.metadata";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_METADATA_PY_SHA256: &str =
    "0476945fab0e06501492c2e773aac50c57484b0e7bfc22c1fb98575177bdeac0";
const EXPECTED_METADATA_RS_SHA256: &str =
    "8256a693817a3af850588b5887cc390fd5dd6660b6d69f0be8a26ba9ec984f69";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FlushMode {
    EmptyOk,
    GapFingerprint,
    FindingError(String),
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_semantic_keys" => assert_semantic_keys(case),
        "has_semantic_fields" => assert_has_semantic(case),
        "tracker_run" => assert_tracker_run(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_semantic_keys(case: &VectorCase) {
    let keys = array_field(&case.expected, "semantic_keys").expect("semantic_keys");
    assert_eq!(keys.len(), SEMANTIC_KEYS.len(), "SEMANTIC_KEYS length");
    let mut sorted: Vec<&str> = SEMANTIC_KEYS.to_vec();
    sorted.sort_unstable();
    for (index, item) in keys.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("semantic_keys[{index}] must be string in {}", case.id);
        };
        assert_eq!(sorted[index], name.as_str(), "key[{index}]");
    }
    let count = usize_field(&case.expected, "semantic_key_count").expect("count");
    assert_eq!(count, SEMANTIC_KEYS.len());
}

fn assert_has_semantic(case: &VectorCase) {
    let spec = object_field(&case.construct, "value").expect("value");
    let value = decode_metadata_value(spec).expect("decode value");
    let got = has_semantic_fields(&value);
    let want = bool_field(&case.expected, "has_semantic").expect("has_semantic");
    assert_eq!(got, want, "has_semantic_fields for {}", case.id);
}

fn assert_tracker_run(case: &VectorCase) {
    let steps = array_field(&case.construct, "steps").expect("steps");
    let _pin_groups = array_field(&case.expected, "groups").expect("groups");

    let mut tracker = UnknownMetadataTracker::new();
    run_steps(&mut tracker, steps).expect("tracker steps");

    let flush_obj = object_field(&case.expected, "flush").expect("flush");
    let want_mode = parse_flush_mode(flush_obj).expect("flush mode");
    let path = string_field(flush_obj, "path").expect("path");
    let got = actual_flush_mode(&tracker, &path);
    assert_flush_equality(&got, &want_mode, &case.id);
}

fn actual_flush_mode(tracker: &UnknownMetadataTracker, path: &str) -> FlushMode {
    match tracker.findings(path) {
        Ok(findings) => {
            assert!(findings.is_empty());
            FlushMode::EmptyOk
        }
        Err(err) => {
            let text = err.to_string();
            if text == FINGERPRINT_CODEC_UNAVAILABLE {
                FlushMode::GapFingerprint
            } else {
                FlushMode::FindingError(text)
            }
        }
    }
}

fn parse_flush_mode(obj: &[(String, JsonValue)]) -> Result<FlushMode, ParseError> {
    let mode = string_field(obj, "mode")?;
    match mode.as_str() {
        "empty_ok" => Ok(FlushMode::EmptyOk),
        "gap_fingerprint" => Ok(FlushMode::GapFingerprint),
        "finding_error" => {
            let needle = string_field(obj, "error_contains")?;
            Ok(FlushMode::FindingError(needle))
        }
        other => Err(ParseError {
            message: format!("unknown flush mode {other}"),
        }),
    }
}

fn run_steps(tracker: &mut UnknownMetadataTracker, steps: &[JsonValue]) -> Result<(), ParseError> {
    for step in steps {
        let obj = as_object_value(step, "step")?;
        let action = string_field(obj, "action")?;
        if action != "note" {
            return Err(ParseError {
                message: format!("unknown step action {action}"),
            });
        }
        let raw_type = string_field(obj, "raw_type")?;
        let line = i64_field(obj, "line")?;
        tracker.note(&raw_type, line);
    }
    Ok(())
}

fn decode_metadata_value(spec: &[(String, JsonValue)]) -> Result<MetadataValue, ParseError> {
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "none" => Ok(MetadataValue::NoneValue),
        "scalar" => Ok(MetadataValue::Scalar),
        "map" => {
            let entries_spec = array_field(spec, "entries")?;
            let mut entries = Vec::with_capacity(entries_spec.len());
            for entry in entries_spec {
                let obj = as_object_value(entry, "entry")?;
                let key_spec = object_field(obj, "key")?;
                let key = decode_metadata_key(key_spec)?;
                let val_spec = object_field(obj, "value")?;
                let value = decode_metadata_value(val_spec)?;
                entries.push((key, value));
            }
            Ok(MetadataValue::Map(entries))
        }
        "list" => {
            let items_spec = array_field(spec, "items")?;
            let mut items = Vec::with_capacity(items_spec.len());
            for item in items_spec {
                let obj = as_object_value(item, "list item")?;
                items.push(decode_metadata_value(obj)?);
            }
            Ok(MetadataValue::List(items))
        }
        other => Err(ParseError {
            message: format!("unknown metadata value kind {other}"),
        }),
    }
}

fn decode_metadata_key(spec: &[(String, JsonValue)]) -> Result<MetadataKey, ParseError> {
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "str" => Ok(MetadataKey::Str(string_field(spec, "text")?)),
        "non_str" => Ok(MetadataKey::NonStr),
        other => Err(ParseError {
            message: format!("unknown metadata key kind {other}"),
        }),
    }
}

#[test]
fn metadata_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(
        !normalized.contains('\r'),
        "vectors.json must not contain CR"
    );
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors sha256");

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

fn assert_flush_equality(got: &FlushMode, want: &FlushMode, case_id: &str) {
    match (got, want) {
        (FlushMode::EmptyOk, FlushMode::EmptyOk) => {}
        (FlushMode::GapFingerprint, FlushMode::GapFingerprint) => {}
        (FlushMode::FindingError(got_msg), FlushMode::FindingError(want_msg)) => {
            assert!(
                got_msg.contains(want_msg),
                "finding_error mismatch for {case_id}: got {got_msg}"
            );
            assert_ne!(got_msg, FINGERPRINT_CODEC_UNAVAILABLE);
        }
        _ => panic!("flush mode mismatch for {case_id}: got {got:?} want {want:?}"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => '?',
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
        string_field(meta, "metadata_py_sha256").expect("metadata_py_sha256"),
        EXPECTED_METADATA_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "metadata_rs_sha256").expect("metadata_rs_sha256"),
        EXPECTED_METADATA_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    assert!(
        gaps.iter().any(|item| {
            matches!(item, JsonValue::Str(s) if s.contains("GAP-metadata-finding-fingerprint"))
        }),
        "expected GAP-metadata-finding-fingerprint"
    );
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
    let meta: Vec<(String, JsonValue)> = root
        .iter()
        .filter(|(key, _)| *key != "vectors")
        .cloned()
        .collect();
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
    let cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    Ok(ParsedDocument { meta, cases })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
    })
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn as_object_value<'a>(
    value: &'a JsonValue,
    ctx: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    as_object(value, ctx)
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

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let raw = i64_field(obj, key)?;
    usize::try_from(raw).map_err(|_| ParseError {
        message: format!("{key} out of usize range"),
    })
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
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
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
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

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    if input.starts_with('-') {
        end = 1;
    }
    while end < input.len() {
        let ch = input.as_bytes()[end];
        if ch.is_ascii_digit() {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 || (end == 1 && input.starts_with('-')) {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    Ok((JsonValue::Number(input[..end].to_owned()), &input[end..]))
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
    let mut chars = input[1..].chars();
    loop {
        let ch = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        if ch == '"' {
            let consumed = input.len() - chars.as_str().len();
            return Ok((out, &input[consumed..]));
        }
        if ch == '\\' {
            let esc = chars.next().ok_or_else(|| ParseError {
                message: "bad escape".into(),
            })?;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() != 4 {
                        return Err(ParseError {
                            message: "bad unicode escape".into(),
                        });
                    }
                    let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                        message: "bad unicode escape".into(),
                    })?;
                    let converted = char::try_from(code).map_err(|_| ParseError {
                        message: "bad unicode scalar".into(),
                    })?;
                    out.push(converted);
                }
                _ => {
                    return Err(ParseError {
                        message: "bad escape".into(),
                    })
                }
            }
        } else {
            out.push(ch);
        }
    }
}
