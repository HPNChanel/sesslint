//! Byte-exact parity for `sesslint.exporter` against pinned Python vectors.

use evidence::exporter::{
    export_to_canonical, ExportJson, ExportRefused, ExportSummary, ExportToCanonicalError, ALL,
};
use evidence::seal::sha256_bytes;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const VECTORS_ROOT_REL: &str = "../../parity/vectors/exporter";
const VECTORS_REL: &str = "../../parity/vectors/exporter/vectors.json";
const COVERAGE_REL: &str = "../../parity/vectors/exporter/coverage.json";
const PROVENANCE_REL: &str = "../../parity/vectors/exporter/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 9;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.exporter";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_EXPORTER_PY_SHA256: &str =
    "d5386b1c85b9ff596e5a6e014d1acaff8e6ad74c9c956d04e9aa0a9e7a4d8ea5";
const EXPECTED_EXPORTER_RS_SHA256: &str =
    "fdc599ed26bfaeed99c784b5a8547e81c5fbd1d044ad63766b92cb208fe1f40c";
const EXPECTED_VECTORS_SHA256: &str =
    "a3a31ce8e6bc3833a485e0f84a0e95336778d5fbbfeb1ac5d4e6727a382ff716";

const LIVE_STORE_UNAVAILABLE: &str = "sesslint.repair.executor.is_live_store_path is not available";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_ROOT_REL)
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn coverage_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn posix_join(base: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(base.to_path_buf(), |acc, part| acc.join(part))
}

#[test]
fn exporter_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(!normalized.contains('\r'), "vectors.json must use LF only");
    assert_eq!(
        sha256_bytes(normalized.as_bytes()),
        EXPECTED_VECTORS_SHA256,
        "vectors.json sha256"
    );

    let prov_raw = std::fs::read_to_string(provenance_path()).expect("PROVENANCE");
    let provenance = parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("PROVENANCE");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE contains_real_data"
    );
    let prov_gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, "GAP-evidence-exporter-live-store")),
        "PROVENANCE must document live-store gap"
    );

    let cov_raw = std::fs::read_to_string(coverage_path()).expect("coverage");
    let coverage = parse_object_only(&cov_raw.replace("\r\n", "\n")).expect("coverage");
    assert_eq!(
        usize_field(&coverage, "covered_count").expect("covered_count"),
        0
    );
    assert_eq!(
        usize_field(&coverage, "not_applicable_count").expect("not_applicable_count"),
        11
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "vector count");
    for case in &doc.cases {
        assert_case(case);
    }
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
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
        string_field(meta, "exporter_py_sha256").expect("exporter_py_sha256"),
        EXPECTED_EXPORTER_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "exporter_rs_sha256").expect("exporter_rs_sha256"),
        EXPECTED_EXPORTER_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, "GAP-evidence-exporter-live-store")),
        "expected live-store gap in vectors metadata"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "export_refused" => assert_export_refused(case),
        "export_summary_to_dict" => assert_export_summary(case),
        "export_to_canonical" => assert_export_not_found(case),
        "export_to_canonical_gap" => assert_export_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    let want = string_array_field(&case.expected, "python_all").expect("python_all");
    let got: Vec<&str> = ALL.to_vec();
    assert_eq!(got, want, "{}", case.id);
}

fn assert_export_refused(case: &VectorCase) {
    assert_eq!(
        ExportRefused::DEFAULT_CODE,
        string_field(&case.expected, "default_code").expect("default_code"),
        "{}",
        case.id
    );
    let default = ExportRefused::new("refused synthetic export");
    assert_eq!(
        default.to_string(),
        string_field(&case.expected, "message_only").expect("message_only"),
        "{}",
        case.id
    );
    assert_eq!(default.code, "EXPORT_REFUSED");
    let custom = ExportRefused::with_code(
        "other",
        string_field(&case.expected, "custom_code").expect("custom_code"),
    );
    assert_eq!(
        custom.to_string(),
        string_field(&case.expected, "custom_message").expect("custom_message"),
        "{}",
        case.id
    );
}

fn assert_export_summary(case: &VectorCase) {
    let summary = ExportSummary {
        input_path: "in.jsonl".to_owned(),
        input_format: "canonical".to_owned(),
        output_path: "out.jsonl".to_owned(),
        input_sha256: "aa".to_owned(),
        output_sha256: "bb".to_owned(),
        event_count: 3,
        dropped_unknown_fields: 1,
        findings_by_severity: vec![
            ("warning".to_owned(), 2),
            ("fatal".to_owned(), 1),
            ("info".to_owned(), 0),
        ],
    };
    let ExportJson::Object(pairs) = summary.to_dict() else {
        panic!("to_dict object {}", case.id);
    };
    let got: Vec<(String, JsonValue)> = pairs
        .iter()
        .map(|(key, value)| (key.clone(), export_json_value(value)))
        .collect();
    let want = object_field(&case.expected, "dict").expect("dict");
    assert_json_object_eq(want, &got, &case.id);
}

fn assert_export_not_found(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "raises").expect("raises"),
        "FileNotFoundError",
        "{}",
        case.id
    );
    let want = string_field(&case.expected, "message").expect("message");
    let root = vectors_root();
    let source_rel = string_field(&case.construct, "source_path").expect("source_path");
    let output_rel = string_field(&case.construct, "output_path").expect("output_path");
    let format = optional_string_field(&case.construct, "format");
    let prev = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&root).expect("chdir vectors root");
    let source = if source_rel.is_empty() {
        PathBuf::new()
    } else {
        PathBuf::from(source_rel.replace('/', std::path::MAIN_SEPARATOR_STR))
    };
    let output = PathBuf::from(output_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let err = export_to_canonical(&source, &output, format.as_deref()).expect_err("export");
    let output_abs = root.join(&output);
    std::env::set_current_dir(&prev).expect("restore cwd");
    assert!(
        matches!(err, ExportToCanonicalError::FileNotFound(_)),
        "{}",
        case.id
    );
    assert_eq!(normalize_slashes(&err.to_string()), want, "{}", case.id);
    assert!(err.source().is_none());
    assert!(!output_abs.exists(), "{}", case.id);
}

fn assert_export_gap(case: &VectorCase) {
    let pin = object_field(&case.expected, "pin").expect("pin");
    assert!(bool_field(pin, "source_is_file").expect("source_is_file"));
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "live_store_path_unavailable",
        "{}",
        case.id
    );
    let root = vectors_root();
    let source_rel = string_field(&case.construct, "source_path").expect("source");
    let output_rel = string_field(&case.construct, "output_path").expect("output");
    let source_abs = posix_join(&root, &source_rel);
    assert!(
        fs::metadata(&source_abs).is_ok_and(|m| m.is_file()),
        "{}: fixture must be a regular file",
        case.id
    );
    let format = optional_string_field(&case.construct, "format");
    let prev = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&root).expect("chdir vectors root");
    let source = PathBuf::from(source_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let output = PathBuf::from(output_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let err = export_to_canonical(&source, &output, format.as_deref()).expect_err("gap");
    let output_abs = root.join(&output);
    std::env::set_current_dir(&prev).expect("restore cwd");
    assert_eq!(err.to_string(), LIVE_STORE_UNAVAILABLE, "{}", case.id);
    assert!(matches!(
        err,
        ExportToCanonicalError::LiveStorePathUnavailable
    ));
    assert!(Error::source(&err).is_none());
    assert!(!output_abs.exists(), "{}", case.id);
}

fn normalize_slashes(text: &str) -> String {
    text.replace('\\', "/")
}

fn export_json_value(value: &ExportJson) -> JsonValue {
    match value {
        ExportJson::Int(number) => JsonValue::Number(*number),
        ExportJson::String(text) => JsonValue::Str(text.clone()),
        ExportJson::Object(pairs) => JsonValue::Object(
            pairs
                .iter()
                .map(|(key, child)| (key.clone(), export_json_value(child)))
                .collect(),
        ),
    }
}

fn assert_json_object_eq(want: &[(String, JsonValue)], got: &[(String, JsonValue)], id: &str) {
    assert_eq!(got.len(), want.len(), "object length {id}");
    for (index, (want_key, want_value)) in want.iter().enumerate() {
        let (got_key, got_value) = &got[index];
        assert_eq!(got_key, want_key, "key order {id}");
        assert_json_eq(want_value, got_value, id, want_key);
    }
}

fn assert_json_eq(want: &JsonValue, got: &JsonValue, id: &str, ctx: &str) {
    match (want, got) {
        (JsonValue::Null, JsonValue::Null) => {}
        (JsonValue::Bool(a), JsonValue::Bool(b)) => assert_eq!(a, b, "{id}:{ctx}"),
        (JsonValue::Str(a), JsonValue::Str(b)) => assert_eq!(a, b, "{id}:{ctx}"),
        (JsonValue::Number(a), JsonValue::Number(b)) => assert_eq!(a, b, "{id}:{ctx}"),
        (JsonValue::Array(a), JsonValue::Array(b)) => {
            assert_eq!(a.len(), b.len(), "{id}:{ctx}");
            for (left, right) in a.iter().zip(b.iter()) {
                assert_json_eq(left, right, id, ctx);
            }
        }
        (JsonValue::Object(a), JsonValue::Object(b)) => assert_json_object_eq(a, b, id),
        _ => panic!("json mismatch {id}:{ctx}"),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    usize::try_from(i64_field(obj, key)?).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

// --- minimal JSON (no serde_json) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
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
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
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
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Object(inner))) => Ok(inner),
        Some(_) => Err(ParseError {
            message: format!("{key} must be object"),
        }),
        None => Err(ParseError {
            message: format!("missing {key}"),
        }),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        Some(_) => None,
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(text))) => Ok(text.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn string_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let JsonValue::Array(items) = obj
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
        .ok_or_else(|| ParseError {
            message: format!("missing {key}"),
        })?
    else {
        return Err(ParseError {
            message: format!("{key} must be array"),
        });
    };
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => Ok(text.clone()),
            _ => Err(ParseError {
                message: format!("{key} items must be strings"),
            }),
        })
        .collect()
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(value))) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(value))) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
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
    match input.as_bytes().first() {
        None => Err(ParseError {
            message: "unexpected end".into(),
        }),
        Some(b'n') => parse_literal(input, "null", JsonValue::Null),
        Some(b't') => parse_literal(input, "true", JsonValue::Bool(true)),
        Some(b'f') => parse_literal(input, "false", JsonValue::Bool(false)),
        Some(b'"') => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        Some(b'[') => parse_array(input),
        Some(b'{') => parse_object(input),
        Some(b'-' | b'0'..=b'9') => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON".into(),
        }),
    }
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    input
        .strip_prefix(word)
        .map(|rest| (value, rest))
        .ok_or_else(|| ParseError {
            message: format!("expected {word}"),
        })
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0usize;
    for (index, ch) in input.char_indices() {
        if ch == '-' || ch.is_ascii_digit() {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    let raw = &input[..end];
    let parsed: i64 = raw.parse().map_err(|_| ParseError {
        message: "bad number".into(),
    })?;
    Ok((JsonValue::Number(parsed), &input[end..]))
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
                message: "expected , or ]".into(),
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
                message: "expected :".into(),
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
                message: "expected , or }".into(),
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
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "bad unicode".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "bad escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
