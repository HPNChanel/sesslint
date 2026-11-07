//! Parity for `sesslint.assessment` against pinned Python vectors.

use checks::assessment::{
    assess_source, AssessmentError, FileIdentity, MaxFileBytes, SourceAssessment,
    CHECK_IMPL_UNAVAILABLE, DEFAULT_MAX_FILE_BYTES, MAX_FILE_BYTES_POSITIVE,
    TRIAGE_REQUIRES_REGULAR_FILE,
};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const VECTORS_REL: &str = "../../parity/vectors/assessment/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/assessment/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/assessment/PROVENANCE.json";
const FIXTURES_REL: &str = "../../parity/vectors/assessment/fixtures";

const EXPECTED_VECTOR_COUNT: usize = 17;
const EXPECTED_VECTORS_SHA256: &str =
    "8edc0a87e947908577695e8f5d9958c48626aff1c0d86c255b8dafea5dfb7f96";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.assessment";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_ASSESSMENT_PY_SHA256: &str =
    "fa64f1ea4b7b7bd1340cdd4ea5ed0c76580086f58a6ce44647a9762d20b8c064";
const EXPECTED_ASSESSMENT_RS_SHA256: &str =
    "d4da13ae39098db38b0be046c381339df095c127b5aa92f09ef836e381c2fa5f";

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

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_REL)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn assessment_module_parity_vectors() {
    let path = vectors_path();
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert_eq!(
        sha256_hex(normalized.as_bytes()),
        EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );

    let prov_raw = fs::read_to_string(provenance_path()).expect("read PROVENANCE");
    let prov = parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("parse PROVENANCE");
    assert!(
        !bool_field(&prov, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must be synthetic"
    );

    let manifest_raw = fs::read_to_string(manifest_path()).expect("read manifest");
    let manifest = parse_object_only(&manifest_raw.replace("\r\n", "\n")).expect("parse manifest");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("vectors_sha256"),
        EXPECTED_VECTORS_SHA256
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("vector_count"),
        EXPECTED_VECTOR_COUNT
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "vector count");
    for case in &doc.cases {
        assert_case(case);
    }
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(string_field(meta, "schema").expect("schema"), EXPECTED_SCHEMA);
    assert_eq!(string_field(meta, "module").expect("module"), EXPECTED_MODULE);
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "assessment_py_sha256").expect("assessment_py_sha256"),
        EXPECTED_ASSESSMENT_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "assessment_rs_sha256").expect("assessment_rs_sha256"),
        EXPECTED_ASSESSMENT_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    assert!(
        gaps.iter().any(|item| matches!(item, JsonValue::Str(s) if s.contains("GAP-assessment-check-impl"))),
        "missing check_impl gap"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constant" => {
            let want = i64_field(&case.expected, "default_max_file_bytes").expect("default");
            assert_eq!(want, DEFAULT_MAX_FILE_BYTES, "{}", case.id);
        }
        "assess_source_raises" => assert_assess_raises(case),
        "assess_source" => assert_assess_source_seam(case),
        "unchanged" => assert_unchanged(case),
        other => panic!("{}: unknown construct {other}", case.id),
    }
}

fn assert_assess_raises(case: &VectorCase) {
    if lookup(&case.expected, "rust_assertion").is_some() {
        let _pin = object_field(&case.expected, "pin").expect("pin");
        let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
        let mode = string_field(assertion, "mode").expect("mode");
        assert_eq!(mode, "io_error", "{}", case.id);
        let want_kind = string_field(assertion, "kind").expect("kind");
        let path = resolve_raises_path(case);
        let cap = max_bytes_from_construct(&case.construct).unwrap_or(MaxFileBytes::Int(
            DEFAULT_MAX_FILE_BYTES,
        ));
        let err = stop(&path, None, cap);
        match &err {
            AssessmentError::Io(source) => {
                let want = io_error_kind(&want_kind);
                assert_eq!(source.kind(), want, "{}", case.id);
            }
            other => panic!("{}: expected io error, got {other:?}", case.id),
        }
        return;
    }

    let want_raises = string_field(&case.expected, "raises").expect("raises");
    let want_msg = string_field(&case.expected, "message").expect("message");
    let path = resolve_raises_path(case);
    let cap = max_bytes_from_construct(&case.construct).unwrap_or(MaxFileBytes::Int(
        DEFAULT_MAX_FILE_BYTES,
    ));
    let err = stop(&path, None, cap);
    match want_raises.as_str() {
        "ValueError" => {
            assert!(matches!(err, AssessmentError::MaxFileBytes), "{}", case.id);
            assert_eq!(err.to_string(), want_msg, "{}", case.id);
            assert_eq!(err.to_string(), MAX_FILE_BYTES_POSITIVE, "{}", case.id);
        }
        "OSError" => {
            assert!(matches!(err, AssessmentError::NotRegular), "{}", case.id);
            assert_eq!(err.to_string(), want_msg, "{}", case.id);
            assert_eq!(err.to_string(), TRIAGE_REQUIRES_REGULAR_FILE, "{}", case.id);
        }
        other => panic!("{}: unsupported raises {other}", case.id),
    }
}

fn assert_assess_source_seam(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "check_impl_unavailable", "{}", case.id);
    let want_msg = string_field(assertion, "message").expect("message");
    assert_eq!(want_msg, CHECK_IMPL_UNAVAILABLE);

    let fixture = string_field(&case.construct, "fixture").expect("fixture");
    let path = fixtures_root().join(fixture);
    let limit = i64_field(&case.construct, "max_file_bytes").expect("max");
    let format = optional_string(&case.construct, "format");
    let err = stop(&path, format.as_deref(), MaxFileBytes::Int(limit));
    assert_check_impl(&err, &case.id);
}

fn assert_unchanged(case: &VectorCase) {
    let want = bool_field(&case.expected, "unchanged").expect("unchanged");
    let fixture = string_field(&case.construct, "fixture").expect("fixture");
    let fingerprint = string_field(&case.construct, "fingerprint").expect("fingerprint");
    let readable = bool_field(&case.construct, "readable_snapshot").expect("readable");
    let path = fixtures_root().join(fixture);
    let item = sealed(&path, &fingerprint, readable);
    assert_eq!(item.unchanged(), want, "{}", case.id);
}

fn resolve_raises_path(case: &VectorCase) -> PathBuf {
    let kind = string_field(&case.construct, "path_kind").expect("path_kind");
    match kind.as_str() {
        "missing" => fixtures_root().join("synthetic-missing.bin"),
        "directory" => fixtures_root(),
        other => panic!("{}: unknown path_kind {other}", case.id),
    }
}

fn io_error_kind(label: &str) -> ErrorKind {
    match label {
        "NotFound" => ErrorKind::NotFound,
        other => panic!("unsupported io kind {other}"),
    }
}

fn max_bytes_from_construct(construct: &[(String, JsonValue)]) -> Option<MaxFileBytes> {
    let tagged = field_value(construct, "max_file_bytes")?;
    let obj = as_object(tagged, "max_file_bytes").ok()?;
    let t = string_field(obj, "t").ok()?;
    match t.as_str() {
        "bool" => Some(MaxFileBytes::Bool(bool_field(obj, "v").ok()?)),
        "int" => Some(MaxFileBytes::Int(i64_field_named(obj, "v").ok()?)),
        _ => None,
    }
}

fn optional_string(construct: &[(String, JsonValue)], key: &str) -> Option<String> {
    match field_value(construct, key)? {
        JsonValue::Str(text) => Some(text.clone()),
        _ => None,
    }
}

fn stop(path: &Path, format: Option<&str>, cap: MaxFileBytes) -> AssessmentError {
    match assess_source(path, format, "neutral", cap) {
        Ok(never) => match never {},
        Err(err) => err,
    }
}

fn assert_check_impl(err: &AssessmentError, case_id: &str) {
    assert!(matches!(err, AssessmentError::CheckImpl), "{case_id}");
    assert_eq!(err.to_string(), CHECK_IMPL_UNAVAILABLE, "{case_id}");
    assert!(Error::source(err).is_none(), "{case_id}");
}

fn sealed(path: &Path, fingerprint: &str, readable: bool) -> SourceAssessment {
    let identity = if path.is_file() {
        identity_from_path(path).expect("identity")
    } else {
        FileIdentity {
            dev: 0,
            ino: 0,
            size: 0,
            mtime_ns: 0,
        }
    };
    SourceAssessment {
        path: path.to_path_buf(),
        source_fingerprint: fingerprint.to_owned(),
        format: None,
        profile: "neutral".to_owned(),
        identity,
        readable_snapshot: readable,
    }
}

fn identity_from_path(path: &Path) -> std::io::Result<FileIdentity> {
    identity_from_meta(&fs::metadata(path)?)
}

fn identity_from_meta(meta: &fs::Metadata) -> std::io::Result<FileIdentity> {
    let mtime_ns = file_mtime_ns(meta).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "st_mtime_ns is not available on this platform",
        )
    })?;
    let (dev, ino) = dev_ino(meta);
    Ok(FileIdentity {
        dev,
        ino,
        size: meta.len(),
        mtime_ns,
    })
}

#[cfg(unix)]
fn dev_ino(meta: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn dev_ino(meta: &fs::Metadata) -> (u64, u64) {
    let _ = meta;
    (0, 0)
}

#[cfg(unix)]
fn file_mtime_ns(meta: &fs::Metadata) -> Option<i128> {
    use std::os::unix::fs::MetadataExt;
    let secs = i128::from(meta.mtime());
    let nanos = i128::from(meta.mtime_nsec());
    Some(secs * 1_000_000_000 + nanos)
}

#[cfg(windows)]
fn file_mtime_ns(meta: &fs::Metadata) -> Option<i128> {
    use std::os::windows::fs::MetadataExt;
    Some(filetime_to_unix_ns(meta.last_write_time()))
}

#[cfg(not(any(unix, windows)))]
fn file_mtime_ns(meta: &fs::Metadata) -> Option<i128> {
    let _ = meta;
    None
}

#[cfg(windows)]
fn filetime_to_unix_ns(ticks: u64) -> i128 {
    const WINDOWS_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    (i128::from(ticks) - WINDOWS_EPOCH_100NS) * 100
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn field_value<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
    let (value, rest) = parse_value(input)?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let meta_obj = as_object(&value, "root")?;
    let vectors_value = meta_obj
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let items = as_array(&vectors_value.1, "vectors")?;
    let mut meta = meta_obj.to_vec();
    meta.retain(|(k, _)| k != "vectors");
    let mut cases = Vec::with_capacity(items.len());
    for item in items {
        cases.push(parse_case(item)?);
    }
    Ok(ParsedDocument { meta, cases })
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input)?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    as_object(&value, "root").map(|obj| obj.to_vec())
}

fn parse_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
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

fn as_array<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [JsonValue], ParseError> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be array"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj.iter().find(|(k, _)| k == key).ok_or_else(|| ParseError {
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field_named(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    i64_field_named(obj, key)
}

fn i64_field_named(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
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
