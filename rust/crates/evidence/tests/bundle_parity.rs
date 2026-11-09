//! Byte-exact parity for `sesslint.bundle` against pinned Python vectors.

use evidence::bundle::{
    build_bundle, get_bundle_schema_path, load_bundle_schema, Bundle, JsonValue as BundleJson,
    ShortHashUnavailable, ValidateDetectionThresholdsUnavailable, VersionInfoUnavailable,
    _build_created_by, _count_records_bounded, _extract_kinds_fallback, _sanitize_evidence,
    _sanitize_remediation, BUNDLE_SCHEMA_VERSION, DEFAULT_JSON_INDENT, FIXTURE_TEMPLATE,
    MAX_PROBE_LINES, SAFE_DISCRIMINATOR_UNAVAILABLE, SCHEMA_PATH_UNAVAILABLE,
    SHORT_HASH_UNAVAILABLE, VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE, VERSION_INFO_UNAVAILABLE,
};
use evidence::seal::sha256_bytes;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_ROOT_REL: &str = "../../parity/vectors/bundle";
const VECTORS_REL: &str = "../../parity/vectors/bundle/vectors.json";
const COVERAGE_REL: &str = "../../parity/vectors/bundle/coverage.json";
const PROVENANCE_REL: &str = "../../parity/vectors/bundle/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 22;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.bundle";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_BUNDLE_PY_SHA256: &str =
    "3c5f7df93eaa410d6ccfc83c17b49ac1f85e45e2007fc9076635bec40965b133";
const EXPECTED_BUNDLE_RS_SHA256: &str =
    "30a0ecf9c7c6ffc6ca001d1a31cfa158fc514adcfab891ff0617303148529564";
const EXPECTED_VECTORS_SHA256: &str =
    "7d1e6e5dc58f5df5ca7db8fd7a5a7eba178df7ee1614e59560b0c069c3314def";
const EXPECTED_FIXTURE_TEMPLATE_SHA256: &str =
    "10d54eb7416be822c1b29e46bcb039c7e685d636a62c07e97a6361cc53cec2d7";

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
fn bundle_module_parity_vectors() {
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
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE contains_real_data"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "vector count");
    for case in &doc.cases {
        assert_case(case);
    }
    assert_coverage_contract(&doc.cases);
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "sanitize_remediation" => assert_sanitize_remediation(case),
        "count_records_bounded" => assert_count_records(case),
        "count_records_bounded_io_error" => assert_count_io_error_pin(case),
        "extract_kinds_fallback" => assert_extract_kinds(case),
        "build_bundle" => assert_build_bundle_gap(case),
        "get_bundle_schema_path" | "load_bundle_schema" => assert_schema_gap(case),
        "build_created_by" => assert_created_by_gap(case),
        "sanitize_evidence" => assert_sanitize_evidence_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "BUNDLE_SCHEMA_VERSION").expect("version"),
        BUNDLE_SCHEMA_VERSION,
        "{}",
        case.id
    );
    assert_eq!(BUNDLE_SCHEMA_VERSION, "sesslint.bundle/v1");
    assert_eq!(
        string_field(&case.expected, "FIXTURE_TEMPLATE_sha256").expect("template sha"),
        EXPECTED_FIXTURE_TEMPLATE_SHA256,
        "{}",
        case.id
    );
    assert_eq!(
        sha256_bytes(FIXTURE_TEMPLATE.as_bytes()),
        EXPECTED_FIXTURE_TEMPLATE_SHA256
    );
    assert!(!FIXTURE_TEMPLATE.contains('\r'));
    assert_eq!(
        i64_field(&case.expected, "DEFAULT_JSON_INDENT").expect("indent"),
        DEFAULT_JSON_INDENT
    );
    assert_eq!(
        usize_field(&case.expected, "MAX_PROBE_LINES").expect("probe"),
        MAX_PROBE_LINES
    );
    assert_eq!(
        usize_field(&case.expected, "RECORD_CHUNK_BYTES").expect("chunk"),
        65_536
    );
    assert_eq!(
        usize_field(&case.expected, "MAX_READLINE_BYTES").expect("readline"),
        1_000_000
    );
    let exports = string_array_field(&case.expected, "python_exports").expect("exports");
    assert!(exports.contains(&"build_bundle".to_owned()));
    assert!(exports.contains(&"Bundle".to_owned()));
    let _ = build_bundle as fn(_, _, _, _, _) -> _;
    let _ = get_bundle_schema_path as fn() -> _;
    let _ = load_bundle_schema as fn() -> _;
    assert_eq!(exports.len(), 6, "{}", case.id);
}

fn assert_sanitize_remediation(case: &VectorCase) {
    let remediation = string_field(&case.construct, "remediation").expect("remediation");
    let basename = string_field(&case.construct, "basename").expect("basename");
    let got = _sanitize_remediation(&remediation, &basename);
    assert_eq!(
        got,
        string_field(&case.expected, "text").expect("text"),
        "{}",
        case.id
    );
}

fn assert_count_records(case: &VectorCase) {
    let rel = string_field(&case.construct, "path").expect("path");
    let path = posix_join(&vectors_root(), &rel);
    let got = _count_records_bounded(&path);
    assert_eq!(
        got,
        i64_field(&case.expected, "count").expect("count"),
        "{}",
        case.id
    );
}

fn assert_count_io_error_pin(case: &VectorCase) {
    assert_eq!(case.id, "count_records_bounded_io_error_pin");
    let dir_rel = string_field(&case.construct, "directory_path").expect("directory_path");
    let miss_rel = string_field(&case.construct, "missing_path").expect("missing_path");
    let dir = posix_join(&vectors_root(), &dir_rel);
    let missing = posix_join(&vectors_root(), &miss_rel);
    assert!(dir.is_dir(), "{}: directory fixture", case.id);
    assert!(
        !missing.exists(),
        "{}: missing fixture must not exist",
        case.id
    );
    let dir_count = _count_records_bounded(&dir);
    let miss_count = _count_records_bounded(&missing);
    assert_eq!(
        dir_count,
        i64_field(&case.expected, "directory_count").expect("directory_count"),
        "{}",
        case.id
    );
    assert_eq!(
        miss_count,
        i64_field(&case.expected, "missing_count").expect("missing_count"),
        "{}",
        case.id
    );
    assert_eq!(dir_count, -1);
    assert_eq!(miss_count, -1);
}

fn assert_extract_kinds(case: &VectorCase) {
    let rel = string_field(&case.construct, "path").expect("path");
    let path = posix_join(&vectors_root(), &rel);
    if case.expected.iter().any(|(k, _)| k == "rust_assertion") {
        match _extract_kinds_fallback(&path) {
            Ok(counter) => panic!("{}: expected seam, got {counter:?}", case.id),
            Err(err) => {
                assert_eq!(err.to_string(), SAFE_DISCRIMINATOR_UNAVAILABLE);
                let pin = object_field(&case.expected, "pin").expect("pin");
                let kinds_obj = object_field(pin, "kinds").expect("pin kinds");
                let _ = kinds_map_from_json(kinds_obj);
            }
        }
        return;
    }
    let counter = _extract_kinds_fallback(&path)
        .unwrap_or_else(|err| panic!("{}: empty-file probe must succeed, got {err}", case.id));
    let want_obj = object_field(&case.expected, "kinds").expect("kinds");
    let want = kinds_map_from_json(want_obj);
    assert_eq!(counter, want, "{}", case.id);
}

fn kinds_map_from_json(pairs: &[(String, JsonValue)]) -> BTreeMap<String, i64> {
    pairs
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                i64_from_json(value).unwrap_or_else(|_| panic!("kind count for {key}")),
            )
        })
        .collect()
}

fn assert_build_bundle_gap(case: &VectorCase) {
    let rel = string_field(&case.construct, "path").expect("path");
    let profile = string_field(&case.construct, "profile").expect("profile");
    let path = posix_join(&vectors_root(), &rel);
    let err = build_bundle(&path, None, &profile, None, None).unwrap_err();
    assert_eq!(err.to_string(), VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE);
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "validate_detection_thresholds_unavailable"
    );
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let _ = err as ValidateDetectionThresholdsUnavailable;
}

fn assert_schema_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "schema_path_unavailable"
    );
    let kind = string_field(&case.construct, "type").expect("type");
    match kind.as_str() {
        "get_bundle_schema_path" => {
            let err = get_bundle_schema_path().unwrap_err();
            assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE);
        }
        "load_bundle_schema" => {
            let err = match load_bundle_schema() {
                Ok(never) => match never {},
                Err(error) => error,
            };
            assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE);
        }
        other => panic!("unexpected schema construct {other}"),
    }
    let _pin = object_field(&case.expected, "pin").expect("pin");
}

fn assert_created_by_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "version_info_unavailable"
    );
    let err = _build_created_by().unwrap_err();
    assert_eq!(err.to_string(), VERSION_INFO_UNAVAILABLE);
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let _ = err as VersionInfoUnavailable;
}

fn assert_sanitize_evidence_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "short_hash_unavailable"
    );
    let evidence_obj = object_field(&case.construct, "evidence").expect("evidence");
    let basename = string_field(&case.construct, "basename").expect("basename");
    let evidence = bundle_pairs_from_json(evidence_obj);
    let err = _sanitize_evidence(&evidence, &basename).unwrap_err();
    assert_eq!(err.to_string(), SHORT_HASH_UNAVAILABLE);
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let _ = err as ShortHashUnavailable;
}

fn bundle_pairs_from_json(pairs: &[(String, JsonValue)]) -> Vec<(String, BundleJson)> {
    pairs
        .iter()
        .map(|(key, value)| (key.clone(), bundle_json_from_parsed(value)))
        .collect()
}

fn bundle_json_from_parsed(value: &JsonValue) -> BundleJson {
    match value {
        JsonValue::Null => BundleJson::Null,
        JsonValue::Bool(b) => BundleJson::Bool(*b),
        JsonValue::Number(n) => BundleJson::Int(*n),
        JsonValue::Str(s) => BundleJson::String(s.clone()),
        JsonValue::Array(items) => {
            BundleJson::Array(items.iter().map(bundle_json_from_parsed).collect())
        }
        JsonValue::Object(obj) => BundleJson::Object(
            obj.iter()
                .map(|(k, v)| (k.clone(), bundle_json_from_parsed(v)))
                .collect(),
        ),
    }
}

fn assert_coverage_contract(cases: &[VectorCase]) {
    let raw = std::fs::read_to_string(coverage_path()).expect("coverage.json");
    let doc = parse_object_only(&raw.replace("\r\n", "\n")).expect("parse coverage");
    let rows = array_field(&doc, "rows").expect("rows");
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    for row in rows {
        let obj = as_object(&row, "coverage row").expect("coverage row object");
        let status = string_field(obj, "status").expect("status");
        match status.as_str() {
            "covered" => {
                covered += 1;
                let test = string_field(obj, "test").expect("test");
                assert_eq!(
                    test,
                    "tests/test_bundle.py::test_count_records_bounded_io_error"
                );
                let ids = string_array_field(obj, "vector_ids").expect("vector_ids");
                assert_eq!(ids, vec!["count_records_bounded_io_error_pin".to_owned()]);
                assert!(
                    cases
                        .iter()
                        .any(|case| case.id == "count_records_bounded_io_error_pin"),
                    "covered vector must exist"
                );
            }
            "not_applicable" => not_applicable += 1,
            other => panic!("unknown coverage status {other}"),
        }
    }
    assert_eq!(covered, 1, "exactly one covered pin test");
    assert_eq!(not_applicable, 57, "not_applicable count");
    let _ = Bundle::to_dict as fn(&Bundle) -> _;
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
        string_field(meta, "bundle_py_sha256").expect("bundle_py_sha256"),
        EXPECTED_BUNDLE_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "bundle_rs_sha256").expect("bundle_rs_sha256"),
        EXPECTED_BUNDLE_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    for marker in [
        "GAP-bundle-build",
        "GAP-bundle-schema-path",
        "GAP-bundle-version-info",
        "GAP-bundle-short-hash",
        "GAP-bundle-safe-discriminator",
    ] {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "missing gap {marker}"
        );
    }
}

// --- minimal JSON (vectors.json only) ---

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

fn string_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items.iter().map(string_from_json).collect()
}

fn string_from_json(value: &JsonValue) -> Result<String, ParseError> {
    match value {
        JsonValue::Str(text) => Ok(text.clone()),
        _ => Err(ParseError {
            message: "expected string".into(),
        }),
    }
}

fn i64_from_json(value: &JsonValue) -> Result<i64, ParseError> {
    match value {
        JsonValue::Number(raw) => Ok(*raw),
        _ => Err(ParseError {
            message: "expected number".into(),
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
        b'0'..=b'9' | b'-' => parse_number_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_number_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
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
