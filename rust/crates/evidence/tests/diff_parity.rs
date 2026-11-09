//! Byte-exact parity for `sesslint.diff` against pinned Python vectors.

use codec::canonical_codec::CanonicalError;
use evidence::diff::{
    _delta_label, _load_side, diff_events, diff_sessions, get_diff_schema_path, load_diff_schema,
    Delta, DeltaCategory, DiffEvent, DiffJson, DiffSessionsError, SessionDiff, DELTA_CATEGORIES,
    DIFF_SCHEMA_VERSION, MAX_ROWS, MINIMIZE_PATH_UNAVAILABLE, RESOLVE_FORMAT_UNAVAILABLE,
    SCHEMA_PATH_UNAVAILABLE,
};
use evidence::seal::sha256_bytes;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_ROOT_REL: &str = "../../parity/vectors/diff";
const VECTORS_REL: &str = "../../parity/vectors/diff/vectors.json";
const COVERAGE_REL: &str = "../../parity/vectors/diff/coverage.json";
const PROVENANCE_REL: &str = "../../parity/vectors/diff/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 17;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.diff";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_DIFF_PY_SHA256: &str =
    "2d597dad56536db2bba2372c6e809ef31bb5784c31442e06ba8f7c34851ddbcf";
const EXPECTED_DIFF_RS_SHA256: &str =
    "5d8f763884f4d11944bef2c9939ce4a88b453a06659f1b0bc92b2800dbb9fa73";
const EXPECTED_VECTORS_SHA256: &str =
    "6b15fc355c25cef262fcc8af5f377bff0811a2ac7ada1286ef5ce133c7ec3bbe";

const HASH_SEAM: &str = "sesslint.canonical.SessionEvent is not available";

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
fn diff_module_parity_vectors() {
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

    let cov_raw = std::fs::read_to_string(coverage_path()).expect("coverage");
    let coverage = parse_object_only(&cov_raw.replace("\r\n", "\n")).expect("coverage");
    assert_eq!(
        usize_field(&coverage, "covered_count").expect("covered_count"),
        0
    );
    assert_eq!(
        usize_field(&coverage, "not_applicable_count").expect("not_applicable_count"),
        17
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "vector count");
    for case in &doc.cases {
        assert_case(case);
    }
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
        string_field(meta, "diff_py_sha256").expect("diff_py_sha256"),
        EXPECTED_DIFF_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "diff_rs_sha256").expect("diff_rs_sha256"),
        EXPECTED_DIFF_RS_SHA256
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "delta_to_dict" => assert_delta_to_dict(case),
        "delta_label" => assert_delta_label(case),
        "session_identical_counts" => assert_session_counts(case),
        "session_output_gap" => assert_session_output_gap(case),
        "diff_events_empty" => assert_diff_events_empty(case),
        "diff_events_hash_gap" => assert_diff_events_hash_gap(case),
        "diff_sessions_path" => assert_diff_sessions_path(case),
        "_load_side_gap" => assert_load_side_gap(case),
        "get_diff_schema_path" => assert_schema_gap(case),
        "load_diff_schema" => assert_schema_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        DIFF_SCHEMA_VERSION,
        string_field(&case.expected, "DIFF_SCHEMA_VERSION").expect("DIFF_SCHEMA_VERSION"),
        "{}",
        case.id
    );
    assert_eq!(
        i64::try_from(MAX_ROWS).expect("MAX_ROWS"),
        i64_field(&case.expected, "MAX_ROWS").expect("MAX_ROWS"),
        "{}",
        case.id
    );
    let want = string_array_field(&case.expected, "DELTA_CATEGORIES").expect("categories");
    let got: Vec<&str> = DELTA_CATEGORIES.to_vec();
    assert_eq!(got, want, "DELTA_CATEGORIES {}", case.id);
    let names = string_array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), 11, "export count {}", case.id);
}

fn assert_delta_to_dict(case: &VectorCase) {
    let delta = delta_from_construct(&case.construct);
    let got = delta_to_json_map(&delta.to_dict());
    let want_obj = object_field(&case.expected, "dict").expect("dict");
    assert_json_object_eq(want_obj, &got, &case.id);
}

fn assert_delta_label(case: &VectorCase) {
    let delta = Delta {
        category: DeltaCategory::Removed,
        event_id: optional_string_field(&case.construct, "event_id"),
        a_index: optional_i64_field(&case.construct, "a_index"),
        b_index: optional_i64_field(&case.construct, "b_index"),
        detail: detail_pairs_from_construct(&case.construct),
    };
    let want = string_field(&case.expected, "label").expect("label");
    assert_eq!(_delta_label(&delta), want, "{}", case.id);
}

fn assert_session_counts(case: &VectorCase) {
    let session = session_from_construct(&case.construct);
    assert_eq!(
        session.identical(),
        bool_field(&case.expected, "identical").expect("identical"),
        "{}",
        case.id
    );
    let want_counts = object_field(&case.expected, "counts").expect("counts");
    let got: BTreeMap<String, i64> = session
        .counts()
        .iter()
        .map(|(name, count)| (name.to_string(), *count))
        .collect();
    for (name, value) in want_counts {
        let JsonValue::Number(count) = value else {
            panic!("count must be number in {}", case.id);
        };
        assert_eq!(got.get(name), Some(count), "counts[{name}] {}", case.id);
    }
}

fn assert_session_output_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "minimize_path_unavailable"
    );
    let session = SessionDiff {
        a_path: "a/synthetic.jsonl".to_owned(),
        b_path: "b/synthetic.jsonl".to_owned(),
        a_format: "synthetic".to_owned(),
        b_format: "synthetic".to_owned(),
        a_event_count: 0,
        b_event_count: 0,
        tool_version: "0".to_owned(),
        deltas: Vec::new(),
    };
    let dict_err = session.to_dict(None).unwrap_err();
    assert_eq!(dict_err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
    assert_eq!(
        session.to_json(None).unwrap_err().to_string(),
        MINIMIZE_PATH_UNAVAILABLE
    );
    assert_eq!(
        session.render_human(None).unwrap_err().to_string(),
        MINIMIZE_PATH_UNAVAILABLE
    );
    let _pin = object_field(&case.expected, "pin").expect("pin");
}

fn assert_diff_events_empty(case: &VectorCase) {
    let deltas = diff_events(&[], &[]).expect("empty does not hash");
    assert_eq!(
        deltas.len(),
        usize_field(&case.expected, "delta_count").expect("delta_count"),
        "{}",
        case.id
    );
}

fn assert_diff_events_hash_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "content_hash_unavailable"
    );
    let event = DiffEvent {
        id: "e1".to_owned(),
        kind: "message".to_owned(),
        parent_id: None,
    };
    let err = diff_events(std::slice::from_ref(&event), std::slice::from_ref(&event)).unwrap_err();
    assert_eq!(err.to_string(), HASH_SEAM);
    let _ = err as CanonicalError;
    let pin = object_field(&case.expected, "pin").expect("pin");
    assert_eq!(
        usize_field(pin, "delta_count").expect("pin delta_count"),
        0,
        "{}",
        case.id
    );
}

fn assert_diff_sessions_path(case: &VectorCase) {
    let root = vectors_root();
    let path_a = posix_join(
        &root,
        &string_field(&case.construct, "path_a").expect("path_a"),
    );
    let path_b = posix_join(
        &root,
        &string_field(&case.construct, "path_b").expect("path_b"),
    );
    let format_a = optional_string_field(&case.construct, "format_a");
    let format_b = optional_string_field(&case.construct, "format_b");
    let rust_mode = string_field(&case.construct, "rust_mode").expect("rust_mode");
    let err = sessions_err(&path_a, &path_b, format_a.as_deref(), format_b.as_deref());
    match rust_mode.as_str() {
        "path_not_found" => match err {
            DiffSessionsError::PathNotFound(_) => {
                assert!(err.to_string().starts_with("Path not found:"));
            }
            other => panic!("{}: expected PathNotFound, got {other:?}", case.id),
        },
        "directory_input" => match err {
            DiffSessionsError::Input(_) => {
                assert!(err
                    .to_string()
                    .contains("Diff input must be a file, not a directory:"));
            }
            other => panic!("{}: expected directory input, got {other:?}", case.id),
        },
        "resolve_format_unavailable" => {
            assert_eq!(err.to_string(), RESOLVE_FORMAT_UNAVAILABLE);
        }
        other => panic!("unknown rust_mode {other} in {}", case.id),
    }
    let pin = object_field(&case.expected, "pin").expect("pin");
    assert_eq!(
        string_field(pin, "raises").expect("pin raises"),
        match rust_mode.as_str() {
            "path_not_found" => "FileNotFoundError",
            "directory_input" => "DiffInputError",
            "resolve_format_unavailable" => "DiffInputError",
            _ => "",
        },
        "pin raises {}",
        case.id
    );
    let _pin_message = string_field(pin, "message").ok();
}

fn assert_load_side_gap(case: &VectorCase) {
    let root = vectors_root();
    let path = posix_join(&root, &string_field(&case.construct, "path").expect("path"));
    let format = optional_string_field(&case.construct, "format");
    let err = _load_side(&path, format.as_deref()).unwrap_err();
    assert_eq!(err.to_string(), RESOLVE_FORMAT_UNAVAILABLE);
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "resolve_format_unavailable"
    );
}

fn assert_schema_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "schema_path_unavailable"
    );
    let kind = string_field(&case.construct, "type").expect("type");
    match kind.as_str() {
        "get_diff_schema_path" => {
            let err = get_diff_schema_path().unwrap_err();
            assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE);
        }
        "load_diff_schema" => {
            let err = match load_diff_schema() {
                Ok(never) => match never {},
                Err(error) => error,
            };
            assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE);
        }
        _ => panic!("schema gap kind"),
    }
    let _pin = object_field(&case.expected, "pin").expect("pin");
}

fn sessions_err(
    a: &Path,
    b: &Path,
    format_a: Option<&str>,
    format_b: Option<&str>,
) -> DiffSessionsError {
    match diff_sessions(a, b, format_a, format_b) {
        Ok(never) => match never {},
        Err(error) => error,
    }
}

fn delta_from_construct(construct: &[(String, JsonValue)]) -> Delta {
    let category = string_field(construct, "category").expect("category");
    Delta {
        category: category_from_str(&category),
        event_id: optional_string_field(construct, "event_id"),
        a_index: optional_i64_field(construct, "a_index"),
        b_index: optional_i64_field(construct, "b_index"),
        detail: detail_from_object(construct),
    }
}

fn detail_from_object(construct: &[(String, JsonValue)]) -> Vec<(String, String)> {
    let Some(obj) = object_field(construct, "detail").ok() else {
        return Vec::new();
    };
    obj.iter()
        .map(|(key, value)| {
            let text = string_from_json(value).expect("detail string");
            (key.clone(), text)
        })
        .collect()
}

fn detail_pairs_from_construct(construct: &[(String, JsonValue)]) -> Vec<(String, String)> {
    detail_from_object(construct)
}

fn session_from_construct(construct: &[(String, JsonValue)]) -> SessionDiff {
    let deltas_json = array_field(construct, "deltas").unwrap_or_default();
    let mut deltas = Vec::new();
    for value in deltas_json {
        let row = as_object(&value, "delta").expect("delta object");
        let category = string_field(row, "category").expect("category");
        deltas.push(Delta {
            category: category_from_str(&category),
            event_id: optional_string_field(row, "event_id"),
            a_index: optional_i64_field(row, "a_index"),
            b_index: optional_i64_field(row, "b_index"),
            detail: detail_from_row(row),
        });
    }
    SessionDiff {
        a_path: "a/synthetic.jsonl".to_owned(),
        b_path: "b/synthetic.jsonl".to_owned(),
        a_format: "synthetic".to_owned(),
        b_format: "synthetic".to_owned(),
        a_event_count: i64_field(construct, "a_event_count").unwrap_or(0),
        b_event_count: i64_field(construct, "b_event_count").unwrap_or(0),
        tool_version: "0".to_owned(),
        deltas,
    }
}

fn detail_from_row(row: &[(String, JsonValue)]) -> Vec<(String, String)> {
    let Some(obj) = object_field(row, "detail").ok() else {
        return Vec::new();
    };
    obj.iter()
        .map(|(key, value)| (key.clone(), string_from_json(value).expect("detail value")))
        .collect()
}

fn category_from_str(text: &str) -> DeltaCategory {
    match text {
        "added" => DeltaCategory::Added,
        "removed" => DeltaCategory::Removed,
        "kind-changed" => DeltaCategory::KindChanged,
        "parent-relinked" => DeltaCategory::ParentRelinked,
        "seq-reordered" => DeltaCategory::SeqReordered,
        "content-changed" => DeltaCategory::ContentChanged,
        other => panic!("unknown category {other}"),
    }
}

fn delta_to_json_map(value: &DiffJson) -> BTreeMap<String, JsonValue> {
    let DiffJson::Object(pairs) = value else {
        panic!("delta dict must be object");
    };
    let mut out = BTreeMap::new();
    for (key, nested) in pairs {
        out.insert(key.clone(), diff_json_to_value(nested));
    }
    out
}

fn diff_json_to_value(value: &DiffJson) -> JsonValue {
    match value {
        DiffJson::Int(raw) => JsonValue::Number(*raw),
        DiffJson::String(text) => JsonValue::Str(text.clone()),
        DiffJson::Object(pairs) => {
            let mut items = Vec::new();
            for (key, nested) in pairs {
                items.push((key.clone(), diff_json_to_value(nested)));
            }
            JsonValue::Object(items)
        }
    }
}

fn assert_json_object_eq(
    want: &[(String, JsonValue)],
    got: &BTreeMap<String, JsonValue>,
    id: &str,
) {
    assert_eq!(want.len(), got.len(), "field count {id}");
    for (key, value) in want {
        let got_value = got
            .get(key)
            .unwrap_or_else(|| panic!("missing {key} in {id}"));
        assert_json_eq(value, got_value, id, key);
    }
}

fn assert_json_eq(want: &JsonValue, got: &JsonValue, id: &str, key: &str) {
    match (want, got) {
        (JsonValue::Str(left), JsonValue::Str(right)) => assert_eq!(left, right, "{key} {id}"),
        (JsonValue::Number(left), JsonValue::Number(right)) => {
            assert_eq!(left, right, "{key} {id}")
        }
        (JsonValue::Bool(left), JsonValue::Bool(right)) => assert_eq!(left, right, "{key} {id}"),
        (JsonValue::Object(left), JsonValue::Object(right)) => {
            assert_eq!(left.len(), right.len(), "{key} object len {id}");
            for (name, nested) in left {
                let got_nested = right
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, value)| value)
                    .unwrap_or_else(|| panic!("missing nested {name} in {id}"));
                assert_json_eq(nested, got_nested, id, name);
            }
        }
        _ => panic!("json mismatch at {key} in {id}"),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        _ => None,
    }
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Option<i64> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => Some(*raw),
        _ => None,
    }
}

// --- minimal JSON ---

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
        Some((_, JsonValue::Null)) if key == "raises" => Ok(String::new()),
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
    usize::try_from(i64_field(obj, key)?).map_err(|_| ParseError {
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
    array_field(obj, key)?
        .iter()
        .map(string_from_json)
        .collect()
}

fn string_from_json(value: &JsonValue) -> Result<String, ParseError> {
    match value {
        JsonValue::Str(s) => Ok(s.clone()),
        _ => Err(ParseError {
            message: "expected string".into(),
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
