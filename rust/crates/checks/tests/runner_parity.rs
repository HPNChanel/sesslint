//! Module-surface parity for `sesslint.checks.runner` against pinned Python vectors.

use checks::runner::{
    run_all_checks, AdapterSkip, ProfileArg, RunAllChecksInput, ALL, COVERAGE_UNAVAILABLE,
    IMPORT_PATHS,
};
use model::canonical::{Payload, SessionEvent};
use model::events::EventValue;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/checks.runner/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/checks.runner/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/checks.runner/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 8;
const EXPECTED_VECTORS_SHA256: &str =
    "64b0bfaa6c1b7db1f025dd5a2f0aba6020a602f4fcd1adbe123c3934c8f3805f";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.checks.runner";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_RUNNER_PY_SHA256: &str =
    "7a46ab2503cb5ce50ae3ff3ca0cd029cd366b0efd42a2623204c499498fc0341";
const EXPECTED_RUNNER_RS_SHA256: &str =
    "1a78321cd7d6144ac84821cbc1b257a266d484685644af1d033c7ebc206e0450";

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
fn runner_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must be synthetic"
    );

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
        string_field(meta, "checks_runner_py_sha256").expect("checks_runner_py_sha256"),
        EXPECTED_RUNNER_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "checks_runner_rs_sha256").expect("checks_runner_rs_sha256"),
        EXPECTED_RUNNER_RS_SHA256
    );

    let py_all = array_field(meta, "python_all").expect("python_all");
    assert_eq!(py_all.len(), ALL.len(), "python_all length");
    for (idx, item) in py_all.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{idx}] must be string");
        };
        assert_eq!(name.as_str(), ALL[idx], "python_all[{idx}]");
    }

    let import_paths = array_field(meta, "python_import_paths").expect("python_import_paths");
    assert_eq!(import_paths.len(), IMPORT_PATHS.len(), "import paths length");
    for (idx, item) in import_paths.iter().enumerate() {
        let JsonValue::Str(path) = item else {
            panic!("python_import_paths[{idx}] must be string");
        };
        assert_eq!(path.as_str(), IMPORT_PATHS[idx], "import_paths[{idx}]");
    }

    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in [
        "GAP-runner-coverage",
        "GAP-runner-profile-name",
        "GAP-runner-detector-profile-deps",
    ] {
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
        "module_all" => {
            let names = array_field(&case.expected, "names").expect("names");
            assert_eq!(names.len(), ALL.len(), "{}", case.id);
            for (idx, item) in names.iter().enumerate() {
                let JsonValue::Str(name) = item else {
                    panic!("{}: names[{idx}] must be string", case.id);
                };
                assert_eq!(name.as_str(), ALL[idx], "{}", case.id);
            }
        }
        "import_paths" => {
            let paths = array_field(&case.expected, "paths").expect("paths");
            assert_eq!(paths.len(), IMPORT_PATHS.len(), "{}", case.id);
            for (idx, item) in paths.iter().enumerate() {
                let JsonValue::Str(path) = item else {
                    panic!("{}: paths[{idx}] must be string", case.id);
                };
                assert_eq!(path.as_str(), IMPORT_PATHS[idx], "{}", case.id);
            }
        }
        "run_all_checks" => assert_run_all_checks(case),
        other => panic!("{}: unknown construct type {other}", case.id),
    }
}

fn assert_run_all_checks(case: &VectorCase) {
    let events = decode_event_list(&case.construct).expect("events");
    let source_path = optional_string(&case.construct, "source_path")
        .unwrap_or_else(|| "<repaired>".to_owned());
    let return_coverage = bool_field(&case.construct, "return_coverage").unwrap_or(false);
    let profile_name;
    let profile = match optional_string(&case.construct, "profile") {
        None => ProfileArg::Absent,
        Some(name) => {
            profile_name = name;
            ProfileArg::Name(profile_name.as_str())
        }
    };
    let skip_specs = adapter_skips(&case.construct).expect("adapter_skips");
    let mut skip_storage: Vec<AdapterSkip<'_>> = Vec::new();
    for spec in &skip_specs {
        skip_storage.push(AdapterSkip {
            check: spec.0.as_str(),
            reason: spec.1.as_str(),
            detail: spec.2.as_str(),
        });
    }
    let mut input = RunAllChecksInput::new(&events);
    input.source_path = source_path.as_str();
    input.return_coverage = return_coverage;
    input.profile = profile;
    input.adapter_skips = &skip_storage;

    if lookup(&case.expected, "rust_assertion").is_some() {
        let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
        let mode = string_field(assertion, "mode").expect("mode");
        let want_msg = string_field(assertion, "message").expect("message");
        let error = run_all_checks(&input).expect_err(&case.id);
        assert_eq!(error.to_string(), want_msg, "{}", case.id);
        match mode.as_str() {
            "coverage_unavailable" => assert_eq!(want_msg, COVERAGE_UNAVAILABLE, "{}", case.id),
            "builtin_unavailable" | "profiles_unavailable" => {}
            other => panic!("{}: unknown rust_assertion mode {other}", case.id),
        }
        return;
    }

    let outcome = string_field(&case.expected, "outcome").expect("outcome");
    assert_eq!(outcome, "ok", "{}", case.id);
    let want_count = usize_field(&case.expected, "findings_count").expect("findings_count");
    let findings = run_all_checks(&input).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_eq!(findings.len(), want_count, "{}", case.id);
}

fn adapter_skips(
    construct: &[(String, JsonValue)],
) -> Result<Vec<(String, String, String)>, ParseError> {
    let items = match construct.iter().find(|(k, _)| k == "adapter_skips") {
        None => return Ok(Vec::new()),
        Some((_, JsonValue::Array(values))) => values,
        _ => {
            return Err(ParseError {
                message: "adapter_skips must be array".into(),
            });
        }
    };
    let mut out = Vec::new();
    for item in items {
        let obj = as_object(item, "adapter_skip")?;
        let check = string_field(obj, "check")?;
        let reason = string_field(obj, "reason")?;
        let detail = optional_string(obj, "detail").unwrap_or_default();
        out.push((check, reason, detail));
    }
    Ok(out)
}

fn decode_event_list(construct: &[(String, JsonValue)]) -> Result<Vec<EventValue>, ParseError> {
    let items = array_field(construct, "events")?;
    items
        .iter()
        .map(|item| {
            let wrapped = as_object(item, "event element")?;
            decode_session_event(wrapped)
        })
        .collect()
}

fn decode_session_event(wrapped: &[(String, JsonValue)]) -> Result<EventValue, ParseError> {
    let format = string_field(wrapped, "format")?;
    if format != "session" {
        return Err(ParseError {
            message: format!("unsupported event format {format}"),
        });
    }
    let entries = array_field(wrapped, "entries")?;
    let id = tagged_string_in_mapping(&entries, "id")?;
    let seq = tagged_i64_in_mapping(&entries, "seq")?;
    let kind_json = lookup_mapping_value(&entries, "kind").ok_or_else(|| ParseError {
        message: "missing kind".into(),
    })?;
    let kind_obj = as_object(kind_json, "kind")?;
    let kind_tag = string_field(kind_obj, "t")?;
    if kind_tag != "str" {
        return Err(ParseError {
            message: "kind.t must be str in runner vectors".into(),
        });
    }
    let kind = string_field(kind_obj, "v")?;

    let mut parent_id: Option<String> = None;
    if let Some(pid_val) = lookup_mapping_value(&entries, "parent_id") {
        let obj = as_object(pid_val, "parent_id")?;
        let tag = string_field(obj, "t")?;
        parent_id = match tag.as_str() {
            "null" => None,
            "str" => Some(string_field(obj, "v")?),
            _ => {
                return Err(ParseError {
                    message: "parent_id must be null or str".into(),
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

    if let Some(extra_value) = lookup_mapping_value(&entries, "extra_fields") {
        event.extra_fields = json_to_payload(extra_value)?;
    }
    if let Some(payload_val) = lookup_mapping_value(&entries, "payload") {
        event.payload = json_to_payload(payload_val)?;
    }
    Ok(EventValue::from_session(event))
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

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn optional_string(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match lookup(obj, key)? {
        JsonValue::Str(text) => Some(text.clone()),
        _ => None,
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
            message: "trailing JSON after object".into(),
        });
    }
    as_object(&value, "root").map(|obj| obj.to_vec())
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
    let (root, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON after document".into(),
        });
    }
    let root = as_object(&root, "root")?;
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
        meta: root.to_vec(),
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
