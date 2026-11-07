//! Parity for `sesslint.adapters.claude_code` against pinned Python vectors.

use adapters::claude_code::{
    _process_claude_line, detect_claude_code, is_supported_claude_version, load_claude_code,
    load_claude_code_session, normalize_version, ClaudeLineContext,
    ClaudeLineLimits, ClaudeLoadSource, ClaudeRawLine, LoadClaudeCodeError,
    SuppliedSecretScanTracker, ALL, CRITICAL_KEYS, DEFAULT_MAX_DEPTH, KNOWN_RECORD_KEYS,
    OPEN_BYTE_SOURCE_UNAVAILABLE, SECRET_SCAN_TRACKER_UNAVAILABLE, SESSION_METADATA_TYPES,
    SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS, SUPPORTED_CLAUDE_VERSIONS, TYPE_MAP,
    _safe_type_value, ProcessClaudeLineError,
};
use adapters::safe_value::PyValue;
use model::canonical::CANONICAL_JSON_BYTES_UNAVAILABLE;
use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.claude_code/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 27;
const EXPECTED_VECTORS_SHA256: &str =
    "6ed5a7e59c2718ecaad853edb84de1024a178386b18833e52d40d6e0ff7aa65c";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.adapters.claude_code";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CLAUDE_PY_SHA256: &str =
    "37d5ada843edb01662cd257042c9c418015c10cd431e017ae16a5c2c3a3f99a1";
const EXPECTED_CLAUDE_RS_SHA256: &str =
    "801bee2f275c752a443201cd3b3fec8220133c95ccb2a40d578bce2ae5cfe456";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vectors_dir() -> PathBuf {
    vectors_path()
        .parent()
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf)
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => assert_module_exports(case),
        "module_constants" => assert_module_constants(case),
        "normalize_version" => {
            let text = string_field(&case.construct, "text").expect("text");
            let want = string_field(&case.expected, "text").expect("expected text");
            assert_eq!(normalize_version(&text), want, "normalize_version {}", case.id);
        }
        "detect_claude_code" => {
            let bytes = bytes_from_hex_field(&case.construct, "bytes_hex").expect("bytes");
            let filename = string_field(&case.construct, "filename").expect("filename");
            let want = f64_field(&case.expected, "score").expect("score");
            assert_eq!(
                detect_claude_code(&bytes, &filename),
                want,
                "detect {}",
                case.id
            );
        }
        "is_supported_claude_version" => {
            let text = string_field(&case.construct, "text").expect("text");
            let marker = bool_field(&case.construct, "is_schema_marker").expect("marker");
            let want = bool_field(&case.expected, "supported").expect("supported");
            let norm = normalize_version(&text);
            assert_eq!(
                is_supported_claude_version(&norm, marker),
                want,
                "is_supported {}",
                case.id
            );
        }
        "safe_type_value" => {
            let py = decode_py_value_field(&case.construct, "val").expect("val");
            let want = string_field(&case.expected, "text").expect("text");
            let got = match &py {
                DecodedPyOwned::Str(text) => _safe_type_value(PyValue::Str(text)),
                DecodedPyOwned::Fixed(val) => _safe_type_value(*val),
            };
            assert_eq!(got, want, "safe_type_value {}", case.id);
        }
        "load_claude_code" => assert_load_claude_code(case),
        "load_claude_code_session" => assert_load_claude_code_session(case),
        "process_claude_line" => assert_process_claude_line(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_module_exports(case: &VectorCase) {
    let names = array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), ALL.len(), "ALL length {}", case.id);
    for (index, item) in names.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{index}] must be string");
        };
        assert_eq!(ALL[index], name.as_str(), "ALL[{index}] {}", case.id);
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_sorted_string_array(
        case,
        "supported_versions",
        sorted_const(&SUPPORTED_CLAUDE_VERSIONS),
    );
    let majors = array_field(&case.expected, "supported_app_major_versions").expect("majors");
    assert_eq!(majors.len(), SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS.len());
    for (index, item) in majors.iter().enumerate() {
        let major = i64_field_on_value(item, "major entry").expect("major");
        assert_eq!(major, SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS[index]);
    }
    assert_sorted_string_array(case, "critical_keys", sorted_slice(&CRITICAL_KEYS));
    assert_sorted_string_array(case, "known_record_keys", sorted_slice(KNOWN_RECORD_KEYS));
    assert_sorted_string_array(
        case,
        "session_metadata_types",
        sorted_const(&SESSION_METADATA_TYPES),
    );
    let depth = i64_field(&case.expected, "default_max_depth").expect("depth");
    assert_eq!(depth, DEFAULT_MAX_DEPTH, "{}", case.id);
    let items = array_field(&case.expected, "type_map").expect("map");
    assert_eq!(items.len(), TYPE_MAP.len(), "type map {}", case.id);
    for item in items {
        let obj = as_object_value(item, "item").expect("item");
        let key = string_field(obj, "key").expect("key");
        let actor = string_field(obj, "actor").expect("actor");
        let kind = string_field(obj, "kind").expect("kind");
        let Some((want_actor, want_kind)) =
            TYPE_MAP.iter().find_map(|(name, a, k)| (*name == key).then_some((*a, *k)))
        else {
            panic!("unknown type {key} in {}", case.id);
        };
        assert_eq!(actor, want_actor, "actor {key} {}", case.id);
        assert_eq!(kind, want_kind, "kind {key} {}", case.id);
    }
}

fn sorted_const<const N: usize>(items: &[&str; N]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().map(|item| (*item).to_string()).collect();
    out.sort();
    out
}

fn sorted_slice(items: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().map(|item| (*item).to_string()).collect();
    out.sort();
    out
}

fn assert_sorted_string_array(case: &VectorCase, key: &str, got_sorted: Vec<String>) {
    let want_items = array_field(&case.expected, key).expect(key);
    let mut want: Vec<String> = want_items
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => text.clone(),
            _ => panic!("{key} entries must be strings in {}", case.id),
        })
        .collect();
    want.sort();
    assert_eq!(got_sorted, want, "{key} {}", case.id);
}

fn assert_load_claude_code(case: &VectorCase) {
    let source = object_field(&case.construct, "source").expect("source");
    let mut bytes_buf = Vec::new();
    let mut path_buf = String::new();
    let src = decode_load_source(case, source, &mut bytes_buf, &mut path_buf).expect("source decode");
    if let Ok(message) = string_field(&case.expected, "message") {
        let err = load_claude_code(src, None).expect_err("error");
        assert_eq!(
            err.to_string().replace('\\', "/"),
            message.replace('\\', "/"),
            "message {}",
            case.id
        );
        return;
    }
    let _pin = object_field(&case.expected, "pin").expect("pin snapshot");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    let err = load_claude_code(src, None).expect_err("gap");
    match mode.as_str() {
        "gap_secret_scan_tracker" => {
            assert_eq!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE, "{}", case.id);
            assert!(matches!(err, LoadClaudeCodeError::SecretScanTracker));
        }
        "gap_open_byte_source" => {
            assert_eq!(err.to_string(), OPEN_BYTE_SOURCE_UNAVAILABLE, "{}", case.id);
            assert!(matches!(err, LoadClaudeCodeError::OpenByteSource));
        }
        other => panic!("unknown load mode {other} in {}", case.id),
    }
}

fn decode_load_source<'a>(
    case: &VectorCase,
    spec: &'a [(String, JsonValue)],
    bytes_buf: &'a mut Vec<u8>,
    path_buf: &'a mut String,
) -> Result<ClaudeLoadSource<'a>, ParseError> {
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "bytes_hex" => {
            *bytes_buf = bytes_from_hex_field(spec, "hex")?;
            Ok(ClaudeLoadSource::Bytes(bytes_buf))
        }
        "path_rel" => {
            *path_buf = string_field(spec, "path")?;
            Ok(ClaudeLoadSource::PathLike(path_buf))
        }
        other => Err(ParseError {
            message: format!("unknown source kind {other} in {}", case.id),
        }),
    }
}

fn assert_load_claude_code_session(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let source = object_field(&case.construct, "source").expect("source");
    let mut bytes_buf = Vec::new();
    let mut path_buf = String::new();
    let src = decode_load_source(case, source, &mut bytes_buf, &mut path_buf).expect("source");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    let err = load_claude_code_session(src, None).expect_err("session gap");
    assert_eq!(mode, "gap_open_byte_source", "{}", case.id);
    assert_eq!(err.to_string(), OPEN_BYTE_SOURCE_UNAVAILABLE, "{}", case.id);
}

fn assert_process_claude_line(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let line_text = string_field(&case.construct, "line_text").expect("line");
    let is_terminal = bool_field(&case.construct, "is_terminal").expect("terminal");
    let raw_bytes = line_text.into_bytes();
    let len = i64::try_from(raw_bytes.len()).expect("len");
    let raw = ClaudeRawLine::try_new(1, raw_bytes, false, 0, len, 1).expect("raw line");
    let limits = ClaudeLineLimits {
        max_depth: DEFAULT_MAX_DEPTH,
    };
    let events = Vec::new();
    let findings = Vec::new();
    let secret_flag = bool_field(&case.construct, "secret_tracker").unwrap_or(false);
    let mut context = ClaudeLineContext {
        secret_tracker: secret_flag.then_some(SuppliedSecretScanTracker),
        record_sizes: Some(Vec::new()),
        ..ClaudeLineContext::default()
    };
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    let result = _process_claude_line(
        &raw,
        is_terminal,
        "syn-process-path.jsonl",
        limits,
        &events,
        &findings,
        &mut context,
    );
    match mode.as_str() {
        "ok_empty" => {
            result.expect("metadata ok");
            assert!(events.is_empty(), "events {}", case.id);
        }
        "gap_fingerprint" => {
            let err = result.expect_err("fingerprint");
            assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE, "{}", case.id);
            assert!(matches!(err, ProcessClaudeLineError::Finding(_)));
        }
        "gap_canonical_json_bytes" => {
            let err = result.expect_err("canonical");
            assert_eq!(err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE, "{}", case.id);
            assert!(matches!(err, ProcessClaudeLineError::Canonical(_)));
        }
        "gap_secret_scan_tracker" => {
            let err = result.expect_err("tracker");
            assert_eq!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE, "{}", case.id);
            assert!(matches!(err, ProcessClaudeLineError::SecretScanTracker));
        }
        other => panic!("unknown process mode {other} in {}", case.id),
    }
}

enum DecodedPyOwned {
    Str(String),
    Fixed(PyValue<'static>),
}

fn decode_py_value_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<DecodedPyOwned, ParseError> {
    decode_py_from_spec(object_field(obj, key)?)
}

fn decode_py_from_spec(spec: &[(String, JsonValue)]) -> Result<DecodedPyOwned, ParseError> {
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "str" => Ok(DecodedPyOwned::Str(string_field(spec, "text")?)),
        "null" => Ok(DecodedPyOwned::Fixed(PyValue::None)),
        "int" => Ok(DecodedPyOwned::Fixed(PyValue::Int)),
        "float" => Ok(DecodedPyOwned::Fixed(PyValue::Float)),
        "bool" => Ok(DecodedPyOwned::Fixed(PyValue::Bool)),
        "list" => {
            let items = array_field(spec, "items")?;
            Ok(DecodedPyOwned::Fixed(PyValue::List(items.len())))
        }
        "dict" | "map" => Ok(DecodedPyOwned::Fixed(PyValue::Dict(0))),
        other => Err(ParseError {
            message: format!("unknown py kind {other}"),
        }),
    }
}

fn as_object_value<'a>(
    value: &'a JsonValue,
    ctx: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    as_object(value, ctx)
}

fn i64_field_on_value(value: &JsonValue, ctx: &str) -> Result<i64, ParseError> {
    match value {
        JsonValue::Number(raw) => raw.parse::<i64>().map_err(|_| ParseError {
            message: format!("{ctx} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{ctx} must be number"),
        }),
    }
}

fn f64_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse::<f64>().map_err(|_| ParseError {
            message: format!("{key} must be f64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn bytes_from_hex_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<u8>, ParseError> {
    let hx = string_field(obj, key)?;
    if hx.is_empty() {
        return Ok(Vec::new());
    }
    if hx.len() % 2 != 0 {
        return Err(ParseError {
            message: format!("{key} hex length must be even"),
        });
    }
    let mut out = Vec::with_capacity(hx.len() / 2);
    let bytes = hx.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let pair = std::str::from_utf8(&bytes[index..index + 2]).map_err(|_| ParseError {
            message: format!("{key} must be ascii hex"),
        })?;
        let byte = u8::from_str_radix(pair, 16).map_err(|_| ParseError {
            message: format!("{key} bad hex"),
        })?;
        out.push(byte);
        index += 2;
    }
    Ok(out)
}

#[test]
fn claude_code_module_parity_vectors() {
    let vdir = vectors_dir();
    std::env::set_current_dir(&vdir).expect("chdir vectors dir");
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
        string_field(meta, "claude_code_py_sha256").expect("claude_code_py_sha256"),
        EXPECTED_CLAUDE_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "claude_code_rs_sha256").expect("claude_code_rs_sha256"),
        EXPECTED_CLAUDE_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    assert!(
        gaps.iter().any(|item| {
            matches!(item, JsonValue::Str(s) if s.contains("GAP-claude-secret-scan-tracker"))
        }),
        "expected tracker gap prose"
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
    let cases = items
        .iter()
        .map(parse_vector_case)
        .collect::<Result<_, _>>()?;
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

// --- hand-rolled JSON parser below ---

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
    let bytes = input.as_bytes();
    while end < bytes.len() {
        let ch = bytes[end];
        if ch.is_ascii_digit() || ch == b'.' || ch == b'e' || ch == b'E' || ch == b'+' || ch == b'-'
        {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
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
