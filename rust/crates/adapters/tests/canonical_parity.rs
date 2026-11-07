//! Parity for `sesslint.adapters.canonical` against pinned Python vectors.

use adapters::canonical::{
    canonical_source_label, classify_session_doc, detect_canonical, load_canonical,
    load_canonical_body, load_canonical_session, normalize_version, safe_type_value,
    CanonicalLoadSource, CanonicalSource, ALL, CRITICAL_KEYS, CRITICAL_TOP_KEYS,
    DECODE_JSON_DUPAWARE_UNAVAILABLE, DEFAULT_MAX_FILE_BYTES, KNOWN_EVENT_KEYS, KNOWN_TOP_KEYS,
    REQUIRED_EVENT_KEYS, SECRET_SCAN_TRACKER_UNAVAILABLE, SUPPORTED_CANONICAL_VERSIONS,
};
use adapters::safe_value::PyValue;
use model::canonical::Payload;
use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.canonical/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 44;
const EXPECTED_VECTORS_SHA256: &str =
    "d28643fa5aa980b057e492cdae61d762bd4d200cddd87056ac89d4fb8000a6f1";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.adapters.canonical";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CANONICAL_PY_SHA256: &str =
    "1b47487f9b63697087937c009c2222dccb9a9e3131f4e807733b30bac0bbe28e";
const EXPECTED_CANONICAL_RS_SHA256: &str =
    "5fdccf9ac434b2f5447573a858545f0bf97fa03a492fea5766b84932cdb06be5";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
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
        "detect_canonical" => {
            let bytes = bytes_from_hex_field(&case.construct, "bytes_hex").expect("bytes");
            let filename = string_field(&case.construct, "filename").expect("filename");
            let want = f64_field(&case.expected, "score").expect("score");
            let got = detect_canonical(&bytes, &filename);
            assert_eq!(got, want, "detect_canonical {}", case.id);
        }
        "classify_session_doc" => {
            let doc = decode_payload_field(&case.construct, "doc").expect("doc");
            let want = bool_field(&case.expected, "is_session_doc").expect("is_session_doc");
            assert_eq!(classify_session_doc(&doc), want, "classify {}", case.id);
        }
        "canonical_source_label" => {
            let owned = decode_source_owned(&case.construct, "source").expect("source");
            let want = string_field(&case.expected, "label").expect("label");
            let got = canonical_source_label(owned.as_canonical());
            assert_eq!(got, want, "label {}", case.id);
        }
        "safe_type_value" => {
            let py = decode_py_value_field(&case.construct, "val").expect("val");
            let want = string_field(&case.expected, "text").expect("text");
            let got = match &py {
                DecodedPyOwned::Str(text) => safe_type_value(PyValue::Str(text)),
                DecodedPyOwned::Fixed(val) => safe_type_value(*val),
            };
            assert_eq!(got, want, "safe_type_value {}", case.id);
        }
        "load_canonical" => assert_load_canonical_gap(case),
        "load_canonical_session" => assert_load_session_gap(case),
        "load_canonical_body" => assert_load_body(case),
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
        "supported_canonical_versions",
        sorted_const(&SUPPORTED_CANONICAL_VERSIONS),
    );
    assert_string_array_exact(
        case,
        "required_event_keys",
        &REQUIRED_EVENT_KEYS.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    );
    assert_sorted_string_array(case, "known_top_keys", sorted_const(&KNOWN_TOP_KEYS));
    assert_sorted_string_array(case, "known_event_keys", sorted_const(&KNOWN_EVENT_KEYS));
    assert_sorted_string_array(case, "critical_keys", sorted_const(&CRITICAL_KEYS));
    assert_sorted_string_array(case, "critical_top_keys", sorted_const(&CRITICAL_TOP_KEYS));
    let max = i64_field(&case.expected, "default_max_file_bytes").expect("max");
    assert_eq!(max, DEFAULT_MAX_FILE_BYTES, "default_max_file_bytes {}", case.id);
}

fn sorted_const<const N: usize>(items: &[&str; N]) -> Vec<String> {
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

fn assert_string_array_exact(case: &VectorCase, key: &str, got: &[String]) {
    let want_items = array_field(&case.expected, key).expect(key);
    assert_eq!(want_items.len(), got.len(), "{key} length {}", case.id);
    for (index, item) in want_items.iter().enumerate() {
        let JsonValue::Str(text) = item else {
            panic!("{key}[{index}] must be string");
        };
        assert_eq!(&got[index], text, "{key}[{index}] {}", case.id);
    }
}

fn assert_load_canonical_gap(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin snapshot");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "gap_secret_scan_tracker", "mode {}", case.id);
    let owned = decode_source_owned(&case.construct, "source").expect("source");
    let err = load_canonical(owned.as_canonical(), None).expect_err("tracker gap");
    assert_eq!(
        err.to_string(),
        SECRET_SCAN_TRACKER_UNAVAILABLE,
        "load_canonical {}",
        case.id
    );
}

fn assert_load_session_gap(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin snapshot");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "gap_secret_scan_tracker", "mode {}", case.id);
    let owned = decode_source_owned(&case.construct, "source").expect("source");
    let err = load_canonical_session(owned.as_canonical(), None).expect_err("tracker gap");
    assert_eq!(
        err.to_string(),
        SECRET_SCAN_TRACKER_UNAVAILABLE,
        "load_canonical_session {}",
        case.id
    );
}

fn assert_load_body(case: &VectorCase) {
    let owned = decode_source_owned(&case.construct, "source").expect("source");
    if let Ok(message) = string_field(&case.expected, "message") {
        let err = load_canonical_body(owned.as_body(), None).expect_err("body error");
        assert_eq!(err.to_string(), message, "body message {}", case.id);
        return;
    }
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    let err = load_canonical_body(owned.as_body(), None).expect_err("body gap");
    match mode.as_str() {
        "gap_fingerprint_codec" => {
            assert_eq!(
                err.to_string(),
                FINGERPRINT_CODEC_UNAVAILABLE,
                "fingerprint {}",
                case.id
            );
        }
        "gap_decode_json" => {
            assert_eq!(
                err.to_string(),
                DECODE_JSON_DUPAWARE_UNAVAILABLE,
                "decode {}",
                case.id
            );
        }
        other => panic!("unknown body rust_assertion {other} in {}", case.id),
    }
}

struct SourceOwned {
    kind: SourceKind,
    bytes: Vec<u8>,
    text: String,
    stream_name: Option<String>,
}

enum SourceKind {
    Bytes,
    Str,
    Stream,
}

impl SourceOwned {
    fn as_canonical(&self) -> CanonicalSource<'_> {
        match self.kind {
            SourceKind::Bytes => CanonicalSource::Bytes(&self.bytes),
            SourceKind::Str => CanonicalSource::Str(&self.text),
            SourceKind::Stream => CanonicalSource::Stream {
                name: self.stream_name.as_deref(),
            },
        }
    }

    fn as_body(&self) -> CanonicalLoadSource<'_> {
        match self.kind {
            SourceKind::Bytes => CanonicalLoadSource::Bytes(&self.bytes),
            SourceKind::Str => CanonicalLoadSource::Str(&self.text),
            SourceKind::Stream => panic!("stream body not in vectors"),
        }
    }
}

fn decode_source_owned(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<SourceOwned, ParseError> {
    let spec = object_field(obj, key)?;
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "bytes_hex" => Ok(SourceOwned {
            kind: SourceKind::Bytes,
            bytes: bytes_from_hex_field(spec, "hex")?,
            text: String::new(),
            stream_name: None,
        }),
        "str" => Ok(SourceOwned {
            kind: SourceKind::Str,
            bytes: Vec::new(),
            text: string_field(spec, "text")?,
            stream_name: None,
        }),
        "stream_name" => Ok(SourceOwned {
            kind: SourceKind::Stream,
            bytes: Vec::new(),
            text: String::new(),
            stream_name: optional_string_field(spec, "text")?,
        }),
        other => Err(ParseError {
            message: format!("unknown source kind {other}"),
        }),
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

fn decode_payload_field(obj: &[(String, JsonValue)], key: &str) -> Result<Payload, ParseError> {
    decode_payload_from_spec(object_field(obj, key)?)
}

fn decode_payload_from_spec(spec: &[(String, JsonValue)]) -> Result<Payload, ParseError> {
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "null" => Ok(Payload::null()),
        "bool" => Ok(Payload::bool_value(bool_field(spec, "value")?)),
        "int" => Ok(Payload::int(i64_field(spec, "value")?)),
        "float" => {
            let raw = string_field(spec, "value").or_else(|_| {
                f64_field(spec, "value").map(|value| value.to_string())
            })?;
            let value: f64 = raw.parse().map_err(|_| ParseError {
                message: "bad float".into(),
            })?;
            Ok(Payload::float(value))
        }
        "str" => Ok(Payload::string(string_field(spec, "text")?)),
        "list" => {
            let items = array_field(spec, "items")?;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let JsonValue::Object(inner) = item else {
                    return Err(ParseError {
                        message: "list item must be object".into(),
                    });
                };
                out.push(decode_payload_from_spec(inner)?);
            }
            Ok(Payload::list(out))
        }
        "map" => {
            let entries = array_field(spec, "entries")?;
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                let JsonValue::Object(obj) = entry else {
                    return Err(ParseError {
                        message: "map entry must be object".into(),
                    });
                };
                let key_spec = object_field(obj, "key")?;
                let value_spec = object_field(obj, "value")?;
                out.push((
                    decode_payload_from_spec(key_spec)?,
                    decode_payload_from_spec(value_spec)?,
                ));
            }
            Ok(Payload::map(out))
        }
        other => Err(ParseError {
            message: format!("unknown payload kind {other}"),
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

#[test]
fn canonical_module_parity_vectors() {
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
        string_field(meta, "canonical_py_sha256").expect("canonical_py_sha256"),
        EXPECTED_CANONICAL_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "canonical_rs_sha256").expect("canonical_rs_sha256"),
        EXPECTED_CANONICAL_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    assert!(
        gaps.iter().any(|item| {
            matches!(item, JsonValue::Str(s) if s.contains("GAP-canonical-secret-scan-tracker"))
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

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
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
