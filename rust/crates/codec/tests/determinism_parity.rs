//! Byte-exact parity for `sesslint.determinism` against pinned Python vectors.

use codec::canonical_codec::{ObjectKey, Value};
use codec::determinism::{
    canonical_json_bytes, finding_sort_key, repeat_hash, stable_sort_findings, HashInput, ALL,
};
use model::codes::{Repairability, Severity};
use model::finding::{
    Finding, FindingInput, FindingSortKey, PyValue, SourceLine, SourceRef, SCHEMA_VERSION,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/determinism/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 8;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn decode_b64(input: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in input.bytes() {
        let val = if ch == b'=' {
            break;
        } else if let Some(index) = TABLE.iter().position(|&b| b == ch) {
            u32::try_from(index).unwrap_or(0)
        } else if ch.is_ascii_whitespace() {
            continue;
        } else {
            panic!("invalid base64");
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn key(name: &str) -> ObjectKey {
    ObjectKey::string(name)
}

fn value_from_json(json: &JsonValue) -> Value {
    match json {
        JsonValue::Null => Value::null(),
        JsonValue::Bool(b) => Value::bool(*b),
        JsonValue::Str(s) => Value::string(s.clone()),
        JsonValue::Number(raw) => {
            if raw.contains('.') || raw.contains('e') || raw.contains('E') {
                Value::float(
                    raw.parse::<f64>()
                        .unwrap_or_else(|_| panic!("bad float in vector: {raw}")),
                )
            } else {
                Value::int(
                    raw.parse::<i64>()
                        .unwrap_or_else(|_| panic!("bad int in vector: {raw}")),
                )
            }
        }
        JsonValue::Array(items) => Value::array(items.iter().map(value_from_json).collect()),
        JsonValue::Object(entries) => Value::object(
            entries
                .iter()
                .map(|(name, item)| (key(name), value_from_json(item)))
                .collect(),
        ),
    }
}

fn newline_from_construct(construct: &[(String, JsonValue)]) -> bool {
    match construct.iter().find(|(k, _)| k == "newline") {
        Some((_, JsonValue::Bool(value))) => *value,
        _ => true,
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(s))) => Some(s.clone()),
        _ => panic!("{key} must be string or null"),
    }
}

fn source_from_object(source: &[(String, JsonValue)]) -> SourceRef {
    let path = string_field(source, "path").expect("source.path");
    let line = match source.iter().find(|(k, _)| k == "line") {
        Some((_, JsonValue::Null)) | None => None,
        Some((_, JsonValue::Number(n))) => Some(
            n.parse::<i64>()
                .unwrap_or_else(|_| panic!("bad source.line: {n}")),
        ),
        _ => panic!("source.line must be number or null"),
    };
    let record_id = match source.iter().find(|(k, _)| k == "record_id") {
        Some((_, JsonValue::Null)) | None => None,
        Some((_, JsonValue::Str(s))) => Some(s.as_str()),
        _ => panic!("source.record_id must be string or null"),
    };
    let line_src = line.map(SourceLine::Int);
    SourceRef::try_new(&path, line_src, record_id)
        .unwrap_or_else(|e| panic!("SourceRef::try_new: {e}"))
}

fn related_from_array(obj: &[(String, JsonValue)]) -> PyValue {
    let items = match obj.iter().find(|(k, _)| k == "related_ids") {
        Some((_, JsonValue::Array(items))) => items,
        _ => panic!("related_ids must be array"),
    };
    let mut args = Vec::new();
    for item in items {
        match item {
            JsonValue::Str(s) => args.push(PyValue::string(s.clone())),
            _ => panic!("related_ids items must be strings"),
        }
    }
    PyValue::tuple(args)
}

fn finding_from_object(obj: &[(String, JsonValue)]) -> Finding {
    let code = string_field(obj, "code").expect("code");
    let severity = match string_field(obj, "severity").expect("severity").as_str() {
        "fatal" => Severity::Fatal,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "info" => Severity::Info,
        other => panic!("bad severity: {other}"),
    };
    let repairability = match string_field(obj, "repairability")
        .expect("repairability")
        .as_str()
    {
        "deterministic" => Repairability::Deterministic,
        "lossy-explicit" => Repairability::LossyExplicit,
        "manual" => Repairability::Manual,
        "unsupported" => Repairability::Unsupported,
        other => panic!("bad repairability: {other}"),
    };
    let message = string_field(obj, "message").expect("message");
    let source_entries = object_field(obj, "source").expect("source");
    let source = PyValue::source(source_from_object(source_entries));
    let related_ids = related_from_array(obj);
    let fingerprint = string_field(obj, "fingerprint").expect("fingerprint");
    let schema_version =
        optional_string_field(obj, "schema_version").unwrap_or_else(|| SCHEMA_VERSION.to_owned());
    let message_template = match optional_string_field(obj, "message_template") {
        None => PyValue::None,
        Some(text) => PyValue::string(text),
    };
    let evidence = match obj.iter().find(|(k, _)| k == "evidence") {
        None | Some((_, JsonValue::Null)) => PyValue::None,
        _ => panic!("evidence not supported in determinism parity vectors"),
    };

    Finding::try_new(FindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(repairability),
        message: PyValue::string(message),
        source,
        related_ids,
        fingerprint: PyValue::string(fingerprint),
        schema_version: PyValue::string(schema_version),
        message_template,
        evidence,
    })
    .unwrap_or_else(|e| panic!("Finding::try_new: {e}"))
}

fn sort_key_to_json_value(key: &FindingSortKey) -> JsonValue {
    JsonValue::Array(vec![
        JsonValue::Str(key.path.clone()),
        JsonValue::Number(key.line.to_string()),
        JsonValue::Number(key.ordinal.to_string()),
        JsonValue::Number(key.severity_rank.to_string()),
        JsonValue::Str(key.code.clone()),
        JsonValue::Str(key.record_id.clone()),
        JsonValue::Str(key.fingerprint.clone()),
        JsonValue::Array(
            key.related_ids
                .iter()
                .cloned()
                .map(JsonValue::Str)
                .collect(),
        ),
        JsonValue::Str(key.message.clone()),
        JsonValue::Str(key.repairability.clone()),
    ])
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "canonical_json_bytes" => {
            let shape = string_field(&case.construct, "shape").expect("shape");
            assert_eq!(shape, "json");
            let raw = object_field(&case.construct, "value").expect("value");
            let value = value_from_json(&JsonValue::Object(raw.to_vec()));
            let newline = newline_from_construct(&case.construct);
            let got = canonical_json_bytes(&value, newline)
                .unwrap_or_else(|err| panic!("{} canonical_json_bytes: {err}", case.id));
            let want_b64 = string_field(&case.expected, "bytes_b64").expect("bytes_b64");
            assert_eq!(got, decode_b64(&want_b64), "bytes mismatch for {}", case.id);
        }
        "finding_sort_key" => {
            let left_obj = object_field(&case.construct, "left").expect("left");
            let right_obj = object_field(&case.construct, "right").expect("right");
            let left = finding_from_object(left_obj);
            let right = finding_from_object(right_obj);
            let left_key = finding_sort_key(&left);
            let right_key = finding_sort_key(&right);
            let want_left = json_array_field(&case.expected, "left_key").expect("left_key");
            let want_right = json_array_field(&case.expected, "right_key").expect("right_key");
            assert_eq!(
                sort_key_to_json_value(&left_key),
                JsonValue::Array(want_left),
                "left_key mismatch for {}",
                case.id
            );
            assert_eq!(
                sort_key_to_json_value(&right_key),
                JsonValue::Array(want_right),
                "right_key mismatch for {}",
                case.id
            );
            let cmp = string_field(&case.expected, "cmp").expect("cmp");
            match cmp.as_str() {
                "left_gt_right" => assert!(
                    left_key > right_key,
                    "expected left sort key > right for {}",
                    case.id
                ),
                other => panic!("unknown cmp {other}"),
            }
        }
        "repeat_hash" => {
            let shape = string_field(&case.construct, "shape").expect("shape");
            let got = match shape.as_str() {
                "bytes" => {
                    let b64 = string_field(&case.construct, "data_b64").expect("data_b64");
                    let raw = decode_b64(&b64);
                    repeat_hash(HashInput::Bytes(raw.as_slice()))
                }
                "text" => {
                    let text = string_field(&case.construct, "text").expect("text");
                    repeat_hash(HashInput::Text(text.as_str()))
                }
                "json" => {
                    let raw = object_field(&case.construct, "value").expect("value");
                    let value = value_from_json(&JsonValue::Object(raw.to_vec()));
                    repeat_hash(HashInput::Json(&value))
                }
                other => panic!("unsupported repeat_hash shape {other}"),
            };
            let digest = got.unwrap_or_else(|err| panic!("{} repeat_hash: {err}", case.id));
            let want = string_field(&case.expected, "digest").expect("digest");
            assert_eq!(digest, want, "repeat_hash digest for {}", case.id);
        }
        "stable_sort_findings" => {
            let raw_list = array_field(&case.construct, "findings").expect("findings");
            let mut findings = Vec::with_capacity(raw_list.len());
            for item in raw_list {
                let obj = match item {
                    JsonValue::Object(o) => o,
                    _ => panic!("finding must be object in {}", case.id),
                };
                findings.push(finding_from_object(obj.as_slice()));
            }
            let ordered = stable_sort_findings(&findings);
            let want_paths = string_array_field(&case.expected, "ordered_paths").expect("paths");
            let want_templates =
                optional_string_array_field(&case.expected, "ordered_message_templates")
                    .expect("templates");
            assert_eq!(ordered.len(), want_paths.len(), "len {}", case.id);
            for (i, f) in ordered.iter().enumerate() {
                assert_eq!(f.source().path(), want_paths[i], "path[{}] {}", i, case.id);
                let got_tpl = f.message_template();
                let exp = &want_templates[i];
                match exp {
                    None => assert!(got_tpl.is_none(), "message_template[{}] {}", i, case.id),
                    Some(w) => assert_eq!(
                        got_tpl,
                        Some(w.as_str()),
                        "message_template[{}] {}",
                        i,
                        case.id
                    ),
                }
            }
        }
        "module_all" => {
            let names_json = array_field(&case.expected, "names").expect("names");
            let want: Vec<String> = names_json
                .iter()
                .map(|item| match item {
                    JsonValue::Str(s) => s.clone(),
                    _ => panic!("name must be string in {}", case.id),
                })
                .collect();
            let got: Vec<String> = ALL.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(got, want, "__all__ order for {}", case.id);
        }
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

#[test]
fn determinism_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let cases = parse_document(&raw).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
    }
}

// --- minimal JSON (vectors.json only) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
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

struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn parse_document(input: &str) -> Result<Vec<VectorCase>, ParseError> {
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
    items.iter().map(parse_vector_case).collect()
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

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn json_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    array_field(obj, key)
}

fn string_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            JsonValue::Str(s) => out.push(s),
            other => {
                return Err(ParseError {
                    message: format!("{key} must be string array, got {other:?}"),
                });
            }
        }
    }
    Ok(out)
}

fn optional_string_array_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Vec<Option<String>>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            JsonValue::Null => out.push(None),
            JsonValue::Str(s) => out.push(Some(s)),
            other => {
                return Err(ParseError {
                    message: format!("{key} entries must be string or null, got {other:?}"),
                });
            }
        }
    }
    Ok(out)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
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
        c if c == b'-' || c.is_ascii_digit() => parse_number(input),
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
    let mut end = 0usize;
    for (idx, ch) in input.char_indices() {
        if ch.is_ascii_digit() || ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E' {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return Err(ParseError {
            message: "bad number".into(),
        });
    }
    Ok((JsonValue::Number(input[..end].to_string()), &input[end..]))
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
