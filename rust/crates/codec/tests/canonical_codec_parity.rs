//! Byte-exact parity for `sesslint._canonical_codec` against pinned Python vectors.

use codec::canonical_codec::{
    canonical_json_bytes, content_identity_bytes, content_identity_hash, payload_content_hash,
    plan_fingerprint, CanonicalError, ObjectKey, Value, ALL, CODEC_INTERFACE_VERSION,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/_canonical_codec/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 17;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

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

fn nested_dicts(wraps: usize) -> Value {
    let mut value = Value::object(vec![(key("leaf"), Value::int(1))]);
    for _ in 0..wraps {
        value = Value::object(vec![(key("k"), value)]);
    }
    value
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

fn build_canonical_input(construct: &[(String, JsonValue)]) -> (Value, bool) {
    let shape = string_field(construct, "shape").ok();
    let newline = match construct.iter().find(|(k, _)| k == "newline") {
        Some((_, JsonValue::Bool(value))) => *value,
        _ => false,
    };
    let value = match shape.as_deref() {
        None | Some("json") => {
            let raw = object_field(construct, "value").expect("value object for json shape");
            value_from_json(&JsonValue::Object(raw.to_vec()))
        }
        Some("halfway_float") => {
            let hex = string_field(construct, "bits").expect("bits");
            let bits = u64::from_str_radix(&hex, 16).expect("hex bits");
            Value::object(vec![(key("tie"), Value::float(f64::from_bits(bits)))])
        }
        Some("float_nan_object") => Value::object(vec![(key("bad"), Value::float(f64::NAN))]),
        Some("float_inf_object") => Value::object(vec![(key("bad"), Value::float(f64::INFINITY))]),
        Some("non_string_key") => {
            let repr = string_field(construct, "repr").expect("repr");
            Value::object(vec![(ObjectKey::non_string(repr), Value::string("x"))])
        }
        Some("cycle_dict") => {
            let (value, cell) = Value::object_cell(vec![(key("key"), Value::string("val"))]);
            cell.borrow_mut().push((key("self"), value.clone()));
            value
        }
        Some("nested_dicts") => {
            let wraps = usize_field(construct, "wraps").expect("wraps");
            nested_dicts(wraps)
        }
        other => panic!("unsupported canonical_json_bytes shape: {other:?}"),
    };
    (value, newline)
}

fn assert_schema_message(error: CanonicalError, want: &str, id: &str) {
    match error {
        CanonicalError::Schema(err) => {
            assert_eq!(err.message(), want, "SchemaError message for {id}");
        }
        other => panic!("expected SchemaError for {id}, got {other:?}"),
    }
}

fn assert_unsupported_message(error: CanonicalError, want: &str, id: &str) {
    match error {
        CanonicalError::Unsupported(message) => {
            assert_eq!(message, want, "Unsupported message for {id}");
        }
        other => panic!("expected Unsupported for {id}, got {other:?}"),
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "canonical_json_bytes" => {
            let (value, newline) = build_canonical_input(&case.construct);
            let result = canonical_json_bytes(&value, newline);
            let outcome = string_field(&case.expected, "result").expect("result");
            if outcome == "ok" {
                let got =
                    result.unwrap_or_else(|err| panic!("{} canonical_json_bytes: {err}", case.id));
                let want_b64 = string_field(&case.expected, "bytes_b64").expect("bytes_b64");
                assert_eq!(got, decode_b64(&want_b64), "bytes mismatch for {}", case.id);
            } else {
                let err = result.expect_err(&format!("expected error for {}", case.id));
                let message = string_field(&case.expected, "exact_message").expect("exact_message");
                assert_schema_message(err, &message, &case.id);
            }
        }
        "payload_content_hash" => {
            let raw = object_field(&case.construct, "value").expect("value");
            let payload = value_from_json(&JsonValue::Object(raw.to_vec()));
            let got = payload_content_hash(&payload)
                .unwrap_or_else(|err| panic!("{} payload_content_hash: {err}", case.id));
            let want = string_field(&case.expected, "digest").expect("digest");
            assert_eq!(got, want, "payload_content_hash for {}", case.id);
        }
        "plan_fingerprint" => {
            let raw = object_field(&case.construct, "value").expect("value");
            let plan = value_from_json(&JsonValue::Object(raw.to_vec()));
            let policy_owned = optional_string_field(&case.construct, "policy").expect("policy");
            let policy = policy_owned.as_deref();
            let got = plan_fingerprint(&plan, policy)
                .unwrap_or_else(|err| panic!("{} plan_fingerprint: {err}", case.id));
            let want = string_field(&case.expected, "fingerprint").expect("fingerprint");
            assert_eq!(got, want, "plan_fingerprint for {}", case.id);
        }
        "content_identity_bytes" => {
            let err =
                content_identity_bytes().expect_err(&format!("expected error for {}", case.id));
            let message = string_field(&case.expected, "exact_message").expect("exact_message");
            assert_unsupported_message(err, &message, &case.id);
        }
        "content_identity_hash" => {
            let err =
                content_identity_hash().expect_err(&format!("expected error for {}", case.id));
            let message = string_field(&case.expected, "exact_message").expect("exact_message");
            assert_unsupported_message(err, &message, &case.id);
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
            assert_eq!(CODEC_INTERFACE_VERSION, "1.0.0");
        }
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

#[test]
fn canonical_codec_module_parity_vectors() {
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

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let raw = string_field(obj, key).or_else(|_| match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(n.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    })?;
    raw.parse::<usize>().map_err(|_| ParseError {
        message: format!("{key} must be usize"),
    })
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string when present"),
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
