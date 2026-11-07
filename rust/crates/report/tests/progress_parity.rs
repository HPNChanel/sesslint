//! Byte-exact parity for `sesslint.progress` against pinned Python vectors.
#![allow(clippy::manual_strip)]

use report::progress::{
    check_token, CancellationToken, OperationCancelled, ProgressEvent, ProgressValue,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/progress/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 7;

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
        "ProgressEvent" => assert_progress_event(case),
        "OperationCancelled" => assert_operation_cancelled_message(case),
        "CancellationToken" => assert_cancellation_token(case),
        "check_token" => assert_check_token(case),
        other => panic!("unsupported construct type in vector {}: {other}", case.id),
    }
}

fn assert_progress_event(case: &VectorCase) {
    let event = build_progress_event(&case.construct);
    let expected_dict = object_field(&case.expected, "to_dict").expect("to_dict");
    assert_to_dict(&event.to_dict(), expected_dict, &case.id);
    let json = string_field(&case.expected, "json").expect("json");
    assert_eq!(event.to_json(), json, "json mismatch for {}", case.id);
}

fn build_progress_event(obj: &[(String, JsonValue)]) -> ProgressEvent {
    let phase = string_field(obj, "phase").expect("phase");
    let completed = i64_field(obj, "completed").expect("completed");
    let total = optional_i64_field(obj, "total").expect("total");
    let item = optional_string_field(obj, "item").expect("item");
    ProgressEvent::new(phase, completed, total, item)
}

fn assert_to_dict(
    actual: &BTreeMap<&'static str, ProgressValue>,
    expected: &[(String, JsonValue)],
    id: &str,
) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "to_dict key count mismatch for {id}"
    );
    for (key, exp) in expected {
        let got = actual
            .get(key.as_str())
            .unwrap_or_else(|| panic!("missing key {key} in Rust to_dict for {id}"));
        match (got, exp) {
            (ProgressValue::Integer(n), JsonValue::Number(s)) => {
                let want: i64 = s
                    .parse()
                    .unwrap_or_else(|_| panic!("bad int in vector {id}"));
                assert_eq!(*n, want, "to_dict[{key}] mismatch for {id}");
            }
            (ProgressValue::String(g), JsonValue::Str(w)) => {
                assert_eq!(g, w, "to_dict[{key}] mismatch for {id}");
            }
            _ => panic!("type mismatch for to_dict[{key}] in {id}"),
        }
    }
}

fn assert_operation_cancelled_message(case: &VectorCase) {
    let message = string_field(&case.expected, "message").expect("message");
    assert_eq!(
        OperationCancelled.to_string(),
        message,
        "OperationCancelled message mismatch for {}",
        case.id
    );
}

fn assert_cancellation_token(case: &VectorCase) {
    let cancel_before = bool_field(&case.construct, "cancel_before").expect("cancel_before");
    let message = string_field(&case.expected, "message").expect("message");
    let raises = string_field(&case.expected, "raises").expect("raises");
    assert_eq!(raises, "OperationCancelled");
    let token = CancellationToken::new();
    if cancel_before {
        token.cancel();
    }
    let err = token
        .throw_if_cancelled()
        .expect_err(&format!("expected cancel for {}", case.id));
    assert_eq!(
        err.to_string(),
        message,
        "throw_if_cancelled for {}",
        case.id
    );
}

fn assert_check_token(case: &VectorCase) {
    let cancel_before = bool_field(&case.construct, "cancel_before").expect("cancel_before");
    let message = string_field(&case.expected, "message").expect("message");
    let raises = string_field(&case.expected, "raises").expect("raises");
    assert_eq!(raises, "OperationCancelled");
    let token = CancellationToken::new();
    if cancel_before {
        token.cancel();
    }
    let err = check_token(Some(&token)).expect_err(&format!("expected cancel for {}", case.id));
    assert_eq!(err.to_string(), message, "check_token for {}", case.id);
}

#[test]
fn progress_module_parity_vectors() {
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
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<i64>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map(Some).map_err(|_| ParseError {
            message: format!("{key} must be i64 when present"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number when present"),
        }),
    }
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
    if input.starts_with(word) {
        Ok((value, &input[word.len()..]))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let num = input[..end].to_string();
    Ok((JsonValue::Number(num), &input[end..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if rest.starts_with(']') {
        return Ok((JsonValue::Array(items), &rest[1..]));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if rest.starts_with(']') {
            return Ok((JsonValue::Array(items), &rest[1..]));
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
    if rest.starts_with('}') {
        return Ok((JsonValue::Object(items), &rest[1..]));
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
        if rest.starts_with('}') {
            return Ok((JsonValue::Object(items), &rest[1..]));
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
