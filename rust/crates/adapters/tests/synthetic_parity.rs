//! Byte-exact parity for `sesslint.adapters.synthetic` against pinned Python vectors.

use adapters::synthetic::{
    advance_synthetic_id, is_synthetic_id, synthetic_event_id, SyntheticIdCollisionGuard,
};
use model::errors::AdapterError;
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.synthetic/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 22;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RunOutcome {
    OkStr(String),
    OkBool(bool),
    OkUnit,
    Err(String),
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    let actual = match kind.as_str() {
        "synthetic_event_id" => {
            let adapter = string_field(&case.construct, "adapter").expect("adapter");
            let ordinal = i64_field(&case.construct, "ordinal").expect("ordinal");
            let source_hint = string_field(&case.construct, "source_hint").expect("source_hint");
            let payload_len = i64_field(&case.construct, "payload_len").expect("payload_len");
            RunOutcome::OkStr(synthetic_event_id(
                &adapter,
                ordinal,
                &source_hint,
                payload_len,
            ))
        }
        "is_synthetic_id" => {
            let event_id = string_field(&case.construct, "event_id").expect("event_id");
            RunOutcome::OkBool(is_synthetic_id(&event_id))
        }
        "advance_synthetic_id" => {
            let candidate_id = string_field(&case.construct, "candidate_id").expect("candidate_id");
            RunOutcome::OkStr(advance_synthetic_id(&candidate_id))
        }
        "guard_run" => run_guard(&case.construct),
        "guard_preloaded_assert_no_collision" => {
            let real_ids = string_list_field(&case.construct, "real_ids").expect("real_ids");
            let synthetic_ids =
                string_list_field(&case.construct, "synthetic_ids").expect("synthetic_ids");
            RunOutcome::from_preloaded_assert_no_collision(&real_ids, &synthetic_ids)
        }
        other => panic!("unsupported construct type {other} in {}", case.id),
    };
    assert_expected(&case.id, actual, &case.expected);
}

impl RunOutcome {
    fn from_preloaded_assert_no_collision(real_ids: &[String], synthetic_ids: &[String]) -> Self {
        let real: BTreeSet<String> = real_ids.iter().cloned().collect();
        let synthetic: BTreeSet<String> = synthetic_ids.iter().cloned().collect();
        let mut collision = real.intersection(&synthetic);
        if let Some(colliding) = collision.next() {
            return RunOutcome::Err(format!(
                "Synthetic ID collision: ID {} exists in both real and synthetic namespaces",
                python_str_repr(colliding)
            ));
        }
        RunOutcome::OkUnit
    }
}

fn python_str_repr(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

fn run_guard(construct: &[(String, JsonValue)]) -> RunOutcome {
    let steps = array_field(construct, "steps").expect("steps");
    let mut guard = SyntheticIdCollisionGuard::new();
    for step in steps {
        let obj = as_object_value(step, "guard step").expect("guard step object");
        let action = string_field(obj, "action").expect("action");
        match action.as_str() {
            "register_real" => {
                let event_id = string_field(obj, "event_id").expect("event_id");
                if let Err(err) = guard.register_real(&event_id) {
                    return RunOutcome::Err(err.to_string());
                }
            }
            "register_synthetic" => {
                let event_id = string_field(obj, "event_id").expect("event_id");
                if let Err(err) = guard.register_synthetic(&event_id) {
                    return RunOutcome::Err(err.to_string());
                }
            }
            "register" => {
                let event_id = string_field(obj, "event_id").expect("event_id");
                let is_synthetic = bool_field(obj, "is_synthetic").expect("is_synthetic");
                if let Err(err) = guard.register(&event_id, is_synthetic) {
                    return RunOutcome::Err(err.to_string());
                }
            }
            "assert_no_collision" => {
                if let Err(err) = guard.assert_no_collision() {
                    return RunOutcome::Err(err.to_string());
                }
            }
            other => panic!("unknown guard action {other}"),
        }
    }
    RunOutcome::OkUnit
}

fn as_object_value<'a>(
    value: &'a JsonValue,
    ctx: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn assert_expected(case_id: &str, actual: RunOutcome, expected: &[(String, JsonValue)]) {
    let result = string_field(expected, "result").expect("result");
    match result.as_str() {
        "ok" => match actual {
            RunOutcome::Err(msg) => panic!("expected ok for {case_id}, got error: {msg}"),
            RunOutcome::OkStr(got) => {
                let want = string_field(expected, "value").expect("value");
                assert_eq!(got, want, "value mismatch for {case_id}");
            }
            RunOutcome::OkBool(got) => {
                let want = bool_field(expected, "value").expect("value");
                assert_eq!(got, want, "bool mismatch for {case_id}");
            }
            RunOutcome::OkUnit => {
                let value = expected.iter().find(|(k, _)| k == "value").map(|(_, v)| v);
                assert!(
                    matches!(value, Some(JsonValue::Null)),
                    "expected null value for {case_id}"
                );
            }
        },
        "error" => {
            let RunOutcome::Err(got) = actual else {
                panic!("expected error for {case_id}, got ok");
            };
            let want = string_field(expected, "display").expect("display");
            assert_eq!(got, want, "display mismatch for {case_id}");
            let raises = string_field(expected, "raises").expect("raises");
            assert_eq!(raises, "AdapterError", "raises mismatch for {case_id}");
            let _probe: AdapterError = AdapterError::new(&got);
        }
        other => panic!("unknown expected result {other} for {case_id}"),
    }
}

#[test]
fn synthetic_module_parity_vectors() {
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

fn string_list_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|value| match value {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} items must be strings"),
            }),
        })
        .collect()
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
    while end < input.len() {
        let ch = input.as_bytes()[end];
        if ch.is_ascii_digit() {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 || (end == 1 && input.starts_with('-')) {
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
