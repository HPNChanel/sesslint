//! Byte-exact parity for `sesslint.repair.assurance` against pinned Python vectors.

use repair::assurance::{
    cap_assurance, compute_assurance_ceiling, LossyFlag, MappingSteps, Plan, Step,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.assurance/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 146;

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
        "cap_assurance" => assert_cap_assurance(case),
        "compute_assurance_ceiling" => assert_compute_ceiling(case),
        other => panic!("unsupported construct type in vector {}: {other}", case.id),
    }
}

fn assert_cap_assurance(case: &VectorCase) {
    let base = string_field(&case.construct, "base").expect("base");
    let step_specs = steps_array(&case.construct).expect("steps");
    let steps = build_steps(step_specs);
    let plan_spec = object_field(&case.construct, "plan").expect("plan");
    let plan_kind = string_field(plan_spec, "kind").expect("plan kind");
    let synthetic_steps: Vec<Step<'static>> = match plan_kind.as_str() {
        "mapping_string_steps" => vec![Step::other(), Step::other()],
        "mapping_keys_only" => vec![Step::other()],
        _ => Vec::new(),
    };
    let plan = build_plan(plan_spec, &steps, &synthetic_steps);
    let ok = bool_field(&case.expected, "ok").expect("ok");
    let result = cap_assurance(&base, &plan);
    if ok {
        let want = string_field(&case.expected, "value").expect("value");
        assert_eq!(
            result,
            Ok(want.as_str()),
            "cap_assurance value mismatch for {}",
            case.id
        );
    } else {
        let message = string_field(&case.expected, "error").expect("error");
        let err = result.expect_err(&format!("expected error for {}", case.id));
        assert_eq!(
            err.to_string(),
            message,
            "cap_assurance error mismatch for {}",
            case.id
        );
    }
}

fn assert_compute_ceiling(case: &VectorCase) {
    let revalidation = string_field(&case.construct, "revalidation").expect("revalidation");
    let policy = string_field(&case.construct, "policy").expect("policy");
    let ok = bool_field(&case.expected, "ok").expect("ok");
    let result = compute_assurance_ceiling(&revalidation, &policy);
    if ok {
        let want = string_field(&case.expected, "value").expect("value");
        assert_eq!(
            result,
            Ok(want.as_str()),
            "ceiling value mismatch for {}",
            case.id
        );
    } else {
        let message = string_field(&case.expected, "error").expect("error");
        let err = result.expect_err(&format!("expected error for {}", case.id));
        assert_eq!(
            err.to_string(),
            message,
            "ceiling error mismatch for {}",
            case.id
        );
    }
}

fn steps_array(construct: &[(String, JsonValue)]) -> Result<&[JsonValue], ParseError> {
    let value = construct
        .iter()
        .find(|(k, _)| k == "steps")
        .ok_or_else(|| ParseError {
            message: "missing key steps".into(),
        })?;
    match &value.1 {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ParseError {
            message: "steps must be array".into(),
        }),
    }
}

fn build_plan<'a>(
    spec: &[(String, JsonValue)],
    steps: &'a [Step<'static>],
    synthetic_steps: &'a [Step<'static>],
) -> Plan<'a> {
    let kind = string_field(spec, "kind").expect("plan kind");
    match kind.as_str() {
        "attribute_steps" => Plan::AttributeSteps(steps),
        "mapping_iterable" => Plan::Mapping(MappingSteps::Iterable(steps)),
        "mapping_not_iterable" => Plan::Mapping(MappingSteps::NotIterable),
        "iterable" => Plan::Iterable(steps),
        "str" => Plan::Str,
        "bytes" => Plan::Bytes,
        "other" => Plan::Other,
        "mapping_string_steps" => Plan::Mapping(MappingSteps::Iterable(synthetic_steps)),
        "mapping_keys_only" => Plan::Iterable(synthetic_steps),
        other => panic!("unknown plan kind in vector harness: {other}"),
    }
}

fn build_steps(specs: &[JsonValue]) -> Vec<Step<'static>> {
    specs.iter().map(build_step).collect()
}

fn build_step(value: &JsonValue) -> Step<'static> {
    let obj = as_object(value, "step").expect("step object");
    let view = string_field(obj, "view").expect("view");
    match view.as_str() {
        "attribute" => {
            let flag = match obj.iter().find(|(k, _)| k == "lossy") {
                None => LossyFlag::Bool(false),
                Some((_, lossy)) => parse_lossy_flag(lossy),
            };
            Step::attribute(flag)
        }
        "mapping" => match obj.iter().find(|(k, _)| k == "lossy") {
            None => Step::mapping(None),
            Some((_, lossy)) => Step::mapping(Some(parse_lossy_flag(lossy))),
        },
        "other" => Step::other(),
        other => panic!("unknown step view in vector harness: {other}"),
    }
}

fn parse_lossy_flag(value: &JsonValue) -> LossyFlag<'static> {
    match value {
        JsonValue::Null => LossyFlag::None,
        JsonValue::Bool(b) => LossyFlag::Bool(*b),
        JsonValue::Number(n) => {
            let parsed: i64 = n.parse().expect("lossy int in vector");
            LossyFlag::Int(parsed)
        }
        JsonValue::Str(s) => match s.as_str() {
            "" => LossyFlag::Str(""),
            "0" => LossyFlag::Str("0"),
            other => panic!("unexpected str lossy in vector: {other:?}"),
        },
        other => panic!("unsupported lossy flag in vector: {other:?}"),
    }
}

#[test]
fn assurance_module_parity_vectors() {
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
    if let Some(rest) = input.strip_prefix(word) {
        Ok((value, rest))
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
    if let Some(tail) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), tail));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), tail));
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
    if let Some(tail) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), tail));
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
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), tail));
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
