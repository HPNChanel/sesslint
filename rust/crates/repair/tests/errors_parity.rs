//! Byte-exact parity for `sesslint.repair.errors` against pinned Python vectors.

#![allow(clippy::redundant_closure)]

use repair::errors::{
    Abstained, ManifestCollision, OutputInvalid, PlanSourceMismatch, PlanTampered,
    PolicyMismatch, RepairError, RepairRefused, VendorProjectionRefused, VendorRepairRefused, ALL,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.errors/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 25;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn build_error(construct: &[(String, JsonValue)]) -> RepairError {
    let kind = string_field(construct, "type").expect("construct type");
    let message = string_field(construct, "message").expect("message");
    let code = optional_string_field(construct, "code").expect("code");
    let reason = optional_string_field(construct, "reason").expect("reason");
    match kind.as_str() {
        "RepairError" => with_optional_code(
            message,
            code.as_deref(),
            |m| RepairError::new(m),
            |m, c| RepairError::with_code(m, c),
        ),
        "PlanTampered" => RepairError::from(with_optional_code_plan(
            message,
            code.as_deref(),
            |m| PlanTampered::new(m),
            |m, c| PlanTampered::with_code(m, c),
        )),
        "Abstained" => RepairError::from(with_optional_code_plan(
            message,
            code.as_deref(),
            |m| Abstained::new(m),
            |m, c| Abstained::with_code(m, c),
        )),
        "PolicyMismatch" => RepairError::from(with_optional_code_plan(
            message,
            code.as_deref(),
            |m| PolicyMismatch::new(m),
            |m, c| PolicyMismatch::with_code(m, c),
        )),
        "OutputInvalid" => RepairError::from(with_optional_code_plan(
            message,
            code.as_deref(),
            |m| OutputInvalid::new(m),
            |m, c| OutputInvalid::with_code(m, c),
        )),
        "RepairRefused" => RepairError::from(with_optional_code_refused(
            message,
            code.as_deref(),
            |m| RepairRefused::new(m),
            |m, c| RepairRefused::with_code(m, c),
        )),
        "VendorRepairRefused" => RepairError::from(RepairRefused::from(
            with_optional_code_plan(
                message,
                code.as_deref(),
                |m| VendorRepairRefused::new(m),
                |m, c| VendorRepairRefused::with_code(m, c),
            ),
        )),
        "ManifestCollision" => RepairError::from(RepairRefused::from(
            with_optional_code_plan(
                message,
                code.as_deref(),
                |m| ManifestCollision::new(m),
                |m, c| ManifestCollision::with_code(m, c),
            ),
        )),
        "VendorProjectionRefused" => {
            let inner = match reason.as_deref() {
                None => VendorProjectionRefused::new(message),
                Some(value) => VendorProjectionRefused::with_reason(message, value),
            };
            RepairError::from(RepairRefused::from(inner))
        }
        "PlanSourceMismatch" => RepairError::from(with_optional_code_plan(
            message,
            code.as_deref(),
            |m| PlanSourceMismatch::new(m),
            |m, c| PlanSourceMismatch::with_code(m, c),
        )),
        other => panic!("unknown construct type in vector: {other}"),
    }
}

fn with_optional_code(
    message: String,
    code: Option<&str>,
    default: impl FnOnce(String) -> RepairError,
    custom: impl FnOnce(String, &str) -> RepairError,
) -> RepairError {
    match code {
        Some(value) => custom(message, value),
        None => default(message),
    }
}

fn with_optional_code_plan<T>(
    message: String,
    code: Option<&str>,
    default: impl FnOnce(String) -> T,
    custom: impl FnOnce(String, &str) -> T,
) -> T {
    match code {
        Some(value) => custom(message, value),
        None => default(message),
    }
}

fn with_optional_code_refused(
    message: String,
    code: Option<&str>,
    default: impl FnOnce(String) -> RepairRefused,
    custom: impl FnOnce(String, &str) -> RepairRefused,
) -> RepairRefused {
    match code {
        Some(value) => custom(message, value),
        None => default(message),
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    if kind == "module_all" {
        let names_json = array_field(&case.expected, "names").expect("names");
        let want: Vec<String> = names_json
            .iter()
            .map(|item| match item {
                JsonValue::Str(s) => s.clone(),
                _ => panic!("name must be string in {}", case.id),
            })
            .collect();
        assert_eq!(ALL.to_vec(), want, "__all__ order for {}", case.id);
        return;
    }

    let error = build_error(&case.construct);
    assert_eq!(
        error.to_string(),
        string_field(&case.expected, "display").expect("display"),
        "display mismatch for {}",
        case.id
    );
    assert_eq!(
        error.code(),
        string_field(&case.expected, "code").expect("code").as_str(),
        "code mismatch for {}",
        case.id
    );
    assert_bool(case, "is_value_error", error.is_value_error());
    assert_bool(case, "is_sesslint_error", error.is_sesslint_error());
    assert_bool(case, "is_repair_refused", error.is_repair_refused());
    assert_bool(case, "is_plan_tampered", error.is_plan_tampered());
    assert_bool(case, "is_abstained", error.is_abstained());
    assert_bool(case, "is_policy_mismatch", error.is_policy_mismatch());
    assert_bool(case, "is_output_invalid", error.is_output_invalid());
    assert_bool(
        case,
        "is_plan_source_mismatch",
        error.is_plan_source_mismatch(),
    );
    assert_bool(
        case,
        "is_vendor_repair_refused",
        error.is_vendor_repair_refused(),
    );
    assert_bool(case, "is_manifest_collision", error.is_manifest_collision());
    assert_bool(
        case,
        "is_vendor_projection_refused",
        error.is_vendor_projection_refused(),
    );
    assert_bool(
        case,
        "is_repair_error",
        error.is_value_error() && error.is_sesslint_error(),
    );

    if let Ok(reason) = string_field(&case.expected, "reason") {
        assert_eq!(
            error.reason(),
            Some(reason.as_str()),
            "reason mismatch for {}",
            case.id
        );
    }
}

fn assert_bool(case: &VectorCase, key: &str, got: bool) {
    let want = bool_field(&case.expected, key).unwrap_or_else(|err| {
        panic!("{} expected.{key}: {err}", case.id);
    });
    assert_eq!(got, want, "{key} mismatch for {}", case.id);
}

#[test]
fn repair_errors_module_parity_vectors() {
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

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    match &value.1 {
        JsonValue::Array(items) => Ok(items.as_slice()),
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
