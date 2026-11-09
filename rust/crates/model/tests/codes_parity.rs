//! Field and Display parity for `sesslint.codes` against pinned Python vectors.

use model::codes::{
    get_code_info, is_valid_code, CodeInfo, Repairability, Severity, CODE_REGISTRY,
};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

const VECTORS_REL: &str = "../../parity/vectors/codes/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 46;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn severity_from_input(input: &[(String, JsonValue)]) -> Severity {
    let kind = string_field(input, "kind").expect("input kind");
    let value = string_field(input, "value").expect("input value");
    if kind == "enum" {
        severity_from_value(&value).expect("enum severity value")
    } else {
        Severity::from_str(&value).expect("known severity string in vector")
    }
}

fn repairability_from_input(input: &[(String, JsonValue)]) -> Repairability {
    let kind = string_field(input, "kind").expect("input kind");
    let value = string_field(input, "value").expect("input value");
    if kind == "enum" {
        repairability_from_value(&value).expect("enum repairability value")
    } else {
        Repairability::from_str(&value).expect("known repairability string in vector")
    }
}

fn severity_from_value(value: &str) -> Result<Severity, String> {
    Severity::from_str(value).map_err(|err| err.to_string())
}

fn repairability_from_value(value: &str) -> Result<Repairability, String> {
    Repairability::from_str(value).map_err(|err| err.to_string())
}

fn registry_row_for_code(code: &str) -> CodeInfo {
    CODE_REGISTRY
        .iter()
        .copied()
        .find(|info| info.code == code)
        .unwrap_or_else(|| panic!("registry missing code {code} in vector harness"))
}

fn assert_code_info_matches(info: CodeInfo, expected: &[(String, JsonValue)], case_id: &str) {
    assert_eq!(
        info.code,
        string_field(expected, "code").expect("code"),
        "code mismatch for {case_id}"
    );
    assert_eq!(
        info.name,
        string_field(expected, "name").expect("name"),
        "name mismatch for {case_id}"
    );
    assert_eq!(
        info.summary,
        string_field(expected, "summary").expect("summary"),
        "summary mismatch for {case_id}"
    );
    let sev = string_field(expected, "default_severity").expect("default_severity");
    assert_eq!(
        info.default_severity,
        severity_from_value(&sev).expect("severity"),
        "default_severity mismatch for {case_id}"
    );
    let rep = string_field(expected, "default_repairability").expect("default_repairability");
    assert_eq!(
        info.default_repairability,
        repairability_from_value(&rep).expect("repairability"),
        "default_repairability mismatch for {case_id}"
    );
    assert_eq!(
        info.category,
        string_field(expected, "category").expect("category"),
        "category mismatch for {case_id}"
    );
    assert_eq!(
        info.override_policy,
        string_field(expected, "override_policy").expect("override_policy"),
        "override_policy mismatch for {case_id}"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "Severity_from_str" => {
            let input = object_field(&case.construct, "input").expect("input");
            let ok = bool_field(&case.expected, "ok").expect("ok");
            if ok {
                let parsed = Severity::parse(severity_from_input(input)).expect("parse severity");
                assert_eq!(
                    parsed.as_str(),
                    string_field(&case.expected, "value").expect("value"),
                    "severity value mismatch for {}",
                    case.id
                );
            } else {
                let raw = string_field(input, "value").expect("input value");
                let err = Severity::from_str(&raw).expect_err("expected severity error");
                assert_eq!(
                    err.value(),
                    string_field(&case.expected, "input_value").expect("input_value"),
                    "severity input_value mismatch for {}",
                    case.id
                );
                assert_eq!(
                    err.to_string(),
                    string_field(&case.expected, "display").expect("display"),
                    "severity display mismatch for {}",
                    case.id
                );
            }
        }
        "Repairability_from_str" => {
            let input = object_field(&case.construct, "input").expect("input");
            let ok = bool_field(&case.expected, "ok").expect("ok");
            if ok {
                let parsed = Repairability::parse(repairability_from_input(input))
                    .expect("parse repairability");
                assert_eq!(
                    parsed.as_str(),
                    string_field(&case.expected, "value").expect("value"),
                    "repairability value mismatch for {}",
                    case.id
                );
            } else {
                let raw = string_field(input, "value").expect("input value");
                let err = Repairability::from_str(&raw).expect_err("expected repairability error");
                assert_eq!(
                    err.value(),
                    string_field(&case.expected, "input_value").expect("input_value"),
                    "repairability input_value mismatch for {}",
                    case.id
                );
                assert_eq!(
                    err.to_string(),
                    string_field(&case.expected, "display").expect("display"),
                    "repairability display mismatch for {}",
                    case.id
                );
            }
        }
        "code_registry_row" => {
            let code = string_field(&case.construct, "code").expect("code");
            let info = registry_row_for_code(&code);
            assert_code_info_matches(info, &case.expected, &case.id);
        }
        "is_valid_code" => {
            let code = string_field(&case.construct, "code").expect("code");
            assert_eq!(
                is_valid_code(&code),
                bool_field(&case.expected, "valid").expect("valid"),
                "is_valid_code mismatch for {}",
                case.id
            );
        }
        "get_code_info" => {
            let code = string_field(&case.construct, "code").expect("code");
            let info = get_code_info(&code).expect("registered code");
            assert_code_info_matches(info, &case.expected, &case.id);
        }
        "get_code_info_error" => {
            let code = string_field(&case.construct, "code").expect("code");
            let err = get_code_info(&code).expect_err("unknown code");
            assert_eq!(
                err.to_string(),
                string_field(&case.expected, "display").expect("display"),
                "get_code_info error display mismatch for {}",
                case.id
            );
        }
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

#[test]
fn codes_module_parity_vectors() {
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
