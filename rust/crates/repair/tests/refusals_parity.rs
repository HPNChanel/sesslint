//! Policy-text parity for `sesslint.repair.refusals` against pinned Python vectors.

use repair::refusals::{
    refusal_rationale_for, RefusalError, RefusalRationale, ALL, REFUSAL_CODES, REFUSAL_REGISTRY,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.refusals/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 15;

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
        "module_all" => {
            let names_json = array_field(&case.expected, "names").expect("names");
            let want: Vec<String> = names_json
                .iter()
                .map(|item| match item {
                    JsonValue::Str(s) => s.clone(),
                    _ => panic!("name must be string in {}", case.id),
                })
                .collect();
            assert_eq!(ALL.to_vec(), want, "__all__ order for {}", case.id);
        }
        "registry_rows" => {
            let rows = array_field(&case.expected, "rows").expect("rows");
            assert_eq!(
                rows.len(),
                REFUSAL_REGISTRY.len(),
                "registry row count for {}",
                case.id
            );
            for (index, row_json) in rows.iter().enumerate() {
                let JsonValue::Object(row_obj) = row_json else {
                    panic!("row must be object in {}", case.id);
                };
                let got = REFUSAL_REGISTRY[index];
                assert_eq!(
                    got.code,
                    string_field(row_obj, "code").expect("code"),
                    "{} row {}",
                    case.id,
                    index
                );
                assert_eq!(
                    got.rationale,
                    string_field(row_obj, "rationale").expect("rationale"),
                    "{} row {}",
                    case.id,
                    index
                );
                assert_eq!(
                    got.demand_citation,
                    string_field(row_obj, "demand_citation").expect("demand_citation"),
                    "{} row {}",
                    case.id,
                    index
                );
                let want_salvage = optional_string_or_null_field(row_obj, "salvage_path")
                    .unwrap_or_else(|err| panic!("{} row {}: {err}", case.id, index));
                assert_eq!(
                    got.salvage_path,
                    want_salvage.as_deref(),
                    "{} row {}",
                    case.id,
                    index
                );
            }
        }
        "refusal_codes_sorted" => {
            let want = array_field(&case.expected, "codes").expect("codes");
            let want: Vec<String> = want
                .iter()
                .map(|item| match item {
                    JsonValue::Str(s) => s.clone(),
                    _ => panic!("code must be string in {}", case.id),
                })
                .collect();
            let mut got: Vec<&str> = REFUSAL_CODES.to_vec();
            got.sort_unstable();
            let got_strings: Vec<String> = got.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(got_strings, want, "sorted REFUSAL_CODES for {}", case.id);
        }
        "refusal_rationale_for" => {
            let code = string_field(&case.construct, "code").expect("code");
            let got = refusal_rationale_for(&code)
                .unwrap_or_else(|err| panic!("{} refusal_rationale_for: {err}", case.id));
            let kind = string_field(&case.expected, "kind").expect("expected kind");
            match kind.as_str() {
                "none" => {
                    assert_eq!(got, None, "expected None for {}", case.id);
                }
                "some" => {
                    let row_obj = object_field(&case.expected, "row").expect("row");
                    let want = rationale_from_row_object(row_obj);
                    let got = got.unwrap_or_else(|| panic!("{} expected Some", case.id));
                    assert_eq!(got, want, "refusal_rationale_for for {}", case.id);
                }
                other => panic!("unknown expected kind {other} in {}", case.id),
            }
        }
        "render" => {
            let code = string_field(&case.construct, "code").expect("code");
            let path =
                optional_string_or_null_field(&case.construct, "path").expect("construct path");
            let rationale = refusal_rationale_for(&code)
                .unwrap_or_else(|err| panic!("{} lookup: {err}", case.id))
                .unwrap_or_else(|| panic!("{} missing rationale for {code}", case.id));
            let rendered = match &path {
                None => rationale.render(None),
                Some(path) => rationale.render(Some(path.as_str())),
            };
            let want = string_field(&case.expected, "text").expect("text");
            assert_eq!(rendered, want, "render for {}", case.id);
        }
        "try_new_error" => {
            let code = string_field(&case.construct, "code").expect("code");
            let rationale = string_field(&case.construct, "rationale").expect("rationale");
            let demand = string_field(&case.construct, "demand_citation").expect("demand_citation");
            let salvage = optional_string_or_null_field(&case.construct, "salvage_path")
                .expect("salvage_path");
            let err = RefusalRationale::try_new(&code, &rationale, &demand, salvage.as_deref())
                .expect_err(&case.id);
            let want = string_field(&case.expected, "message").expect("message");
            assert_eq!(err.to_string(), want, "try_new message for {}", case.id);
            assert!(
                matches!(
                    err,
                    RefusalError::UnknownCode { .. }
                        | RefusalError::EmptyRationale { .. }
                        | RefusalError::UnrecognizedCitation { .. }
                        | RefusalError::EmptySalvagePath { .. }
                ),
                "unexpected error variant for {}",
                case.id
            );
        }
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn rationale_from_row_object(obj: &[(String, JsonValue)]) -> RefusalRationale {
    let code = string_field(obj, "code").expect("code");
    let rationale = string_field(obj, "rationale").expect("rationale");
    let demand = string_field(obj, "demand_citation").expect("demand_citation");
    let salvage = optional_string_or_null_field(obj, "salvage_path").expect("salvage_path");
    RefusalRationale::try_new(&code, &rationale, &demand, salvage.as_deref())
        .unwrap_or_else(|err| panic!("vector row must construct: {err}"))
}

#[test]
fn refusals_module_parity_vectors() {
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

fn optional_string_or_null_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    match &value.1 {
        JsonValue::Null => Ok(None),
        JsonValue::Str(s) => Ok(Some(s.clone())),
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
