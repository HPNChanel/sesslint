//! Byte-exact parity for `sesslint.adapters.links.extract_links` against pinned Python vectors.

use adapters::links::{extract_links, Link, ObjectValue};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.links/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 11;

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
    assert_eq!(kind, "extract_links", "unsupported type in {}", case.id);

    let obj = object_field(&case.construct, "obj").expect("obj");
    let map = json_object_to_map(obj);

    let mut links = initial_links(&case.construct).expect("initial_links");
    let record_id = optional_string_field(&case.construct, "record_id");
    let line = optional_i64_field(&case.construct, "line");

    extract_links(&map, &mut links, record_id.as_deref(), line);

    let expected_links = expected_link_rows(&case.expected).expect("expected links");
    assert_eq!(
        links.len(),
        expected_links.len(),
        "link count for {}",
        case.id
    );
    for (index, (got, want)) in links.iter().zip(expected_links.iter()).enumerate() {
        assert_eq!(got, want, "link[{index}] mismatch for {}", case.id);
    }
}

fn initial_links(construct: &[(String, JsonValue)]) -> Result<Vec<Link>, ParseError> {
    match construct.iter().find(|(k, _)| k == "initial_links") {
        None => Ok(Vec::new()),
        Some((_, JsonValue::Array(items))) => items.iter().map(parse_link).collect(),
        _ => Err(ParseError {
            message: "initial_links must be array when present".into(),
        }),
    }
}

fn expected_link_rows(expected: &[(String, JsonValue)]) -> Result<Vec<Link>, ParseError> {
    let items = array_field(expected, "links")?;
    items.iter().map(parse_link).collect()
}

fn parse_link(value: &JsonValue) -> Result<Link, ParseError> {
    let obj = as_object(value, "link")?;
    Ok(Link {
        kind: string_field(obj, "kind")?,
        target: string_field(obj, "target")?,
        record_id: optional_string_field(obj, "record_id"),
        line: optional_i64_field(obj, "line"),
    })
}

fn json_object_to_map(obj: &[(String, JsonValue)]) -> BTreeMap<String, ObjectValue> {
    obj.iter()
        .map(|(key, value)| (key.clone(), json_to_object_value(value)))
        .collect()
}

fn json_to_object_value(value: &JsonValue) -> ObjectValue {
    match value {
        JsonValue::Str(s) => ObjectValue::Str(s.clone()),
        JsonValue::Number(raw) => raw
            .parse::<i64>()
            .map(ObjectValue::Int)
            .unwrap_or(ObjectValue::Other),
        JsonValue::Bool(b) => ObjectValue::Bool(*b),
        JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => ObjectValue::Other,
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(s))) => Some(s.clone()),
        _ => panic!("{key} must be string or null"),
    }
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Option<i64> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Number(raw))) => Some(raw.parse::<i64>().expect("i64")),
        _ => panic!("{key} must be number or null"),
    }
}

#[test]
fn links_module_parity_vectors() {
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
