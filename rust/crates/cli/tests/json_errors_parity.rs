//! Byte-exact parity for `sesslint.cli._json_errors` against pinned Python vectors.

use cli::json_errors::{error_document, wants_json, JsonArgs, TextSink, TrackedStream};
use std::fmt;
use std::io;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli._json_errors/vectors.json";
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

#[derive(Clone, Copy)]
enum RawMode {
    Integer,
    NonInteger,
    Fail,
}

struct ParitySink {
    mode: RawMode,
}

impl TextSink for ParitySink {
    fn write_text(&mut self, s: &str) -> io::Result<Option<usize>> {
        match self.mode {
            RawMode::Fail => Err(io::Error::other("synthetic-write-fail")),
            RawMode::NonInteger => Ok(None),
            RawMode::Integer => Ok(Some(s.len())),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn isatty(&self) -> bool {
        false
    }

    fn fileno(&self) -> io::Result<i32> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "fileno"))
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "error_document" => assert_error_document(case),
        "wants_json" => assert_wants_json(case),
        "tracked_stream" => assert_tracked_stream(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_error_document(case: &VectorCase) {
    let message = string_field(&case.construct, "message").expect("message");
    let expected_doc = string_field(&case.expected, "document").expect("document");
    let expected_len = i64_field(&case.expected, "bytes_len").expect("bytes_len");

    let document = error_document(&message);
    assert_eq!(document, expected_doc, "document mismatch for {}", case.id);
    let bytes = document.as_bytes();
    assert_eq!(
        bytes,
        expected_doc.as_bytes(),
        "document utf-8 bytes mismatch for {}",
        case.id
    );
    assert_eq!(
        bytes.len() as i64,
        expected_len,
        "bytes_len mismatch for {}",
        case.id
    );
    if case.id == "error_document_ascii_message" {
        assert!(
            bytes.windows(2).any(|w| w == b": "),
            "missing default json.dumps key separator for {}",
            case.id
        );
        assert!(
            bytes.windows(2).any(|w| w == b", "),
            "missing default json.dumps item separator for {}",
            case.id
        );
    }
}

fn assert_wants_json(case: &VectorCase) {
    let argv = string_list_field(&case.construct, "argv").expect("argv");
    let args = parse_json_args(&case.construct);
    let expected = bool_field(&case.expected, "value").expect("value");
    assert_eq!(
        wants_json(&argv, args.as_ref()),
        expected,
        "wants_json mismatch for {}",
        case.id
    );
}

fn parse_json_args(construct: &[(String, JsonValue)]) -> Option<JsonArgs> {
    let spec = match construct.iter().find(|(k, _)| k == "args") {
        Some((_, value)) => value,
        None => return None,
    };
    if matches!(spec, JsonValue::Null) {
        return None;
    }
    let obj = as_object_value(spec, "args").expect("args object");
    if bool_field(obj, "json_surface").ok() == Some(false) {
        return Some(JsonArgs::default());
    }
    let mut args = JsonArgs::default();
    if let Some(json) = optional_bool_field(obj, "json").expect("json parse") {
        args.json = Some(json);
    }
    if let Some(fmt) = optional_string_field(obj, "output_format").expect("output_format parse") {
        args.output_format = Some(fmt);
    }
    Some(args)
}

fn assert_tracked_stream(case: &VectorCase) {
    let limit = usize_field(&case.construct, "diagnostic_limit").expect("diagnostic_limit");
    let writes = string_list_field(&case.construct, "writes").expect("writes");
    let raw_mode = optional_string_field(&case.construct, "raw_mode")
        .expect("raw_mode parse")
        .unwrap_or_else(|| "integer".to_string());
    let mode = match raw_mode.as_str() {
        "integer" => RawMode::Integer,
        "non_integer" => RawMode::NonInteger,
        "fail" => RawMode::Fail,
        other => panic!("unknown raw_mode {other} in {}", case.id),
    };

    let mut stream = TrackedStream::new(ParitySink { mode }, limit);
    let expected_results = array_field(&case.expected, "write_results").expect("write_results");
    assert_eq!(
        expected_results.len(),
        writes.len(),
        "write count mismatch for {}",
        case.id
    );

    for (chunk, expected_item) in writes.iter().zip(expected_results.iter()) {
        let item_obj = as_object_value(expected_item, "write_result").expect("write_result");
        let ok = bool_field(item_obj, "ok").expect("ok");
        if ok {
            let count = i64_field(item_obj, "count").expect("count");
            assert_eq!(
                stream.write(chunk).unwrap(),
                count as usize,
                "write count for {}",
                case.id
            );
        } else {
            assert!(
                stream.write(chunk).is_err(),
                "expected write error for {}",
                case.id
            );
        }
    }

    let expected_nonempty = bool_field(&case.expected, "nonempty").expect("nonempty");
    let expected_diagnostic = string_field(&case.expected, "diagnostic").expect("diagnostic");
    assert_eq!(
        stream.nonempty, expected_nonempty,
        "nonempty mismatch for {}",
        case.id
    );
    assert_eq!(
        stream.diagnostic(),
        expected_diagnostic.as_str(),
        "diagnostic mismatch for {}",
        case.id
    );
}

#[test]
fn json_errors_module_parity_vectors() {
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

#[derive(Debug, Clone)]
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
    let obj = as_object_value(value, "vector")?;
    let id = string_field(obj, "id")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn as_object_value<'a>(
    value: &'a JsonValue,
    ctx: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        JsonValue::Null if ctx == "args" => Ok(&[]),
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
    as_object_value(&value.1, key)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
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
        Some((_, JsonValue::Null)) => Ok(None),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(value))) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn optional_bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<bool>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Bool(value))) => Ok(Some(*value)),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse::<i64>().map_err(|_| ParseError {
            message: format!("bad i64 for {key}"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let value = i64_field(obj, key)?;
    usize::try_from(value).map_err(|_| ParseError {
        message: format!("{key} out of range"),
    })
}

fn string_list_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => items
            .iter()
            .map(|item| match item {
                JsonValue::Str(s) => Ok(s.clone()),
                _ => Err(ParseError {
                    message: format!("{key} items must be strings"),
                }),
            })
            .collect(),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
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
