//! Byte-exact parity for `sesslint.adapters.safe_value` against pinned Python vectors.

use adapters::safe_value::{safe_discriminator, safe_type_value, PyValue, ALL};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.safe_value/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 299;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.adapters.safe_value";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SAFE_VALUE_PY_SHA256: &str =
    "dd864071a538898e7eed4bf318edbf4a2169373e56557d44ccd7bdcf98d518ee";
const EXPECTED_SAFE_VALUE_RS_SHA256: &str =
    "178188f5f9ff93a9fb1a69a16608e78ec9e4875e3c3c661a8ad4071a53a720b3";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

enum DecodedPyValue {
    Str(String),
    Fixed(PyValue<'static>),
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => {
            let names = array_field(&case.expected, "python_all").expect("python_all");
            assert_eq!(names.len(), ALL.len(), "ALL length for {}", case.id);
            for (index, item) in names.iter().enumerate() {
                let JsonValue::Str(name) = item else {
                    panic!("python_all[{index}] must be string in {}", case.id);
                };
                assert_eq!(ALL[index], name.as_str(), "ALL[{index}] for {}", case.id);
            }
        }
        "safe_type_value" => {
            let decoded = decoded_py_value_field(&case.construct, "val").expect("val");
            let got = match &decoded {
                DecodedPyValue::Str(text) => safe_type_value(PyValue::Str(text)),
                DecodedPyValue::Fixed(val) => safe_type_value(*val),
            };
            let want = string_field(&case.expected, "value").expect("value");
            assert_eq!(got, want, "safe_type_value mismatch for {}", case.id);
        }
        "safe_discriminator" => {
            let decoded = decoded_py_value_field(&case.construct, "val").expect("val");
            let (got_tv, got_trunc) = match &decoded {
                DecodedPyValue::Str(text) => safe_discriminator(PyValue::Str(text)),
                DecodedPyValue::Fixed(val) => safe_discriminator(*val),
            };
            let want_tv = string_field(&case.expected, "type_value").expect("type_value");
            let want_trunc = bool_field(&case.expected, "is_truncated").expect("is_truncated");
            assert_eq!(got_tv, want_tv, "type_value mismatch for {}", case.id);
            assert_eq!(
                got_trunc, want_trunc,
                "is_truncated mismatch for {}",
                case.id
            );
        }
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn decoded_py_value_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<DecodedPyValue, ParseError> {
    let spec = object_field(obj, key)?;
    decode_py_value_from_spec(spec)
}

fn decode_py_value_from_spec(spec: &[(String, JsonValue)]) -> Result<DecodedPyValue, ParseError> {
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "str" => {
            if spec.iter().any(|(key, _)| key == "fill") {
                let prefix = string_field(spec, "prefix")?;
                let fill = string_field(spec, "fill")?;
                let count = usize_field(spec, "count")?;
                if fill.chars().count() != 1 {
                    return Err(ParseError {
                        message: "str fill must be one character".into(),
                    });
                }
                return Ok(DecodedPyValue::Str(prefix + &fill.repeat(count)));
            }
            let text = string_field(spec, "text")?;
            Ok(DecodedPyValue::Str(text))
        }
        "bytes_hex" => {
            let hx = string_field(spec, "hex")?;
            let len = if hx.is_empty() {
                0
            } else {
                hx.len().checked_div(2).ok_or_else(|| ParseError {
                    message: "bad bytes_hex".into(),
                })?
            };
            if !hx.is_empty() && hx.len() % 2 != 0 {
                return Err(ParseError {
                    message: "odd bytes_hex length".into(),
                });
            }
            Ok(DecodedPyValue::Fixed(PyValue::Bytes(len)))
        }
        "list" => {
            let items = array_field(spec, "items")?;
            Ok(DecodedPyValue::Fixed(PyValue::List(items.len())))
        }
        "dict" => {
            let entries = object_field(spec, "entries")?;
            Ok(DecodedPyValue::Fixed(PyValue::Dict(entries.len())))
        }
        "set" => {
            let items = array_field(spec, "items")?;
            Ok(DecodedPyValue::Fixed(PyValue::Set(items.len())))
        }
        "tuple" => {
            let items = array_field(spec, "items")?;
            Ok(DecodedPyValue::Fixed(PyValue::Tuple(items.len())))
        }
        "none" => Ok(DecodedPyValue::Fixed(PyValue::None)),
        "int" => Ok(DecodedPyValue::Fixed(PyValue::Int)),
        "float" => Ok(DecodedPyValue::Fixed(PyValue::Float)),
        "bool" => Ok(DecodedPyValue::Fixed(PyValue::Bool)),
        "frozenset" => Ok(DecodedPyValue::Fixed(PyValue::Other("frozenset"))),
        other => Err(ParseError {
            message: format!("unknown val kind {other}"),
        }),
    }
}

#[test]
fn safe_value_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let doc = parse_document_with_meta(&raw).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &doc.cases {
        assert_case(case);
    }
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(
        string_field(meta, "schema").expect("schema"),
        EXPECTED_SCHEMA
    );
    assert_eq!(
        string_field(meta, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "safe_value_py_sha256").expect("safe_value_py_sha256"),
        EXPECTED_SAFE_VALUE_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "safe_value_rs_sha256").expect("safe_value_rs_sha256"),
        EXPECTED_SAFE_VALUE_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter().any(|item| {
            matches!(item, JsonValue::Str(s) if s.contains("str_subclass_type_name"))
        }),
        "expected str_subclass gap"
    );
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

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
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
    let cases: Vec<VectorCase> = items
        .iter()
        .map(parse_vector_case)
        .collect::<Result<_, _>>()?;
    Ok(ParsedDocument {
        meta: root.clone(),
        cases,
    })
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be a usize"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be a number"),
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
    let mut tail = end;
    if input.as_bytes().get(tail) == Some(&b'.') {
        tail += 1;
        let frac_start = tail;
        while tail < input.len() && input.as_bytes()[tail].is_ascii_digit() {
            tail += 1;
        }
        if tail == frac_start {
            return Err(ParseError {
                message: "invalid number".into(),
            });
        }
        end = tail;
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
