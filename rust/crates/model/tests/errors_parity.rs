//! Byte-exact Display parity for `sesslint.errors` against pinned Python vectors.

use model::errors::{
    AdapterError, AssuranceError, AtomicWriteError, ContentLeakError, FileTooLargeError,
    FindingError, HeaderMissingError, MaxRecordsExceededError, OperationalError, SchemaError,
    SesslintError, SourceChangedError, UnknownFieldError, VersionError,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/errors/vectors.json";

#[derive(Debug, Clone, PartialEq, Eq)]
struct VectorCase {
    id: String,
    construct: Construct,
    expected: Expected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Construct {
    kind: String,
    message: String,
    code: Option<String>,
    version: Option<Option<String>>,
    field_name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Expected {
    display: String,
    code: String,
    is_schema: bool,
    is_value_error: bool,
    is_os_error: bool,
    reason_code: Option<String>,
    version: Option<Option<String>>,
    field_name: Option<Option<String>>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn build_error(construct: &Construct) -> SesslintError {
    match construct.kind.as_str() {
        "SesslintError" => {
            if let Some(code) = &construct.code {
                SesslintError::with_code(&construct.message, code)
            } else {
                SesslintError::new(&construct.message)
            }
        }
        "SchemaError" => {
            let inner = if let Some(code) = &construct.code {
                SchemaError::with_code(&construct.message, code)
            } else {
                SchemaError::new(&construct.message)
            };
            inner.into()
        }
        "VersionError" => {
            let version = construct.version.clone().flatten();
            VersionError::new(&construct.message, version).into()
        }
        "UnknownFieldError" => {
            let field_name = construct.field_name.clone().flatten();
            UnknownFieldError::new(&construct.message, field_name).into()
        }
        "FindingError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| FindingError::new(m).into(),
            |m, c| FindingError::with_code(m, c).into(),
        ),
        "AssuranceError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| AssuranceError::new(m).into(),
            |m, c| AssuranceError::with_code(m, c).into(),
        ),
        "ContentLeakError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| ContentLeakError::new(m).into(),
            |m, c| ContentLeakError::with_code(m, c).into(),
        ),
        "FileTooLargeError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| FileTooLargeError::new(m).into(),
            |m, c| FileTooLargeError::with_code(m, c).into(),
        ),
        "MaxRecordsExceededError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| MaxRecordsExceededError::new(m).into(),
            |m, c| MaxRecordsExceededError::with_code(m, c).into(),
        ),
        "HeaderMissingError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| HeaderMissingError::new(m).into(),
            |m, c| HeaderMissingError::with_code(m, c).into(),
        ),
        "SourceChangedError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| SourceChangedError::new(m).into(),
            |m, c| SourceChangedError::with_code(m, c).into(),
        ),
        "AtomicWriteError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| AtomicWriteError::new(m).into(),
            |m, c| AtomicWriteError::with_code(m, c).into(),
        ),
        "OperationalError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| OperationalError::new(m).into(),
            |m, c| OperationalError::with_code(m, c).into(),
        ),
        "AdapterError" => with_optional_code(
            &construct.message,
            construct.code.as_deref(),
            |m| AdapterError::new(m).into(),
            |m, c| AdapterError::with_code(m, c).into(),
        ),
        other => panic!("unknown construct type in vector: {other}"),
    }
}

fn with_optional_code(
    message: &str,
    code: Option<&str>,
    default: impl FnOnce(&str) -> SesslintError,
    custom: impl FnOnce(&str, &str) -> SesslintError,
) -> SesslintError {
    match code {
        Some(value) => custom(message, value),
        None => default(message),
    }
}

fn assert_case(case: &VectorCase) {
    let error = build_error(&case.construct);
    assert_eq!(
        error.to_string(),
        case.expected.display,
        "display mismatch for {}",
        case.id
    );
    assert_eq!(
        error.code(),
        case.expected.code.as_str(),
        "code mismatch for {}",
        case.id
    );
    assert_eq!(
        error.is_schema(),
        case.expected.is_schema,
        "is_schema mismatch for {}",
        case.id
    );
    assert_eq!(
        error.is_value_error(),
        case.expected.is_value_error,
        "is_value_error mismatch for {}",
        case.id
    );
    assert_eq!(
        error.is_os_error(),
        case.expected.is_os_error,
        "is_os_error mismatch for {}",
        case.id
    );
    if let Some(reason) = &case.expected.reason_code {
        assert_eq!(
            error.reason_code(),
            Some(reason.as_str()),
            "reason_code mismatch for {}",
            case.id
        );
    }
    if let Some(version) = &case.expected.version {
        assert_eq!(
            error.version(),
            version.as_deref(),
            "version mismatch for {}",
            case.id
        );
    }
    if let Some(field_name) = &case.expected.field_name {
        assert_eq!(
            error.field_name(),
            field_name.as_deref(),
            "field_name mismatch for {}",
            case.id
        );
    }
}

#[test]
fn errors_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let cases = parse_document(&raw).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(cases.len(), 32, "unexpected vector count");
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
    let construct = parse_construct(object_field(obj, "construct")?)?;
    let expected = parse_expected(object_field(obj, "expected")?)?;
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn parse_construct(obj: &[(String, JsonValue)]) -> Result<Construct, ParseError> {
    Ok(Construct {
        kind: string_field(obj, "type")?,
        message: string_field(obj, "message")?,
        code: optional_string_field(obj, "code")?,
        version: optional_nullable_string_field(obj, "version")?,
        field_name: optional_nullable_string_field(obj, "field_name")?,
    })
}

fn parse_expected(obj: &[(String, JsonValue)]) -> Result<Expected, ParseError> {
    Ok(Expected {
        display: string_field(obj, "display")?,
        code: string_field(obj, "code")?,
        is_schema: bool_field(obj, "is_schema")?,
        is_value_error: bool_field(obj, "is_value_error")?,
        is_os_error: bool_field(obj, "is_os_error")?,
        reason_code: optional_string_field(obj, "reason_code")?,
        version: optional_nullable_string_field(obj, "version")?,
        field_name: optional_nullable_string_field(obj, "field_name")?,
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

fn optional_nullable_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<Option<String>>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(Some(None)),
        Some((_, JsonValue::Str(s))) => Ok(Some(Some(s.clone()))),
        _ => Err(ParseError {
            message: format!("{key} must be string or null when present"),
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
    if input.starts_with(word) {
        Ok((value, &input[word.len()..]))
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
