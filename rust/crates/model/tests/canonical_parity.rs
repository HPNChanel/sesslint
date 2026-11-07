//! Parity for `sesslint.canonical` parse/load helpers against pinned Python vectors.

use model::canonical::{
    load_session_file, parse_session, parse_session_event, parse_session_header,
    parse_session_lines, validate_rfc3339_utc, Payload, Session, SessionEvent, SessionHeader,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/canonical/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 12;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[test]
fn canonical_module_parity_vectors() {
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

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "parse_session_header" => {
            let value = object_field(&case.construct, "value").expect("value");
            let obj = json_object_to_payload(value).expect("header value");
            let header = parse_session_header(&obj).expect("parse_session_header");
            assert_session_header_matches(&header, &case.expected);
        }
        "parse_session_header_error" => {
            let value = object_field(&case.construct, "value").expect("value");
            let obj = json_object_to_payload(value).expect("header value");
            let err = parse_session_header(&obj).expect_err("expected error");
            assert_eq!(
                err.to_string(),
                string_field(&case.expected, "error").expect("error"),
                "message mismatch for {}",
                case.id
            );
        }
        "parse_session_event" => {
            let value = object_field(&case.construct, "value").expect("value");
            let obj = json_object_to_payload(value).expect("event value");
            let ev = parse_session_event(&obj, None).expect("parse_session_event");
            assert_session_event_matches(&ev, &case.expected);
        }
        "parse_session_event_error" => {
            let value = object_field(&case.construct, "value").expect("value");
            let obj = json_object_to_payload(value).expect("event value");
            let mut seen = std::collections::BTreeSet::new();
            if let Ok(ids) = array_field(&case.construct, "seen_ids_before") {
                for item in ids {
                    let JsonValue::Str(s) = item else {
                        panic!("seen_ids_before must be strings in {}", case.id);
                    };
                    seen.insert(s.clone());
                }
            }
            let err = parse_session_event(&obj, Some(&mut seen)).expect_err("expected error");
            assert_eq!(
                err.to_string(),
                string_field(&case.expected, "error").expect("error"),
                "message mismatch for {}",
                case.id
            );
        }
        "parse_session" => {
            let value = object_field(&case.construct, "value").expect("value");
            let obj = json_object_to_payload(value).expect("session value");
            let session = parse_session(&obj).expect("parse_session");
            assert_session_matches(&session, &case.expected);
        }
        "parse_session_lines" => {
            let lines = array_field(&case.construct, "lines").expect("lines");
            let owned: Vec<String> = lines
                .iter()
                .map(|line| match line {
                    JsonValue::Str(s) => s.clone(),
                    other => panic!("lines[{other:?}] must be string in {}", case.id),
                })
                .collect();
            let session =
                parse_session_lines(owned.iter().map(|s| s.as_str())).expect("parse_session_lines");
            assert_session_matches(&session, &case.expected);
        }
        "load_session_file_bytes" => {
            let b64 = string_field(&case.construct, "file_bytes_b64").expect("file_bytes_b64");
            let raw = decode_base64_standard(&b64).unwrap_or_else(|e| panic!("base64: {e}"));
            let dir = std::env::temp_dir();
            let path = dir.join(format!(
                "sesslint-canonical-parity-{}.jsonl",
                std::process::id()
            ));
            std::fs::write(&path, raw).expect("write temp session file");
            let session = load_session_file(&path).expect("load_session_file");
            std::fs::remove_file(&path).ok();
            assert_session_matches(&session, &case.expected);
        }
        "validate_rfc3339_direct" => {
            let ts = string_field(&case.construct, "ts").expect("ts");
            let field = string_field(&case.construct, "field").expect("field");
            let ok = bool_field(&case.expected, "ok").expect("ok");
            let result = validate_rfc3339_utc(&ts, &field);
            if ok {
                result.expect("validate ok");
            } else {
                let err = result.expect_err("validate err");
                assert_eq!(
                    err.to_string(),
                    string_field(&case.expected, "error").expect("error"),
                    "validate_rfc3339_utc mismatch for {}",
                    case.id
                );
            }
        }
        other => panic!("unknown construct type in {}: {other}", case.id),
    }
}

fn assert_payload_eq(actual: &Payload, expected_json: &[(String, JsonValue)], ctx: &str) {
    let expected = json_object_to_payload(expected_json).unwrap_or_else(|e| panic!("{ctx}: {e}"));
    assert_eq!(
        format!("{actual:#?}"),
        format!("{expected:#?}"),
        "{ctx} Payload mismatch"
    );
}

fn assert_session_header_matches(header: &SessionHeader, exp: &[(String, JsonValue)]) {
    assert_eq!(
        header.schema_version,
        string_field(exp, "schema_version").expect("schema_version"),
        "schema_version"
    );
    assert_eq!(
        header.session_id,
        string_field(exp, "session_id").expect("session_id"),
        "session_id"
    );
    assert_eq!(
        header.created_at,
        string_field(exp, "created_at").expect("created_at"),
        "created_at"
    );
    match lookup(exp, "title") {
        Some(JsonValue::Null) | None => assert!(header.title.is_none(), "title"),
        Some(JsonValue::Str(s)) => assert_eq!(header.title.as_deref(), Some(s.as_str()), "title"),
        other => panic!("bad title expected: {other:?}"),
    }
    let meta = object_field(exp, "metadata").expect("metadata");
    assert_payload_eq(&header.metadata, meta, "metadata");
    match lookup(exp, "source") {
        None | Some(JsonValue::Null) => assert!(header.source.is_none(), "source"),
        Some(JsonValue::Str(s)) => {
            let got = header
                .source
                .as_ref()
                .and_then(Payload::as_str)
                .expect("source str");
            assert_eq!(got, s, "source");
        }
        Some(JsonValue::Object(obj)) => {
            let src = header.source.as_ref().expect("source map");
            assert_payload_eq(src, obj, "source");
        }
        other => panic!("bad source: {other:?}"),
    }
    match lookup(exp, "version") {
        None | Some(JsonValue::Null) => assert!(header.version.is_none(), "version"),
        Some(JsonValue::Number(n)) => assert_eq!(header.version, Some(*n), "version"),
        other => panic!("bad version: {other:?}"),
    }
    let extra = object_field(exp, "extra_fields").expect("extra_fields");
    assert_payload_eq(&header.extra_fields, extra, "header.extra_fields");
}

fn assert_session_event_matches(ev: &SessionEvent, exp: &[(String, JsonValue)]) {
    assert_eq!(ev.id, string_field(exp, "id").expect("id"), "id");
    match lookup(exp, "parent_id") {
        Some(JsonValue::Null) | None => assert!(ev.parent_id.is_none(), "parent_id"),
        Some(JsonValue::Str(s)) => assert_eq!(ev.parent_id.as_deref(), Some(s.as_str())),
        other => panic!("bad parent_id: {other:?}"),
    }
    assert_eq!(ev.seq, i64_field(exp, "seq").expect("seq"), "seq");
    assert_eq!(ev.ts, string_field(exp, "ts").expect("ts"), "ts");
    assert_eq!(
        ev.actor,
        string_field(exp, "actor").expect("actor"),
        "actor"
    );
    assert_eq!(ev.kind, string_field(exp, "kind").expect("kind"), "kind");
    let payload = object_field(exp, "payload").expect("payload");
    assert_payload_eq(&ev.payload, payload, "payload");
    optional_string_eq(exp, "content_hash", &ev.content_hash);
    optional_string_eq(exp, "correlation_id", &ev.correlation_id);
    optional_string_eq(exp, "branch_id", &ev.branch_id);
    optional_string_eq(exp, "interaction_id", &ev.interaction_id);
    optional_string_eq(exp, "agent_id", &ev.agent_id);
    optional_string_eq(exp, "execution_state", &ev.execution_state);
    optional_i64_eq(exp, "source_line", &ev.source_line);
    optional_string_eq(exp, "source_record_hash", &ev.source_record_hash);
    optional_string_eq(exp, "original_id", &ev.original_id);
    optional_string_eq(exp, "source_adapter", &ev.source_adapter);
    optional_string_eq(exp, "source_location", &ev.source_location);
    optional_string_eq(exp, "side_effects", &ev.side_effects);
    let extra = object_field(exp, "extra_fields").expect("extra_fields");
    assert_payload_eq(&ev.extra_fields, extra, "event.extra_fields");
}

fn assert_session_matches(session: &Session, exp: &[(String, JsonValue)]) {
    let header = object_field(exp, "header").expect("header");
    assert_session_header_matches(&session.header, header);
    let events = array_field(exp, "events").expect("events");
    assert_eq!(session.events.len(), events.len(), "events len");
    for (idx, item) in events.iter().enumerate() {
        let JsonValue::Object(obj) = item else {
            panic!("events[{idx}] must be object");
        };
        assert_session_event_matches(&session.events[idx], obj);
    }
    let extra = object_field(exp, "extra_fields").expect("extra_fields");
    assert_payload_eq(&session.extra_fields, extra, "session.extra_fields");
}

fn optional_string_eq(exp: &[(String, JsonValue)], key: &str, got: &Option<String>) {
    match lookup(exp, key) {
        None | Some(JsonValue::Null) => assert!(got.is_none(), "{key}"),
        Some(JsonValue::Str(want)) => assert_eq!(got.as_deref(), Some(want.as_str()), "{key}"),
        other => panic!("bad {key}: {other:?}"),
    }
}

fn optional_i64_eq(exp: &[(String, JsonValue)], key: &str, got: &Option<i64>) {
    match lookup(exp, key) {
        None | Some(JsonValue::Null) => assert!(got.is_none(), "{key}"),
        Some(JsonValue::Number(n)) => assert_eq!(*got, Some(*n), "{key}"),
        other => panic!("bad {key}: {other:?}"),
    }
}

fn json_object_to_payload(obj: &[(String, JsonValue)]) -> Result<Payload, String> {
    let mut pairs = Vec::with_capacity(obj.len());
    for (key, value) in obj {
        pairs.push((Payload::string(key.clone()), json_value_to_payload(value)?));
    }
    Ok(Payload::map(pairs))
}

fn json_value_to_payload(value: &JsonValue) -> Result<Payload, String> {
    Ok(match value {
        JsonValue::Null => Payload::null(),
        JsonValue::Bool(b) => Payload::bool_value(*b),
        JsonValue::Number(n) => Payload::int(*n),
        JsonValue::Str(s) => Payload::string(s.clone()),
        JsonValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_value_to_payload(item)?);
            }
            Payload::list(out)
        }
        JsonValue::Object(entries) => json_object_to_payload(entries)?,
    })
}

fn decode_base64_standard(input: &str) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Result<u8, String> {
        match byte {
            b'A'..=b'Z' => Ok(byte - b'A'),
            b'a'..=b'z' => Ok(byte - b'a' + 26),
            b'0'..=b'9' => Ok(byte - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 byte {byte}")),
        }
    }

    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        .collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if !cleaned.len().is_multiple_of(4) {
        return Err("invalid base64 length".into());
    }

    let mut out: Vec<u8> = Vec::with_capacity(cleaned.len() / 4 * 3);
    for chunk in cleaned.chunks_exact(4) {
        let a = value(chunk[0])?;
        let b = value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            None
        } else {
            Some(value(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            None
        } else {
            Some(value(chunk[3])?)
        };

        match (c, d) {
            (Some(c), Some(d)) => {
                let triple = (u32::from(a) << 18)
                    | (u32::from(b) << 12)
                    | (u32::from(c) << 6)
                    | u32::from(d);
                out.push((triple >> 16) as u8);
                out.push((triple >> 8) as u8);
                out.push(triple as u8);
            }
            (Some(c), None) => {
                if chunk[3] != b'=' {
                    return Err("invalid base64 padding".into());
                }
                let triple = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6);
                out.push((triple >> 16) as u8);
                out.push((triple >> 8) as u8);
            }
            (None, None) => {
                if chunk[2] != b'=' || chunk[3] != b'=' {
                    return Err("invalid base64 padding".into());
                }
                let triple = (u32::from(a) << 18) | (u32::from(b) << 12);
                out.push((triple >> 16) as u8);
            }
            (None, Some(_)) => return Err("invalid base64 padding order".into()),
        }
    }
    Ok(out)
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

// --- minimal JSON (vectors.json) with integers ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
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
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
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
    let first = input.as_bytes()[0];
    match first {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_number_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        idx += 1;
    }
    if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let start_digits = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    let digits = &input[start_digits..idx];
    let magnitude: i64 = digits.parse().map_err(|_| ParseError {
        message: "number overflow".into(),
    })?;
    let value = if negative { -magnitude } else { magnitude };
    Ok((JsonValue::Number(value), &input[idx..]))
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
