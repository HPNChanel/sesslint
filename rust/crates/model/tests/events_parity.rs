//! Parity for `sesslint._events` helpers against pinned Python vectors.

use model::canonical::SessionEvent;
use model::events::{
    copy_events_as_dicts, copy_events_as_dicts_strict, event_content_fingerprint, event_corr_id,
    event_id, event_kind, event_parent_id, to_event_dict, EventField, EventMapping, EventValue,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/_events/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 27;

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
fn events_module_parity_vectors() {
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
        "event_kind" => {
            let m = event_mapping_from_construct(&case.construct, "mapping");
            let ev = EventValue::Mapping(m);
            let got = event_kind(&ev).expect("event_kind");
            assert_optional_str_matches(&case.expected, "value", got, &case.id);
        }
        "event_id" => {
            let m = event_mapping_from_construct(&case.construct, "mapping");
            let ev = EventValue::Mapping(m);
            let got = event_id(&ev).expect("event_id");
            assert_optional_str_matches(&case.expected, "value", got, &case.id);
        }
        "event_parent_id" => {
            let m = event_mapping_from_construct(&case.construct, "mapping");
            let ev = EventValue::Mapping(m);
            let got = event_parent_id(&ev).expect("event_parent_id");
            assert_optional_str_matches(&case.expected, "value", got, &case.id);
        }
        "event_corr_id" => {
            let m = event_mapping_from_construct(&case.construct, "mapping");
            let ev = EventValue::Mapping(m);
            let got = event_corr_id(&ev).expect("event_corr_id");
            assert_optional_str_matches(&case.expected, "value", got, &case.id);
        }
        "event_content_fingerprint" => {
            let source = string_field(&case.construct, "source").expect("source");
            let ev = match source.as_str() {
                "mapping" => {
                    let m = event_mapping_from_construct(&case.construct, "mapping");
                    EventValue::Mapping(m)
                }
                "attr_content_hash" => {
                    let ch = string_field(&case.construct, "content_hash").expect("content_hash");
                    let mut event = SessionEvent::new(
                        "evt-synthetic",
                        None,
                        1,
                        "2024-02-29T00:00:00Z",
                        "assistant",
                        "message",
                    );
                    event.content_hash = Some(ch);
                    EventValue::from_session(event)
                }
                other => panic!("unknown content_fingerprint source in {}: {other}", case.id),
            };
            let got = event_content_fingerprint(&ev).expect("fingerprint");
            assert_eq!(
                got,
                string_field(&case.expected, "value").expect("expected value"),
                "{}",
                case.id
            );
        }
        "to_event_dict" => {
            let m = event_mapping_from_construct(&case.construct, "mapping");
            let ev = EventValue::Mapping(m);
            let got = to_event_dict(&ev).expect("to_event_dict");
            let want = event_mapping_from_expected_ordered(&case.expected, "ordered");
            assert_eq!(got, want, "{}", case.id);
        }
        "copy_events_as_dicts" => {
            let events = decode_events_list(&case.construct, "events");
            let got = copy_events_as_dicts(&events).expect("copy_events_as_dicts");
            assert_dicts_eq(&got, &case.expected, "dicts", &case.id);
        }
        "copy_events_as_dicts_strict" => {
            let events = decode_events_list(&case.construct, "events");
            let got = copy_events_as_dicts_strict(&events).expect("copy_events_as_dicts_strict");
            assert_dicts_eq(&got, &case.expected, "dicts", &case.id);
        }
        "session_event_getters" => {
            let ev_obj = object_field(&case.construct, "event").expect("event");
            let kind = string_field(ev_obj, "kind").expect("kind");
            let id = string_field(ev_obj, "id").expect("id");
            match lookup(ev_obj, "parent_id") {
                Some(JsonValue::Null) | None => {}
                other => panic!(
                    "{}: parent_id must be null or absent, got {other:?}",
                    case.id
                ),
            }
            let corr = string_field(ev_obj, "correlation_id").expect("correlation_id");
            let mut event =
                SessionEvent::new(id, None, 1, "2024-02-29T00:00:00Z", "assistant", kind);
            event.correlation_id = Some(corr);
            let ev = EventValue::from_session(event);
            assert_eq!(
                event_kind(&ev).unwrap().as_deref(),
                Some(
                    string_field(&case.expected, "kind")
                        .expect("expected kind")
                        .as_str()
                ),
                "{}",
                case.id
            );
            assert_eq!(
                event_id(&ev).unwrap().as_deref(),
                Some(
                    string_field(&case.expected, "id")
                        .expect("expected id")
                        .as_str()
                ),
                "{}",
                case.id
            );
            assert_eq!(event_parent_id(&ev).unwrap(), None, "{}", case.id);
            assert_eq!(
                event_corr_id(&ev).unwrap().as_deref(),
                Some(
                    string_field(&case.expected, "correlation_id")
                        .expect("expected correlation_id")
                        .as_str()
                ),
                "{}",
                case.id
            );
        }
        other => panic!("unknown construct type in {}: {other}", case.id),
    }
}

fn assert_optional_str_matches(
    expected: &[(String, JsonValue)],
    key: &str,
    got: Option<String>,
    case_id: &str,
) {
    match lookup(expected, key) {
        None | Some(JsonValue::Null) => assert!(got.is_none(), "{case_id}: expected null"),
        Some(JsonValue::Str(want)) => assert_eq!(got.as_deref(), Some(want.as_str()), "{case_id}"),
        other => panic!("{case_id}: bad expected {key}: {other:?}"),
    }
}

fn assert_dicts_eq(
    got: &[EventMapping],
    expected_root: &[(String, JsonValue)],
    key: &str,
    case_id: &str,
) {
    let arr = array_field(expected_root, key).expect(key);
    assert_eq!(got.len(), arr.len(), "{case_id}: dicts len");
    for (i, item) in arr.iter().enumerate() {
        let JsonValue::Array(pairs) = item else {
            panic!("{case_id}: dicts[{i}] must be array of key/tag pairs");
        };
        let want = mapping_array_to_event_mapping(pairs);
        assert_eq!(&got[i], &want, "{case_id}: dicts[{i}]");
    }
}

fn decode_events_list(construct: &[(String, JsonValue)], key: &str) -> Vec<EventValue> {
    let items = array_field(construct, key).expect(key);
    items
        .iter()
        .map(|item| {
            let JsonValue::Object(entries) = item else {
                panic!("event entry must be object");
            };
            EventValue::Mapping(event_mapping_from_entries_object(entries))
        })
        .collect()
}

fn event_mapping_from_entries_object(entries: &[(String, JsonValue)]) -> EventMapping {
    let arr = array_field(entries, "entries").expect("entries");
    mapping_array_to_event_mapping(&arr)
}

fn event_mapping_from_construct(construct: &[(String, JsonValue)], key: &str) -> EventMapping {
    let arr = array_field(construct, key).expect(key);
    mapping_array_to_event_mapping(&arr)
}

fn event_mapping_from_expected_ordered(
    expected: &[(String, JsonValue)],
    key: &str,
) -> EventMapping {
    let arr = array_field(expected, key).expect(key);
    mapping_array_to_event_mapping(&arr)
}

fn mapping_array_to_event_mapping(arr: &[JsonValue]) -> EventMapping {
    let mut out = Vec::new();
    for pair in arr {
        let JsonValue::Array(two) = pair else {
            panic!("mapping pair must be array");
        };
        if two.len() != 2 {
            panic!("mapping pair must have length 2");
        }
        let JsonValue::Str(key) = &two[0] else {
            panic!("mapping key must be string");
        };
        let field = json_to_event_field(&two[1]);
        out.push((key.clone(), field));
    }
    EventMapping::new(out)
}

fn json_to_event_field(value: &JsonValue) -> EventField {
    let obj = as_object(value, "tagged field").unwrap_or_else(|e| panic!("{e}"));
    let tag = string_field(obj, "t").expect("t");
    match tag.as_str() {
        "null" => EventField::Null,
        "bool" => EventField::Bool(bool_field(obj, "v").expect("v")),
        "int" => EventField::Int(i64_field(obj, "v").expect("v")),
        "str" => EventField::Str(string_field(obj, "v").expect("v")),
        "map" => {
            let nested = array_field(obj, "entries").expect("entries");
            EventField::Mapping(mapping_array_to_event_mapping(&nested))
        }
        other => panic!("unknown field tag {other}"),
    }
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
