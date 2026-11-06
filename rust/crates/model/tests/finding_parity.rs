//! Parity for `sesslint.finding` against pinned Python vectors.

use model::codes::{Repairability, Severity};
use model::finding::{
    enforce_content_free_text, make_finding, parse_finding_dict, sort_findings, DictValue, Finding,
    FindingInput, MakeFindingInput, PyValue, SourceLine, SourceRef, ALL, DEFAULT_TEXT_CONTEXT,
    SCHEMA_VERSION,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/finding/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 22;

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
fn finding_module_parity_vectors() {
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
        "ALL" => {
            let names = array_field(&case.expected, "names").expect("names");
            assert_eq!(
                names.len(),
                ALL.len(),
                "ALL length mismatch for {}",
                case.id
            );
            for (index, value) in names.iter().enumerate() {
                let JsonValue::Str(name) = value else {
                    panic!("ALL[{index}] must be string in {}", case.id);
                };
                assert_eq!(
                    ALL[index],
                    name.as_str(),
                    "ALL[{index}] mismatch for {}",
                    case.id
                );
            }
        }
        "enforce_content_free_text" => {
            let text = string_field(&case.construct, "text").expect("text");
            let context = string_field(&case.construct, "context")
                .unwrap_or_else(|_| DEFAULT_TEXT_CONTEXT.to_owned());
            let ok = bool_field(&case.expected, "ok").expect("ok");
            let result = enforce_content_free_text(&text, &context);
            if ok {
                result.expect("expected enforce ok");
            } else {
                let display = string_field(&case.expected, "display").expect("display");
                let err = result.expect_err("expected enforce error");
                assert_eq!(
                    err.to_string(),
                    display,
                    "enforce display mismatch for {}",
                    case.id
                );
            }
        }
        "SourceRef_try" => {
            let path = string_field(&case.construct, "path").expect("path");
            let line = line_construct(&case.construct);
            let result = SourceRef::try_new(&path, line, None);
            let ok = bool_field(&case.expected, "ok").expect("ok");
            if ok {
                let source = result.expect("expected SourceRef ok");
                assert_eq!(
                    source.path(),
                    string_field(&case.expected, "path").expect("path"),
                    "path mismatch for {}",
                    case.id
                );
                match lookup(&case.expected, "line") {
                    Some(JsonValue::Null) => assert!(source.line().is_none(), "{}", case.id),
                    Some(JsonValue::Number(n)) => {
                        assert_eq!(source.line(), Some(*n), "line mismatch for {}", case.id)
                    }
                    other => panic!("expected line null or number in {}: {other:?}", case.id),
                }
                match lookup(&case.expected, "record_id") {
                    None | Some(JsonValue::Null) => assert!(
                        source.record_id().is_none(),
                        "record_id mismatch for {}",
                        case.id
                    ),
                    Some(JsonValue::Str(s)) => assert_eq!(source.record_id(), Some(s.as_str())),
                    other => panic!("bad record_id expected in {}: {other:?}", case.id),
                }
            } else {
                let display = string_field(&case.expected, "display").expect("display");
                let err = result.expect_err("expected SourceRef error");
                assert_eq!(
                    err.to_string(),
                    display,
                    "SourceRef display mismatch for {}",
                    case.id
                );
            }
        }
        "sort_findings" => {
            let items = match lookup(&case.construct, "findings") {
                Some(JsonValue::Array(items)) => items,
                _ => panic!("missing findings array in {}", case.id),
            };
            let mut rust_findings = Vec::with_capacity(items.len());
            for item in items {
                let obj = as_object(item, "finding").expect("finding object");
                let code = string_field(obj, "code").expect("code");
                let severity = string_field(obj, "severity").expect("severity");
                let repairability = string_field(obj, "repairability").expect("repairability");
                let message = string_field(obj, "message").expect("message");
                let fingerprint = string_field(obj, "fingerprint").expect("fingerprint");
                let source_obj = object_field(obj, "source").expect("source");
                let path = string_field(source_obj, "path").expect("source.path");
                let line = match lookup(source_obj, "line") {
                    None | Some(JsonValue::Null) => None,
                    Some(JsonValue::Number(n)) => Some(SourceLine::Int(*n)),
                    other => panic!("bad source.line in {}: {other:?}", case.id),
                };
                let record_id = match lookup(source_obj, "record_id") {
                    None | Some(JsonValue::Null) => None,
                    Some(JsonValue::Str(s)) => Some(s.as_str()),
                    other => panic!("bad source.record_id in {}: {other:?}", case.id),
                };
                let source = SourceRef::try_new(&path, line, record_id).expect("SourceRef");
                let related = array_field(obj, "related_ids").expect("related_ids");
                let related_tuple: Vec<PyValue> = related
                    .into_iter()
                    .map(|entry| match entry {
                        JsonValue::Str(text) => PyValue::string(text),
                        other => panic!("related_ids must be strings in {}: {other:?}", case.id),
                    })
                    .collect();
                let finding = Finding::try_new(FindingInput {
                    code: PyValue::string(code),
                    severity: PyValue::severity(
                        Severity::parse(&severity).expect("severity in vector"),
                    ),
                    repairability: PyValue::repairability(
                        Repairability::parse(&repairability).expect("repairability"),
                    ),
                    message: PyValue::string(message),
                    source: PyValue::source(source),
                    related_ids: PyValue::tuple(related_tuple),
                    fingerprint: PyValue::string(fingerprint),
                    schema_version: PyValue::string(SCHEMA_VERSION),
                    message_template: PyValue::None,
                    evidence: PyValue::None,
                })
                .expect("Finding::try_new");
                rust_findings.push(finding);
            }
            let sorted = sort_findings(&rust_findings);
            let order = array_field(&case.expected, "order").expect("order");
            assert_eq!(sorted.len(), order.len(), "order length {}", case.id);
            for (index, step) in order.iter().enumerate() {
                let obj = as_object(step, "step").expect("order step");
                assert_eq!(
                    sorted[index].severity().as_str(),
                    string_field(obj, "severity").expect("severity"),
                    "severity at {} in {}",
                    index,
                    case.id
                );
                assert_eq!(
                    sorted[index].source().path(),
                    string_field(obj, "path").expect("path"),
                    "path at {} in {}",
                    index,
                    case.id
                );
                match lookup(obj, "line") {
                    Some(JsonValue::Null) => assert!(sorted[index].source().line().is_none()),
                    Some(JsonValue::Number(n)) => {
                        assert_eq!(sorted[index].source().line(), Some(*n));
                    }
                    other => panic!("bad order.line in {}: {other:?}", case.id),
                }
                assert_eq!(
                    sorted[index].code(),
                    string_field(obj, "code").expect("code"),
                    "code at {} in {}",
                    index,
                    case.id
                );
            }
        }
        "make_finding" => {
            let code = string_field(&case.construct, "code").expect("code");
            let message_template = string_field(&case.construct, "message_template")
                .unwrap_or_else(|_| "{line}".to_owned());
            let source_obj = object_field(&case.construct, "source").expect("source");
            let path = string_field(source_obj, "path").expect("source.path");
            let line = match lookup(source_obj, "line") {
                None | Some(JsonValue::Null) => None,
                Some(JsonValue::Number(n)) => Some(SourceLine::Int(*n)),
                other => panic!("bad source.line in {}: {other:?}", case.id),
            };
            let source = SourceRef::try_new(&path, line, None).expect("SourceRef");
            let fingerprint = string_field(&case.construct, "fingerprint").expect("fingerprint");
            let related = array_field(&case.construct, "related_ids").unwrap_or_default();
            let related_tuple: Vec<PyValue> = related
                .into_iter()
                .map(|entry| match entry {
                    JsonValue::Str(text) => PyValue::string(text),
                    other => panic!("related_ids must be strings in {}: {other:?}", case.id),
                })
                .collect();
            let omit_sev = bool_field(&case.construct, "severity_omitted").unwrap_or(false);
            let severity = if omit_sev {
                PyValue::None
            } else if let Some(JsonValue::Str(s)) = lookup(&case.construct, "severity") {
                PyValue::string(s.clone())
            } else {
                PyValue::None
            };
            let repairability = match lookup(&case.construct, "repairability") {
                Some(JsonValue::Str(s)) => PyValue::string(s.clone()),
                _ => PyValue::None,
            };
            let input = MakeFindingInput {
                code: PyValue::string(code),
                severity,
                repairability,
                message_template: PyValue::string(message_template),
                template_args: PyValue::None,
                source: PyValue::source(source),
                related_ids: PyValue::tuple(related_tuple),
                evidence: PyValue::None,
                fingerprint: PyValue::string(fingerprint),
                adapter_id: None,
                adapter_version: None,
                profile_id: None,
                profile_version: None,
                ordinal: None,
                context: None,
            };
            let ok = bool_field(&case.expected, "ok").expect("ok");
            let result = make_finding(&input);
            if ok {
                let got = result.expect("make_finding ok");
                assert_eq!(
                    got.message(),
                    string_field(&case.expected, "message").expect("message"),
                    "message mismatch for {}",
                    case.id
                );
                assert_eq!(
                    got.severity().as_str(),
                    string_field(&case.expected, "severity").expect("severity"),
                    "severity mismatch for {}",
                    case.id
                );
                assert_eq!(
                    got.repairability().as_str(),
                    string_field(&case.expected, "repairability").expect("repairability"),
                    "repairability mismatch for {}",
                    case.id
                );
                assert_eq!(
                    got.fingerprint(),
                    string_field(&case.expected, "fingerprint").expect("fingerprint"),
                    "fingerprint mismatch for {}",
                    case.id
                );
            } else {
                let display = string_field(&case.expected, "display").expect("display");
                let err = result.expect_err("make_finding error");
                assert_eq!(
                    err.to_string(),
                    display,
                    "make_finding display mismatch for {}",
                    case.id
                );
            }
        }
        "parse_finding_dict" => {
            let obj = lookup(&case.construct, "obj").expect("obj");
            let py = json_to_py_value(obj).expect("json to PyValue");
            let ok = bool_field(&case.expected, "ok").expect("ok");
            let result = parse_finding_dict(&py);
            if ok {
                let finding = result.expect("parse ok");
                let to_dict = object_field(&case.expected, "to_dict").expect("to_dict");
                let got = finding_to_ordered_json(&finding);
                let expected = object_to_ordered_json(to_dict);
                assert_json_ordered_eq(&got, &expected, &case.id);
            } else {
                let display = string_field(&case.expected, "display").expect("display");
                let err = result.expect_err("parse error");
                assert_eq!(
                    err.to_string(),
                    display,
                    "parse display mismatch for {}",
                    case.id
                );
            }
        }
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn finding_to_ordered_json(finding: &Finding) -> Vec<(String, JsonValue)> {
    finding
        .to_dict()
        .iter()
        .map(|(key, value)| ((*key).to_owned(), dict_value_to_json(value)))
        .collect()
}

fn dict_value_to_json(value: &DictValue) -> JsonValue {
    match value {
        DictValue::Str(text) => JsonValue::Str(text.clone()),
        DictValue::Int(number) => JsonValue::Number(*number),
        DictValue::Bool(flag) => JsonValue::Bool(*flag),
        DictValue::None => JsonValue::Null,
        DictValue::Bytes(bytes) => JsonValue::Str(format!("bytes:{bytes:?}")),
        DictValue::List(items) => JsonValue::Array(items.iter().map(dict_value_to_json).collect()),
        DictValue::Tuple(items) => JsonValue::Array(items.iter().map(dict_value_to_json).collect()),
        DictValue::Set(items) => JsonValue::Array(items.iter().map(dict_value_to_json).collect()),
        DictValue::FrozenSet(items) => {
            JsonValue::Array(items.iter().map(dict_value_to_json).collect())
        }
        DictValue::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .map(|(key, child)| (key.clone(), dict_value_to_json(child)))
                .collect(),
        ),
    }
}

fn object_to_ordered_json(entries: &[(String, JsonValue)]) -> Vec<(String, JsonValue)> {
    entries.to_vec()
}

fn assert_json_ordered_eq(
    left: &[(String, JsonValue)],
    right: &[(String, JsonValue)],
    case_id: &str,
) {
    assert_eq!(left.len(), right.len(), "top-level key count {case_id}");
    for index in 0..left.len() {
        assert_eq!(
            left[index].0, right[index].0,
            "key order mismatch at {index} for {case_id}"
        );
        assert_json_value_eq(&left[index].1, &right[index].1, case_id);
    }
}

fn assert_json_value_eq(left: &JsonValue, right: &JsonValue, case_id: &str) {
    match (left, right) {
        (JsonValue::Null, JsonValue::Null) => {}
        (JsonValue::Bool(a), JsonValue::Bool(b)) => assert_eq!(a, b, "{case_id}"),
        (JsonValue::Str(a), JsonValue::Str(b)) => assert_eq!(a, b, "{case_id}"),
        (JsonValue::Number(a), JsonValue::Number(b)) => assert_eq!(a, b, "{case_id}"),
        (JsonValue::Array(a), JsonValue::Array(b)) => {
            assert_eq!(a.len(), b.len(), "array len {case_id}");
            for (i, pair) in a.iter().zip(b.iter()).enumerate() {
                assert_json_value_eq(pair.0, pair.1, &format!("{case_id}[{i}]"));
            }
        }
        (JsonValue::Object(a), JsonValue::Object(b)) => {
            assert_eq!(a.len(), b.len(), "object len {case_id}");
            for index in 0..a.len() {
                assert_eq!(a[index].0, b[index].0, "object key {case_id}");
                assert_json_value_eq(&a[index].1, &b[index].1, case_id);
            }
        }
        _ => panic!("json type mismatch for {case_id}: {left:?} vs {right:?}"),
    }
}

fn json_to_py_value(value: &JsonValue) -> Result<PyValue, String> {
    Ok(match value {
        JsonValue::Null => PyValue::None,
        JsonValue::Bool(flag) => PyValue::bool_value(*flag),
        JsonValue::Str(text) => PyValue::string(text.clone()),
        JsonValue::Number(number) => PyValue::int(*number),
        JsonValue::Array(items) => PyValue::List(
            items
                .iter()
                .map(json_to_py_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        JsonValue::Object(entries) => PyValue::Map(
            entries
                .iter()
                .map(|(key, child)| Ok((PyValue::string(key.clone()), json_to_py_value(child)?)))
                .collect::<Result<Vec<_>, String>>()?,
        ),
    })
}

fn line_construct(obj: &[(String, JsonValue)]) -> Option<SourceLine> {
    match lookup(obj, "line") {
        None => None,
        Some(JsonValue::Null) => None,
        Some(JsonValue::Bool(flag)) => Some(SourceLine::Bool(*flag)),
        Some(JsonValue::Number(n)) => Some(SourceLine::Int(*n)),
        Some(other) => panic!("unsupported SourceRef line construct: {other:?}"),
    }
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, value)| value)
}

// --- minimal JSON (vectors.json) with numbers ---

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
