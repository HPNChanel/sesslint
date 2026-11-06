//! Parity for `sesslint.policy.abstention` against pinned Python vectors.

use checks::abstention::{
    check_step_scope, extract_side_effects, find_ambiguous_events, must_abstain,
    should_abstain_from_repair, Abstention, AbstentionError, AffectedRegion, AmbiguousEvents,
    PyInt,
};
use model::codes::{Repairability, Severity};
use model::events::{EventField, EventMapping, EventValue};
use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/policy.abstention/vectors.json";
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

#[test]
fn abstention_module_parity_vectors() {
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
        "extract_side_effects" => {
            let m = event_mapping_from_construct(&case.construct, "mapping");
            let ev = EventValue::Mapping(m);
            let got = extract_side_effects(&ev, None).expect("extract_side_effects");
            assert_eq!(
                got,
                string_field(&case.expected, "value").expect("expected value"),
                "{}",
                case.id
            );
        }
        "affected_region_all_indices" => {
            let indices = index_set(&case.construct, "indices");
            let ids = id_set(&case.construct, "ids");
            let ranges = ranges_from_construct(&case.construct);
            let region = AffectedRegion::new(indices, ids, ranges, false).expect("region");
            let total_len = match lookup(&case.construct, "total_len") {
                None | Some(JsonValue::Null) => None,
                Some(JsonValue::Number(n)) => Some(*n),
                other => panic!("{}: bad total_len: {other:?}", case.id),
            };
            let got = region.all_indices(total_len).expect("all_indices");
            assert_sorted_i64_set_matches(&case.expected, "indices", &got, &case.id);
        }
        "should_abstain_from_repair" => {
            let findings = decode_findings(&case.construct, "findings");
            let events = decode_events(&case.construct, "events");
            let policy = string_field(&case.construct, "policy").expect("policy");
            let acknowledge = bool_field(&case.construct, "acknowledge_side_effects")
                .expect("acknowledge_side_effects");
            let excludes =
                bool_field(&case.construct, "excludes_execution_dependence").expect("excludes");
            let has_fn = bool_field(&case.construct, "has_recipe_region_fn").expect("has_fn");
            let step_storage: Option<i64> = match lookup(&case.construct, "step") {
                None | Some(JsonValue::Null) => None,
                Some(JsonValue::Number(n)) => Some(*n),
                other => panic!("{}: bad step: {other:?}", case.id),
            };
            let step_ref = step_storage.as_ref();
            let region = if has_fn {
                Some(
                    decode_region(object_field(&case.construct, "region").expect("region"))
                        .expect("region decode"),
                )
            } else {
                None
            };
            let callback = region.as_ref().map(|region| {
                let region = region.clone();
                move |_step: &i64, _events: &[EventValue]| Ok(Some(region.clone()))
            });
            let got = should_abstain_from_repair(
                &findings,
                &events,
                policy.as_str(),
                acknowledge,
                step_ref,
                callback.as_ref().map(|c| c as _),
                excludes,
            )
            .expect("should_abstain_from_repair");
            assert_abstention(&case.expected, "abstention", &got, &case.id);
        }
        "must_abstain" => {
            let findings = decode_findings(&case.construct, "findings");
            let events = decode_events(&case.construct, "events");
            let allow = bool_field(&case.construct, "allow_unknown_side_effects").expect("allow");
            let got = must_abstain(&findings, &events, allow).expect("must_abstain");
            assert_abstention(&case.expected, "abstention", &got, &case.id);
        }
        "find_ambiguous_events" => {
            let findings = decode_findings_optional(&case.construct, "findings");
            let events = decode_events(&case.construct, "events");
            let got = find_ambiguous_events(&events, findings.as_deref()).expect("ambiguous");
            assert_ambiguous(&case.expected, "ambiguous", &got, &case.id);
        }
        "check_step_scope" => {
            let step = i64_field(&case.construct, "step").expect("step");
            let events = decode_events(&case.construct, "events");
            let findings = decode_findings_optional(&case.construct, "findings");
            let has_fn = bool_field(&case.construct, "has_recipe_region_fn").expect("has_fn");
            let excludes =
                bool_field(&case.construct, "excludes_execution_dependence").expect("excludes");
            let region_opt = if has_fn {
                Some(
                    decode_region(object_field(&case.construct, "region").expect("region"))
                        .expect("region decode"),
                )
            } else {
                None
            };
            let callback = region_opt.map(|region| {
                let region = region.clone();
                move |_s: &i64, _evs: &[EventValue]| Ok(Some(region.clone()))
            });
            let got = check_step_scope(
                &step,
                &events,
                callback.as_ref().map(|c| c as _),
                findings.as_deref(),
                excludes,
                None,
            )
            .expect("check_step_scope");
            let ok = bool_field(&case.expected, "ok").expect("expected ok");
            assert_eq!(got.0, ok, "{}", case.id);
            match lookup(&case.expected, "reason") {
                None | Some(JsonValue::Null) => assert!(got.1.is_none(), "{}", case.id),
                Some(JsonValue::Str(want)) => {
                    assert_eq!(got.1, Some(want.as_str()), "{}", case.id);
                }
                other => panic!("{}: bad expected reason: {other:?}", case.id),
            }
        }
        other => panic!("unknown construct type in {}: {other}", case.id),
    }
}

fn decode_region(region: &[(String, JsonValue)]) -> Result<AffectedRegion, AbstentionError> {
    let indices = index_set(region, "indices");
    let ids = id_set(region, "ids");
    let ranges = ranges_from_construct(region);
    let unproven = bool_field_optional(region, "unproven");
    AffectedRegion::new(indices, ids, ranges, unproven)
}

fn bool_field_optional(obj: &[(String, JsonValue)], key: &str) -> bool {
    match lookup(obj, key) {
        None | Some(JsonValue::Null) => false,
        Some(JsonValue::Bool(flag)) => *flag,
        Some(other) => panic!("{key} must be bool or null, got {other:?}"),
    }
}

fn array_field_or_empty(obj: &[(String, JsonValue)], key: &str) -> Vec<JsonValue> {
    match lookup(obj, key) {
        None | Some(JsonValue::Null) => Vec::new(),
        Some(JsonValue::Array(items)) => items.clone(),
        Some(other) => panic!("{key} must be array or null, got {other:?}"),
    }
}

fn index_set(obj: &[(String, JsonValue)], key: &str) -> Vec<PyInt> {
    let arr = array_field_or_empty(obj, key);
    arr.iter()
        .map(|item| match item {
            JsonValue::Number(n) => PyInt::Int(*n),
            other => panic!("{key} entry must be number, got {other:?}"),
        })
        .collect()
}

fn id_set(obj: &[(String, JsonValue)], key: &str) -> Vec<String> {
    let arr = array_field_or_empty(obj, key);
    arr.iter()
        .map(|item| match item {
            JsonValue::Str(s) => s.clone(),
            other => panic!("{key} entry must be string, got {other:?}"),
        })
        .collect()
}

fn ranges_from_construct(obj: &[(String, JsonValue)]) -> checks::abstention::RangesInput {
    let pairs = array_field_or_empty(obj, "ranges");
    let mut out = Vec::with_capacity(pairs.len());
    for item in pairs {
        let JsonValue::Array(two) = item else {
            panic!("range pair must be array");
        };
        if two.len() != 2 {
            panic!("range pair must have length 2");
        }
        let JsonValue::Number(a) = &two[0] else {
            panic!("range start must be number");
        };
        let JsonValue::Number(b) = &two[1] else {
            panic!("range end must be number");
        };
        out.push((PyInt::Int(*a), PyInt::Int(*b)));
    }
    checks::abstention::RangesInput::Sequence(out)
}

fn decode_events(construct: &[(String, JsonValue)], key: &str) -> Vec<EventValue> {
    let items = array_field(construct, key).expect(key);
    items
        .iter()
        .map(|item| {
            let wrapped = as_object(item, "event element").expect("event wrapper");
            EventValue::Mapping(event_mapping_from_construct(wrapped, "entries"))
        })
        .collect()
}

fn decode_findings(construct: &[(String, JsonValue)], key: &str) -> Vec<Finding> {
    let arr = array_field_or_empty(construct, key);
    arr.iter().map(decode_finding_object).collect()
}

fn decode_findings_optional(construct: &[(String, JsonValue)], key: &str) -> Option<Vec<Finding>> {
    match lookup(construct, key) {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Array(items)) => Some(items.iter().map(decode_finding_object).collect()),
        other => panic!("bad {key}: {other:?}"),
    }
}

fn decode_finding_object(value: &JsonValue) -> Finding {
    let obj = as_object(value, "finding").unwrap();
    let code = string_field(obj, "code").expect("code");
    let severity = match string_field(obj, "severity").expect("severity").as_str() {
        "FATAL" => Severity::Fatal,
        "ERROR" => Severity::Error,
        "WARNING" => Severity::Warning,
        "INFO" => Severity::Info,
        other => panic!("unknown severity {other}"),
    };
    let repairability = match string_field(obj, "repairability")
        .expect("repairability")
        .as_str()
    {
        "DETERMINISTIC" => Repairability::Deterministic,
        "LOSSY_EXPLICIT" | "LOSSYEXPLICIT" => Repairability::LossyExplicit,
        "MANUAL" => Repairability::Manual,
        "UNSUPPORTED" => Repairability::Unsupported,
        other => panic!("unknown repairability {other}"),
    };
    let message = string_field(obj, "message").expect("message");
    let src = object_field(obj, "source").expect("source");
    let path = string_field(src, "path").expect("path");
    let line = match lookup(src, "line") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Number(n)) => Some(SourceLine::Int(*n)),
        other => panic!("bad source.line: {other:?}"),
    };
    let record_id = match lookup(src, "record_id") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Str(s)) => Some(s.as_str()),
        other => panic!("bad record_id: {other:?}"),
    };
    let source = SourceRef::try_new(path.as_str(), line, record_id).expect("SourceRef");
    let related = array_field_or_empty(obj, "related_ids");
    let related_ids: Vec<String> = related
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => s.clone(),
            other => panic!("related_id must be str: {other:?}"),
        })
        .collect();
    let fingerprint = string_field(obj, "fingerprint").expect("fingerprint");
    let schema_version =
        string_field(obj, "schema_version").unwrap_or_else(|_| SCHEMA_VERSION.to_owned());
    let message_template = match lookup(obj, "message_template") {
        None | Some(JsonValue::Null) => PyValue::None,
        Some(JsonValue::Str(s)) => PyValue::string(s.clone()),
        other => panic!("bad message_template: {other:?}"),
    };
    let evidence = match lookup(obj, "evidence") {
        None | Some(JsonValue::Null) => PyValue::None,
        other => panic!("evidence must be null in vectors: {other:?}"),
    };
    Finding::try_new(FindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(repairability),
        message: PyValue::string(message),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(
            related_ids
                .into_iter()
                .map(PyValue::string)
                .collect::<Vec<_>>(),
        ),
        fingerprint: PyValue::string(fingerprint),
        schema_version: PyValue::string(schema_version),
        message_template,
        evidence,
    })
    .expect("Finding::try_new")
}

fn assert_abstention(expected_root: &[(String, JsonValue)], key: &str, got: &Abstention, id: &str) {
    let obj = object_field(expected_root, key).expect(key);
    let abstain = bool_field(obj, "abstain").expect("abstain");
    assert_eq!(got.abstain(), abstain, "{id}");
    let reasons = array_field(obj, "reasons").expect("reasons");
    assert_eq!(got.reasons().len(), reasons.len(), "{id}");
    for (i, item) in reasons.iter().enumerate() {
        let JsonValue::Str(want) = item else {
            panic!("{id}: reason[{i}] must be string");
        };
        assert_eq!(&got.reasons()[i], want, "{id}");
    }
}

fn assert_ambiguous(
    expected_root: &[(String, JsonValue)],
    key: &str,
    got: &AmbiguousEvents,
    id: &str,
) {
    let obj = object_field(expected_root, key).expect(key);
    let want_indices: BTreeSet<i64> = array_field(obj, "indices")
        .expect("indices")
        .iter()
        .map(|item| match item {
            JsonValue::Number(n) => *n,
            other => panic!("{id}: index must be number: {other:?}"),
        })
        .collect();
    assert_eq!(got.indices(), &want_indices, "{id}");
    let want_ids: BTreeSet<String> = array_field(obj, "ids")
        .expect("ids")
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => s.clone(),
            other => panic!("{id}: id must be string: {other:?}"),
        })
        .collect();
    assert_eq!(got.ids(), &want_ids, "{id}");
    let reasons = array_field(obj, "reasons").expect("reasons");
    assert_eq!(got.reasons().len(), reasons.len(), "{id}");
    for (i, item) in reasons.iter().enumerate() {
        let JsonValue::Str(want) = item else {
            panic!("{id}: reason[{i}] must be string");
        };
        assert_eq!(&got.reasons()[i], want, "{id}");
    }
}

fn assert_sorted_i64_set_matches(
    expected_root: &[(String, JsonValue)],
    key: &str,
    got: &BTreeSet<i64>,
    id: &str,
) {
    let arr = array_field(expected_root, key).expect(key);
    let want: BTreeSet<i64> = arr
        .iter()
        .map(|item| match item {
            JsonValue::Number(n) => *n,
            other => panic!("{id}: {key} entry must be number: {other:?}"),
        })
        .collect();
    assert_eq!(got, &want, "{id}");
}

fn event_mapping_from_construct(construct: &[(String, JsonValue)], key: &str) -> EventMapping {
    let arr = array_field(construct, key).expect(key);
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
