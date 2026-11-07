//! Package-surface parity for `sesslint.policy` (`__init__.py` re-exports) against Python vectors.
//!
//! Compares sorted [`checks::TOOL_KINDS`] membership to the vector (frozenset order is not a contract).

use checks::{must_abstain, Abstention, SAFE_SIDE_EFFECT, TOOL_KINDS};
use model::codes::{Repairability, Severity};
use model::events::{EventField, EventMapping, EventValue};
use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/policy/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/policy/manifest.json";
const EXPECTED_VECTOR_COUNT: usize = 5;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.policy";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_LIB_RS_SHA256: &str =
    "96e315021816ea1f6770bf0d97e3ca1600f5d695b3fa556c61b398b364746804";
const EXPECTED_VECTORS_SHA256: &str =
    "d842847fc7f091503cdf568021450fdf3d687c93a1c1a81fabdf2866714c9b54";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

#[test]
fn policy_package_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    // Match `generate` output: document is LF-only; worktrees may carry CRLF on Windows.
    let normalized = raw.replace("\r\n", "\n");

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest_manifest = manifest_raw.replace("\r\n", "\n");
    let manifest = parse_object_only(&manifest_manifest).expect("parse manifest.json");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
        "vectors_sha256 must match generator output"
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT,
        "manifest vector_count"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
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
        string_field(meta, "checks_lib_rs_sha256").expect("checks_lib_rs_sha256"),
        EXPECTED_LIB_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter()
            .any(|item| matches!(item, JsonValue::Str(s) if s.contains("frozenset"))),
        "expected frozenset order gap in known_parity_gaps"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "package_dunder_all" => {
            let names = string_array(&case.expected, "names").expect("names");
            assert_eq!(
                names,
                vec![
                    "SAFE_SIDE_EFFECT",
                    "TOOL_KINDS",
                    "Abstention",
                    "must_abstain"
                ],
                "{}",
                case.id
            );
        }
        "package_safe_side_effect" => {
            assert_eq!(SAFE_SIDE_EFFECT, "none", "{}", case.id);
            assert_eq!(
                string_field(&case.expected, "value").expect("value"),
                SAFE_SIDE_EFFECT,
                "{}",
                case.id
            );
        }
        "package_tool_kinds_membership" => {
            let want = string_array(&case.expected, "sorted_members").expect("sorted_members");
            let mut got: Vec<&str> = TOOL_KINDS.to_vec();
            got.sort_unstable();
            assert_eq!(got, want, "{}", case.id);
            assert!(TOOL_KINDS.contains(&"tool_call"), "{}", case.id);
            assert!(TOOL_KINDS.contains(&"tool_use"), "{}", case.id);
            assert!(TOOL_KINDS.contains(&"tool_result"), "{}", case.id);
        }
        "package_must_abstain" => {
            let findings = decode_findings(&case.construct, "findings");
            let events = decode_events(&case.construct, "events");
            let allow = bool_field(&case.construct, "allow_unknown_side_effects")
                .expect("allow_unknown_side_effects");
            let got = must_abstain(&findings, &events, allow).expect("must_abstain");
            assert_abstention(&case.expected, "abstention", &got, &case.id);
        }
        other => panic!("{}: unknown construct type {other}", case.id),
    }
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

fn event_mapping_from_construct(construct: &[(String, JsonValue)], key: &str) -> EventMapping {
    let nested = array_field(construct, key).expect(key);
    mapping_array_to_event_mapping(&nested)
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

fn decode_findings(construct: &[(String, JsonValue)], key: &str) -> Vec<Finding> {
    let arr = array_field_or_empty(construct, key);
    arr.iter().map(decode_finding_object).collect()
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

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

// --- minimal JSON (vectors.json) ---

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

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    Ok(as_object(&value, "root")?.to_vec())
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
    let cases: Result<Vec<VectorCase>, _> = items.iter().map(parse_vector_case).collect();
    Ok(ParsedDocument {
        meta: root.clone(),
        cases: cases?,
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn array_field_or_empty(obj: &[(String, JsonValue)], key: &str) -> Vec<JsonValue> {
    match lookup(obj, key) {
        None | Some(JsonValue::Null) => Vec::new(),
        Some(JsonValue::Array(items)) => items.clone(),
        Some(other) => panic!("{key} must be array or null, got {other:?}"),
    }
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let JsonValue::Str(s) = item else {
            return Err(ParseError {
                message: format!("{key} entries must be strings"),
            });
        };
        out.push(s);
    }
    Ok(out)
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
