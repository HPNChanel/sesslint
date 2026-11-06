//! Module-surface parity for `sesslint.checks.graph` against pinned Python vectors.
//!
//! Compares constants, fingerprints, confinement helpers, and graph checks that return
//! no findings (finding-producing paths are recorded as known parity gaps).

use checks::graph::{
    self, Confinement, GraphEndpoint, GraphScalar, RejectedDecoy, CONF_SEG_KEY, MAX_GRAPH_FINDINGS,
    MAX_MEMBER_SAMPLE_SIZE,
};
use model::events::{EventField, EventMapping, EventValue};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/checks.graph/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/checks.graph/manifest.json";
const EXPECTED_VECTOR_COUNT: usize = 20;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.checks.graph";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_GRAPH_RS_SHA256: &str =
    "3bdd9fa51178eb7bc7ce232cdaa01ce3b3fff5a43b7face1458e03bf1210f382";
const EXPECTED_VECTORS_SHA256: &str =
    "b77e32da294651994f6a8634cb7062a4a73fd8c94bda9abab1d7b03fafd69bf2";

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
fn graph_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest_normalized = manifest_raw.replace("\r\n", "\n");
    let manifest = parse_object_only(&manifest_normalized).expect("parse manifest.json");
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
        string_field(meta, "checks_graph_rs_sha256").expect("checks_graph_rs_sha256"),
        EXPECTED_GRAPH_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter().any(|item| matches!(item, JsonValue::Str(s) if s.contains("FINGERPRINT_CODEC_UNAVAILABLE"))),
        "expected fingerprint codec gap in known_parity_gaps"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_dunder_all" => {
            let names = string_array(&case.expected, "names").expect("names");
            assert_eq!(names.len(), graph::ALL.len(), "{}", case.id);
            for (got, exp) in names.iter().zip(graph::ALL.iter()) {
                assert_eq!(got, *exp, "{}", case.id);
            }
        }
        "module_constants" => {
            assert_eq!(
                i64_field(&case.expected, "MAX_GRAPH_FINDINGS").expect("MAX_GRAPH_FINDINGS"),
                MAX_GRAPH_FINDINGS as i64,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(&case.expected, "MAX_MEMBER_SAMPLE_SIZE").expect("MAX_MEMBER_SAMPLE_SIZE"),
                MAX_MEMBER_SAMPLE_SIZE as i64,
                "{}",
                case.id
            );
        }
        "compute_graph_fingerprint" => {
            let code = string_field(&case.construct, "code").expect("code");
            let id_specs = array_field(&case.construct, "ids").expect("ids");
            let scalars: Vec<GraphScalar> = id_specs
                .iter()
                .map(|spec| decode_graph_scalar(spec, &case.id))
                .collect();
            let got = graph::compute_graph_fingerprint(&code, scalars);
            assert_eq!(
                got,
                string_field(&case.expected, "fingerprint").expect("fingerprint"),
                "{}",
                case.id
            );
        }
        "is_qualifying_parent_candidate" => {
            let events = decode_event_list(&case.construct, "events");
            let candidate = event_value_from_construct(object_field(&case.construct, "candidate").expect("candidate"));
            let child = event_value_from_construct(object_field(&case.construct, "child").expect("child"));
            let missing = optional_string_construct(&case.construct, "missing_parent_id");
            let (q, reason) = graph::is_qualifying_parent_candidate(
                &candidate,
                &child,
                &events,
                missing.as_deref(),
            );
            assert_eq!(
                q,
                bool_field(&case.expected, "qualifies").expect("qualifies"),
                "{}",
                case.id
            );
            assert_eq!(
                reason,
                string_field(&case.expected, "reason").expect("reason"),
                "{}",
                case.id
            );
        }
        "find_qualifying_parent_candidates" => {
            let events = decode_event_list(&case.construct, "events");
            let child = event_value_from_construct(object_field(&case.construct, "child").expect("child"));
            let target_idx = usize_field(&case.construct, "target_idx").expect("target_idx");
            let missing = optional_string_construct(&case.construct, "missing_parent_id");
            let (qi, rej, conf, reason) = graph::find_qualifying_parent_candidates(
                &events,
                &child,
                target_idx,
                missing.as_deref(),
            );
            assert_eq!(
                qi,
                usize_array(&case.expected, "qualifying_indices").expect("qualifying_indices"),
                "{}",
                case.id
            );
            assert_rejected_decoys(&case.expected, "rejected_decoys", &rej, &case.id);
            assert_confinement(&case.expected, "confinement", &conf, &case.id);
            assert_eq!(
                reason,
                string_field(&case.expected, "reason").expect("reason"),
                "{}",
                case.id
            );
        }
        "same_compaction_segment" => {
            let events = decode_event_list(&case.construct, "events");
            let a = decode_graph_endpoint(object_field(&case.construct, "endpoint_a").expect("endpoint_a"), &events);
            let b = decode_graph_endpoint(object_field(&case.construct, "endpoint_b").expect("endpoint_b"), &events);
            let got = graph::same_compaction_segment(&events, a, b);
            assert_eq!(
                got,
                bool_field(&case.expected, "same").expect("same"),
                "{}",
                case.id
            );
        }
        "check_missing_parent" | "check_cycles" | "check_components" | "check_heads" | "check_graph" => {
            let events = decode_event_list(&case.construct, "events");
            let source_path = optional_string_construct(&case.construct, "source_path")
                .unwrap_or_else(|| "<canonical>".to_owned());
            assert_eq!(
                i64_field(&case.expected, "findings_count").expect("findings_count"),
                0,
                "{}",
                case.id
            );
            let empty = match kind.as_str() {
                "check_missing_parent" => graph::check_missing_parent(
                    &events,
                    Some(source_path.as_str()),
                    None,
                    None,
                    None,
                ),
                "check_cycles" => graph::check_cycles(
                    &events,
                    Some(source_path.as_str()),
                    None,
                    None,
                    None,
                ),
                "check_components" => graph::check_components(
                    &events,
                    Some(source_path.as_str()),
                    None,
                    None,
                    None,
                ),
                "check_heads" => graph::check_heads(
                    &events,
                    Some(source_path.as_str()),
                    None,
                    None,
                    None,
                ),
                "check_graph" => graph::check_graph(
                    &events,
                    Some(source_path.as_str()),
                    None,
                    None,
                ),
                _ => unreachable!(),
            };
            let got = empty.unwrap_or_else(|err| panic!("{}: {err}", case.id));
            assert!(got.is_empty(), "{}: expected no findings", case.id);
        }
        other => panic!("{}: unknown construct type {other}", case.id),
    }
}

fn decode_graph_scalar(value: &JsonValue, case_id: &str) -> GraphScalar {
    let obj = as_object(value, "graph scalar").unwrap_or_else(|e| panic!("{case_id}: {e}"));
    match string_field(obj, "kind").expect("scalar kind").as_str() {
        "str" => GraphScalar::from(string_field(obj, "v").expect("v").as_str()),
        "bool" => GraphScalar::from(bool_field(obj, "v").expect("v")),
        "int" => GraphScalar::from(i64_field(obj, "v").expect("v")),
        other => panic!("{case_id}: unknown scalar kind {other}"),
    }
}

fn decode_graph_endpoint<'a>(
    obj: &[(String, JsonValue)],
    events: &'a [EventValue],
) -> GraphEndpoint<'a> {
    match string_field(obj, "kind").expect("endpoint kind").as_str() {
        "seq" => GraphEndpoint::Seq(i64_field(obj, "v").expect("v")),
        "event" => {
            let idx = usize_field(obj, "index").expect("index");
            GraphEndpoint::Event(&events[idx])
        }
        other => panic!("unknown endpoint kind {other}"),
    }
}

fn assert_rejected_decoys(
    expected_root: &[(String, JsonValue)],
    key: &str,
    got: &[RejectedDecoy],
    case_id: &str,
) {
    let arr = array_field(expected_root, key).expect(key);
    assert_eq!(got.len(), arr.len(), "{case_id}");
    for (i, item) in arr.iter().enumerate() {
        let obj = as_object(item, "decoy").unwrap_or_else(|e| panic!("{case_id}: {e}"));
        assert_eq!(got[i].id, string_field(obj, "id").expect("id"), "{case_id}");
        assert_eq!(
            got[i].index,
            usize_field(obj, "index").expect("index"),
            "{case_id}"
        );
        assert_eq!(
            got[i].reason,
            string_field(obj, "reason").expect("reason"),
            "{case_id}"
        );
    }
}

fn assert_confinement(
    expected_root: &[(String, JsonValue)],
    key: &str,
    got: &Confinement,
    case_id: &str,
) {
    let obj = object_field(expected_root, key).expect(key);
    assert_eq!(
        got.branch,
        bool_field(obj, "branch").expect("branch"),
        "{case_id}"
    );
    assert_eq!(
        got.segment,
        bool_field(obj, CONF_SEG_KEY).expect(CONF_SEG_KEY),
        "{case_id}"
    );
}

fn optional_string_construct(
    construct: &[(String, JsonValue)],
    key: &str,
) -> Option<String> {
    match lookup(construct, key) {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Str(s)) => Some(s.clone()),
        Some(other) => panic!("{key} must be null or string, got {other:?}"),
    }
}

fn decode_event_list(construct: &[(String, JsonValue)], key: &str) -> Vec<EventValue> {
    let items = array_field(construct, key).expect(key);
    items
        .iter()
        .map(|item| {
            let wrapped = as_object(item, "event element").expect("event wrapper");
            EventValue::Mapping(event_mapping_from_construct(wrapped, "entries"))
        })
        .collect()
}

fn event_value_from_construct(obj: &[(String, JsonValue)]) -> EventValue {
    EventValue::Mapping(event_mapping_from_construct(obj, "entries"))
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

fn usize_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<usize>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let JsonValue::Number(n) = item else {
            return Err(ParseError {
                message: format!("{key} entries must be numbers"),
            });
        };
        out.push(usize::try_from(n).map_err(|_| ParseError {
            message: format!("{key} entry must fit usize"),
        })?);
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
