//! Dispositions for the 14 `def test_` functions in pinned `tests/cli/test_mcp.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (243 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. Recorded outcomes are hand-parsed from
//! `mcp_server/vectors.json`. Expected values are the pinned assertions.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 14;
const MCP_VECTOR_COUNT: usize = 24;
const COVERED_COUNT: usize = 6;
const NOT_APPLICABLE_COUNT: usize = 8;
const VECTORS_REL: &str = "parity/vectors/mcp_server/vectors.json";

/// Pinned `sesslint.mcp_server.PROTOCOL_VERSION`.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Ordered `TOOLS` names from pinned `test_tools_list_is_static`.
const TOOL_NAMES: [&str; 3] = ["sesslint_check", "sesslint_precheck", "sesslint_scan"];

/// Published coverage leaves these `not_applicable`. Do not upgrade them.
const MUST_STAY_NOT_APPLICABLE: &[&str] = &[
    "test_tools_call_check_reports_findings_as_result",
    "test_tools_call_precheck_gate",
    "test_tools_call_scan_directory",
    "test_full_recorded_sequence_through_serve",
    "test_deterministic_responses",
    "test_no_values_leak_in_tool_results",
];

/// `covered` names one vector id in `mcp_server/vectors.json` whose construct is
/// the same function and the same success or failure mode as that entire pinned
/// test. `not_applicable` is a mode no single vector records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Covered {
        vector_id: &'static str,
        needles: &'static [&'static str],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    Row {
        name: "test_initialize_handshake",
        disposition: Disposition::Covered {
            vector_id: "initialize_handshake",
            needles: &[
                "\"id\": 1",
                "\"protocolVersion\": \"2025-06-18\"",
                "\"serverInfo\": {\"name\": \"sesslint\"",
                "\"capabilities\": {\"tools\":",
            ],
        },
    },
    Row {
        name: "test_initialized_notification_is_dropped",
        disposition: Disposition::Covered {
            vector_id: "initialized_notification",
            needles: &[
                "\"method\": \"notifications/initialized\"",
                "\"type\": \"handle_line\"",
                "\"kind\": \"none\"",
            ],
        },
    },
    Row {
        name: "test_tools_list_returns_three_readonly_tools",
        disposition: Disposition::Covered {
            vector_id: "tools_list",
            needles: &[
                "\"id\": 2",
                "\"name\": \"sesslint_check\"",
                "\"name\": \"sesslint_precheck\"",
                "\"name\": \"sesslint_scan\"",
                "\"type\": \"object\"",
                "\"required\": [\"path\"]",
            ],
        },
    },
    // Pinned test reads TOOLS in order. module_constants.tool_names is that list.
    Row {
        name: "test_tools_list_is_static",
        disposition: Disposition::Covered {
            vector_id: "module_constants",
            needles: &[
                "\"type\": \"module_constants\"",
                "        \"tool_names\": [\n          \"sesslint_check\",\n          \"sesslint_precheck\",\n          \"sesslint_scan\"\n        ]",
            ],
        },
    },
    Row {
        name: "test_tools_call_check_reports_findings_as_result",
        disposition: Disposition::NotApplicable(
            "sesslint_check success needs sesslint.api behind the MCP backend seam",
        ),
    },
    Row {
        name: "test_tools_call_precheck_gate",
        disposition: Disposition::NotApplicable(
            "sesslint_precheck success needs sesslint.precheck behind the MCP backend seam",
        ),
    },
    Row {
        name: "test_tools_call_scan_directory",
        disposition: Disposition::NotApplicable(
            "sesslint_scan success needs sesslint.api behind the MCP backend seam",
        ),
    },
    Row {
        name: "test_missing_path_is_iserror_result_not_protocol_error",
        disposition: Disposition::Covered {
            vector_id: "missing_path",
            needles: &["\"id\": 6", "\"isError\": true", "io-error"],
        },
    },
    // invalid_bogus_tool, invalid_missing_path, invalid_unknown_arg, and
    // invalid_bad_profile each record one case. None is this entire test.
    Row {
        name: "test_invalid_params_produce_error_objects",
        disposition: Disposition::NotApplicable(
            "four invalid-params handle_line cases; no one vector is that entire test",
        ),
    },
    // unknown_method (-32601) and malformed_json (-32700) are different modes.
    Row {
        name: "test_unknown_method_and_malformed_json",
        disposition: Disposition::NotApplicable(
            "unknown-method and parse-error are two handle_line failure modes",
        ),
    },
    Row {
        name: "test_ping_responds_empty_result",
        disposition: Disposition::Covered {
            vector_id: "ping",
            needles: &["\"id\": 8", "\"result\": {}"],
        },
    },
    // serve_oversized_then_ping is a different serve mode.
    Row {
        name: "test_full_recorded_sequence_through_serve",
        disposition: Disposition::NotApplicable(
            "recorded serve sequence calls sesslint_precheck through the backend seam",
        ),
    },
    // deterministic_tools_list records kind "equal" only, not pinned response bytes.
    Row {
        name: "test_deterministic_responses",
        disposition: Disposition::NotApplicable(
            "deterministic_tools_list checks Rust self-equality and does not record pinned Python response bytes",
        ),
    },
    Row {
        name: "test_no_values_leak_in_tool_results",
        disposition: Disposition::NotApplicable(
            "tool-result scan needs sesslint_check success behind the MCP backend seam",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_initialize_handshake",
    "test_initialized_notification_is_dropped",
    "test_tools_list_returns_three_readonly_tools",
    "test_tools_list_is_static",
    "test_tools_call_check_reports_findings_as_result",
    "test_tools_call_precheck_gate",
    "test_tools_call_scan_directory",
    "test_missing_path_is_iserror_result_not_protocol_error",
    "test_invalid_params_produce_error_objects",
    "test_unknown_method_and_malformed_json",
    "test_ping_responds_empty_result",
    "test_full_recorded_sequence_through_serve",
    "test_deterministic_responses",
    "test_no_values_leak_in_tool_results",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("mcp_server vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_mcp_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    let mut covered_ids = BTreeSet::new();
    for row in ROWS {
        assert!(
            names.insert(row.name),
            "duplicate pinned test name {}",
            row.name
        );
        match row.disposition {
            Disposition::Covered { vector_id, needles } => {
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert!(!needles.is_empty(), "{}", row.name);
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                for needle in needles {
                    assert!(!needle.is_empty(), "{}", row.name);
                }
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(!reason.is_empty(), "{}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, COVERED_COUNT);
    assert_eq!(not_applicable, NOT_APPLICABLE_COUNT);
    assert_eq!(
        covered_ids.into_iter().collect::<Vec<_>>(),
        [
            "initialize_handshake",
            "initialized_notification",
            "missing_path",
            "module_constants",
            "ping",
            "tools_list",
        ]
    );
    for name in MUST_STAY_NOT_APPLICABLE {
        let row = ROWS
            .iter()
            .find(|row| row.name == *name)
            .unwrap_or_else(|| panic!("missing locked row {name}"));
        assert!(
            matches!(row.disposition, Disposition::NotApplicable(_)),
            "{name} must stay not_applicable"
        );
    }
}

#[test]
fn covered_vector_ids_are_present_in_mcp_server_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "mcp_server vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.mcp_server\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), MCP_VECTOR_COUNT);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id);
        let evidence = assert_entire_pinned_test(row.name, slice);
        for needle in needles {
            assert!(
                evidence.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}

fn assert_entire_pinned_test(name: &str, slice: &str) -> String {
    match name {
        "test_initialize_handshake" => assert_initialize(slice),
        "test_initialized_notification_is_dropped" => assert_notification(slice),
        "test_tools_list_returns_three_readonly_tools" => assert_tools_list(slice),
        "test_tools_list_is_static" => assert_tools_static(slice),
        "test_missing_path_is_iserror_result_not_protocol_error" => assert_missing_path(slice),
        "test_ping_responds_empty_result" => assert_ping(slice),
        other => panic!("covered row {other} has no pinned checker"),
    }
}

fn assert_initialize(slice: &str) -> String {
    let construct = parse_field_object(slice, "construct");
    assert_eq!(str_field(&construct, "type"), "handle_line");
    let request = parse_b64_object(&construct, "raw_b64");
    assert_eq!(str_field(&request, "jsonrpc"), "2.0");
    assert_eq!(i64_field(&request, "id"), 1);
    assert_eq!(str_field(&request, "method"), "initialize");
    let params = object(&request, "params");
    assert_eq!(str_field(params, "protocolVersion"), PROTOCOL_VERSION);
    assert!(object(params, "capabilities").is_empty());
    let client = object(params, "clientInfo");
    assert_eq!(str_field(client, "name"), "test");
    assert_eq!(str_field(client, "version"), "0");

    let (text, response) = decode_response(slice);
    assert_eq!(i64_field(&response, "id"), 1);
    let result = object(&response, "result");
    assert_eq!(str_field(result, "protocolVersion"), PROTOCOL_VERSION);
    assert_eq!(str_field(object(result, "serverInfo"), "name"), "sesslint");
    let capabilities = object(result, "capabilities");
    let keys: Vec<&str> = capabilities.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, ["tools"]);
    text
}

fn assert_notification(slice: &str) -> String {
    let construct = parse_field_object(slice, "construct");
    assert_eq!(str_field(&construct, "type"), "handle_line");
    let request_text = decode_b64_utf8(str_field(&construct, "raw_b64"));
    let request = parse_object_owned(&request_text);
    assert_eq!(str_field(&request, "jsonrpc"), "2.0");
    assert_eq!(str_field(&request, "method"), "notifications/initialized");
    assert!(!has_key(&request, "id"));
    let expected = parse_field_object(slice, "expected");
    assert_eq!(expected.len(), 1);
    assert_eq!(str_field(&expected, "kind"), "none");
    format!("{request_text}{slice}")
}

fn assert_tools_list(slice: &str) -> String {
    let construct = parse_field_object(slice, "construct");
    assert_eq!(str_field(&construct, "type"), "handle_line");
    let request = parse_b64_object(&construct, "raw_b64");
    assert_eq!(i64_field(&request, "id"), 2);
    assert_eq!(str_field(&request, "method"), "tools/list");
    assert!(!has_key(&request, "params"));

    let (text, response) = decode_response(slice);
    assert_eq!(i64_field(&response, "id"), 2);
    let tools = array(object(&response, "result"), "tools");
    assert_eq!(tools.len(), TOOL_NAMES.len());
    let mut names = BTreeSet::new();
    for tool_value in tools {
        let tool = as_object(tool_value);
        assert!(names.insert(str_field(tool, "name")), "duplicate tool name");
        let schema = object(tool, "inputSchema");
        assert_eq!(str_field(schema, "type"), "object");
        let required = array(schema, "required");
        assert!(required
            .iter()
            .any(|item| matches!(item, JsonValue::Str(text) if text == "path")));
    }
    assert_eq!(names, BTreeSet::from(TOOL_NAMES));
    text
}

fn assert_tools_static(slice: &str) -> String {
    let construct = parse_field_object(slice, "construct");
    assert_eq!(str_field(&construct, "type"), "module_constants");
    let expected = parse_field_object(slice, "expected");
    assert_eq!(string_array(&expected, "tool_names"), TOOL_NAMES);
    slice.to_string()
}

fn assert_missing_path(slice: &str) -> String {
    let construct = parse_field_object(slice, "construct");
    assert_eq!(str_field(&construct, "type"), "handle_line");
    let request = parse_b64_object(&construct, "raw_b64");
    assert_eq!(i64_field(&request, "id"), 6);
    assert_eq!(str_field(&request, "method"), "tools/call");
    let params = object(&request, "params");
    assert_eq!(str_field(params, "name"), "sesslint_check");
    assert_eq!(str_field(object(params, "arguments"), "path"), "nope.jsonl");

    let (text, response) = decode_response(slice);
    assert!(!has_key(&response, "error"));
    let result = object(&response, "result");
    assert!(bool_field(result, "isError"));
    let content = array(result, "content");
    let first = content.first().expect("tool result content");
    assert!(str_field(as_object(first), "text").contains("io-error"));
    text
}

fn assert_ping(slice: &str) -> String {
    let construct = parse_field_object(slice, "construct");
    assert_eq!(str_field(&construct, "type"), "handle_line");
    let request = parse_b64_object(&construct, "raw_b64");
    assert_eq!(i64_field(&request, "id"), 8);
    assert_eq!(str_field(&request, "method"), "ping");
    let (text, response) = decode_response(slice);
    assert!(object(&response, "result").is_empty());
    text
}

fn decode_response(slice: &str) -> (String, Vec<(String, JsonValue)>) {
    let expected = parse_field_object(slice, "expected");
    assert_eq!(str_field(&expected, "kind"), "bytes");
    let text = decode_b64_utf8(str_field(&expected, "b64"));
    let response = parse_object_owned(&text);
    (text, response)
}

fn parse_b64_object(obj: &[(String, JsonValue)], key: &str) -> Vec<(String, JsonValue)> {
    parse_object_owned(&decode_b64_utf8(str_field(obj, key)))
}

fn decode_b64_utf8(encoded: &str) -> String {
    let bytes = decode_base64(encoded).unwrap_or_else(|err| panic!("base64: {err}"));
    String::from_utf8(bytes).unwrap_or_else(|err| panic!("recorded outcome is not utf-8: {err}"))
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    fn sextet(byte: u8) -> Result<u32, String> {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(format!("invalid base64 byte {byte}")),
        };
        Ok(u32::from(value))
    }

    if !input.is_ascii() {
        return Err("base64 is not ascii".to_string());
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length is not a multiple of 4".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let (first, second, third, fourth) = (chunk[0], chunk[1], chunk[2], chunk[3]);
        let third_pad = third == b'=';
        let fourth_pad = fourth == b'=';
        if first == b'=' || second == b'=' || (third_pad && !fourth_pad) {
            return Err("invalid base64 padding".to_string());
        }
        let a = sextet(first)?;
        let b = sextet(second)?;
        let c = if third_pad { 0 } else { sextet(third)? };
        let d = if fourth_pad { 0 } else { sextet(fourth)? };
        out.push(u8::try_from((a << 2) | (b >> 4)).expect("base64 byte"));
        if !third_pad {
            out.push(u8::try_from(((b & 0x0f) << 4) | (c >> 2)).expect("base64 byte"));
        }
        if !fourth_pad {
            out.push(u8::try_from(((c & 0x03) << 6) | d).expect("base64 byte"));
        }
    }
    Ok(out)
}

fn field_source<'a>(slice: &'a str, key: &str) -> &'a str {
    let marker = format!("\"{key}\"");
    let pos = slice
        .find(&marker)
        .unwrap_or_else(|| panic!("missing JSON field {key}"));
    let after_key = slice[pos + marker.len()..].trim_start();
    assert!(after_key.starts_with(':'), "{key} is not a JSON field");
    after_key[1..].trim_start()
}

fn parse_field_object(slice: &str, key: &str) -> Vec<(String, JsonValue)> {
    let (value, _) =
        parse_value(field_source(slice, key)).unwrap_or_else(|err| panic!("{key}: {err}"));
    match value {
        JsonValue::Object(obj) => obj,
        _ => panic!("{key} must be an object"),
    }
}

fn parse_object_owned(input: &str) -> Vec<(String, JsonValue)> {
    let (value, rest) = parse_value(input.trim_start()).unwrap_or_else(|err| panic!("json: {err}"));
    if !rest.trim().is_empty() {
        panic!("trailing JSON");
    }
    match value {
        JsonValue::Object(obj) => obj,
        _ => panic!("expected object"),
    }
}

fn object<'a>(pairs: &'a [(String, JsonValue)], key: &str) -> &'a [(String, JsonValue)] {
    match pairs.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Object(obj))) => obj,
        Some(_) => panic!("{key} must be an object"),
        None => panic!("missing {key}"),
    }
}

fn as_object(value: &JsonValue) -> &[(String, JsonValue)] {
    match value {
        JsonValue::Object(obj) => obj,
        _ => panic!("expected object"),
    }
}

fn array<'a>(pairs: &'a [(String, JsonValue)], key: &str) -> &'a [JsonValue] {
    match pairs.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Array(items))) => items,
        Some(_) => panic!("{key} must be an array"),
        None => panic!("missing {key}"),
    }
}

fn string_array<'a>(pairs: &'a [(String, JsonValue)], key: &str) -> Vec<&'a str> {
    array(pairs, key)
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => text.as_str(),
            _ => panic!("{key} items must be strings"),
        })
        .collect()
}

fn str_field<'a>(pairs: &'a [(String, JsonValue)], key: &str) -> &'a str {
    match pairs.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Str(text))) => text,
        Some(_) => panic!("{key} must be a string"),
        None => panic!("missing {key}"),
    }
}

fn i64_field(pairs: &[(String, JsonValue)], key: &str) -> i64 {
    match pairs.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Number(value))) => *value,
        Some(_) => panic!("{key} must be a number"),
        None => panic!("missing {key}"),
    }
}

fn bool_field(pairs: &[(String, JsonValue)], key: &str) -> bool {
    match pairs.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(value))) => *value,
        Some(_) => panic!("{key} must be a bool"),
        None => panic!("missing {key}"),
    }
}

fn has_key(pairs: &[(String, JsonValue)], key: &str) -> bool {
    pairs.iter().any(|(name, _)| name == key)
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".to_string(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(text, rest)| (JsonValue::Str(text), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".to_string(),
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
            message: "invalid number".to_string(),
        });
    }
    let start_digits = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx < bytes.len() && matches!(bytes[idx], b'.' | b'e' | b'E') {
        return Err(ParseError {
            message: "non-integer JSON number".to_string(),
        });
    }
    let magnitude: i64 = input[start_digits..idx].parse().map_err(|_| ParseError {
        message: "number overflow".to_string(),
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
                message: "expected , or ] in array".to_string(),
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
                message: "expected : in object".to_string(),
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
                message: "expected , or } in object".to_string(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".to_string(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".to_string(),
        })?;
        match ch {
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".to_string(),
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
                                message: "bad \\u escape".to_string(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".to_string(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode scalar".to_string(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".to_string(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
