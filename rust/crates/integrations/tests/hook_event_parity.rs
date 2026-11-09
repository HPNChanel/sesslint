//! Byte-exact parity for `sesslint.hook_event` against pinned Python vectors.

use integrations::hook_event::{
    classify_checked, planned_check, run_hook, CheckedFinding, HookError, HookResult, ALL,
    CHECK_FILE_UNAVAILABLE, HOOK_RESULT_SCHEMA, MAX_END_HOOK_TRANSCRIPT_BYTES,
    MAX_FAST_HOOK_TRANSCRIPT_BYTES, MAX_HOOK_PAYLOAD_BYTES, SHORT_HASH_UNAVAILABLE,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_ROOT_REL: &str = "../../parity/vectors/hook_event";
const VECTORS_REL: &str = "../../parity/vectors/hook_event/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/hook_event/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/hook_event/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 22;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.hook_event";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_HOOK_PY_SHA256: &str =
    "e8edbee94875815b747b77d4a62ac682c7492e90fa4ce4478fa18f4851437cd9";
const EXPECTED_HOOK_RS_SHA256: &str =
    "fc8d9a39675e377e1356da8afb4d6b18ed77035d371e4a22fe19bbd750e36fb9";
const EXPECTED_VECTORS_SHA256: &str =
    "1cc96a9c66ce05d0037197624ede0b904e53b02be9b05b45b544ac4fb25c79ee";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_ROOT_REL)
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

#[test]
fn hook_event_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    let prov_gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, "GAP-hook-event-short-hash")),
        "PROVENANCE must document short_hash gap"
    );
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, "GAP-hook-event-check-file")),
        "PROVENANCE must document check_file gap"
    );

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
        assert_vector_case(case);
    }

    assert_rust_short_hash_seam();
    assert_rust_check_file_seam();
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
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
        string_field(meta, "hook_event_py_sha256").expect("hook_event_py_sha256"),
        EXPECTED_HOOK_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "hook_event_rs_sha256").expect("hook_event_rs_sha256"),
        EXPECTED_HOOK_RS_SHA256,
        "hook_event.rs hash must remain pinned"
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, "GAP-hook-event-short-hash")),
        "expected short_hash gap"
    );
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, "GAP-hook-event-check-file")),
        "expected check_file gap"
    );
}

fn assert_vector_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "planned_check" => assert_planned_check(case),
        "classify_checked" => assert_classify_checked(case),
        "run_hook" => assert_run_hook(case),
        other => panic!("{}: unsupported construct type {other}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "hook_result_schema").expect("hook_result_schema"),
        HOOK_RESULT_SCHEMA
    );
    assert_eq!(
        u64::try_from(
            i64_field(&case.expected, "max_hook_payload_bytes").expect("max_hook_payload_bytes")
        )
        .expect("max_hook_payload_bytes fits u64"),
        MAX_HOOK_PAYLOAD_BYTES
    );
    assert_eq!(
        u64::try_from(
            i64_field(&case.expected, "max_fast_hook_transcript_bytes")
                .expect("max_fast_hook_transcript_bytes")
        )
        .expect("max_fast_hook_transcript_bytes fits u64"),
        MAX_FAST_HOOK_TRANSCRIPT_BYTES
    );
    assert_eq!(ALL.len(), 5);
    assert!(ALL.contains(&"run_hook"));
    let _ = MAX_END_HOOK_TRANSCRIPT_BYTES;
    let _ = case.id;
}

fn assert_planned_check(case: &VectorCase) {
    let event = string_field(&case.construct, "event").expect("event");
    let profile = optional_string_field(&case.construct, "profile");
    let format = optional_string_field(&case.construct, "format");
    let got = planned_check(&event, profile.as_deref(), format.as_deref());
    assert_eq!(
        got.profile,
        string_field(&case.expected, "profile").expect("profile")
    );
    assert_optional_string(&case.expected, "format", got.format);
    assert_select_field(&case.expected, got.select);
    assert_eq!(
        got.max_file_bytes,
        u64::try_from(i64_field(&case.expected, "max_file_bytes").expect("max_file_bytes"))
            .expect("max_file_bytes fits u64"),
        "max_file_bytes mismatch for {}",
        case.id
    );
}

fn assert_select_field(expected: &[(String, JsonValue)], got: Option<&[&str]>) {
    match array_field_optional(expected, "select") {
        None => assert_eq!(got, None, "select must be absent"),
        Some(items) => {
            let want: Vec<String> = items
                .iter()
                .map(|item| match item {
                    JsonValue::Str(text) => text.clone(),
                    _ => panic!("select items must be strings"),
                })
                .collect();
            let got_codes: Option<Vec<String>> =
                got.map(|slice| slice.iter().map(|code| (*code).to_owned()).collect());
            assert_eq!(got_codes, Some(want));
        }
    }
}

fn assert_classify_checked(case: &VectorCase) {
    let event = string_field(&case.construct, "event").expect("event");
    let session_id = optional_string_field(&case.construct, "session_id");
    let fail_on = optional_string_field(&case.construct, "fail_on");
    let limitation = string_field(&case.construct, "limitation").expect("limitation");
    let finding_rows = array_field(&case.construct, "findings").expect("findings");
    let owned_findings: Vec<(String, String)> = finding_rows
        .iter()
        .map(|row| {
            let obj = as_object(row, "finding").expect("finding object");
            (
                string_field_obj(obj, "code").expect("code"),
                string_field_obj(obj, "severity").expect("severity"),
            )
        })
        .collect();
    let findings: Vec<CheckedFinding<'_>> = owned_findings
        .iter()
        .map(|(code, severity)| CheckedFinding {
            code: code.as_str(),
            severity: severity.as_str(),
        })
        .collect();
    let result = classify_checked(
        &event,
        session_id.as_deref(),
        fail_on.as_deref(),
        &limitation,
        &findings,
    );
    assert_hook_result_payload(case.id.as_str(), &result, &case.expected);
}

fn assert_run_hook(case: &VectorCase) {
    let event = string_field(&case.construct, "event").expect("event");
    let profile = optional_string_field(&case.construct, "profile");
    let format = optional_string_field(&case.construct, "format");
    let fail_on = optional_string_field(&case.construct, "fail_on");
    let data = run_hook_payload(&case.construct);
    let result = run_hook(
        &event,
        &data,
        profile.as_deref(),
        format.as_deref(),
        fail_on.as_deref(),
    )
    .unwrap_or_else(|err| panic!("{}: run_hook must succeed on skip path, got {err}", case.id));
    assert_hook_result_payload(case.id.as_str(), &result, &case.expected);
}

fn run_hook_payload(construct: &[(String, JsonValue)]) -> Vec<u8> {
    if let Some(pattern) = optional_string_field(construct, "payload_pattern") {
        return match pattern.as_str() {
            "oversized_open_brace" => vec![b'{'; (MAX_HOOK_PAYLOAD_BYTES as usize) + 1],
            other => panic!("unknown payload_pattern {other}"),
        };
    }
    if let Some(hex) = optional_string_field(construct, "payload_raw_hex") {
        return decode_hex(&hex).unwrap_or_else(|msg| panic!("payload_raw_hex: {msg}"));
    }
    let obj = object_field(construct, "payload_object").expect("payload_object");
    encode_json_object(obj)
}

fn encode_json_object(pairs: &[(String, JsonValue)]) -> Vec<u8> {
    let mut out = String::from("{");
    let mut first = true;
    for (key, value) in pairs {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(key);
        out.push_str("\":");
        encode_json_value(&mut out, value);
    }
    out.push('}');
    out.into_bytes()
}

fn encode_json_value(out: &mut String, value: &JsonValue) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        JsonValue::Str(text) => {
            out.push('"');
            for ch in text.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    other => out.push(other),
                }
            }
            out.push('"');
        }
        JsonValue::Number(number) => out.push_str(&number.to_string()),
        JsonValue::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                encode_json_value(out, item);
            }
            out.push(']');
        }
        JsonValue::Object(nested) => {
            let nested_bytes = encode_json_object(nested);
            out.push_str(std::str::from_utf8(&nested_bytes).expect("utf-8 object"));
        }
    }
}

fn push_json_string_for_payload(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if !input.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let high = from_hex_digit(bytes[idx])?;
        let low = from_hex_digit(bytes[idx + 1])?;
        out.push((high << 4) | low);
        idx += 2;
    }
    Ok(out)
}

fn from_hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex digit".into()),
    }
}

fn assert_hook_result_payload(id: &str, result: &HookResult, expected: &[(String, JsonValue)]) {
    let kind = string_field(expected, "kind").expect("kind");
    assert_eq!(kind, "hook_result", "{id}: expected hook_result");
    assert_eq!(
        result.event,
        string_field(expected, "event").expect("event"),
        "{id}: event"
    );
    assert_eq!(
        result.verdict.as_str(),
        string_field(expected, "verdict").expect("verdict"),
        "{id}: verdict"
    );
    assert_eq!(
        result.reason,
        string_field(expected, "reason").expect("reason"),
        "{id}: reason"
    );
    assert_eq!(
        result.exit_code,
        i64_field(expected, "exit_code").expect("exit_code"),
        "{id}: exit_code"
    );
    assert_findings(id, result, expected);
    assert_optional_string(expected, "top_code", result.top_code.as_deref());
    assert_optional_string(expected, "session_id", result.session_id.as_deref());
    assert_eq!(
        result.line(),
        string_field(expected, "line").expect("line"),
        "{id}: line"
    );
    assert_eq!(
        result.to_json(),
        string_field(expected, "to_json").expect("to_json"),
        "{id}: to_json"
    );
    assert_eq!(
        result.to_claude_json(),
        string_field(expected, "to_claude_json").expect("to_claude_json"),
        "{id}: to_claude_json"
    );
    assert_eq!(
        result.system_message(),
        string_field(expected, "system_message").expect("system_message"),
        "{id}: system_message"
    );
}

fn assert_findings(id: &str, result: &HookResult, expected: &[(String, JsonValue)]) {
    let want_obj = object_field(expected, "findings_by_code").expect("findings_by_code");
    assert_eq!(
        result.findings_by_code.len(),
        want_obj.len(),
        "{id}: findings_by_code length"
    );
    for (code, count_value) in want_obj {
        let want = match count_value {
            JsonValue::Number(number) => *number,
            _ => panic!("{id}: finding count must be number"),
        };
        assert_eq!(
            result.findings_by_code.get(code),
            Some(&want),
            "{id}: count for {code}"
        );
    }
}

fn assert_optional_string(obj: &[(String, JsonValue)], key: &str, got: Option<&str>) {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => assert_eq!(got, None, "{key} must be absent"),
        Some((_, JsonValue::Str(want))) => assert_eq!(got, Some(want.as_str()), "{key} mismatch"),
        Some(_) => panic!("{key} must be string or null"),
    }
}

fn assert_rust_short_hash_seam() {
    let data = br#"{"session_id":"sess-synthetic","transcript_path":"fixtures/tiny.jsonl"}"#;
    let error = run_hook("SessionStart", data, None, None, None)
        .expect_err("non-empty session_id must hit short_hash seam");
    assert_eq!(error, HookError::ShortHashUnavailable);
    assert_eq!(error.to_string(), SHORT_HASH_UNAVAILABLE);
}

fn assert_rust_check_file_seam() {
    let root = vectors_root();
    let exact = root.join("fixtures/exact_fast_budget.jsonl");
    assert!(exact.is_file(), "exact_fast_budget fixture must exist");
    let path = exact.to_str().expect("utf-8 path");
    let mut payload = String::from(r#"{"transcript_path":"#);
    push_json_string_for_payload(&mut payload, path);
    payload.push('}');
    let error = run_hook("SessionStart", payload.as_bytes(), None, None, None)
        .expect_err("file at fast budget must hit check_file seam");
    assert_eq!(error, HookError::CheckFileUnavailable);
    assert_eq!(error.to_string(), CHECK_FILE_UNAVAILABLE);
    assert!(!error.to_string().contains(path));
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(s))) => Some(s.clone()),
        Some(_) => panic!("{key} must be string or null when present"),
    }
}

fn array_field_optional(obj: &[(String, JsonValue)], key: &str) -> Option<Vec<JsonValue>> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Array(items))) => Some(items.clone()),
        Some(_) => panic!("{key} must be array or null"),
    }
}

// --- minimal JSON (vectors.json only) ---

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
    let id = string_field_obj(obj, "id")?;
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
    string_field_obj(obj, key)
}

fn string_field_obj(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
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
