//! Dispositions for the 17 `def test_` functions in pinned
//! `tests/test_verify_parse_parity.py` (DW-T-08).
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440`. This integration test
//! links `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`]
//! only. It does not call `verify`.
//!
//! `covered` names one id in `parity/vectors/verify/vectors.json` when that
//! vector is the entire pinned test: one `_parse_session_events` call, the
//! same bytes or the same limit recipe, and that call's recorded outcome.
//! `not_applicable` is the invalid-UTF-8 string gap, a `verify()` fixture
//! call, or a plan round trip that no one vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 17;
const COVERED_COUNT: usize = 9;
const NOT_APPLICABLE_COUNT: usize = 8;
const VERIFY_VECTOR_COUNT: usize = 12;
const VECTORS_REL: &str = "parity/vectors/verify/vectors.json";
const COVERAGE_REL: &str = "parity/vectors/verify/coverage.json";
const MANIFEST_REL: &str = "parity/vectors/verify/manifest.json";
const PROVENANCE_REL: &str = "parity/vectors/verify/PROVENANCE.json";

/// Python `DEFAULT_READER_LIMITS` at the pin (`sesslint.io`).
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 100;
const MAX_FILE_BYTES: usize = 100 * 1024 * 1024;

const HEADER_LINE: &str = concat!(
    r#"{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","#,
    r#""session_id":"parity-sess"}"#
);
const EVENT_LINE: &str = concat!(
    r#"{"actor":"user","id":"msg-0","kind":"message","parent_id":null,"#,
    r#""payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}"#
);

const PLAN_MARKERS: &[&str] = &[
    "RepairPlan",
    "load_plan",
    "from_dict",
    "min_policy",
    "recipe_version",
    "expected_plan",
    "compute_plan_fingerprint",
    "transformation_audit",
    "output-parse-failed",
    "UnicodeDecodeError",
];

/// `covered` cites one verify vector that is the entire pinned test.
/// `not_applicable` records a gap this file must not turn into a passing `verify()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Covered(Covered),
    NotApplicable(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Covered {
    vector_id: &'static str,
    input: Input,
    expect: Expect,
}

/// Pinned input of one `_parse_session_events` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    /// Replace the `"hi"` token, quotes included, with this JSON token.
    Token(&'static str),
    /// Replace `"hi"` with a JSON string of this value.
    Quoted(&'static str),
    Headerless,
    Valid,
    /// Generator recipe for a limit the vector file does not inline.
    Recipe(&'static str),
}

/// Outcome recorded for that single call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    ValueError(&'static str),
    OversizedFile,
    Headerless,
    Valid,
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    // HEADER + event whose text is the bare token NaN. One ValueError.
    Row {
        name: "test_parse_events_rejects_nan",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_rejects_nan",
            input: Input::Token("NaN"),
            expect: Expect::ValueError("Out-of-range or non-standard numeric constant: NaN"),
        }),
    },
    Row {
        name: "test_parse_events_rejects_infinity",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_rejects_infinity",
            input: Input::Token("Infinity"),
            expect: Expect::ValueError("Out-of-range or non-standard numeric constant: Infinity"),
        }),
    },
    Row {
        name: "test_parse_events_rejects_out_of_range_float",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_rejects_out_of_range_float",
            input: Input::Token("1e999"),
            expect: Expect::ValueError("Out-of-range float: 1e999"),
        }),
    },
    // depth is max_depth + 10. The recipe is that whole line, not a sample.
    Row {
        name: "test_parse_events_rejects_deep_nesting",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_rejects_deep_nesting",
            input: Input::Recipe("deep_nesting"),
            expect: Expect::ValueError("Nesting depth exceeds maximum limit"),
        }),
    },
    // The quoted run is max_line_bytes + 1. The recipe is that whole line.
    Row {
        name: "test_parse_events_rejects_oversized_line",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_rejects_oversized_line",
            input: Input::Recipe("oversized_line"),
            expect: Expect::ValueError("Event record line exceeds maximum line byte limit"),
        }),
    },
    Row {
        name: "test_parse_events_rejects_nul_byte",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_rejects_nul_byte",
            input: Input::Quoted("a\u{0}b"),
            expect: Expect::ValueError("Forbidden NUL byte in event record line"),
        }),
    },
    Row {
        name: "test_parse_events_rejects_invalid_utf8",
        disposition: Disposition::NotApplicable(
            "bytes ff fe inside the second line make _parse_session_events raise ValueError; Python UnicodeDecodeError text is not the Rust invalid UTF-8 string",
        ),
    },
    // The body is max_file_bytes + 1. The message records both sizes.
    Row {
        name: "test_parse_events_rejects_oversized_file",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_rejects_oversized_file",
            input: Input::Recipe("oversized_file"),
            expect: Expect::OversizedFile,
        }),
    },
    Row {
        name: "test_parse_events_tolerates_headerless_jsonl",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_tolerates_headerless",
            input: Input::Headerless,
            expect: Expect::Headerless,
        }),
    },
    Row {
        name: "test_parse_events_accepts_valid_jsonl",
        disposition: Disposition::Covered(Covered {
            vector_id: "parse_accepts_valid_jsonl",
            input: Input::Valid,
            expect: Expect::Valid,
        }),
    },
    Row {
        name: "test_plan_roundtrip_preserves_safety_fields",
        disposition: Disposition::NotApplicable(concat!(
            "RepairPlan.from_dict(plan.to_dict()) on fixtures/repair/exec_basic/plan.json ",
            "keeps every step min_policy and recipe_version; ",
            "no verify vector is that entire test",
        )),
    },
    Row {
        name: "test_plan_roundtrip_through_file",
        disposition: Disposition::NotApplicable(concat!(
            "load_plan reads back json.dumps(plan.to_dict()) from a file and requires equality; ",
            "no verify vector is that entire test",
        )),
    },
    Row {
        name: "test_plan_from_dict_rejects_missing_required_step_field",
        disposition: Disposition::NotApplicable(concat!(
            "from_dict raises ValueError for a missing seq, recipe, min_policy, or recipe_version; ",
            "no verify vector is that entire test",
        )),
    },
    Row {
        name: "test_plan_from_dict_unwraps_expected_plan",
        disposition: Disposition::NotApplicable(concat!(
            "from_dict unwraps expected_plan and ignores the note field; ",
            "no verify vector is that entire test",
        )),
    },
    Row {
        name: "test_plan_from_dict_recomputes_missing_fingerprint",
        disposition: Disposition::NotApplicable(concat!(
            "from_dict recomputes a deleted fingerprint with compute_plan_fingerprint; ",
            "no verify vector is that entire test",
        )),
    },
    Row {
        name: "test_load_plan_rejects_plan_missing_safety_fields",
        disposition: Disposition::NotApplicable(concat!(
            "load_plan raises ValueError when every step lacks min_policy; ",
            "no verify vector is that entire test",
        )),
    },
    Row {
        name: "test_verify_rejects_nan_in_output",
        disposition: Disposition::NotApplicable(concat!(
            "verify() on the _write_ok_bundle fixture expects transformation_audit ",
            "to fail with output-parse-failed; ",
            "Rust returns sesslint.report.parse_manifest is not available",
        )),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_parse_events_rejects_nan",
    "test_parse_events_rejects_infinity",
    "test_parse_events_rejects_out_of_range_float",
    "test_parse_events_rejects_deep_nesting",
    "test_parse_events_rejects_oversized_line",
    "test_parse_events_rejects_nul_byte",
    "test_parse_events_rejects_invalid_utf8",
    "test_parse_events_rejects_oversized_file",
    "test_parse_events_tolerates_headerless_jsonl",
    "test_parse_events_accepts_valid_jsonl",
    "test_plan_roundtrip_preserves_safety_fields",
    "test_plan_roundtrip_through_file",
    "test_plan_from_dict_rejects_missing_required_step_field",
    "test_plan_from_dict_unwraps_expected_plan",
    "test_plan_from_dict_recomputes_missing_fingerprint",
    "test_load_plan_rejects_plan_missing_safety_fields",
    "test_verify_rejects_nan_in_output",
];

const VECTOR_IDS: &[&str] = &[
    "module_all",
    "dataclass_serialization",
    "render_verify_human_formatting",
    "parse_rejects_nan",
    "parse_rejects_infinity",
    "parse_rejects_out_of_range_float",
    "parse_rejects_deep_nesting",
    "parse_rejects_oversized_line",
    "parse_rejects_nul_byte",
    "parse_rejects_oversized_file",
    "parse_tolerates_headerless",
    "parse_accepts_valid_jsonl",
];

fn read_rel(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!text.contains('\r'), "{rel} contains CR");
    text
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\n      \"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        let id = &tail[..end];
        assert!(!id.is_empty(), "blank vector id");
        ids.push(id);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("verify vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn json_string_field(slice: &str, key: &str) -> String {
    let marker = format!("\"{key}\": \"");
    let start = slice
        .find(&marker)
        .unwrap_or_else(|| panic!("missing JSON string {key}"));
    let chars = slice[start + marker.len()..].chars();
    let mut out = String::new();
    for ch in chars {
        match ch {
            '"' => return out,
            '\\' => panic!("JSON string {key} contains an escape"),
            _ => out.push(ch),
        }
    }
    panic!("unterminated JSON string {key}");
}

fn object_after<'a>(slice: &'a str, key: &str) -> &'a str {
    let marker = format!("\"{key}\": ");
    let pos = slice
        .find(&marker)
        .unwrap_or_else(|| panic!("missing JSON object {key}"));
    let rest = slice[pos + marker.len()..].trim_start();
    assert!(rest.is_ascii(), "{key} object is not ASCII");
    assert!(rest.starts_with('{'), "{key} is not an object");
    let bytes = rest.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (idx, byte) in bytes.iter().enumerate() {
        if in_string {
            if escape {
                escape = false;
            } else if *byte == b'\\' {
                escape = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..=idx];
                }
            }
            _ => {}
        }
    }
    panic!("{key} object is truncated");
}

fn framed(event_line: &str) -> Vec<u8> {
    format!("{HEADER_LINE}\n{event_line}\n").into_bytes()
}

fn pinned_bytes(input: Input) -> Vec<u8> {
    match input {
        Input::Token(token) => framed(&EVENT_LINE.replace("\"hi\"", token)),
        Input::Quoted(value) => framed(&EVENT_LINE.replace("\"hi\"", &format!("\"{value}\""))),
        Input::Headerless => format!("{EVENT_LINE}\n").into_bytes(),
        Input::Valid => framed(EVENT_LINE),
        Input::Recipe(name) => panic!("recipe {name} is not an inlined payload"),
    }
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

fn coverage_row<'a>(json: &'a str, name: &str) -> &'a str {
    let marker = format!("\"test\": \"tests/test_verify_parse_parity.py::{name}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("coverage.json is missing {name}"));
    let brace = json[..start]
        .rfind('{')
        .unwrap_or_else(|| panic!("coverage row for {name} has no object"));
    let rest = &json[start..];
    let end_rel = rest
        .find("\n    }")
        .unwrap_or_else(|| panic!("coverage row for {name} is truncated"));
    &json[brace..start + end_rel + "\n    }".len()]
}

fn assert_one_vector_id(row: &str, name: &str, vector_id: &str) {
    let needle = format!("\"vector_ids\": [\n        \"{vector_id}\"\n      ]");
    assert!(
        row.contains(&needle),
        "{name} coverage row is not exactly vector {vector_id}: {row}"
    );
    assert_eq!(
        row.matches(&format!("\"{vector_id}\"")).count(),
        1,
        "{name} cites {vector_id} more than once"
    );
    assert!(row.contains("\"status\": \"covered\""), "{name}");
    assert!(!row.contains("not_applicable"), "{name}");
}

fn assert_coverage_not_applicable(row: &str, name: &str) {
    assert!(
        row.contains("\"status\": \"not_applicable\""),
        "{name}: {row}"
    );
    assert!(!row.contains("vector_ids"), "{name} names a vector");
    assert!(!row.contains("\"covered\""), "{name}");
}

fn assert_not_applicable_reason(name: &str, reason: &str) {
    assert!(!reason.is_empty(), "{name}");
    match name {
        "test_parse_events_rejects_invalid_utf8" => {
            assert!(reason
                .contains("Python UnicodeDecodeError text is not the Rust invalid UTF-8 string"));
        }
        "test_verify_rejects_nan_in_output" => {
            assert!(reason.contains("sesslint.report.parse_manifest is not available"));
            assert!(!reason.contains("PASSED"));
        }
        "test_plan_roundtrip_preserves_safety_fields"
        | "test_plan_roundtrip_through_file"
        | "test_plan_from_dict_rejects_missing_required_step_field"
        | "test_plan_from_dict_unwraps_expected_plan"
        | "test_plan_from_dict_recomputes_missing_fingerprint"
        | "test_load_plan_rejects_plan_missing_safety_fields" => {
            assert!(
                reason.contains("no verify vector is that entire test"),
                "{name}"
            );
        }
        other => panic!("unexpected not_applicable test {other}"),
    }
}

fn error_object(message: &str) -> String {
    assert!(
        !message.contains(['"', '\\', '\n', '\r']),
        "message is not a single JSON line"
    );
    format!(
        "{{\n        \"kind\": \"error\",\n        \"exc_type\": \"ValueError\",\n        \"message\": \"{message}\"\n      }}"
    )
}

fn ok_object(session_id: Option<&str>) -> String {
    let header = match session_id {
        Some(id) => format!("\"{id}\""),
        None => "null".to_string(),
    };
    format!(
        "{{\n        \"kind\": \"ok\",\n        \"header_session_id\": {header},\n        \"event_count\": 1,\n        \"first_event_id\": \"msg-0\"\n      }}"
    )
}

fn expect_message(expect: Expect) -> String {
    match expect {
        Expect::ValueError(message) => message.to_string(),
        Expect::OversizedFile => format!(
            "File size {} bytes exceeds maximum limit ({} bytes)",
            MAX_FILE_BYTES + 1,
            MAX_FILE_BYTES
        ),
        Expect::Headerless | Expect::Valid => panic!("ok outcome has no error message"),
    }
}

fn assert_expected(slice: &str, id: &str, expect: Expect) {
    let expected = object_after(slice, "expected");
    let want = match expect {
        Expect::ValueError(_) | Expect::OversizedFile => error_object(&expect_message(expect)),
        Expect::Headerless => ok_object(None),
        Expect::Valid => ok_object(Some("parity-sess")),
    };
    assert_eq!(
        expected, want,
        "{id} expected object is not that entire call"
    );
    assert_eq!(slice.matches("\"kind\":").count(), 1, "{id}");
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_payload_shape(input: Input, decoded: &[u8], id: &str) {
    match input {
        Input::Token(token) => {
            assert!(
                contains_bytes(decoded, token.as_bytes()),
                "{id} is missing token {token}"
            );
            assert!(
                !contains_bytes(decoded, b"\"hi\""),
                "{id} still has the hi text"
            );
        }
        Input::Quoted(value) => {
            assert!(
                contains_bytes(decoded, value.as_bytes()),
                "{id} is missing the quoted value"
            );
            assert!(
                !contains_bytes(decoded, b"\"hi\""),
                "{id} still has the hi text"
            );
        }
        Input::Headerless | Input::Valid => {
            assert!(
                contains_bytes(decoded, b"\"hi\""),
                "{id} dropped the event text"
            );
            assert!(!decoded.contains(&0), "{id} contains a NUL");
        }
        Input::Recipe(name) => panic!("recipe {name} has no inlined payload"),
    }
}

fn assert_raw_is_entire_test(slice: &str, id: &str, input: Input, expect: Expect) {
    let construct = object_after(slice, "construct");
    let b64 = json_string_field(construct, "raw_b64");
    let want = format!(
        "{{\n        \"type\": \"parse_session_events\",\n        \"raw_b64\": \"{b64}\"\n      }}"
    );
    assert_eq!(construct, want, "{id} construct is not one raw payload");
    assert!(
        !construct.contains("recipe"),
        "{id} mixes a recipe into raw bytes"
    );
    let decoded = decode_base64(&b64).unwrap_or_else(|err| panic!("{id}: {err}"));
    assert_eq!(
        decoded,
        pinned_bytes(input),
        "{id} bytes are not the pinned test input"
    );
    assert_payload_shape(input, &decoded, id);
    assert_expected(slice, id, expect);
}

fn assert_recipe_is_entire_test(slice: &str, id: &str, name: &str, expect: Expect) {
    let construct = object_after(slice, "construct");
    let want = format!(
        "{{\n        \"type\": \"parse_session_events\",\n        \"recipe\": \"{name}\"\n      }}"
    );
    assert_eq!(
        construct, want,
        "{id} construct is not the single recipe {name}"
    );
    assert!(
        !construct.contains("raw_b64"),
        "{id} inlines a sample beside {name} (depth {}, line {}, file {})",
        MAX_DEPTH + 10,
        MAX_LINE_BYTES + 1,
        MAX_FILE_BYTES + 1
    );
    assert_eq!(json_string_field(construct, "type"), "parse_session_events");
    assert_eq!(json_string_field(construct, "recipe"), name);
    assert_expected(slice, id, expect);
}

fn assert_vector_is_entire_test(json: &str, spec: Covered) {
    let slice = vector_slice(json, spec.vector_id);
    assert!(
        slice.starts_with(&format!("\n      \"id\": \"{}\",", spec.vector_id)),
        "{}",
        spec.vector_id
    );
    assert_eq!(
        slice.matches("\n      \"id\": \"").count(),
        1,
        "{} is more than one vector",
        spec.vector_id
    );
    assert_eq!(slice.matches("\"type\":").count(), 1, "{}", spec.vector_id);
    match spec.input {
        Input::Recipe(name) => {
            assert_recipe_is_entire_test(slice, spec.vector_id, name, spec.expect);
        }
        input => assert_raw_is_entire_test(slice, spec.vector_id, input, spec.expect),
    }
}

#[test]
fn workspace_export_is_only_the_package_name() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
}

#[test]
fn every_pinned_parse_parity_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(COVERED_COUNT + NOT_APPLICABLE_COUNT, PINNED_TEST_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
    let mut covered_ids = BTreeSet::new();
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    for row in ROWS {
        assert!(names.insert(row.name), "duplicate pinned test {}", row.name);
        match row.disposition {
            Disposition::Covered(spec) => {
                assert!(spec.vector_id.starts_with("parse_"), "{}", row.name);
                assert!(
                    covered_ids.insert(spec.vector_id),
                    "duplicate covered vector {}",
                    spec.vector_id
                );
                match spec.input {
                    Input::Token(token) | Input::Quoted(token) | Input::Recipe(token) => {
                        assert!(!token.is_empty(), "{}", row.name);
                    }
                    Input::Headerless | Input::Valid => {}
                }
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert_not_applicable_reason(row.name, reason);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered, COVERED_COUNT);
    assert_eq!(not_applicable, NOT_APPLICABLE_COUNT);
}

#[test]
fn covered_parse_vectors_are_the_entire_pinned_tests() {
    let vectors = read_rel(VECTORS_REL);
    let coverage = read_rel(COVERAGE_REL);
    let manifest = read_rel(MANIFEST_REL);
    let provenance = read_rel(PROVENANCE_REL);
    let pin = format!("\"python_commit\": \"{PIN}\"");
    for (label, text) in [
        ("vectors", vectors.as_str()),
        ("coverage", coverage.as_str()),
        ("manifest", manifest.as_str()),
        ("provenance", provenance.as_str()),
    ] {
        assert!(text.contains(&pin), "{label} is not pinned to {PIN}");
    }
    assert!(vectors.contains("\"module\": \"sesslint.verify\""));
    assert!(manifest.contains("\"vector_count\": 12"));
    assert!(manifest.contains("\"module\": \"sesslint.verify\""));
    assert!(provenance.contains("\"contains_real_data\": false"));
    assert!(vectors.contains(
        "Python _parse_session_events surfaces CPython UnicodeDecodeError text; Rust reports invalid UTF-8"
    ));
    assert!(vectors.contains("sesslint.report.parse_manifest is not available"));
    assert!(coverage.contains("\"covered_count\": 10"));
    assert!(coverage.contains("\"not_applicable_count\": 129"));
    assert_eq!(coverage.matches("\"status\": \"covered\"").count(), 10);
    assert_eq!(
        coverage.matches("\"status\": \"not_applicable\"").count(),
        129
    );
    assert!(coverage
        .contains("\"test\": \"tests/test_verify.py::test_render_verify_human_formatting\""));

    let ids = vector_ids(&vectors);
    assert_eq!(ids.as_slice(), VECTOR_IDS);
    assert_eq!(ids.len(), VERIFY_VECTOR_COUNT);

    let mut covered_ids = Vec::new();
    for row in ROWS {
        let cov = coverage_row(&coverage, row.name);
        match row.disposition {
            Disposition::Covered(spec) => {
                assert_one_vector_id(cov, row.name, spec.vector_id);
                assert_vector_is_entire_test(&vectors, spec);
                covered_ids.push(spec.vector_id);
            }
            Disposition::NotApplicable(reason) => {
                assert_coverage_not_applicable(cov, row.name);
                assert_not_applicable_reason(row.name, reason);
            }
        }
    }
    assert_eq!(covered_ids.len(), COVERED_COUNT);

    let mut unmapped: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| !covered_ids.contains(id))
        .collect();
    unmapped.sort_unstable();
    assert_eq!(
        unmapped.as_slice(),
        [
            "dataclass_serialization",
            "module_all",
            "render_verify_human_formatting",
        ]
        .as_slice()
    );

    for id in &ids {
        let slice = vector_slice(&vectors, id);
        let kind = json_string_field(slice, "type");
        match kind.as_str() {
            "module_all"
            | "dataclass_serialization"
            | "render_verify_human"
            | "parse_session_events" => {}
            other => panic!("{id} has construct {other}"),
        }
        if covered_ids.contains(id) {
            assert_eq!(kind, "parse_session_events", "{id}");
        }
        for marker in PLAN_MARKERS {
            assert!(!slice.contains(marker), "{id} contains {marker}");
        }
    }
}
