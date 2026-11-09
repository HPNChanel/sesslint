//! Dispositions for the 43 `def test_` functions in pinned `tests/test_canonical.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (994 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `canonical/vectors.json` whose construct is the
//! same function and the same success or failure mode as that entire pinned
//! test. One example inside a sweep, a different input string, or a shared
//! field such as `schema_version` is not coverage. `not_applicable` records a
//! `sesslint.canonical` call this package cannot reach without a `Cargo.toml`
//! change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 43;
const CANONICAL_VECTOR_COUNT: usize = 12;
const VECTORS_REL: &str = "parity/vectors/canonical/vectors.json";

/// `covered` names a vector id in `canonical/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
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

/// Vector id, construct type, and whether the expected result is an error.
const CANONICAL_VECTORS: &[(&str, &str, bool)] = &[
    (
        "header_minimal_parsed_fields",
        "parse_session_header",
        false,
    ),
    (
        "header_bad_schema_version_sl301_suffix",
        "parse_session_header_error",
        true,
    ),
    ("event_minimal", "parse_session_event", false),
    ("event_duplicate_id", "parse_session_event_error", true),
    ("event_self_parent", "parse_session_event_error", true),
    (
        "event_bad_actor_sorted_expected_actors",
        "parse_session_event_error",
        true,
    ),
    ("session_framed_experimental_fields", "parse_session", false),
    ("session_flat_experimental_fields", "parse_session", false),
    (
        "parse_session_lines_blank_line_one_event",
        "parse_session_lines",
        false,
    ),
    (
        "load_session_file_small_jsonl",
        "load_session_file_bytes",
        false,
    ),
    (
        "validate_rfc3339_utc_ok_leap_day",
        "validate_rfc3339_direct",
        false,
    ),
    (
        "validate_rfc3339_utc_calendar_fail_original_ts_in_message",
        "validate_rfc3339_direct",
        true,
    ),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_frozen_dataclasses",
        disposition: Disposition::NotApplicable(
            "FrozenInstanceError on Session, SessionHeader, and SessionEvent; no canonical vector records immutability",
        ),
    },
    Row {
        name: "test_canonical_json_determinism",
        disposition: Disposition::NotApplicable(
            "to_canonical_json and canonical_bytes key-order equality; no canonical vector calls those functions",
        ),
    },
    Row {
        name: "test_canonical_json_unicode_preservation",
        disposition: Disposition::NotApplicable(
            "to_canonical_json keeps non-ASCII text unescaped; no canonical vector calls to_canonical_json",
        ),
    },
    Row {
        name: "test_event_round_trip",
        disposition: Disposition::NotApplicable(
            "parse_session_event and to_canonical_json round trip of one tool_call event; event_minimal is a different parse_session_event success",
        ),
    },
    Row {
        name: "test_session_round_trip",
        disposition: Disposition::NotApplicable(
            "dump_session then parse_session_lines equality for three events; the parse_session_lines vector is one success event and dump_session has no vector",
        ),
    },
    Row {
        name: "test_rfc3339_utc_rejection",
        disposition: Disposition::NotApplicable(
            "parse_session_header and parse_session_event reject seven non-UTC timestamp strings; validate_rfc3339_direct vectors are a leap-day success and a different calendar failure",
        ),
    },
    Row {
        name: "test_actor_and_kind_validation",
        disposition: Disposition::NotApplicable(
            "parse_session_event rejects actor bogus_actor and kind bogus_kind and accepts every valid actor and kind; event_bad_actor_sorted_expected_actors is actor nope alone",
        ),
    },
    Row {
        name: "test_seq_type_validation",
        disposition: Disposition::NotApplicable(
            "parse_session_event rejects seq values -1, true, and a string; no canonical vector records a seq type error",
        ),
    },
    Row {
        name: "test_parent_id_self_reference_rejected",
        disposition: Disposition::NotApplicable(
            "parse_session_event rejects self parent id evt_self; event_self_parent is the same error mode for id evt-self",
        ),
    },
    Row {
        name: "test_missing_parent_allowed_in_canonical_parser",
        disposition: Disposition::NotApplicable(
            "parse_session_event accepts parent id evt_does_not_exist; event_minimal succeeds with parent_id null",
        ),
    },
    Row {
        name: "test_duplicate_event_id_rejected",
        disposition: Disposition::NotApplicable(
            "parse_session_lines rejects duplicate id duplicate_id; event_duplicate_id is parse_session_event_error for evt-1",
        ),
    },
    Row {
        name: "test_experimental_fields_allowed_and_roundtripped",
        disposition: Disposition::NotApplicable(
            "parse_session_event keeps experimental_custom_trace and to_canonical_json round-trips it; the parse_session experimental vectors use other field names",
        ),
    },
    Row {
        name: "test_empty_events_session_allowed",
        disposition: Disposition::NotApplicable(
            "dump_session and parse_session_lines of a header and zero events; parse_session_lines_blank_line_one_event parses one event",
        ),
    },
    Row {
        name: "test_bom_crlf_and_trailing_whitespace",
        disposition: Disposition::NotApplicable(
            "load_session_file accepts a BOM, CRLF, and trailing spaces; load_session_file_small_jsonl is a different byte string",
        ),
    },
    Row {
        name: "test_deeply_nested_payload_rejection",
        disposition: Disposition::NotApplicable(
            "parse_session_event rejects a payload deeper than MAX_PAYLOAD_DEPTH; no canonical vector records a depth error",
        ),
    },
    Row {
        name: "test_size_limit_rejection",
        disposition: Disposition::NotApplicable(
            "load_session_file rejects a file past the non-streaming byte limit; load_session_file_small_jsonl is a small success",
        ),
    },
    Row {
        name: "test_adversarial_keys_handled_safely",
        disposition: Disposition::NotApplicable(
            "parse_session_event keeps payload keys __proto__ and constructor; no canonical vector records those keys",
        ),
    },
    Row {
        name: "test_file_persistence_helper",
        disposition: Disposition::NotApplicable(
            "dump_session_file then load_session_file equality; no canonical vector calls dump_session_file",
        ),
    },
    Row {
        name: "test_parse_session_framed_and_flat",
        disposition: Disposition::NotApplicable(
            "parse_session succeeds for one flat document and one framed document without experimental fields; both parse_session vectors are different documents that include experimental fields",
        ),
    },
    Row {
        name: "test_header_validation_errors",
        disposition: Disposition::NotApplicable(
            "parse_session_header rejects seven header shape errors; header_bad_schema_version_sl301_suffix is an unsupported schema version",
        ),
    },
    Row {
        name: "test_event_optional_fields_type_checks",
        disposition: Disposition::NotApplicable(
            "parse_session_event accepts one fully populated optional-field event and rejects nine type errors; event_minimal leaves those fields null",
        ),
    },
    Row {
        name: "test_to_canonical_json_type_error",
        disposition: Disposition::NotApplicable(
            "to_canonical_json maps a callable TypeError to SchemaError; no canonical vector calls to_canonical_json",
        ),
    },
    Row {
        name: "test_load_session_file_edge_cases",
        disposition: Disposition::NotApplicable(
            "load_session_file fails for a missing path, an empty file, and invalid UTF-8; load_session_file_small_jsonl is a small success",
        ),
    },
    Row {
        name: "test_load_session_file_single_json_document",
        disposition: Disposition::NotApplicable(
            "load_session_file reads one JSON object document; load_session_file_small_jsonl is a different JSONL byte string",
        ),
    },
    Row {
        name: "test_parse_session_lines_malformed_json",
        disposition: Disposition::NotApplicable(
            "parse_session_lines rejects a broken header and a broken event line; parse_session_lines_blank_line_one_event is a success",
        ),
    },
    Row {
        name: "test_compute_content_hash_deterministic",
        disposition: Disposition::NotApplicable(
            "compute_content_hash is stable across key order; no canonical vector calls compute_content_hash",
        ),
    },
    Row {
        name: "test_calendar_date_validation",
        disposition: Disposition::NotApplicable(
            "parse_session_header rejects four invalid calendar timestamps; validate_rfc3339_utc_calendar_fail_original_ts_in_message calls validate_rfc3339_direct on a different timestamp",
        ),
    },
    Row {
        name: "test_canonical_json_nan_inf_rejected",
        disposition: Disposition::NotApplicable(
            "to_canonical_json rejects NaN, inf, and negative inf; no canonical vector calls to_canonical_json",
        ),
    },
    Row {
        name: "test_cycle_detection_in_payload_and_canonical_json",
        disposition: Disposition::NotApplicable(
            "parse_session_event and to_canonical_json reject cyclic dict and list containers; no canonical vector records a cycle",
        ),
    },
    Row {
        name: "test_provenance_and_source_fields_roundtrip",
        disposition: Disposition::NotApplicable(
            "dump_session and parse_session_lines round-trip header source and version plus event source fields; no canonical vector is that round trip",
        ),
    },
    Row {
        name: "test_framed_session_unknown_field_rejected",
        disposition: Disposition::NotApplicable(
            "parse_session rejects unknown field evil and accepts experimental_batch on an empty event list; session_framed_experimental_fields is a different success document",
        ),
    },
    Row {
        name: "test_parse_session_missing_events_field_rejected",
        disposition: Disposition::NotApplicable(
            "parse_session rejects a document that omits events; no canonical vector records that error",
        ),
    },
    Row {
        name: "test_parse_session_lines_line_number_accuracy",
        disposition: Disposition::NotApplicable(
            "parse_session_lines reports malformed JSON on event line 4; parse_session_lines_blank_line_one_event is a success",
        ),
    },
    Row {
        name: "test_schema_loader_helpers",
        disposition: Disposition::NotApplicable(
            "get_session_schema_path and load_session_schema, including a missing schema path; no canonical vector reads a schema",
        ),
    },
    Row {
        name: "test_canonical_json_valid_float",
        disposition: Disposition::NotApplicable(
            "to_canonical_json of one finite float; no canonical vector calls to_canonical_json",
        ),
    },
    Row {
        name: "test_session_header_experimental_fields_and_validations",
        disposition: Disposition::NotApplicable(
            "parse_session_header accepts an experimental field, source, and version, then rejects bad source and version types; header_minimal_parsed_fields is a different success header",
        ),
    },
    Row {
        name: "test_session_event_source_adapter_and_location_validation",
        disposition: Disposition::NotApplicable(
            "parse_session_event rejects non-string source_adapter and source_location; no canonical vector records those type errors",
        ),
    },
    Row {
        name: "test_parse_session_type_validations",
        disposition: Disposition::NotApplicable(
            "parse_session rejects a non-mapping body, a non-list events field, and a non-mapping header; no canonical vector records those type errors",
        ),
    },
    Row {
        name: "test_parse_session_lines_all_blank",
        disposition: Disposition::NotApplicable(
            "parse_session_lines rejects a stream of only blank lines; parse_session_lines_blank_line_one_event is a success with one event",
        ),
    },
    Row {
        name: "test_to_canonical_json_rejects_non_string_keys",
        disposition: Disposition::NotApplicable(
            "to_canonical_json rejects eight non-string key cases; no canonical vector calls to_canonical_json",
        ),
    },
    Row {
        name: "test_to_canonical_json_unserializable_maps_to_schema_error",
        disposition: Disposition::NotApplicable(
            "to_canonical_json maps bytes, a set, and a custom object to SchemaError; no canonical vector calls to_canonical_json",
        ),
    },
    Row {
        name: "test_validate_rfc3339_utc_offset_variations",
        disposition: Disposition::NotApplicable(
            "parse_session_event accepts nine UTC offset spellings and rejects one invalid calendar offset; validate_rfc3339_direct vectors use different timestamps",
        ),
    },
    Row {
        name: "test_depth_validation_and_io_alignment",
        disposition: Disposition::NotApplicable(
            "_validate_depth matches check_nesting_depth at the depth cap and one step past it; no canonical vector records that alignment",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_frozen_dataclasses",
    "test_canonical_json_determinism",
    "test_canonical_json_unicode_preservation",
    "test_event_round_trip",
    "test_session_round_trip",
    "test_rfc3339_utc_rejection",
    "test_actor_and_kind_validation",
    "test_seq_type_validation",
    "test_parent_id_self_reference_rejected",
    "test_missing_parent_allowed_in_canonical_parser",
    "test_duplicate_event_id_rejected",
    "test_experimental_fields_allowed_and_roundtripped",
    "test_empty_events_session_allowed",
    "test_bom_crlf_and_trailing_whitespace",
    "test_deeply_nested_payload_rejection",
    "test_size_limit_rejection",
    "test_adversarial_keys_handled_safely",
    "test_file_persistence_helper",
    "test_parse_session_framed_and_flat",
    "test_header_validation_errors",
    "test_event_optional_fields_type_checks",
    "test_to_canonical_json_type_error",
    "test_load_session_file_edge_cases",
    "test_load_session_file_single_json_document",
    "test_parse_session_lines_malformed_json",
    "test_compute_content_hash_deterministic",
    "test_calendar_date_validation",
    "test_canonical_json_nan_inf_rejected",
    "test_cycle_detection_in_payload_and_canonical_json",
    "test_provenance_and_source_fields_roundtrip",
    "test_framed_session_unknown_field_rejected",
    "test_parse_session_missing_events_field_rejected",
    "test_parse_session_lines_line_number_accuracy",
    "test_schema_loader_helpers",
    "test_canonical_json_valid_float",
    "test_session_header_experimental_fields_and_validations",
    "test_session_event_source_adapter_and_location_validation",
    "test_parse_session_type_validations",
    "test_parse_session_lines_all_blank",
    "test_to_canonical_json_rejects_non_string_keys",
    "test_to_canonical_json_unserializable_maps_to_schema_error",
    "test_validate_rfc3339_utc_offset_variations",
    "test_depth_validation_and_io_alignment",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are indented further.
    const MARKER: &str = "\n      \"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("canonical vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
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
fn every_pinned_canonical_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(CANONICAL_VECTORS.len(), CANONICAL_VECTOR_COUNT);
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
                    needles
                        .iter()
                        .any(|needle| needle.starts_with("\"type\": \"")),
                    "{} covered row is missing a construct type needle",
                    row.name
                );
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
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
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn covered_vector_ids_are_present_in_canonical_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "canonical vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.canonical\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = CANONICAL_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in CANONICAL_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"error\":"),
            fails,
            "{id} error mode does not match the vector file"
        );
    }

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
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
