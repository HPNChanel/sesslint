//! Dispositions for the 34 `def test_` functions in pinned
//! `tests/adapters/test_canonical.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (710 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.adapters`.
//!
//! `covered` names one id in `adapters.canonical/vectors.json` whose construct
//! is the same function and the same success or failure mode as that entire
//! pinned test. One example inside a sweep, a different input string, or a
//! shared field such as `schema_version` is not coverage. `not_applicable`
//! records a `sesslint.adapters.canonical` call this package cannot reach
//! without a `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 34;
const ADAPTER_VECTOR_COUNT: usize = 44;
const VECTORS_REL: &str = "parity/vectors/adapters.canonical/vectors.json";

/// `covered` names a vector id in `adapters.canonical/vectors.json`.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from that
/// vector file.
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
/// A thrown `load_canonical_body` failure is the key `"message"`. Scores,
/// labels, pin summaries, and gap assertions are not that key.
const ADAPTER_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("normalize_trim", "normalize_version", false),
    ("normalize_v_prefix", "normalize_version", false),
    ("normalize_nbsp_v", "normalize_version", false),
    ("normalize_empty", "normalize_version", false),
    ("normalize_v_alone", "normalize_version", false),
    ("normalize_vx", "normalize_version", false),
    ("normalize_version_word", "normalize_version", false),
    ("detect_empty", "detect_canonical", false),
    ("detect_schema_v1", "detect_canonical", false),
    ("detect_schema_version_key", "detect_canonical", false),
    ("detect_partial_v2", "detect_canonical", false),
    ("detect_unrelated", "detect_canonical", false),
    ("detect_substring", "detect_canonical", false),
    ("classify_events_null", "classify_session_doc", false),
    ("classify_events_identity", "classify_session_doc", false),
    ("classify_schema_only", "classify_session_doc", false),
    ("classify_version_only", "classify_session_doc", false),
    ("classify_schema_blocked", "classify_session_doc", false),
    ("classify_empty_map", "classify_session_doc", false),
    ("classify_list", "classify_session_doc", false),
    ("classify_string", "classify_session_doc", false),
    ("label_bytes", "canonical_source_label", false),
    ("label_str_dot", "canonical_source_label", false),
    ("label_str_slash", "canonical_source_label", false),
    ("label_str_backslash", "canonical_source_label", false),
    ("label_stream_missing", "canonical_source_label", false),
    ("label_stream_name", "canonical_source_label", false),
    ("safe_type_str", "safe_type_value", false),
    ("safe_type_none", "safe_type_value", false),
    ("safe_type_list", "safe_type_value", false),
    ("safe_type_dict", "safe_type_value", false),
    ("gap_load_minimal_bytes", "load_canonical", false),
    ("gap_load_empty_fixture", "load_canonical", false),
    ("gap_load_bad_schema", "load_canonical", false),
    ("gap_load_decorative", "load_canonical", false),
    ("gap_load_nul", "load_canonical", false),
    ("gap_session_minimal", "load_canonical_session", false),
    ("gap_session_decorative", "load_canonical_session", false),
    ("body_missing_path", "load_canonical_body", true),
    ("body_whitespace_only", "load_canonical_body", false),
    ("body_empty_object", "load_canonical_body", false),
    ("body_nul_gate", "load_canonical_body", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_write_minimal_golden",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/canonical/minimal.json then dump_canonical byte-matches snapshots/canonical_minimal.json; gap_load_minimal_bytes is one gapped load of those bytes and dump_canonical has no vector",
        ),
    },
    Row {
        name: "test_round_trip_minimal",
        disposition: Disposition::NotApplicable(
            "load_canonical, dump_canonical, load_canonical, and dump_canonical again on the minimal fixture; gap_load_minimal_bytes is one gapped load and dump_canonical has no vector",
        ),
    },
    Row {
        name: "test_round_trip_empty",
        disposition: Disposition::NotApplicable(
            "load_canonical and dump_canonical round-trip fixtures/canonical/empty.json; gap_load_empty_fixture is one gapped load of those bytes",
        ),
    },
    Row {
        name: "test_round_trip_checkpoint",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/canonical/with_checkpoint.json keeps source checkpoints through dump_canonical; no adapters.canonical vector records checkpoints",
        ),
    },
    Row {
        name: "test_version_999_SL301",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/canonical/v999.json returns one event and one SL301 unsupported finding; no adapters.canonical vector records SL301",
        ),
    },
    Row {
        name: "test_unknown_critical_SL302",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/canonical/unknown_critical.json returns SL302 findings for unknown_critical and unknown_critical_field; no adapters.canonical vector records SL302",
        ),
    },
    Row {
        name: "test_decorative_unknown_key_no_finding",
        disposition: Disposition::NotApplicable(
            "load_canonical keeps decorative_doc_note and decorative_color with zero findings; gap_load_decorative is a different document with id evt_syn_001 and no decorative keys",
        ),
    },
    Row {
        name: "test_bad_schema_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of wrong.schema/v1 returns one SL001 finding with reason invalid_schema and severity ERROR; gap_load_bad_schema records those bytes as a secret-scan gap and omits reason invalid_schema",
        ),
    },
    Row {
        name: "test_missing_required_top_level_keys_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical returns SL001 for a missing schema key, a missing version key, and a missing events key; no adapters.canonical vector records those three field findings, and one document would not be the sweep",
        ),
    },
    // Five detect_canonical scores. Each committed vector is one score.
    Row {
        name: "test_detect_confidences",
        disposition: Disposition::NotApplicable(
            "detect_canonical scores empty bytes at 0.0, schema v1 at 1.0, schema_version at 1.0, schema v2 at 0.6, and unrelated JSON at 0.0; detect_empty, detect_schema_v1, detect_schema_version_key, detect_partial_v2, and detect_unrelated are one score each, so none is the whole sweep",
        ),
    },
    Row {
        name: "test_empty_legal",
        disposition: Disposition::NotApplicable(
            "load_canonical of the empty fixture path returns zero events and zero findings; gap_load_empty_fixture is a gapped load of those bytes and does not open the path",
        ),
    },
    Row {
        name: "test_trailing_garbage_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of a canonical object followed by a second object returns SL001 malformed_json; no adapters.canonical vector records trailing garbage",
        ),
    },
    Row {
        name: "test_events_type_confusion_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical returns SL001 invalid_events_type for events null and for events as an object; classify_events_null is classify_session_doc of a different document, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_duplicate_ids_preserved",
        disposition: Disposition::NotApplicable(
            "load_canonical keeps two events that both use id dup_001 and returns zero findings; no adapters.canonical vector records duplicate event ids",
        ),
    },
    Row {
        name: "test_non_utf8_bytes_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of bytes ff fe 00 00 followed by text returns one SL001 finding; no adapters.canonical vector records those bytes",
        ),
    },
    Row {
        name: "test_nul_bytes_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of a document with a NUL between schema and version returns SL001 forbidden_nul_byte; gap_load_nul and body_nul_gate append the NUL after a different document",
        ),
    },
    Row {
        name: "test_empty_file_refused",
        disposition: Disposition::NotApplicable(
            "load_canonical of empty bytes returns SL001 empty_input; detect_empty calls detect_canonical on empty bytes and returns score 0.0",
        ),
    },
    Row {
        name: "test_max_file_bytes_limit",
        disposition: Disposition::NotApplicable(
            "load_canonical of a path with ReaderLimits max_file_bytes 10 returns SL001 size_limit_exceeded; no adapters.canonical vector passes ReaderLimits",
        ),
    },
    Row {
        name: "test_max_records_limit",
        disposition: Disposition::NotApplicable(
            "load_canonical of ten events with ReaderLimits max_records 5 raises MaxRecordsExceededError; no adapters.canonical vector records that exception",
        ),
    },
    Row {
        name: "test_per_event_missing_required_keys_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of one event missing id, parent_id, kind, and ts returns four SL001 findings; module_constants lists those key names and is not that load",
        ),
    },
    Row {
        name: "test_sha256_stability",
        disposition: Disposition::NotApplicable(
            "dump_canonical twice on the minimal fixture returns identical bytes and identical sha256 digests; no adapters.canonical vector calls dump_canonical",
        ),
    },
    Row {
        name: "test_load_canonical_session",
        disposition: Disposition::NotApplicable(
            "load_canonical_session of the minimal fixture path checks schema_version, session_id canonical-session, version 1, and ids evt_001 and evt_002; gap_session_minimal is a gapped byte load that records only counts",
        ),
    },
    Row {
        name: "test_dump_canonical_accepts_session",
        disposition: Disposition::NotApplicable(
            "dump_canonical of the minimal Session equals dump_canonical of its events and snapshots/canonical_minimal.json; no adapters.canonical vector calls dump_canonical",
        ),
    },
    Row {
        name: "test_null_or_empty_id_rejected_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical returns SL001 invalid_id for id null and for id whitespace; no adapters.canonical vector records invalid_id, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_non_string_id_rejected_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of integer id 12345 returns SL001 invalid_id; no adapters.canonical vector records that id type",
        ),
    },
    Row {
        name: "test_invalid_parent_id_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical returns two SL001 invalid_parent_id findings for parent_id empty string and parent_id 123; no adapters.canonical vector records invalid_parent_id",
        ),
    },
    Row {
        name: "test_invalid_payload_type_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of a string payload returns SL001 invalid_payload_type; no adapters.canonical vector records that reason",
        ),
    },
    Row {
        name: "test_invalid_source_type_SL001",
        disposition: Disposition::NotApplicable(
            "load_canonical of integer source 12345 returns SL001 invalid_source_type; no adapters.canonical vector records that reason",
        ),
    },
    Row {
        name: "test_stream_read_size_limit_bounded",
        disposition: Disposition::NotApplicable(
            "load_canonical of a 200-byte stream with max_file_bytes 100 returns SL001 size_limit_exceeded; no adapters.canonical vector reads a stream under ReaderLimits",
        ),
    },
    Row {
        name: "test_load_canonical_session_preserves_document_metadata",
        disposition: Disposition::NotApplicable(
            "load_canonical_session keeps session_id custom-sess-42, created_at, title, and metadata; gap_session_decorative is a different document and a secret-scan gap",
        ),
    },
    Row {
        name: "test_10k_events_size_limit",
        disposition: Disposition::NotApplicable(
            "load_canonical of a 10000-event document with max_file_bytes 50000 returns SL001 size_limit_exceeded; no adapters.canonical vector records that size gate",
        ),
    },
    Row {
        name: "test_unicode_utf8_roundtrip",
        disposition: Disposition::NotApplicable(
            "dump_canonical and load_canonical round-trip a payload with Vietnamese text and an emoji; no adapters.canonical vector calls dump_canonical",
        ),
    },
    Row {
        name: "test_single_doc_without_version_key_loads_cleanly",
        disposition: Disposition::NotApplicable(
            "load_canonical of a schema_version document that omits version returns one event and zero findings; detect_schema_version_key is detect_canonical of a different byte string and a score of 1.0",
        ),
    },
    Row {
        name: "test_dump_canonical_json_format_parses_with_canonical_model",
        disposition: Disposition::NotApplicable(
            "dump_canonical format json of the minimal fixture then sesslint.canonical.parse_session; no adapters.canonical vector calls dump_canonical or parse_session",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_write_minimal_golden",
    "test_round_trip_minimal",
    "test_round_trip_empty",
    "test_round_trip_checkpoint",
    "test_version_999_SL301",
    "test_unknown_critical_SL302",
    "test_decorative_unknown_key_no_finding",
    "test_bad_schema_SL001",
    "test_missing_required_top_level_keys_SL001",
    "test_detect_confidences",
    "test_empty_legal",
    "test_trailing_garbage_SL001",
    "test_events_type_confusion_SL001",
    "test_duplicate_ids_preserved",
    "test_non_utf8_bytes_SL001",
    "test_nul_bytes_SL001",
    "test_empty_file_refused",
    "test_max_file_bytes_limit",
    "test_max_records_limit",
    "test_per_event_missing_required_keys_SL001",
    "test_sha256_stability",
    "test_load_canonical_session",
    "test_dump_canonical_accepts_session",
    "test_null_or_empty_id_rejected_SL001",
    "test_non_string_id_rejected_SL001",
    "test_invalid_parent_id_SL001",
    "test_invalid_payload_type_SL001",
    "test_invalid_source_type_SL001",
    "test_stream_read_size_limit_bounded",
    "test_load_canonical_session_preserves_document_metadata",
    "test_10k_events_size_limit",
    "test_unicode_utf8_roundtrip",
    "test_single_doc_without_version_key_loads_cleanly",
    "test_dump_canonical_json_format_parses_with_canonical_model",
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
        .unwrap_or_else(|| panic!("adapters.canonical vectors.json is missing id {id}"));
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
fn every_pinned_adapter_canonical_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(ADAPTER_VECTORS.len(), ADAPTER_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_adapter_canonical_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "adapter canonical vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.adapters.canonical\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = ADAPTER_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in ADAPTER_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"message\":"),
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
