//! Dispositions for the 25 column-0 `def test_` functions in pinned
//! `tests/checks/test_identity.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (829 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! A column-0 scan finds all 25 tests. Each of those names has one disposition.
//!
//! `covered` names one id in `checks.identity/vectors.json` whose construct is
//! the same function and the same success or failure mode as that entire pinned
//! test. One example inside a sweep, a different input string, or a shared
//! count such as `check_findings_len` 0 on a different event list is not
//! coverage. `not_applicable` records a `check_identities` finding,
//! `diff_field_names` of two events, a `compute_identity_fingerprint`
//! permutation, `cap_findings`, `load_canonical`, a canonical method, or a
//! source-text mode this package cannot reach without a `Cargo.toml` change,
//! or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 25;
const IDENTITY_VECTOR_COUNT: usize = 10;
const VECTORS_REL: &str = "parity/vectors/checks.identity/vectors.json";

/// `covered` names a vector id in `checks.identity/vectors.json`.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from that
/// vector file.
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

/// Vector id, construct type, and whether the expected result is an error.
/// These records are successes. The vector file has no `"error"` field.
/// Top-level ids only: nested `"id": "evt"` is a fingerprint argument.
const IDENTITY_VECTORS: &[(&str, &str, bool)] = &[
    ("empty_list_silent", "identity_events", false),
    ("two_distinct_string_ids_silent", "identity_events", false),
    (
        "empty_and_whitespace_ids_ignored",
        "identity_events",
        false,
    ),
    (
        "spaced_and_trimmed_distinct_silent",
        "identity_events",
        false,
    ),
    ("mapping_bool_true_single_silent", "identity_events", false),
    ("mapping_int_neg7_single_silent", "identity_events", false),
    (
        "fingerprint_evt_sorted_hashes_ba",
        "identity_fingerprint",
        false,
    ),
    (
        "fingerprint_evt_no_payload_hashes",
        "identity_fingerprint",
        false,
    ),
    (
        "diff_field_names_zero_session_events",
        "identity_diff_field_names",
        false,
    ),
    // The id says diff_field_names. The construct type is identity_events.
    (
        "diff_field_names_one_session_event",
        "identity_events",
        false,
    ),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_identical_collapse_candidate",
        disposition: Disposition::NotApplicable(
            "load_canonical of sl003_identical.json then check_identities returns one identical-duplicate warning; duplicate SessionEvent findings are absent from checks.identity vectors, and every identity_events record has check_findings_len 0",
        ),
    },
    Row {
        name: "test_conflicting_error_manual",
        disposition: Disposition::NotApplicable(
            "load_canonical of sl003_conflicting.json then check_identities returns one conflicting-duplicate error whose differing_fields include parent_id; no identity vector records a finding",
        ),
    },
    Row {
        name: "test_mixed_and_null_ignored",
        disposition: Disposition::NotApplicable(
            "check_identities on sl003_mixed.json returns one identical-duplicate and one conflicting-duplicate and ignores two null ids; no identity vector records a finding",
        ),
    },
    Row {
        name: "test_singletons_clean",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/canonical/minimal.json then check_identities of evt_001 and evt_002 returns []; two_distinct_string_ids_silent is evt-par-id-a and evt-par-id-b and does not call load_canonical",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "check_identities on a four-event permutation keeps sorted record ids and equal fingerprints; no identity vector records a finding or a second ordering",
        ),
    },
    Row {
        name: "test_cap",
        disposition: Disposition::NotApplicable(
            "check_identities of 1500 conflicting ids at MAX_IDENTITY_FINDINGS returns an overflow-summary after the cap; no identity vector records overflow",
        ),
    },
    Row {
        name: "test_vendor_free",
        disposition: Disposition::NotApplicable(
            "identity.py contains none of claude, openai, toolUse, or call_id; no identity vector reads that source file",
        ),
    },
    Row {
        name: "test_immutability",
        disposition: Disposition::NotApplicable(
            "check_identities leaves a two-event deepcopy unchanged; no identity vector records immutability",
        ),
    },
    Row {
        name: "test_scale_100k_identical_ids",
        disposition: Disposition::NotApplicable(
            "check_identities of 100000 identical evt-scale events returns one identical-duplicate with truncated record_indexes; no identity vector records a finding",
        ),
    },
    Row {
        name: "test_fifty_variant_diffs_bounded_evidence",
        disposition: Disposition::NotApplicable(
            "check_identities of 50 conflicting evt-diverge events returns one conflicting-duplicate with 32 record indexes; no identity vector records a finding",
        ),
    },
    Row {
        name: "test_non_string_id_coercion",
        disposition: Disposition::NotApplicable(
            "check_identities of SessionEvent id 1 and id 1-as-text returns one finding with coerced true; mapping_int_neg7_single_silent is one mapping id -7 and check_findings_len 0",
        ),
    },
    // check_identities([]) == []. The construct is identity_events of events []
    // with check_findings_len 0.
    Row {
        name: "test_empty_events_list",
        disposition: Disposition::Covered {
            vector_id: "empty_list_silent",
            needles: &[
                "\"type\": \"identity_events\"",
                "\"events\": []",
                "\"check_findings_len\": 0",
            ],
        },
    },
    Row {
        name: "test_unicode_ids_codepoint_sorting",
        disposition: Disposition::NotApplicable(
            "check_identities of duplicated alpha and beta ids returns those record ids in codepoint order; no identity vector records a finding or those ids",
        ),
    },
    Row {
        name: "test_credential_in_id_suppressed_safely",
        disposition: Disposition::NotApplicable(
            "check_identities of a duplicated credential-shaped id clears source.record_id and omits that id from the message and evidence; no identity vector records a finding",
        ),
    },
    Row {
        name: "test_diff_field_names_direct",
        disposition: Disposition::NotApplicable(
            "diff_field_names of two SessionEvents returns branch_id, parent_id, payload, and seq; diff_field_names_zero_session_events has field_names_len 0 for an empty list, and diff_field_names_one_session_event is identity_events for one silent event",
        ),
    },
    Row {
        name: "test_canonical_event_alias_and_methods",
        disposition: Disposition::NotApplicable(
            "CanonicalEvent is SessionEvent and to_canonical_bytes, to_canonical_dict, canonical_bytes, canonical_hash, and payload_hash succeed; no identity vector calls those canonical methods",
        ),
    },
    Row {
        name: "test_compute_identity_fingerprint_direct",
        disposition: Disposition::NotApplicable(
            "compute_identity_fingerprint of id1 with hashes h1 then h2 equals the swapped list and has length 16; fingerprint_evt_sorted_hashes_ba is one identity_fingerprint of id evt with hashes b and a",
        ),
    },
    Row {
        name: "test_cap_findings_direct",
        disposition: Disposition::NotApplicable(
            "cap_findings of one SL003 finding with max_findings 10 returns that finding; empty_list_silent records cap_findings_len 0 beside an empty identity_events list",
        ),
    },
    Row {
        name: "test_diff_field_names_none_vs_missing",
        disposition: Disposition::NotApplicable(
            "diff_field_names reports experimental_foo and check_identities returns one conflicting-duplicate; diff_field_names_zero_session_events is an empty list with field_names_len 0, and no identity vector records that finding",
        ),
    },
    Row {
        name: "test_empty_and_whitespace_id_ignored",
        disposition: Disposition::NotApplicable(
            "check_identities of two empty-string ids and two three-space ids returns []; empty_and_whitespace_ids_ignored is a different sweep with one of each blank form, mappings, null, and evt-par-id-only",
        ),
    },
    Row {
        name: "test_mapping_event_duck_typing",
        disposition: Disposition::NotApplicable(
            "check_identities of two identical evt-map dicts returns one identical-duplicate; mapping_bool_true_single_silent and mapping_int_neg7_single_silent are one silent mapping each",
        ),
    },
    Row {
        name: "test_windows_backslash_path_normalization",
        disposition: Disposition::NotApplicable(
            "check_identities with a backslash source_path stores forward slashes; no identity vector sets source_path",
        ),
    },
    Row {
        name: "test_source_line_zero_or_negative_guarded",
        disposition: Disposition::NotApplicable(
            "check_identities of two events with source_line 0 stores source.line None; no identity vector records source_line",
        ),
    },
    Row {
        name: "test_cap_findings_overflow_schema_valid",
        disposition: Disposition::NotApplicable(
            "check_identities with max_findings 2 returns an overflow-summary that parse_finding_dict round-trips; no identity vector records overflow or parse_finding_dict",
        ),
    },
    Row {
        name: "test_provenance_coordinates_do_not_cause_conflicting_duplicate",
        disposition: Disposition::NotApplicable(
            "check_identities treats differing source_line, source_location, and source_record_hash as identical-duplicate and a payload change as conflicting-duplicate; no identity vector records either finding",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_identical_collapse_candidate",
    "test_conflicting_error_manual",
    "test_mixed_and_null_ignored",
    "test_singletons_clean",
    "test_determinism",
    "test_cap",
    "test_vendor_free",
    "test_immutability",
    "test_scale_100k_identical_ids",
    "test_fifty_variant_diffs_bounded_evidence",
    "test_non_string_id_coercion",
    "test_empty_events_list",
    "test_unicode_ids_codepoint_sorting",
    "test_credential_in_id_suppressed_safely",
    "test_diff_field_names_direct",
    "test_canonical_event_alias_and_methods",
    "test_compute_identity_fingerprint_direct",
    "test_cap_findings_direct",
    "test_diff_field_names_none_vs_missing",
    "test_empty_and_whitespace_id_ignored",
    "test_mapping_event_duck_typing",
    "test_windows_backslash_path_normalization",
    "test_source_line_zero_or_negative_guarded",
    "test_cap_findings_overflow_schema_valid",
    "test_provenance_coordinates_do_not_cause_conflicting_duplicate",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested fingerprint ids are indented further.
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
        .unwrap_or_else(|| panic!("checks.identity vectors.json is missing id {id}"));
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
fn every_pinned_identity_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(IDENTITY_VECTORS.len(), IDENTITY_VECTOR_COUNT);
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
    assert_eq!(covered, 1);
    assert_eq!(not_applicable, 24);
}

#[test]
fn covered_vector_ids_are_present_in_identity_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "identity vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.identity\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = IDENTITY_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in IDENTITY_VECTORS {
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
