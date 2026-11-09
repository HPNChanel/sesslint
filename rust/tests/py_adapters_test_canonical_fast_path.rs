//! Dispositions for the 2 `def test_` functions in pinned
//! `tests/adapters/test_canonical_fast_path.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (87 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `adapters.canonical/vectors.json` whose construct
//! is the same function and the same success or failure mode as that entire
//! pinned test. One parametrized row inside an equivalence sweep, a patched
//! `_common_event`, or a shared helper such as `load_canonical` is not
//! coverage. `not_applicable` records a `sesslint.adapters.canonical` call
//! this package cannot reach without a `Cargo.toml` change, or a mode no vector
//! records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 2;
const ADAPTERS_CANONICAL_VECTOR_COUNT: usize = 44;
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
const ADAPTERS_CANONICAL_VECTORS: &[(&str, &str, bool)] = &[
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
    ("body_missing_path", "load_canonical_body", false),
    ("body_whitespace_only", "load_canonical_body", false),
    ("body_empty_object", "load_canonical_body", false),
    ("body_nul_gate", "load_canonical_body", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_common_matches_diagnostic",
        disposition: Disposition::NotApplicable(
            "_parse_canonical_event_record with _common_event patched to None must equal the fast path across fourteen parametrized field mutations; no adapters.canonical vector calls _parse_canonical_event_record or records that mock equivalence",
        ),
    },
    Row {
        name: "test_stream_depth_matches_full_record_validation",
        disposition: Disposition::NotApplicable(
            "load_canonical with _common_event disabled must match the full parser across depth, ReaderLimits.max_depth, critical_future extension, interleaved invalid and clean siblings, and two repeated loads; gap_load vectors pin load_canonical hygiene seams, not that fast-versus-diagnostic equality grid",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_common_matches_diagnostic",
    "test_stream_depth_matches_full_record_validation",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
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
fn every_pinned_adapters_canonical_fast_path_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(ADAPTERS_CANONICAL_VECTORS.len(), ADAPTERS_CANONICAL_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_adapters_canonical_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "adapters.canonical vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.adapters.canonical\""));
    assert!(
        json.contains("GAP-canonical-secret-scan-tracker"),
        "adapters.canonical vectors record the load_canonical hygiene seam"
    );

    let ids = vector_ids(&json);
    let expected: Vec<&str> = ADAPTERS_CANONICAL_VECTORS
        .iter()
        .map(|(id, _, _)| *id)
        .collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in ADAPTERS_CANONICAL_VECTORS {
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
