//! Dispositions for the 2 `def test_` functions in pinned `tests/fuzz/test_fuzz_secret_casefold.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (56 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! The pinned module is Hypothesis property tests over `sesslint.checks.hygiene`
//! ASCII shadow scanning (`_GENERIC_ASSIGNMENT_LOWER` vs `REFERENCE`) and
//! `SecretScanTracker` digests on original bytes. `covered` names a vector id
//! whose construct is the same function and the same success or failure mode as
//! that entire pinned test. `not_applicable` records a property sweep no vector
//! has. This package has no proptest and cannot run those generated sweeps.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 2;
const HYGIENE_VECTOR_COUNT: usize = 95;
const VECTORS_REL: &str = "parity/vectors/checks.hygiene/vectors.json";

/// `covered` names a vector id in `checks.hygiene/vectors.json`.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
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
        name: "test_folded_scanner_is_span_equivalent",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given over keyword, middle, value, prefix, and suffix equating lower-shadow group-1 spans to REFERENCE.finditer; no hygiene or secret_families vector is that generated sweep",
        ),
    },
    Row {
        name: "test_tracker_hashes_original_case_sensitive_bytes",
        disposition: Disposition::NotApplicable(
            "Parametrized keywords with two case-distinct synthetic values, occurrence_count 2, distinct match_sha256 digests, and content-free str(to_dict); hygiene_tracker vectors are single-feed snapshots, not that full parametrized contract",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_folded_scanner_is_span_equivalent",
    "test_tracker_hashes_original_case_sensitive_bytes",
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
        .unwrap_or_else(|| panic!("checks.hygiene vectors.json is missing id {id}"));
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
fn every_pinned_fuzz_secret_casefold_test_has_one_disposition() {
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
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_hygiene_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "checks.hygiene vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.hygiene\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), HYGIENE_VECTOR_COUNT);
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
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
