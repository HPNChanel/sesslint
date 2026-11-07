//! Dispositions for the 3 `def test_` functions in pinned `tests/test_properties.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (111 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! The pinned module is Hypothesis property tests over `sesslint.finding` and
//! `sesslint.canonical`. `covered` names a vector id whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! `not_applicable` records a property sweep or operator contract no vector has.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 3;
const FINDING_VECTOR_COUNT: usize = 22;
const FINDING_VECTORS_REL: &str = "parity/vectors/finding/vectors.json";
const CANONICAL_VECTORS_REL: &str = "parity/vectors/canonical/vectors.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum VectorSource {
    Finding,
    Canonical,
}

/// `covered` names a vector id in `finding/vectors.json` or `canonical/vectors.json`.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change, or a mode absent from those vector files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum Disposition {
    Covered {
        source: VectorSource,
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
        name: "test_finding_sort_is_idempotent",
        disposition: Disposition::NotApplicable(
            "Hypothesis sort_findings twice with list equality; sort_findings_path_line_severity is one fixed-order example, not idempotency over generated lists",
        ),
    },
    Row {
        name: "test_finding_ordering_totality",
        disposition: Disposition::NotApplicable(
            "Finding rich comparison lt, gt, and eq across random pairs; finding_sort_key is a key tuple, not dataclass operator totality",
        ),
    },
    Row {
        name: "test_canonical_json_roundtrip_and_determinism",
        disposition: Disposition::NotApplicable(
            "Hypothesis to_canonical_json and canonical_bytes over arbitrary JSON; canonical vectors omit those calls per known_parity_gaps and are single-shot parse vectors",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_finding_sort_is_idempotent",
    "test_finding_ordering_totality",
    "test_canonical_json_roundtrip_and_determinism",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
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
        .unwrap_or_else(|| panic!("vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_canonical_vectors_pinned() {
    let path = vectors_path(CANONICAL_VECTORS_REL);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "canonical vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.canonical\""));
}

fn read_vectors(rel: &str, module: &str, count: usize) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(json.contains(&format!("\"module\": \"{module}\"")));
    let ids = vector_ids(&json);
    assert_eq!(ids.len(), count);
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), count);
    json
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_properties_test_has_one_disposition() {
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
            Disposition::Covered {
                source: _,
                vector_id,
                needles,
            } => {
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
fn covered_vector_ids_are_present_in_parity_vectors() {
    let finding = read_vectors(
        FINDING_VECTORS_REL,
        "sesslint.finding",
        FINDING_VECTOR_COUNT,
    );
    assert_canonical_vectors_pinned();

    let finding_ids: BTreeSet<&str> = vector_ids(&finding).into_iter().collect();

    for row in ROWS {
        let Disposition::Covered {
            source,
            vector_id,
            needles,
        } = row.disposition
        else {
            continue;
        };
        let (json, id_set) = match source {
            VectorSource::Finding => (&finding, &finding_ids),
            VectorSource::Canonical => {
                panic!(
                    "{} names canonical vector {vector_id}; canonical vectors embed event ids and are not counted here",
                    row.name
                );
            }
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
