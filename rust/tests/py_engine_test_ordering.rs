//! Dispositions for the 3 `def test_` functions in pinned `tests/engine/test_ordering.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (203 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.determinism`, `sesslint.finding`,
//! or `sesslint.report`.
//!
//! `covered` names one id in `determinism/vectors.json` whose construct is the
//! same function and the same success or failure mode as that entire pinned test.
//! One example inside a sweep, a different input string, or a shared field such as
//! `schema_version` is not coverage. `not_applicable` records a call this package
//! cannot reach without a `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 3;
const DETERMINISM_VECTOR_COUNT: usize = 8;
const VECTORS_REL: &str = "parity/vectors/determinism/vectors.json";

/// `covered` names a vector id in `determinism/vectors.json`. `not_applicable`
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

/// Vector id and construct type recorded in `determinism/vectors.json`.
const DETERMINISM_VECTORS: &[(&str, &str)] = &[
    (
        "determinism_canonical_json_bytes_newline_true",
        "canonical_json_bytes",
    ),
    (
        "determinism_canonical_json_bytes_newline_false",
        "canonical_json_bytes",
    ),
    (
        "determinism_finding_sort_key_path_order",
        "finding_sort_key",
    ),
    ("determinism_repeat_hash_bytes", "repeat_hash"),
    ("determinism_repeat_hash_text", "repeat_hash"),
    ("determinism_repeat_hash_json_object", "repeat_hash"),
    (
        "determinism_stable_sort_paths_and_stability",
        "stable_sort_findings",
    ),
    ("determinism_module_all_export_order", "module_all"),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_shuffled_findings_sort_identically",
        disposition: Disposition::NotApplicable(
            "stable_sort_findings on four session.jsonl findings shuffled ten times with seed 0x026 must match one sorted reference; determinism_stable_sort_paths_and_stability is three parity/stab findings with ordered_paths and ordered_message_templates, not that quartet or shuffle loop",
        ),
    },
    Row {
        name: "test_event_dict_permutation_produces_identical_bytes",
        disposition: Disposition::NotApplicable(
            "canonical_json_bytes and repeat_hash on two evt_001 event dicts with permuted key order must match; determinism_canonical_json_bytes_newline_true and determinism_canonical_json_bytes_newline_false are café/zz objects with newline flags, and determinism_repeat_hash_json_object hashes a different z/a map",
        ),
    },
    Row {
        name: "test_fr094_position_first_exact_order_three_entry_points",
        disposition: Disposition::NotApplicable(
            "ten findings spanning FR-094 tie levels must sort identically under sort_findings, stable_sort_findings, and render_json findings fingerprints across five shuffled permutations with seed 0x094; no determinism, finding, or report vector is that multi-entry-point sweep, and sort_findings_path_line_severity is one six-finding path-line-severity list",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_shuffled_findings_sort_identically",
    "test_event_dict_permutation_produces_identical_bytes",
    "test_fr094_position_first_exact_order_three_entry_points",
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
        .unwrap_or_else(|| panic!("determinism vectors.json is missing id {id}"));
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
fn every_pinned_engine_ordering_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(DETERMINISM_VECTORS.len(), DETERMINISM_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_determinism_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "determinism vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.determinism\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = DETERMINISM_VECTORS.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct) in DETERMINISM_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
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
