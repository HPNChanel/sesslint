//! Dispositions for the 5 `def test_` functions in pinned `tests/test_rule_docs.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (89 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! The pinned module imports `CODE_REGISTRY` from `sesslint.codes` but each test
//! is a repository `docs/codes` layout gate. `covered` names a vector id in
//! `codes/vectors.json` whose construct is the same check as that pinned test.
//! `not_applicable` records a docs-tree or markdown-structure check no vector
//! has; reaching `sesslint.codes` from this package would require a `Cargo.toml`
//! change, and a single `code_registry_row` is not that full gate.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 5;
const CODES_VECTOR_COUNT: usize = 46;
const VECTORS_REL: &str = "parity/vectors/codes/vectors.json";

/// `covered` names a vector id in `codes/vectors.json`. `not_applicable` records
/// a check this package cannot reach without a `Cargo.toml` change, or a mode
/// absent from that vector file.
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
        name: "test_codes_directory_exists",
        disposition: Disposition::NotApplicable(
            "docs/codes directory existence; no codes vector checks that repo path is a directory",
        ),
    },
    Row {
        name: "test_all_registry_codes_have_docs",
        disposition: Disposition::NotApplicable(
            "every CODE_REGISTRY key has docs/codes/{code}.md; code_registry_row is one code, not that completeness sweep",
        ),
    },
    Row {
        name: "test_no_extra_or_stale_code_docs",
        disposition: Disposition::NotApplicable(
            "docs/codes SL*.md set minus registry keys; no codes vector glob-compares that tree",
        ),
    },
    Row {
        name: "test_code_doc_structure_and_sections",
        disposition: Disposition::NotApplicable(
            "per-code markdown title and REQUIRED_SECTIONS headings; no codes vector reads doc files",
        ),
    },
    Row {
        name: "test_code_doc_fixture_reference_exists",
        disposition: Disposition::NotApplicable(
            "Tested Fixture Path regex and fixture file on disk; no codes vector resolves doc fixture paths",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_codes_directory_exists",
    "test_all_registry_codes_have_docs",
    "test_no_extra_or_stale_code_docs",
    "test_code_doc_structure_and_sections",
    "test_code_doc_fixture_reference_exists",
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
        .unwrap_or_else(|| panic!("codes vectors.json is missing id {id}"));
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
fn every_pinned_rule_doc_test_has_one_disposition() {
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
}

#[test]
fn covered_vector_ids_are_present_in_codes_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "codes vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.codes\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), CODES_VECTOR_COUNT);
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
