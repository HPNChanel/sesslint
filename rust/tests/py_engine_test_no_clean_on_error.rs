//! Dispositions for the 4 `def test_` functions in pinned
//! `tests/engine/test_no_clean_on_error.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (114 splitlines).
//! `hostile_error_fixtures` is a module-scoped pytest fixture, not a test; the
//! first three pinned functions iterate that full hostile error fixture list.
//! Each row is the entire function, not one fixture row. A healthy exit-zero
//! vector, a missing-path raise, or one hostile file is not the never-clean
//! sweep. This integration test crate links `sesslint-rust-workspace`, whose
//! library exports [`PACKAGE_NAME`] only.
//!
//! `parity/vectors/report/vectors.json` at commit `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`
//! is not used for coverage here.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 4;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. `not_applicable` names the missing stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// Present so a later whole-pytest vector can be claimed. None qualifies.
    #[expect(dead_code)]
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
        name: "test_hostile_fixtures_never_verdict_clean_in_api",
        disposition: Disposition::NotApplicable(
            "no cli vector is check_file on every hostile_error_fixtures row asserting assurance A0 or A1, nonempty findings, and at least one error or fatal severity count; check_file is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_hostile_fixtures_never_verdict_clean_in_cli_human",
        disposition: Disposition::NotApplicable(
            "no cli vector is main check on every hostile_error_fixtures row asserting nonzero exit and human stdout excluding valid canonical session, valid claude code session, and valid openai agents session; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_hostile_fixtures_never_verdict_clean_in_cli_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is main check with json on every hostile_error_fixtures row asserting nonzero exit and parsed JSON with verdict not clean or healthy when present, assurance A0 or A1 when present, and nonempty findings when present; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_recursive_directory_scan_detects_all_hostile",
        disposition: Disposition::NotApplicable(
            "no cli vector is check_dir recursive on fixtures hostile asserting totals invalid or unsupported or unreadable positive and total positive, then main check on that directory exit 1, then main check with -r exit 2; removed_flag_hint_recursive_short is only a removed -r hint, not that sweep; check_dir and main are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_hostile_fixtures_never_verdict_clean_in_api",
    "test_hostile_fixtures_never_verdict_clean_in_cli_human",
    "test_hostile_fixtures_never_verdict_clean_in_cli_json",
    "test_recursive_directory_scan_detects_all_hostile",
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
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
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
fn pinned_no_clean_on_error_row_count_equals_four() {
    assert_eq!(ROWS.len(), 4);
    assert_eq!(PINNED_TEST_COUNT, 4);
}

#[test]
fn every_pinned_no_clean_on_error_test_has_one_disposition() {
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
fn covered_vector_ids_are_present_in_cli_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
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
