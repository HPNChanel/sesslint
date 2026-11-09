//! Dispositions for the 5 `def test_` functions in pinned `tests/test_e2e_cycle.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (260 splitlines). Each row is
//! the entire check, repair, verify, and re-check cycle asserted in that
//! function, including CLI stdout or JSON capture where the pytest uses `main`.
//! One check, one repair, or one verify stop alone is not the cycle. This
//! integration test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `parity/vectors/report/vectors.json` at commit `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`
//! is not used for coverage here.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 5;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest end-to-end cycle. `not_applicable` names the missing stop.
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
        name: "test_e2e_cycle_canonical_identical_duplicates",
        disposition: Disposition::NotApplicable(
            "no cli vector is api.check_file then api.repair then api.verify then api.check_file on a canonical SL003 duplicate session asserting one SL003 finding and A2 assurance, verify ok with every check ok, recheck zero findings with A4 and zero error and warning counts, and a second repair whose output bytes match the first repair; api.check_file, api.repair, and api.verify are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_e2e_cycle_canonical_torn_terminal_record",
        disposition: Disposition::NotApplicable(
            "no cli vector is api.check_file then api.repair then api.verify then api.check_file on a canonical SL002 torn terminal session asserting SL002 with A0 assurance, verify ok, and recheck zero findings with A4; api.check_file, api.repair, and api.verify are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_e2e_cli_full_cycle",
        disposition: Disposition::NotApplicable(
            "no cli vector is main check then main repair then main verify with json then main check on a duplicate canonical session asserting exit code zero at each step, initial stdout mentions warning count or SL003, verify stdout JSON ok true, and final stdout Session is healthy with errors zero and warnings zero; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_e2e_vendor_format_writeback",
        disposition: Disposition::NotApplicable(
            "no cli vector is api.check_file SL002 on torn vendor adapter input then main repair with vendor write-back then byte identity of surviving adapter records then api.check_file without error or fatal severity then main verify exit zero; api.check_file and main are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_e2e_cycle_non_neutral_profile_binding",
        disposition: Disposition::NotApplicable(
            "no cli vector is api.repair under profile claude-strict then manifest revalidation profile_id and profile_version bindings then api.verify without plan file then api.verify with plan file under the same binding; api.repair and api.verify are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_e2e_cycle_canonical_identical_duplicates",
    "test_e2e_cycle_canonical_torn_terminal_record",
    "test_e2e_cli_full_cycle",
    "test_e2e_vendor_format_writeback",
    "test_e2e_cycle_non_neutral_profile_binding",
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
fn every_pinned_e2e_cycle_test_has_one_disposition() {
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
