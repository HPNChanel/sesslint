//! Dispositions for the six test functions in pinned
//! `tests/scan/test_read_errors.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (155 splitlines). Exactly
//! six test functions, in module order. None is parametrized. Each row is the
//! whole function. A docstring is not an assertion. A comment is not an
//! assertion. Nested `crashing_checks`, `too_large_checks`, and
//! `exploding_scan` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these six names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these six names.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! A scan vector that only says unreadable is not the whole pytest, and that
//! old pin is not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `check_dir`, `check_file`,
//! or `scan_path` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 6;
const PINNED_SPLITLINES: usize = 155;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these six functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A scan vector that only says unreadable is not the whole pytest.
/// `not_applicable` names the missing stop and the nearest different test.
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
        name: "test_binary_file_classified_as_unreadable",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_binary_file_classified_as_unreadable: recursive check_dir on the directory whose only file was written with write_bytes reports len(files) 1, files[0].verdict unreadable, totals.unreadable 1, and totals.healthy 0; a scan vector that only says unreadable is not the whole pytest; missing stop: that file count, that unreadable verdict, that unreadable total, and that healthy total together; The invalid-UTF-8 classification is not this; test_invalid_utf8_classified_as_unreadable is that invalid-UTF-8 classification",
        ),
    },
    Row {
        name: "test_invalid_utf8_classified_as_unreadable",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_invalid_utf8_classified_as_unreadable: recursive check_dir on the directory whose only file was written with write_bytes that are not UTF-8 reports len(files) 1, files[0].verdict unreadable, totals.unreadable 1, and totals.healthy 0; a scan vector that only says unreadable is not the whole pytest; missing stop: that file count, that unreadable verdict, that unreadable total, and that healthy total together; The binary-file classification is not this; test_binary_file_classified_as_unreadable is that binary-file classification",
        ),
    },
    Row {
        name: "test_check_file_nonexistent_raises_filenotfound",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_nonexistent_raises_filenotfound: check_file on the missing path raises FileNotFoundError; it does not assert a message; missing stop: that FileNotFoundError together; The invalid-UTF-8 classification is not this; test_invalid_utf8_classified_as_unreadable is that invalid-UTF-8 classification",
        ),
    },
    Row {
        name: "test_scan_fault_isolation_on_unhandled_exception",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_fault_isolation_on_unhandled_exception: recursive check_dir reports totals.healthy 1 and totals.invalid 1, the file whose path contains crashing has verdict invalid, and findings[0].message contains Failed to process file; missing stop: that healthy total, that invalid total, that invalid verdict, and that finding text together; The missing-path FileNotFoundError is not this; test_check_file_nonexistent_raises_filenotfound is that missing-path FileNotFoundError",
        ),
    },
    Row {
        name: "test_scan_fault_isolation_on_file_too_large",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_fault_isolation_on_file_too_large: recursive check_dir reports totals.healthy 1 and totals.skipped 1, the file whose path contains huge has verdict skipped, skipped_reason file-too-large, and no findings; missing stop: that healthy total, that skipped total, that skipped verdict, that skipped reason, and that empty findings together; The unhandled-exception invalid file is not this; test_scan_fault_isolation_on_unhandled_exception is that unhandled-exception invalid file",
        ),
    },
    Row {
        name: "test_scan_fault_isolation_on_unhandled_scan_single_file_exception",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_fault_isolation_on_unhandled_scan_single_file_exception: recursive check_dir reports totals.healthy 1 and totals.unreadable 1, the file whose path contains fatal has verdict unreadable and error_count 1, and findings[0].message contains INTERNAL_ERROR; a scan vector that only says unreadable is not the whole pytest; missing stop: that healthy total, that unreadable total, that unreadable verdict, that error count, and that INTERNAL_ERROR text together; The file-too-large skip is not this; test_scan_fault_isolation_on_file_too_large is that file-too-large skip",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_binary_file_classified_as_unreadable",
    "test_invalid_utf8_classified_as_unreadable",
    "test_check_file_nonexistent_raises_filenotfound",
    "test_scan_fault_isolation_on_unhandled_exception",
    "test_scan_fault_isolation_on_file_too_large",
    "test_scan_fault_isolation_on_unhandled_scan_single_file_exception",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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

fn vector_slice<'a>(json: &'a str, id: &str, corpus: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("{corpus} vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_python_commit_one_space(json: &str, corpus: &str) {
    // The corpus stores one space after the colon.
    let commit = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&commit),
        "{corpus} vectors python_commit spacing does not match {commit}"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "{corpus} python_commit has no space after the colon"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":  \"{PIN}\"")),
        "{corpus} python_commit has more than one space after the colon"
    );
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_scan_test_read_errors_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 155);
}

#[test]
fn pinned_scan_test_read_errors_row_count_equals_six() {
    assert_eq!(ROWS.len(), 6);
    assert_eq!(PINNED_TEST_COUNT, 6);
    assert_eq!(PINNED_NAMES.len(), 6);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_scan_test_read_errors_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 6);
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
                assert!(
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
                    row.name
                );
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
    let json = read_vectors(CLI_VECTORS_REL);
    assert_python_commit_one_space(&json, "cli");
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
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
        let slice = vector_slice(&json, vector_id, "cli");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}

#[test]
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 6);

    let json = read_vectors(API_VECTORS_REL);
    assert_python_commit_one_space(&json, "api");
    assert!(json.contains("\"module\": \"sesslint.api\""));

    let ids = vector_ids(&json);
    assert_eq!(API_VECTOR_COUNT, 77);
    assert_eq!(ids.len(), API_VECTOR_COUNT);
    assert_eq!(ids.len(), 77);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    assert_eq!(id_set.len(), 77);
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
    }
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "api");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
