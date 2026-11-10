//! Dispositions for the eleven test functions in pinned
//! `tests/test_bench_smoke.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (205 splitlines). Exactly
//! eleven test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helpers `_write_notes` and `_fields` are not tests.
//! `_VALID_BLOCK` is not a test. A committed benchmark block is not a whole
//! pytest by itself.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these eleven names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these eleven names.
//! `parity/vectors/reference/vectors.json` has 12 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Those ids are module exports
//! and `reference_equivalent` probes. They are not
//! `verify_reference_disclosure_recorded`, and that old pin is not a Covered
//! source.
//! `parity/vectors/scan/vectors.json` has 21 ids and
//! `parity/vectors/finding/vectors.json` has 22 ids, both on that old pin.
//! Those corpora are not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `check_file`,
//! `run_benchmark`, or `verify_reference_disclosure_recorded` without a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const PINNED_SPLITLINES: usize = 205;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these eleven functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. A committed benchmark block is not a whole pytest by
/// itself. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
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
        name: "test_bench_smoke_assertions",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bench_smoke_assertions: check_file has an empty findings list, assurance A4, an error count of 0, and a warning count of 0, and run_benchmark returns 0; the docstring, the generator size, and the call budgets are not assertions; missing stop: that empty list, that assurance, those two zero counts, and that zero exit together; The functional-failure test is not this; test_bench_functional_failure_not_excused is that functional-failure test",
        ),
    },
    Row {
        name: "test_bench_functional_failure_not_excused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bench_functional_failure_not_excused: run_benchmark returns 1; the patched check_file, the constructed finding, and the comment are not assertions; missing stop: that exit 1 together; The smoke assertion is not this; test_bench_smoke_assertions is that smoke assertion",
        ),
    },
    Row {
        name: "test_reference_validator_accepts_committed_block",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reference_validator_accepts_committed_block: verify_reference_disclosure_recorded returns true; the docstring is not an assertion; a committed benchmark block is not a whole pytest by itself; missing stop: that true result together; The missing-fields reject is not this; test_reference_validator_missing_fields is that missing-fields reject",
        ),
    },
    Row {
        name: "test_reference_validator_missing_fields",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reference_validator_missing_fields: verify_reference_disclosure_recorded returns false after the input-size field is emptied; missing stop: that false result together; The committed-block accept is not this; test_reference_validator_accepts_committed_block is that committed-block accept",
        ),
    },
    Row {
        name: "test_reference_validator_stale_status_mismatch",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reference_validator_stale_status_mismatch: verify_reference_disclosure_recorded returns false after status is set to PASS; the docstring is not an assertion; missing stop: that false result together; The partial-breach reject is not this; test_reference_validator_partial_breach_classes is that partial-breach reject",
        ),
    },
    Row {
        name: "test_reference_validator_partial_breach_classes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reference_validator_partial_breach_classes: verify_reference_disclosure_recorded returns false after breach classes names only time; missing stop: that false result together; The missing-date-or-host reject is not this; test_reference_validator_missing_date_or_host is that missing-date-or-host reject",
        ),
    },
    Row {
        name: "test_reference_validator_missing_date_or_host",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reference_validator_missing_date_or_host: verify_reference_disclosure_recorded returns false after the date is emptied and returns false after the host is emptied; the docstring is not an assertion; missing stop: those two false results together; The no-markers reject is not this; test_reference_validator_no_markers is that no-markers reject",
        ),
    },
    Row {
        name: "test_reference_validator_no_markers",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reference_validator_no_markers: verify_reference_disclosure_recorded returns false when the notes contain no baseline markers; missing stop: that false result together; The consistent-pass accept is not this; test_reference_validator_pass_run_consistent is that consistent-pass accept",
        ),
    },
    Row {
        name: "test_reference_validator_pass_run_consistent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reference_validator_pass_run_consistent: verify_reference_disclosure_recorded returns true after the time field and the peak-memory field are replaced, breach classes are none, and status is PASS; the docstring is not an assertion; missing stop: that true result together; The no-markers reject is not this; test_reference_validator_no_markers is that no-markers reject",
        ),
    },
    Row {
        name: "test_benchmark_current_run_disclosure_on_breach",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_benchmark_current_run_disclosure_on_breach: run_benchmark returns 1, stdout contains a run-context label, a date key, and a host key, and the combined output contains breach classes for time and memory and a budget word; it does not assert the validator; the call budgets and the docstring are not assertions; missing stop: that exit 1 and those output checks together; The valid-reference breach test is not this; test_benchmark_breach_nonzero_even_with_valid_reference is that valid-reference breach test",
        ),
    },
    Row {
        name: "test_benchmark_breach_nonzero_even_with_valid_reference",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_benchmark_breach_nonzero_even_with_valid_reference: verify_reference_disclosure_recorded returns true and run_benchmark returns 1; reading the capture is not an assertion; the call budgets and the docstring are not assertions; missing stop: that true result and that exit 1 together; The disclosure test is not this; test_benchmark_current_run_disclosure_on_breach is that disclosure test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_bench_smoke_assertions",
    "test_bench_functional_failure_not_excused",
    "test_reference_validator_accepts_committed_block",
    "test_reference_validator_missing_fields",
    "test_reference_validator_stale_status_mismatch",
    "test_reference_validator_partial_breach_classes",
    "test_reference_validator_missing_date_or_host",
    "test_reference_validator_no_markers",
    "test_reference_validator_pass_run_consistent",
    "test_benchmark_current_run_disclosure_on_breach",
    "test_benchmark_breach_nonzero_even_with_valid_reference",
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
fn pinned_test_bench_smoke_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 205);
}

#[test]
fn pinned_test_bench_smoke_row_count_equals_eleven() {
    assert_eq!(ROWS.len(), 11);
    assert_eq!(PINNED_TEST_COUNT, 11);
    assert_eq!(PINNED_NAMES.len(), 11);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_bench_smoke_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 11);
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
    assert_eq!(not_applicable, 11);

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
