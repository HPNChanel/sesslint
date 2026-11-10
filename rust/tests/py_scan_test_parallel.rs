//! Dispositions for the sixteen test functions in pinned
//! `tests/scan/test_parallel.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (184 splitlines). Exactly
//! sixteen test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helper `_build_tree` is not a test.
//! `FIXTURES_DIR`, `HEALTHY`, and `MIXED_DIR` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these sixteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these sixteen names. An API vector that only calls
//! `check_dir` or `scan` with `jobs` is not one of these pytests unless it
//! is the entire function.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `session_link_wire_round_trip` builds one SessionLink wire. It is not a
//! FileResult round trip, and that old pin is not a Covered source.
//! `parity/vectors/finding/vectors.json` has 22 ids on that old pin.
//! `parse_round_trip_complete` builds one Finding wire. It is not the mixed
//! directory finding round trip. Those corpora are not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `scan_path`, `check_dir`,
//! `FileResult`, `Finding`, or `main` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 16;
const PINNED_SPLITLINES: usize = 184;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these sixteen functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// An API vector that only calls `check_dir` or `scan` with `jobs` is not
/// this pytest unless it is the entire function.
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
        name: "test_file_result_wire_roundtrip_with_findings",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_file_result_wire_roundtrip_with_findings: a recursive scan of the mixed directory with no jobs argument has a non-empty files list, and each file equals FileResult.from_wire of to_wire with equal findings; it does not assert Finding.from_dict; missing stop: that non-empty files list and those two equalities on every file together; session_link_wire_round_trip is on the old pin and is not this pytest; The finding dict round trip is not this; test_finding_from_dict_roundtrip is that finding dict round trip",
        ),
    },
    Row {
        name: "test_finding_from_dict_roundtrip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_finding_from_dict_roundtrip: a recursive scan of the mixed directory with no jobs argument collects a non-empty findings list, and Finding.from_dict of to_dict equals each finding; it does not assert FileResult wire equality; missing stop: that non-empty list and that equal restored finding together; parse_round_trip_complete is on the old pin and is not this pytest; The skipped FileResult round trip is not this; test_wire_roundtrip_skipped_result is that skipped FileResult round trip",
        ),
    },
    Row {
        name: "test_wire_roundtrip_skipped_result",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_wire_roundtrip_skipped_result: one FileResult with path x/y.jsonl, verdict skipped, and skipped_reason symlink-skipped equals FileResult.from_wire of to_wire; it does not scan and it does not assert findings; missing stop: that one equal restored result together; The jobs 1 versus jobs 4 byte comparison is not this; test_parallel_output_byte_identical is that jobs 1 versus jobs 4 byte comparison",
        ),
    },
    Row {
        name: "test_parallel_output_byte_identical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_output_byte_identical: recursive scans of one built tree with jobs 1 and jobs 4 have equal to_json, equal totals, and equal file paths in order; missing stop: that json, those totals, and that path order together; The repeated jobs 4 comparison is not this; test_parallel_repeat_runs_identical is that repeated jobs 4 comparison",
        ),
    },
    Row {
        name: "test_parallel_repeat_runs_identical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_repeat_runs_identical: two recursive scans of one built tree, both with jobs 4, have equal to_json; it does not assert totals or path order; missing stop: that equal json together; The mixed-directory jobs comparison is not this; test_parallel_mixed_fixture_matches_sequential is that mixed-directory jobs comparison",
        ),
    },
    Row {
        name: "test_parallel_mixed_fixture_matches_sequential",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_mixed_fixture_matches_sequential: recursive scans of the mixed directory with jobs 1 and jobs 3 have equal to_json, and the sequential totals.total is at least 4; it does not assert equal totals or path order; missing stop: that equal json and that minimum total together; The fixtures-directory totals comparison is not this; test_parallel_fixtures_tree_byte_identical_to_sequential is that fixtures-directory totals comparison",
        ),
    },
    Row {
        name: "test_parallel_fixtures_tree_byte_identical_to_sequential",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_fixtures_tree_byte_identical_to_sequential: recursive scans of the fixtures directory with jobs 1 and jobs 4 have equal to_json, equal totals.total, and totals.total greater than 0; the docstring is not an assertion; it does not assert path order or the whole totals object; missing stop: that equal json, that equal total, and that positive total together; The spawn start-method test is not this; test_parallel_pool_start_method_is_spawn is that spawn start-method test",
        ),
    },
    Row {
        name: "test_parallel_pool_start_method_is_spawn",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_pool_start_method_is_spawn: the patched pool factory requires mp_context to be a BaseContext, the recorded start methods equal spawn, and a recursive jobs 2 scan has totals.total at least 1; the docstring is not an assertion; the type-ignore comment is not an assertion; missing stop: that context type, that spawn list, and that minimum total together; The sorted progress-name test is not this; test_parallel_progress_emits_in_file_order is that sorted progress-name test",
        ),
    },
    Row {
        name: "test_parallel_progress_emits_in_file_order",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_progress_emits_in_file_order: a recursive jobs 3 scan with a progress callback has sorted non-None items equal to the sorted file names under the tree; it does not assert callback order; missing stop: that sorted equality together; The jobs ValueError test is not this; test_jobs_validation is that jobs ValueError test",
        ),
    },
    Row {
        name: "test_jobs_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_jobs_validation: recursive scans of the mixed directory with jobs 0, jobs -2, and jobs True each raise ValueError matching jobs; the type-ignore comment is not an assertion; missing stop: those three raises together; The single-file jobs json comparison is not this; test_single_file_ignores_jobs is that single-file jobs json comparison",
        ),
    },
    Row {
        name: "test_single_file_ignores_jobs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_file_ignores_jobs: scans of one file with jobs 1 and jobs 4 have equal to_json; it does not recurse and it does not assert totals; missing stop: that equal json together; The CLI json jobs 4 scan is not this; test_cli_scan_jobs_json is that CLI json jobs 4 scan",
        ),
    },
    Row {
        name: "test_cli_scan_jobs_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_jobs_json: main scan of a built tree with --json and --jobs 4 returns code 0 or 1, stdout parses as json, schema_version is sesslint.scan-report/v1, and totals.total equals the files length; missing stop: that code set, that parsed object, that schema version, and that equal length together; The CLI auto jobs scan is not this; test_cli_scan_jobs_auto is that CLI auto jobs scan",
        ),
    },
    Row {
        name: "test_cli_scan_jobs_auto",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_jobs_auto: main scan of a built tree with --json and --jobs auto returns code 0 or 1, and stdout parses as json; it does not assert schema_version or totals; missing stop: that code set and that parsed stdout together; The CLI bogus jobs scan is not this; test_cli_scan_jobs_invalid is that CLI bogus jobs scan",
        ),
    },
    Row {
        name: "test_cli_scan_jobs_invalid",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_jobs_invalid: main scan of a built tree with --jobs bogus returns code 2, and stderr contains --jobs; it does not assert a longer error sentence; missing stop: that exit code and that stderr fragment together; The single-file jobs note is not this; test_cli_scan_jobs_single_file_note is that single-file jobs note",
        ),
    },
    Row {
        name: "test_cli_scan_jobs_single_file_note",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_jobs_single_file_note: main scan of one file with --jobs 4 returns code 0, and stderr contains ignored for single-file; missing stop: that exit code and that stderr fragment together; The check_dir jobs passthrough is not this; test_api_check_dir_jobs_passthrough is that check_dir jobs passthrough",
        ),
    },
    Row {
        name: "test_api_check_dir_jobs_passthrough",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_check_dir_jobs_passthrough: check_dir on one built tree, recursive, with jobs 1 and jobs 3, has equal to_json; it does not assert totals; an API vector that only calls check_dir or scan with jobs is not this pytest unless it is the entire function; missing stop: that equal json together; The single-file jobs note is not this; test_cli_scan_jobs_single_file_note is that single-file jobs note",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_file_result_wire_roundtrip_with_findings",
    "test_finding_from_dict_roundtrip",
    "test_wire_roundtrip_skipped_result",
    "test_parallel_output_byte_identical",
    "test_parallel_repeat_runs_identical",
    "test_parallel_mixed_fixture_matches_sequential",
    "test_parallel_fixtures_tree_byte_identical_to_sequential",
    "test_parallel_pool_start_method_is_spawn",
    "test_parallel_progress_emits_in_file_order",
    "test_jobs_validation",
    "test_single_file_ignores_jobs",
    "test_cli_scan_jobs_json",
    "test_cli_scan_jobs_auto",
    "test_cli_scan_jobs_invalid",
    "test_cli_scan_jobs_single_file_note",
    "test_api_check_dir_jobs_passthrough",
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
fn pinned_scan_test_parallel_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 184);
}

#[test]
fn pinned_scan_test_parallel_row_count_equals_sixteen() {
    assert_eq!(ROWS.len(), 16);
    assert_eq!(PINNED_TEST_COUNT, 16);
    assert_eq!(PINNED_NAMES.len(), 16);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_scan_test_parallel_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 16);
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
    assert_eq!(not_applicable, 16);

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
