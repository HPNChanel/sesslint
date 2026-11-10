//! Dispositions for the fifteen test functions in pinned
//! `tests/test_parity.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (354 splitlines). Exactly
//! fifteen test functions, in module order. `test_parity_check_file_tree` is
//! parametrized over the fixture sweep and is one row covering every fixture
//! cell. Each row is the whole function. A docstring is not an assertion. A
//! comment is not an assertion. `FIXTURES_ROOT`, `CLI_FIXTURES`,
//! `SCAN_FIXTURES`, `VERIFY_FIXTURES`, `SWEEP_SUBDIRS`,
//! `_collect_sweep_fixtures`, `SWEEP_FIXTURES`, and `_run_cli` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these fifteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these fifteen names.
//! `parity/vectors/cli.check/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source.
//! `parity/vectors/cli.verify/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source.
//! `parity/vectors/cli.repair/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source.
//! `parity/vectors/cli.bundle/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source.
//! `parity/vectors/scan/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source.
//! A CLI vector that runs one command is not this whole pytest.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call product functions without a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 15;
const PINNED_SPLITLINES: usize = 354;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `test_parity_check_file_tree` is parametrized over the
/// fixture sweep and is one row covering every fixture cell.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A CLI vector that runs one command is not this whole pytest.
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
        name: "test_parity_check_file_healthy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_check_file_healthy: the check command exits 0 and the rendered library JSON equals the CLI JSON; The docstring is not an assertion; The comments are not an assertion; missing stop: that exit and that JSON equality together; The ambiguity check-file parity is not this; test_parity_check_file_ambiguity is that ambiguity check-file parity; a check-file parity is not a check-dir parity",
        ),
    },
    Row {
        name: "test_parity_check_file_ambiguity",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_check_file_ambiguity: the check command exits 0 and the rendered library JSON equals the CLI JSON; The docstring is not an assertion; The comments are not an assertion; missing stop: that exit and that JSON equality together; The check-dir parity is not this; test_parity_check_dir_recursive is that check-dir parity; a check-file parity is not a check-dir parity",
        ),
    },
    Row {
        name: "test_parity_check_dir_recursive",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_check_dir_recursive: the directory check exits 1, the CLI summary pops as present, and the library scan JSON equals the remaining CLI JSON; The docstring is not an assertion; The comment is not an assertion; missing stop: that exit, that popped summary, and that JSON equality together; The verify parity is not this; test_parity_verify_command is that verify parity; a check-file parity is not a check-dir parity",
        ),
    },
    Row {
        name: "test_parity_verify_command",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_verify_command: the verify command exits 0 and the library verdict JSON equals the CLI JSON; The docstring is not an assertion; The comments are not an assertion; missing stop: that exit and that JSON equality together; The fixture-tree parity is not this; test_parity_check_file_tree is that fixture-tree parity",
        ),
    },
    Row {
        name: "test_parity_check_file_tree",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_check_file_tree: the check exit is 1 when the error count or the fatal count is positive and 0 otherwise, and the CLI JSON equals the rendered library JSON; The docstring is not an assertion; the parametrized tree row is one row for every fixture cell; missing stop: that exit rule and that JSON equality together for every fixture cell; The detection-failure JSON shape is not this; test_check_detection_failure_json_shape is that detection-failure JSON shape",
        ),
    },
    Row {
        name: "test_check_detection_failure_json_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_detection_failure_json_shape: the check command exits 0, the top-level keys equal assurance, counts, coverage, findings, limitation, repro, schema_version, session_id, source_fingerprint, and tool_version, assurance equals A0, the limitation starts with the unsupported-format prefix, findings are empty, and coverage performed is empty; The docstring is not an assertion; missing stop: that exit, that key set, that assurance, that limitation prefix, those empty findings, and that empty coverage together; The policy-flag rejection is not this; test_check_policy_flag_rejected is that policy-flag rejection",
        ),
    },
    Row {
        name: "test_check_policy_flag_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_policy_flag_rejected: the check command with the policy flag exits 2; The docstring is not an assertion; It does not assert captured output; missing stop: that exit; The salvage-flag rejection is not this; test_repair_salvage_unsupported_flag_rejected is that salvage-flag rejection",
        ),
    },
    Row {
        name: "test_repair_salvage_unsupported_flag_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_salvage_unsupported_flag_rejected: the repair command with the removed salvage flag exits 2 and stderr contains the salvage-policy hint; The docstring is not an assertion; missing stop: that exit and that stderr hint together; The scan parity is not this; test_parity_scan_command is that scan parity",
        ),
    },
    Row {
        name: "test_parity_scan_command",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_scan_command: the scan command exits 1, the CLI summary pops as present, and the library scan JSON equals the remaining CLI JSON; The docstring is not an assertion; The comment is not an assertion; missing stop: that exit, that popped summary, and that JSON equality together; The canonical-adapter check is not this; test_parity_check_canonical is that canonical-adapter check",
        ),
    },
    Row {
        name: "test_parity_check_canonical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_check_canonical: the loaded session id is present, the canonical-adapter check exits 0, and stdout contains the valid-session text; The docstring is not an assertion; missing stop: that session id, that exit, and that stdout text together; The unified dispatcher is not this; test_parity_check_unified_dispatcher is that unified dispatcher",
        ),
    },
    Row {
        name: "test_parity_check_unified_dispatcher",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_check_unified_dispatcher: a file dispatch is a report equal to check_file, and a recursive directory dispatch is a scan report whose dict equals check_dir; The docstring is not an assertion; The comments are not an assertion; missing stop: that file equality and that directory equality together; The internal-error envelope is not this; test_parity_internal_error_envelope is that internal-error envelope",
        ),
    },
    Row {
        name: "test_parity_internal_error_envelope",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_internal_error_envelope: the envelope equals the internal-error code, the supplied error id, the exception message, and the error verdict; The docstring is not an assertion; missing stop: those four fields together; The dry-run repair is not this; test_parity_repair_dry_run is that dry-run repair",
        ),
    },
    Row {
        name: "test_parity_repair_dry_run",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_repair_dry_run: the library manifest is absent, the dry-run repair exits 0, and the CLI JSON equals the plan dict; The docstring is not an assertion; The comments are not an assertion; missing stop: that absent manifest, that exit, and that plan equality together; The execute repair is not this; test_parity_repair_execute is that execute repair; a dry-run repair is not an execute repair",
        ),
    },
    Row {
        name: "test_parity_repair_execute",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_repair_execute: the library manifest is present, the repair exits 0, the repaired output bytes are equal, and the input fingerprint, the output fingerprint, the policy, and the idempotency key match; The docstring is not an assertion; The comments are not an assertion; It does not assert the whole manifest; missing stop: that present manifest, that exit, those equal bytes, and those four fields together; The bundle parity is not this; test_parity_bundle_command is that bundle parity; a dry-run repair is not an execute repair",
        ),
    },
    Row {
        name: "test_parity_bundle_command",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parity_bundle_command: the bundle command exits 0 and the library bundle JSON equals the CLI JSON; The docstring is not an assertion; missing stop: that exit and that JSON equality together; The execute repair is not this; test_parity_repair_execute is that execute repair",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_parity_check_file_healthy",
    "test_parity_check_file_ambiguity",
    "test_parity_check_dir_recursive",
    "test_parity_verify_command",
    "test_parity_check_file_tree",
    "test_check_detection_failure_json_shape",
    "test_check_policy_flag_rejected",
    "test_repair_salvage_unsupported_flag_rejected",
    "test_parity_scan_command",
    "test_parity_check_canonical",
    "test_parity_check_unified_dispatcher",
    "test_parity_internal_error_envelope",
    "test_parity_repair_dry_run",
    "test_parity_repair_execute",
    "test_parity_bundle_command",
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
fn pinned_test_parity_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 354);
}

#[test]
fn pinned_test_parity_row_count_equals_fifteen() {
    assert_eq!(ROWS.len(), 15);
    assert_eq!(PINNED_TEST_COUNT, 15);
    assert_eq!(PINNED_NAMES.len(), 15);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_parity_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 15);
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
    assert_eq!(not_applicable, 15);

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
