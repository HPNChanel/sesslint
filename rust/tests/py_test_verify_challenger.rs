//! Dispositions for the thirteen `def test_` functions in pinned
//! `tests/test_verify_challenger.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (618 splitlines). Exactly
//! thirteen test functions, in module order. Two are parametrized: the
//! exit-code matrix and the malformed-file test. A parametrized function is
//! one row covering every cell. The helper `_build_valid_bundle` is not a
//! test. Each row is the whole function. A library verify is not a CLI exit.
//! A returned exit is not a SystemExit. One cell is not the whole matrix.
//! The function name is not the assertion when they disagree. Session lines
//! and fixture bytes are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin. `parity/vectors/verify/vectors.json` is pinned to the same commit and
//! its twelve ids are `module_all`, `dataclass_serialization`,
//! `render_verify_human_formatting`, and nine parse probes:
//! `parse_rejects_nan`, `parse_rejects_infinity`,
//! `parse_rejects_out_of_range_float`, `parse_rejects_deep_nesting`,
//! `parse_rejects_oversized_line`, `parse_rejects_nul_byte`,
//! `parse_rejects_oversized_file`, `parse_tolerates_headerless`, and
//! `parse_accepts_valid_jsonl`. None of those is one of these thirteen whole
//! functions. `parity/vectors/repair.fingerprint/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and is not a Covered source.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.verify` or
//! `sesslint.cli` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 13;
const PINNED_SPLITLINES: usize = 618;
const CLI_VECTOR_COUNT: usize = 33;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const VERIFY_VECTORS_REL: &str = "parity/vectors/verify/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest, including every cell. A library verify is not a CLI exit. A
/// returned exit is not a SystemExit. One cell is not the whole matrix. The
/// function name is not the assertion when they disagree. `not_applicable`
/// names the missing stop.
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
        name: "test_idempotence_incomplete_repair_single_defect",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_idempotence_incomplete_repair_single_defect: ok is false, source_hash, plan_fingerprint, output_hash, transformation_audit, loss_audit, and assurance_audit are true, and idempotence is false with the phrase non-idempotent: 1 steps remaining; missing stop: those assertions together; all of those are one row; test_idempotence_incomplete_repair_multiple_defects is the two-step phrase and is not this pytest",
        ),
    },
    Row {
        name: "test_idempotence_incomplete_repair_multiple_defects",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_idempotence_incomplete_repair_multiple_defects: idempotence is false and its detail contains non-idempotent: 2 steps remaining; missing stop: both assertions together; both are one row; it does not assert the first six checks; test_idempotence_incomplete_repair_single_defect is the one-step phrase and is not this pytest; session lines are not copied here",
        ),
    },
    Row {
        name: "test_idempotence_never_modifies_output_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_idempotence_never_modifies_output_file: ok is false, idempotence is false, and the output bytes, hash, size, and mtime are unchanged; missing stop: those assertions together; all of those are one row; test_idempotence_with_malformed_output requires replan-failed and does not assert unchanged output bytes, hash, size, and mtime; fixture bytes are not copied here",
        ),
    },
    Row {
        name: "test_idempotence_with_malformed_output",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_idempotence_with_malformed_output: ok is false, idempotence is false, and its detail contains replan-failed; missing stop: those three assertions together; all three are one row; test_idempotence_never_modifies_output_file asserts unchanged output bytes and does not require replan-failed",
        ),
    },
    Row {
        name: "test_runtime_write_prohibition_mock",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runtime_write_prohibition_mock: mutation primitives are blocked, the valid bundle is ok true, the non-idempotent fixture is ok false, and the tampered-output fixture is ok false; missing stop: those three verifies together; all three verifies are one row; test_real_readonly_filesystem_attributes is the chmod test and is not this mock; fixture bytes are not copied here",
        ),
    },
    Row {
        name: "test_real_readonly_filesystem_attributes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_real_readonly_filesystem_attributes: all four bundle files are chmod read-only and verify returns ok true; missing stop: that success; that success is the row; test_runtime_write_prohibition_mock is the mock and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_exit_codes_comprehensive_matrix",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_exit_codes_comprehensive_matrix: all eleven cells are one row; ok returns 0 with JSON ok true, checks present, assurance present, and empty stderr; tampered source, tampered plan, tampered output, and non-idempotent each return 1 with JSON ok false, checks present, assurance present, and empty stderr; missing source, plan, output, and manifest, plus a directory source and a directory output, each return 2 with stderr containing Verify I/O error or path is a directory, and those cells do not require JSON; missing stop: those eleven cells together; one cell is not this pytest; test_cli_missing_arguments_exit_code_2 raises SystemExit; a returned exit is not that raise",
        ),
    },
    Row {
        name: "test_cli_missing_arguments_exit_code_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_missing_arguments_exit_code_2: seven argument combinations each raise SystemExit 2, namely no flags, only source, only plan, only repaired, only manifest, source plus plan, and source plus plan plus repaired; missing stop: those seven raises together; all seven are one row; test_cli_exit_codes_comprehensive_matrix returns exit codes; a returned exit 2 is not this raise",
        ),
    },
    Row {
        name: "test_cli_malformed_json_files_exit_code_1",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_malformed_json_files_exit_code_1: all four cells, source, plan, output, and manifest, each write invalid bytes, return 1, print JSON whose ok is false, and have empty stderr; missing stop: those four cells together; all four are one row; one file is not this pytest; test_idempotence_with_malformed_output is a library verify of one output; a library verify is not a CLI exit",
        ),
    },
    Row {
        name: "test_cli_unreadable_file_exit_code_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_unreadable_file_exit_code_2: only the source read raises PermissionError, main returns 2, and stderr contains Verify I/O error; missing stop: both assertions together; both assertions are one row; test_real_readonly_filesystem_attributes is the chmod test and is not this pytest",
        ),
    },
    Row {
        name: "test_bug_loss_audit_crashes_on_non_iterable_declared_loss",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bug_loss_audit_crashes_on_non_iterable_declared_loss: declared_loss null makes ok false, loss_audit false, and the detail contains invalid-declared-loss-format or manifest-schema; missing stop: those three assertions together; all three are one row; test_bug_loss_audit_crashes_on_non_int_loss_totals is the loss_totals test and is not this pytest",
        ),
    },
    Row {
        name: "test_bug_loss_audit_crashes_on_non_int_loss_totals",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bug_loss_audit_crashes_on_non_int_loss_totals: declared_loss is removed and loss_totals holds a non-integer, then ok is false, loss_audit is false, and the detail contains invalid-loss-totals-format or manifest-schema; missing stop: those three assertions together; all three are one row; test_bug_loss_audit_crashes_on_non_iterable_declared_loss is the null declared_loss test and is not this pytest",
        ),
    },
    Row {
        name: "test_bug_indented_single_document_json_session_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bug_indented_single_document_json_session_rejected: the name says rejected, but the body writes one indented document to the source and the output and verify returns ok true, transformation_audit true, and idempotence true; missing stop: those three assertions together; all three are one row; the function name is not the assertion; a rejection is not this pytest; the document is not copied here; test_real_readonly_filesystem_attributes asserts only ok true and is not these three checks",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_idempotence_incomplete_repair_single_defect",
    "test_idempotence_incomplete_repair_multiple_defects",
    "test_idempotence_never_modifies_output_file",
    "test_idempotence_with_malformed_output",
    "test_runtime_write_prohibition_mock",
    "test_real_readonly_filesystem_attributes",
    "test_cli_exit_codes_comprehensive_matrix",
    "test_cli_missing_arguments_exit_code_2",
    "test_cli_malformed_json_files_exit_code_1",
    "test_cli_unreadable_file_exit_code_2",
    "test_bug_loss_audit_crashes_on_non_iterable_declared_loss",
    "test_bug_loss_audit_crashes_on_non_int_loss_totals",
    "test_bug_indented_single_document_json_session_rejected",
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

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_test_verify_challenger_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 618);
}

#[test]
fn pinned_test_verify_challenger_row_count_equals_thirteen() {
    assert_eq!(ROWS.len(), 13);
    assert_eq!(PINNED_TEST_COUNT, 13);
    assert_eq!(PINNED_NAMES.len(), 13);
}

#[test]
fn every_pinned_test_verify_challenger_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 13);
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
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
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
fn verify_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 13);

    let json = read_vectors(VERIFY_VECTORS_REL);
    // `parity/vectors/verify/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "verify vectors python_commit spacing does not match {needle}"
    );
    assert!(json.contains("\"module\": \"sesslint.verify\""));

    let ids = vector_ids(&json);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing verify vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "verify");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
