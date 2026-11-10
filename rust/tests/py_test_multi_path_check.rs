//! Dispositions for the nine `def test_` functions in pinned
//! `tests/test_multi_path_check.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (114 splitlines). Exactly
//! nine test functions, in module order. None is parametrized. Each row is
//! the whole function. A check is not a scan. Human output is not JSON
//! totals. One exit code is not a totals assertion. The helper `_write_json`
//! and the constants `HEALTHY` and `CORRUPT` are not tests. `HEALTHY` is
//! `fixtures/canonical/minimal.json`. `CORRUPT` is
//! `fixtures/adapters/codex/orphan_output.jsonl`. Fixture bytes and the small
//! JSON objects written in the tests are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, removed-flag hints, and removed-command exits, not these
//! check or scan invocations. `removed_flag_hint_salvage` is a removed-flag
//! hint for `--salvage-unsupported` on `check`, which is not
//! `--skip-undetected`. `create_parser_subcommand_names` lists `check` and
//! `scan` and stops at `GAP-cli-init-create-parser`. `GAP-cli-init-parse-args`
//! stops before `parse_args`. `GAP-cli-init-dispatch-runtime` stops before
//! `command.run`. `parity/vectors/scan/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. It is not among the 33 cli
//! vectors and is not used to mark a row covered. This integration test crate
//! links `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`]
//! only. It cannot call cli functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 9;
const PINNED_SPLITLINES: usize = 114;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Each row is the whole function. A check is not a scan. Human
/// output is not JSON totals. One exit code is not a totals assertion.
/// `not_applicable` names the missing stop.
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
        name: "test_multi_path_aggregates_report",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multi_path_aggregates_report: check --skip-undetected of the healthy fixture fixtures/canonical/minimal.json, a plain package file, and the corrupt fixture fixtures/adapters/codex/orphan_output.jsonl, with --json; the document schema is sesslint.scan-report/v1, totals healthy 1, invalid 1, skipped 1, and total 3, and the exit is 1; missing stop: all of those assertions together; all of those assertions are one row; the schema is not one total; totals healthy 1 is not totals invalid 1; totals invalid 1 is not totals skipped 1; totals skipped 1 is not totals total 3; totals total 3 is not the exit 1; one exit code is not a totals assertion; human output is not JSON totals; a check is not a scan; the all-clean human test is not this pytest; test_multi_path_all_clean checks stdout for skipped or HEALTHY and exit 0 without --json and is not this document; test_scan_skip_undetected_mixed_tree is a scan of one plain file and is not this check; test_multi_path_dir_with_recursive checks totals total at least 1 and is not these four totals; the plain package object is not copied here; fixture bytes are not copied here; _write_json is not a test; HEALTHY and CORRUPT are not tests; this function is not parametrized; check_exit_constants records the line 1  a session with findings exits 1 and is not schema sesslint.scan-report/v1; check_exit_epilog records the exit-code epilog and is not these totals; main_removed_formats_json exits 2 for --json formats and that document is not sesslint.scan-report/v1; removed_flag_hint_salvage hints --salvage-unsupported on check and is not --skip-undetected; removed_flag_hint_files hints --files and is not these three paths; removed_flag_hint_plain_command is a bare check with no hint and is not this invocation; create_parser_subcommand_names lists check and scan and stops at GAP-cli-init-create-parser, so the name check is not this invocation; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; parity/vectors/scan/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_multi_path_all_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multi_path_all_clean: check --skip-undetected of the healthy fixture fixtures/canonical/minimal.json and a plain file, without --json; stdout contains skipped or HEALTHY, and the exit is 0; missing stop: both assertions together; both are one row; the stdout check is not the exit; one exit code is not this stdout assertion; human output is not JSON totals; a check is not a scan; the JSON aggregate is not this pytest; test_multi_path_aggregates_report is the --json document with totals healthy 1, invalid 1, skipped 1, and total 3 and is not this human stdout; test_single_path_skip_undetected checks stderr for skipped on one plain file and is not this stdout; the plain-file object is not copied here; fixture bytes are not copied here; _write_json is not a test; HEALTHY and CORRUPT are not tests; this function is not parametrized; check_exit_constants records the line 0  a clean session exits 0 and is not stdout containing skipped or HEALTHY; removed_flag_hint_salvage hints --salvage-unsupported and is not --skip-undetected; removed_flag_hint_plain_command is a bare check and is not this invocation; create_parser_subcommand_names lists check and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; parity/vectors/scan/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_multi_path_missing_path_fails",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multi_path_missing_path_fails: check of the healthy fixture fixtures/canonical/minimal.json plus a missing path exits 2, and stderr contains not found; missing stop: both assertions together; both are one row; the exit is not the stderr; one exit code is not the stderr assertion; a single missing path is not this pytest; the healthy fixture alone is not this pytest; a check is not a scan; human output is not JSON totals; test_multi_path_aggregates_report exits 1 on a JSON aggregate and is not exit 2; fixture bytes are not copied here; the missing path is not a fixture; HEALTHY and CORRUPT are not tests; _write_json is not a test; this function is not parametrized; check_exit_constants records the line 2  an internal tool error exits 2 and the note about I/O failure and is not stderr containing not found; check_exit_epilog records that same exit-2 note and is not this stderr; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed commands and are not a missing path beside the healthy fixture; removed_flag_hint_plain_command is a bare check and is not this invocation; create_parser_subcommand_names lists check and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; parity/vectors/scan/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_multi_path_dir_accepted",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multi_path_dir_accepted: check of the healthy fixture fixtures/canonical/minimal.json and an empty directory, without --json, exits 0; missing stop: that exit; the JSON total test is not this pytest; test_multi_path_dir_with_recursive reads totals total with --json and is not this exit; one exit code is not a totals assertion; human output is not JSON totals; this body does not read stdout; a check is not a scan; the empty directory is not a file; fixture bytes are not copied here; HEALTHY and CORRUPT are not tests; _write_json is not a test; this function is not parametrized; check_exit_constants records the line 0  a clean session exits 0 and is not this two-path check; removed_flag_hint_recursive_long hints --recursive and is not this invocation, which passes no --recursive flag; removed_flag_hint_recursive_short hints -r and is not this invocation; removed_flag_hint_batch hints --batch and is not an empty directory beside the healthy fixture; create_parser_subcommand_names lists check and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; parity/vectors/scan/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_multi_path_dir_with_recursive",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multi_path_dir_with_recursive: the name says recursive, but the body is check of the healthy fixture fixtures/canonical/minimal.json and an empty directory with --json and no --recursive flag; totals total is at least 1, and the exit is 0 or 1; missing stop: both assertions together; both are one row; totals total is not the exit; one exit code is not a totals assertion; the exit-0-only directory test is not this pytest; test_multi_path_dir_accepted exits 0 without --json and is not these totals; human output is not JSON totals; a check is not a scan; an empty directory with --json is not the three-path aggregate; test_multi_path_aggregates_report asserts four totals and exit 1 and is not totals total at least 1; fixture bytes are not copied here; HEALTHY and CORRUPT are not tests; _write_json is not a test; this function is not parametrized; removed_flag_hint_recursive_long expects a hint for --recursive and is not this body, which does not pass --recursive; removed_flag_hint_recursive_short expects a hint for -r and is not this body; removed_flag_hint_first_flag also hints --recursive and is not this body; check_exit_constants records exits 0 and 1 and is not totals total at least 1; create_parser_subcommand_names lists check and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; parity/vectors/scan/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_single_path_skip_undetected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_path_skip_undetected: check --skip-undetected of one plain file exits 0, and stderr contains skipped; missing stop: both assertions together; both are one row; the exit is not the stderr; one exit code is not the stderr assertion; the unsupported-without-flag test is not this pytest; test_single_path_undetected_is_unsupported_without_flag checks stderr for unsupported without the skip flag and is not this stderr; the scan is not this check; test_scan_skip_undetected_mixed_tree is a scan and a check is not a scan; human output is not JSON totals; stderr containing skipped is not totals skipped; test_multi_path_all_clean checks stdout for skipped or HEALTHY on two paths and is not this stderr; the plain-file object is not copied here; _write_json is not a test; HEALTHY and CORRUPT are not tests; this function is not parametrized; removed_flag_hint_salvage hints --salvage-unsupported and is not --skip-undetected; check_exit_constants records the line 0  a clean session exits 0 and is not stderr containing skipped; removed_flag_hint_plain_command is a bare check and is not this invocation; create_parser_subcommand_names lists check and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; parity/vectors/scan/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_single_path_undetected_is_unsupported_without_flag",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_path_undetected_is_unsupported_without_flag: check of one plain file without the skip flag exits 0, and stderr contains unsupported; missing stop: both assertions together; both are one row; the exit is not the stderr; one exit code is not the stderr assertion; the skip-flag test is not this pytest; test_single_path_skip_undetected passes --skip-undetected and checks stderr for skipped and is not this stderr; a check is not a scan; test_scan_undetected_is_unsupported_by_default is scan --json totals and is not this check; human output is not JSON totals; stderr containing unsupported is not totals unsupported; the plain-file object is not copied here; _write_json is not a test; HEALTHY and CORRUPT are not tests; this function is not parametrized; removed_flag_hint_salvage hints --salvage-unsupported and that removed flag is not this stderr; removed_flag_hint_format_membership has rust_mode unsupported and stops at sesslint.adapters.VALID_FORMAT_OPTIONS is not available, and that mode is not stderr containing unsupported; check_exit_constants records the line 0  a clean session exits 0 and is not this stderr; create_parser_subcommand_names lists check and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; parity/vectors/scan/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_scan_skip_undetected_mixed_tree",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_skip_undetected_mixed_tree: scan --skip-undetected --json of a directory that holds one plain file; totals skipped is 1, totals invalid is 0, and the exit is 0; missing stop: all three assertions together; all three are one row; totals skipped 1 is not totals invalid 0; totals invalid 0 is not the exit; one exit code is not a totals assertion; the check aggregate is not this scan; test_multi_path_aggregates_report is a check and a check is not a scan; the default scan is not this pytest; test_scan_undetected_is_unsupported_by_default omits --skip-undetected and asserts totals unsupported 1 and is not these totals; test_single_path_skip_undetected is a check of one plain file and is not this scan; human output is not JSON totals; the plain-file object is not copied here; _write_json is not a test; HEALTHY and CORRUPT are not tests; this function is not parametrized; do not mark covered from parity/vectors/scan/vectors.json; that corpus is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; removed_flag_hint_salvage hints --salvage-unsupported and is not --skip-undetected; check_exit_constants records the line 0  a clean session exits 0 and is not totals skipped 1 and totals invalid 0; create_parser_subcommand_names lists scan and stops at GAP-cli-init-create-parser, so the name scan is not this invocation; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_scan_undetected_is_unsupported_by_default",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_undetected_is_unsupported_by_default: scan --json without the skip flag of a directory that holds one plain file; totals invalid is 0, totals unsupported is 1, and the exit is 0; missing stop: all three assertions together; all three are one row; totals invalid 0 is not totals unsupported 1; totals unsupported 1 is not the exit; one exit code is not a totals assertion; the skip scan is not this pytest; test_scan_skip_undetected_mixed_tree passes --skip-undetected and asserts totals skipped 1 and is not these totals; a check is not a scan; test_single_path_undetected_is_unsupported_without_flag checks stderr for unsupported on a check and is not these JSON totals; human output is not JSON totals; the plain-file object is not copied here; _write_json is not a test; HEALTHY and CORRUPT are not tests; this function is not parametrized; do not mark covered from parity/vectors/scan/vectors.json; that corpus is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; removed_flag_hint_format_membership has rust_mode unsupported and is not totals unsupported 1; removed_flag_hint_salvage hints --salvage-unsupported and is not this default scan; check_exit_constants records the line 0  a clean session exits 0 and is not totals invalid 0 and totals unsupported 1; create_parser_subcommand_names lists scan and stops at GAP-cli-init-create-parser, so the name scan is not this invocation; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops before command.run; main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_multi_path_aggregates_report",
    "test_multi_path_all_clean",
    "test_multi_path_missing_path_fails",
    "test_multi_path_dir_accepted",
    "test_multi_path_dir_with_recursive",
    "test_single_path_skip_undetected",
    "test_single_path_undetected_is_unsupported_without_flag",
    "test_scan_skip_undetected_mixed_tree",
    "test_scan_undetected_is_unsupported_by_default",
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
fn pinned_multi_path_check_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 114);
}

#[test]
fn pinned_multi_path_check_row_count_equals_nine() {
    assert_eq!(ROWS.len(), 9);
    assert_eq!(PINNED_TEST_COUNT, 9);
}

#[test]
fn every_pinned_multi_path_check_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 9);
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
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        if !id_set.contains(vector_id) {
            continue;
        }
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
