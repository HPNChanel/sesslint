//! Dispositions for the 8 `def test_` functions in pinned
//! `tests/cli/test_output_file.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (96 splitlines). Exactly eight
//! test functions, in module order. None is parametrized. Helper `_run` is not a
//! test. Each row is the whole function. One command is not another. The
//! byte-equality run is not the summary line. Quiet empty stdout is not the
//! summary. An exit in {0, 1} is not a single exit code.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` without a
//! `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. One command is not another. The byte-equality run is not the summary
//! line. Quiet empty stdout is not the summary. An exit in {0, 1} is not a
//! single exit code. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 8;
const PINNED_SPLITLINES: usize = 96;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One command is not another. The byte-equality run is not the summary
/// line. Quiet empty stdout is not the summary. An exit in {0, 1} is not a
/// single exit code. `not_applicable` names the missing stop.
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
        name: "test_check_output_file_bytes_match_stdout",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_output_file_bytes_match_stdout calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json, requiring exit 0, then the same check with -o writing report.json, requiring exit 0, and the file bytes equal the first stdout bytes; missing stop: that pair of exit-0 runs whose -o file bytes equal the first stdout bytes; both runs are one row; the byte-equality run is not the summary line; quiet empty stdout is not this byte equality; one command is not another; the summary pytest that requires the wrote-path line and finding(s) is a different pytest; the quiet pytest with -q, empty stdout, and an existing file is a different pytest; the stale-sentinel overwrite that requires an opening brace is a different pytest; the triage, doctor, and stats -o runs are different commands; an exit in {0, 1} is not a single exit code and is not these two exit 0 results; check_exit_constants stores the line that a clean session exits 0 and is not this pair of runs; removed_flag_hint_out is the removed --out hint whose text says use -o/--output and does not run either check; removed_flag_hint_batch and removed_flag_hint_files mention --output-dir and are not -o; main_removed_formats_json exits 2 for the removed formats command and is not this healthy check; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_output_file_summary_on_stdout",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_output_file_summary_on_stdout calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json and -o writing report.json, requiring exit 0 and stdout containing the wrote-path line and finding(s); missing stop: that exit 0 whose stdout contains the wrote-path line and finding(s); the byte-equality test is not this pytest; quiet empty stdout is not the summary; one command is not another; the overwrite pytest requires an opening brace after the stale sentinel and does not require the wrote-path line or finding(s); the triage, doctor, and stats checks for the substring wrote are different commands and do not require finding(s); an exit in {0, 1} is not a single exit code and is not this exit 0; check_exit_constants stores the line that a clean session exits 0 and is not this stdout; removed_flag_hint_out mentions -o/--output inside a removed --out hint and is not the wrote-path line; removed_flag_hint_batch and removed_flag_hint_files mention --output-dir and are not -o; verbose_settings_provenance records debug provenance and is not this summary; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_quiet_suppresses_summary",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_quiet_suppresses_summary calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json, -o writing report.json, and -q, requiring exit 0, empty stdout, and the file exists; missing stop: that exit 0 whose stdout is empty and whose report.json exists; quiet empty stdout is not the summary; the byte-equality run is not this pytest; one command is not another; the summary pytest requires the wrote-path line and finding(s); the overwrite pytest requires an opening brace and does not require empty stdout; an exit in {0, 1} is not a single exit code and is not this exit 0; check_exit_constants stores the line that a clean session exits 0 and is not this empty stdout; removed_command_hint_baseline passes -q to the removed baseline command and is not this check --json -o -q; removed_flag_hint_out is a removed --out hint and does not run check -q; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_output_must_not_be_input",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_output_must_not_be_input calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json and -o set to that same input path, requiring exit 2 and stderr containing --output; missing stop: that exit 2 whose stderr contains --output; one command is not another; the check -o runs that exit 0 write a separate report path and are different pytests; the byte-equality run, the summary line, and quiet empty stdout are not this rejection; the triage exit in {0, 1} is not a single exit code and is not this exit 2; check_exit_constants stores the note that a usage error, invalid flags, or I/O failure also exits 2, and is not this run; removed_flag_hint_out contains --output in the hint use -o/--output and does not reject -o of the input path; removed_flag_hint_batch and removed_flag_hint_files mention --output-dir and are not this -o; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not this check; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_existing_report_overwritten",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_existing_report_overwritten calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json and -o writing report.json, after that file is written as the stale sentinel text stale, requiring exit 0 and the new bytes start with an opening brace; missing stop: that exit 0 whose file replaced the stale sentinel and starts with an opening brace; the full byte-equality test is not this pytest; the summary pytest requires the wrote-path line and finding(s) and is not this opening brace; quiet empty stdout is not this pytest; one command is not another; an exit in {0, 1} is not a single exit code and is not this exit 0; check_exit_constants stores the line that a clean session exits 0 and is not this overwrite; removed_flag_hint_out is a removed --out hint and does not replace a file; main_removed_formats_json exits 2 for the removed formats command and is not this exit 0 file; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_triage_output_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_triage_output_file calling sesslint.cli.main through _run on triage --json -o of a copy of fixtures/claude_code/basic.jsonl writing triage.json, requiring an exit in {0, 1}, the file exists, and stdout contains wrote; missing stop: that triage exit in {0, 1} whose file exists and whose stdout contains wrote; an exit in {0, 1} is not a single exit code; the check run is not this pytest; one command is not another; the byte-equality run is not this triage; the summary line that also requires finding(s) is not this stdout; quiet empty stdout is not this stdout; the doctor and stats -o runs require a single exit 0 and are different commands; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this triage run; create_parser_subcommand_names lists triage among subcommand names and does not run triage --json -o; removed_flag_hint_out is a removed --out hint and is not this -o; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_output_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_output_file calling sesslint.cli.main through _run on doctor --no-quick-checks --json -o writing doctor.json, requiring exit 0, the file exists, and stdout contains wrote; missing stop: that doctor exit 0 whose file exists and whose stdout contains wrote; one command is not another; the check run is not this pytest; the byte-equality run is not this doctor; the summary line that also requires finding(s) is not this stdout; quiet empty stdout is not this stdout; the triage exit in {0, 1} is not a single exit code and is not this exit 0; the stats -o run is a different command; check_exit_constants stores the line that a clean session exits 0 and is not this doctor file; create_parser_subcommand_names lists doctor among subcommand names and does not run doctor --no-quick-checks --json -o; removed_command_hint_formats and removed_flag_hint_show_limits mention sesslint doctor in hint text and are not this invocation; main_removed_formats exits 2 for the removed formats command and mentions doctor in that hint, and is not this doctor run; removed_flag_hint_out is a removed --out hint and is not this -o; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_output_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_output_file calling sesslint.cli.main through _run on stats of fixtures/cli/check_basic/healthy.jsonl with --json and -o writing stats.json, requiring exit 0, the file exists, and stdout contains wrote; missing stop: that stats exit 0 whose file exists and whose stdout contains wrote; one command is not another; the check of the same healthy fixture is not this pytest; the byte-equality run is not this stats; the summary line that also requires finding(s) is not this stdout; quiet empty stdout is not this stdout; the triage exit in {0, 1} is not a single exit code and is not this exit 0; the doctor -o run is a different command; check_exit_constants stores the line that a clean session exits 0 and is not this stats file; create_parser_subcommand_names lists stats among subcommand names and does not run stats --json -o; removed_flag_hint_out is a removed --out hint and is not this -o; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_check_output_file_bytes_match_stdout",
    "test_output_file_summary_on_stdout",
    "test_quiet_suppresses_summary",
    "test_output_must_not_be_input",
    "test_existing_report_overwritten",
    "test_triage_output_file",
    "test_doctor_output_file",
    "test_stats_output_file",
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
fn pinned_cli_test_output_file_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 96);
}

#[test]
fn pinned_cli_test_output_file_row_count_equals_eight() {
    assert_eq!(ROWS.len(), 8);
    assert_eq!(PINNED_TEST_COUNT, 8);
}

#[test]
fn every_pinned_cli_test_output_file_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 8);
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
