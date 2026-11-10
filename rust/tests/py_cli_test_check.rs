//! Dispositions for the twelve `def test_` functions in pinned
//! `tests/cli/test_check.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (223 splitlines). The module
//! covers `sesslint check` on a healthy fixture, one synthetic broken session,
//! ambiguous input, a directory, a missing path, non-UTF-8 bytes, repro
//! binding, and clean, warning-only, and error status lines. Exactly twelve
//! test functions, in module order. None is parametrized. Helpers
//! `_plain_valid_session_lines` and `_status_lines_contradict` are not tests.
//! Each row is the whole function. A healthy exit-0 vector is not any of these
//! whole functions. One mode is not the whole pytest. One invocation is not
//! the whole pytest. This integration test crate links
//! `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`] only. It
//! cannot call `sesslint.cli.main` or `sesslint.report.parse_report` without a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 12;
const PINNED_SPLITLINES: usize = 223;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A healthy exit-0 vector is not any of these whole functions. One
/// mode is not the whole pytest. One invocation is not the whole pytest.
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
        name: "test_check_healthy_human",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_healthy_human calling sesslint.cli.main on check fixtures/cli/check_basic/healthy.jsonl asserting exit 0, stdout contains the read-only marker [read-only] and the lowercased word healthy, and stderr is empty; missing stop: that human check on the healthy fixture; check_exit_constants only stores the phrase a clean session exits 0 and is not this whole run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not check on the healthy fixture; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_healthy_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_healthy_json calling sesslint.cli.main on check fixtures/cli/check_basic/healthy.jsonl --json asserting exit 0, stderr is empty, schema_version is sesslint.report/v1, counts.total is 0, counts.by_severity.error is 0, and sesslint.report.parse_report agrees the total is 0; missing stop: that JSON report and parse_report total on the healthy fixture; the human read-only check is not this whole function; check_exit_constants only stores exit-code phrases and does not record the report schema or zero counts; a healthy exit-0 vector is not this whole function; sesslint.cli.main and sesslint.report.parse_report are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_finding_exit1",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_finding_exit1 checking one synthetic broken session twice: human mode with --adapter claude-code-jsonl exits 1 and stdout contains Integrity check failed and SL101, and JSON mode exits 1 with counts.total at least 1 and one finding code SL101; missing stop: both modes of that broken session; one mode is not the whole pytest; cli vectors do not record that synthetic session, adapter claude-code-jsonl, exit 1, or SL101; check_exit_constants only stores the phrase a session with findings exits 1 and is not this whole run; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_ambiguity_fail_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_ambiguity_fail_closed calling sesslint.cli.main three times on fixtures/cli/check_ambiguity/polyglot.json: default check exits 0, stderr lowercased mentions unsupported, and stdout lowercased does not say healthy; --fail-on-unsupported exits 1 and its captured streams are discarded; --json exits 0 with assurance A0, limitation starting Unsupported: format-undetected, empty findings, and empty coverage.performed; missing stop: all three invocations together; one invocation is not the whole pytest; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_directory_accepted",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_directory_accepted calling sesslint.cli.main on check of an empty temporary directory asserting exit 0; missing stop: that directory check exit 0; captured streams are not asserted; a healthy exit-0 vector is not this whole function; check_exit_constants only stores the phrase a clean session exits 0 and is not this directory scan; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_nonexistent_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_nonexistent_file calling sesslint.cli.main on check of a missing path does_not_exist.jsonl asserting exit 2 and stderr lowercased contains not found; missing stop: that missing-path exit 2 and not found stderr; cli main vectors exit 2 only for removed subcommands, not a missing path; check_exit_constants only stores an internal tool error exits 2 and is not this whole run; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_binary_non_utf8_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_binary_non_utf8_file calling sesslint.cli.main on check --json of non-UTF-8 bytes asserting the exit is 1 or 2, and when the exit is 1 and stdout is non-empty that stdout is sesslint.report/v1 JSON; missing stop: that closed exit on non-UTF-8 bytes and the conditional report schema; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_json_repro_binds_coverage_values",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_json_repro_binds_coverage_values calling sesslint.cli.main on check fixtures/cli/check_basic/healthy.jsonl --json asserting exit 0, repro.adapter name and version equal the coverage adapter id and version, repro.profile name and version equal the coverage profile id and version, detection.method is auto, detection.confidence is null, and platform.architecture is a non-empty string; missing stop: that repro binding to coverage values; the zero-count schema checks are not this whole function; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_json_repro_manual_format",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_json_repro_manual_format calling sesslint.cli.main on check fixtures/cli/check_basic/healthy.jsonl --adapter claude-code-jsonl --json asserting exit 0, detection.method is manual, and detection.confidence is null; missing stop: manual detection with null confidence on that explicit adapter; auto detection on the same fixture is not this whole function; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_clean_run_status_is_not_contradictory",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_clean_run_status_is_not_contradictory calling sesslint.cli.main on check fixtures/cli/check_basic/healthy.jsonl --color never asserting exit 0, _status_lines_contradict is false, the only plain Valid line is Valid Claude Code session, stdout contains Session is healthy and verdict: healthy /, and stdout does not contain healthy with warnings; missing stop: those non-contradictory clean status lines; a healthy exit-0 vector is not this whole function; check_exit_constants only stores a clean session exits 0 and is not these status lines; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_warning_only_run_status_is_not_contradictory",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_warning_only_run_status_is_not_contradictory calling sesslint.cli.main on check --color never of a duplicate-id session asserting exit 0, _status_lines_contradict is false, there is no plain Valid line, and stdout contains healthy with warnings, Session is healthy with warnings, verdict: healthy with warnings, warnings: 1, and SL003; missing stop: that warning-only status on the duplicate-id session; a healthy exit-0 vector is not this whole function; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_error_run_status_is_not_contradictory",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_error_run_status_is_not_contradictory calling sesslint.cli.main on check --adapter claude-code-jsonl --color never of the synthetic broken session asserting exit 1, _status_lines_contradict is false, there is no plain Valid line, stdout does not contain healthy with warnings, and stdout contains Integrity check failed and verdict: invalid; missing stop: those non-contradictory error status lines; the human and JSON modes of test_check_finding_exit1 are not this whole function; a healthy exit-0 vector is not this whole function; check_exit_constants only stores a session with findings exits 1 and is not these status lines; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_check_healthy_human",
    "test_check_healthy_json",
    "test_check_finding_exit1",
    "test_check_ambiguity_fail_closed",
    "test_check_directory_accepted",
    "test_check_nonexistent_file",
    "test_check_binary_non_utf8_file",
    "test_check_json_repro_binds_coverage_values",
    "test_check_json_repro_manual_format",
    "test_clean_run_status_is_not_contradictory",
    "test_warning_only_run_status_is_not_contradictory",
    "test_error_run_status_is_not_contradictory",
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
fn pinned_cli_test_check_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 223);
}

#[test]
fn pinned_cli_test_check_row_count_equals_twelve() {
    assert_eq!(ROWS.len(), 12);
    assert_eq!(PINNED_TEST_COUNT, 12);
}

#[test]
fn every_pinned_cli_test_check_test_has_one_disposition() {
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
