//! Dispositions for the eight `def test_` functions in pinned
//! `tests/cli/test_ac02_exit_codes.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (215 splitlines). The module
//! covers AC-02 (FR-098): per-code exit lines and notes, clean and findings
//! sessions, internal tool errors, `NO_COLOR`, user-facing docs, `--help`, and
//! documented codes versus observed exits. Exactly eight test functions, in
//! module order. None is parametrized. Helpers `_findings_session`, `_run`, and
//! `_assert_per_code_wording` are not tests. Each row is the whole function.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main`,
//! `sesslint.cli.CHECK_EXIT_LINES`, `sesslint.cli.CHECK_EXIT_NOTES`, or
//! `sesslint.api.check_file` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 8;
const PINNED_SPLITLINES: usize = 215;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A vector that only stores exit-code constants is not any of these
/// whole runs. One exit is not the whole pytest. One document is not the whole
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
        name: "test_contract_constant_is_the_per_code_lines",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_contract_constant_is_the_per_code_lines asserting CHECK_EXIT_LINES equals the ordered lines 0  a clean session exits 0, 1  a session with findings exits 1, and 2  an internal tool error exits 2, CHECK_EXIT_NOTES equals the ordered notes (also verification passed / dry-run plan generated), (also verification failed / repair refused), and (also usage error / invalid flags / I/O failure), and the removed summary sentence an internal tool error exits 2, a session with findings exits 1, a clean session exits 0 is absent from the newline-joined lines; check_exit_constants only stores those exit-code lines and notes and does not record the absent summary sentence; a vector that only stores exit-code constants is not this whole run; sesslint.cli.CHECK_EXIT_LINES and sesslint.cli.CHECK_EXIT_NOTES are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_clean_session_exits_0",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_clean_session_exits_0 calling sesslint.cli.main through _run on check fixtures/cli/check_basic/healthy.jsonl asserting exit 0, stdout contains Session is healthy, stdout lacks Integrity check failed, and stderr lacks Operational error; cli main vectors are main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json with exit 2 only, not check on the healthy fixture; check_exit_constants only stores the phrase a clean session exits 0 and is not this whole run; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_session_with_findings_exits_1",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_session_with_findings_exits_1 building a synthetic findings session with _findings_session (one orphan tool result) then calling sesslint.cli.main through _run on check of that session with --adapter claude-code-jsonl asserting exit 1, stdout contains Integrity check failed and SL101, and stderr lacks Operational error; cli vectors do not record that synthetic session, adapter claude-code-jsonl, exit 1, or SL101 on stdout; check_exit_constants only stores the phrase a session with findings exits 1 and is not this whole run; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_internal_tool_error_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_internal_tool_error_exits_2 patching sesslint.api.check_file to raise RuntimeError with text simulated internal tool error then calling sesslint.cli.main through _run on check fixtures/cli/check_basic/healthy.jsonl asserting exit 2, stderr contains the operational-error prefix Operational error [ERR- and the patched exception text, neither stdout nor stderr contains a traceback, and stdout is not a healthy report because it lacks Session is healthy and the Valid prefix; cli main vectors exit 2 only for removed subcommands, not a patched internal tool error; check_exit_constants only stores the phrase an internal tool error exits 2 and is not this whole run; sesslint.api.check_file and sesslint.cli.main are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_no_color_keeps_exit_codes_and_strips_ansi",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_color_keeps_exit_codes_and_strips_ansi setting NO_COLOR=1 and running three checks with --color always: the healthy fixture exits 0 with Session is healthy and no ANSI on stdout, the synthetic findings session with --adapter claude-code-jsonl exits 1 with SL101 and no ANSI on stdout, and check_file patched to RuntimeError simulated internal tool error exits 2 with Operational error [ERR- and no ANSI on stderr; one exit is not the whole pytest; check_exit_constants only stores the three exit phrases and is not these three runs; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_docs_state_ac02_contract_exactly",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_docs_state_ac02_contract_exactly reading README.md, docs/CI_TEMPLATES.md, docs/REPORTING_CORRUPTION.md, and every man/*.1 page, requiring the man directory to be non-empty, and asserting through _assert_per_code_wording that each document contains the ordered phrases a clean session exits 0, a session with findings exits 1, and an internal tool error exits 2 and the ordered notes (also verification passed / dry-run plan generated), (also verification failed / repair refused), and (also usage error / invalid flags / I/O failure), and omits the summary sentence an internal tool error exits 2, a session with findings exits 1, a clean session exits 0; one document is not the whole pytest; check_exit_constants and check_exit_epilog store exit wording and do not read those documents",
        ),
    },
    Row {
        name: "test_cli_help_states_ac02_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_help_states_ac02_contract calling sesslint.cli.main with --help expecting SystemExit code 0, asserting Exit codes: is present, and asserting the section after Exit codes: and before Important Notes: equals the three ordered lines plus the three notes, and that the summary sentence an internal tool error exits 2, a session with findings exits 1, a clean session exits 0 is absent from the full help text; check_exit_epilog stores epilog lines, Important Notes, and len 423 and is not this main --help run; check_exit_constants only stores exit-code constants and is not this whole run; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_documented_codes_match_observed_behavior",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_documented_codes_match_observed_behavior observing three check runs with --color never: the healthy fixture exits 0, the synthetic findings session with --adapter claude-code-jsonl exits 1, and check_file patched to RuntimeError simulated internal tool error exits 2, then asserting README.md and the newline-joined contract lines each contain a clean session exits 0, a session with findings exits 1, and an internal tool error exits 2; observed exits are 0, 1, and 2, and README plus the joined contract lines contain each phrase with its code; a vector that only stores exit-code constants is not this whole run; sesslint.cli.main and sesslint.api.check_file are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_contract_constant_is_the_per_code_lines",
    "test_clean_session_exits_0",
    "test_session_with_findings_exits_1",
    "test_internal_tool_error_exits_2",
    "test_no_color_keeps_exit_codes_and_strips_ansi",
    "test_docs_state_ac02_contract_exactly",
    "test_cli_help_states_ac02_contract",
    "test_documented_codes_match_observed_behavior",
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
fn pinned_cli_test_ac02_exit_codes_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 215);
}

#[test]
fn pinned_cli_test_ac02_exit_codes_row_count_equals_eight() {
    assert_eq!(ROWS.len(), 8);
    assert_eq!(PINNED_TEST_COUNT, 8);
}

#[test]
fn every_pinned_cli_test_ac02_exit_codes_test_has_one_disposition() {
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
