//! Dispositions for the twenty-one `def test_` functions in pinned
//! `tests/cli/test_doctor.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (384 splitlines). The module
//! covers `doctor_report` root existence and file counts, absent roots, payload
//! absence from `to_json` plus `render_human`, default quick-check verdicts, a
//! `None` config path, an API schema match, CLI human and JSON runs, an agent
//! filter, equal `to_json` from two reports, the `MAX_FILE_COUNT` constant,
//! Claude index counts, ok and absent homes, malformed and truncated index
//! writes, an absent Codex index, named-threads phases, state-database phases,
//! an orphan edge and non-database bytes, sidecars that stay outside the
//! session count, the index object shape, and the closed state enum. Exactly
//! twenty-one test functions, in module order. None is parametrized. Helpers
//! `_claude_records`, `_make_home`, `_write_index`, and `_mk_codex_state_db`
//! are not tests. Each row is the whole function. A two-phase or three-phase
//! function is one row. A CLI exit is not an API report. One index state is
//! not a multi-phase test. The constant 10000 is not a file walk. One key is
//! not the whole pytest. The shape test is not the schema enum.
//! `parity/vectors/doctor/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and its gaps say `doctor_report`
//! stops at `sesslint.adapters.supported_adapters`, `index_health` stops at
//! `sesslint.indexes.discover_index_files`, and `load_doctor_schema` stops at
//! `sesslint._resources.schema_path`; that older corpus is not these rows.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main`,
//! `sesslint.doctor.doctor_report`, or `sesslint.doctor.load_doctor_schema`,
//! and it cannot read `sesslint.doctor.MAX_FILE_COUNT`, without a `Cargo.toml`
//! change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 21;
const PINNED_SPLITLINES: usize = 384;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A CLI exit is not an API report. One index state is not a
/// multi-phase test. The constant 10000 is not a file walk. One key is not
/// the whole pytest. The shape test is not the schema enum. The doctor corpus
/// at `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not these rows.
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
        name: "test_doctor_report_lists_roots",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_report_lists_roots calling doctor_report(env={}, home=home, quick_checks=False) on a home where both roots exist, asserting claude file_count is 3, codex file_count is 1, and tool_version is truthy; missing stop: that whole API report; quick_checks is false; a CLI exit is not an API report; test_doctor_cli_exit_0 is not this pytest; one index state is not this report; the constant 10000 is not a file walk and is not these file counts; create_parser_subcommand_names lists doctor with gap_id GAP-cli-init-create-parser and is not a doctor_report; removed_command_hint_formats and removed_flag_hint_show_limits mention sesslint doctor and are not this report; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not this API report; empty_report_human_json_keys is a constructed DoctorReport with empty roots, not both roots with those file counts; count_files_walk_sorted counts 7 and is not these roots; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-doctor-doctor-report says doctor_report stops at sesslint.adapters.supported_adapters, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_absent_root",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_absent_root calling doctor_report(env={}, home=home, quick_checks=False) when neither root directory is created, asserting every root exists is false and every file_count is 0; missing stop: that absent-root API report; quick_checks is false; a CLI exit is not an API report; the both-roots file-count report is not this pytest; one index state is not this report; count_files_missing_dir returns count 0 for one missing development path and is not every doctor root; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-doctor-doctor-report says doctor_report stops at sesslint.adapters.supported_adapters, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_no_filenames_no_payloads",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_no_filenames_no_payloads calling doctor_report(env={}, home=home) and asserting to_json plus render_human contains neither the synthetic session filenames nor the message text; missing stop: both absences together; both absences are one row; a CLI exit is not an API report; empty_report_human_json_keys renders one constructed report and does not prove those absences; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, GAP-doctor-doctor-report says doctor_report stops at sesslint.adapters.supported_adapters, and GAP-doctor-minimize-path says to_json and render_human call sesslint.report.minimize_path, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_quick_verdicts",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_quick_verdicts calling doctor_report(env={}, home=home) with default quick checks and asserting claude.checked is from 1 through 5 and the sum of verdict counts equals checked; missing stop: that checked range together with the verdict-count sum; one bound is not the whole pytest; a CLI exit is not an API report; quick_verdicts_empty has checked 0; quick_verdicts_ignores_non_files has checked 0; verdict_rules_order has checked 5 from synthetic outcomes and is not this claude root; doctor_constants records MAX_QUICK_CHECKS 5 and is not this checked range; GAP-doctor-check-file says quick_verdicts stops at sesslint.api.check_file when at least one regular file is selected; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_config_none",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_config_none building an empty home, changing to a different working directory, and calling doctor_report(env={}, home=home, quick_checks=False), asserting config_path is None; missing stop: that None config_path; quick_checks is false; a CLI exit is not an API report; empty_report_human_json_keys has config_path null on a constructed report and does not change the working directory; verbose_settings_provenance records a debug line that a config file is none and is not this doctor_report; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-doctor-doctor-report says doctor_report stops at sesslint.adapters.supported_adapters, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_json_schema",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_json_schema calling doctor_report with CLAUDE_CONFIG_DIR and CODEX_HOME, home injected, and quick_checks false, then asserting to_dict schema_version equals the load_doctor_schema const and DOCTOR_SCHEMA_VERSION, every schema required key is present, and every root has every roots-item required key; missing stop: that whole schema match; one key is not the whole pytest; this is not a CLI run; capsys is unused; a CLI exit is not an API report; test_doctor_cli_json is not this API schema walk; empty_report_human_json_keys lists to_dict keys on a constructed report with empty roots and does not call load_doctor_schema; doctor_constants records DOCTOR_SCHEMA_VERSION and is not this key walk; GAP-doctor-load-schema says load_doctor_schema stops at sesslint._resources.schema_path; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report and sesslint.doctor.load_doctor_schema are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_cli_exit_0",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_cli_exit_0 calling sesslint.cli.main on [\"doctor\", \"--no-quick-checks\"] asserting exit 0 and stdout contains SessLint doctor, tool version, and roots:; missing stop: all three phrases on that exit-0 run; all three phrases are one row; one phrase is not the whole pytest; the temporary home is not injected; an API report is not this CLI exit; empty_report_human_json_keys contains those phrases on a constructed DoctorReport and is not main(); main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not doctor --no-quick-checks exit 0; removed_command_hint_formats and main_removed_formats_json mention sesslint doctor on the removed formats command, not this stdout; create_parser_subcommand_names lists doctor and is not this run; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_cli_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_cli_json calling sesslint.cli.main on [\"doctor\", \"--no-quick-checks\", \"--json\"] asserting exit 0, schema_version equals DOCTOR_SCHEMA_VERSION, and roots is a list of length 2; missing stop: that JSON exit together with the schema_version equality and the roots length; one key is not the whole pytest; the temporary home is not injected; the API to_dict schema walk is not this CLI run; an API report is not this CLI exit; the human doctor exit is not this JSON run; main_removed_formats_json exits 2 with a JSON error for removed formats, not doctor --json exit 0; doctor_constants records DOCTOR_SCHEMA_VERSION without a roots list of length 2; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_agent_filter",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_agent_filter calling sesslint.cli.main on [\"doctor\", \"--agent\", \"claude\", \"--no-quick-checks\"] asserting exit 0, stdout contains claude, and the section after roots: does not contain codex; missing stop: both halves together; both halves are one row; the temporary home is not injected; an API report is not this CLI exit; the unfiltered doctor exit is not this agent filter; create_parser_subcommand_names lists doctor and is not this stdout split; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_deterministic calling doctor_report twice with quick_checks false on the same home and asserting the two to_json texts are equal; missing stop: that double call; a single snapshot is not two calls; a CLI exit is not an API report; empty_report_human_json_keys is one constructed json text, not two doctor_report calls; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-doctor-doctor-report says doctor_report stops at sesslint.adapters.supported_adapters, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_file_count_bound",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_file_count_bound asserting MAX_FILE_COUNT equals 10000; missing stop: that constant equality; the assertion is only that constant; the docstring mentions a capped walk and a flag, but the body does not assert them; the constant 10000 is not a file walk; tmp_path is unused; count_files_cap is a file walk expecting a capped count of 10000, and that walk is not this constant; doctor_constants also records MAX_QUICK_CHECKS and MAX_TOP_CODES, so it is not this pytest; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a cli vector, so that older corpus is not this row; sesslint.doctor.MAX_FILE_COUNT is not readable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_stale_divergent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_stale_divergent writing three session files and an index of two ids, then calling doctor_report(agents=[\"claude\"], env={}, home=home, quick_checks=False) and asserting index state stale-divergent, sessions_on_disk 3, and index_entries 2; missing stop: that state with both counts; one index state is not this count pair; a CLI exit is not an API report; index_diag_to_dict_absent is state absent with sessions_on_disk 2, not stale-divergent with sessions_on_disk 3 and index_entries 2; helper _write_index is not this test; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_ok_and_absent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_ok_and_absent calling doctor_report on two homes: a matching index is state ok, and an empty projects directory is state absent with index_entries None; missing stop: both homes together; both homes are one row; one index state is not a multi-phase test; the stale-divergent count pair is not this pytest; the codex rollout with no index is not this pytest; index_diag_to_dict_absent is one constructed absent dict and is not both homes; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_malformed_and_truncated",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_malformed_and_truncated writing non-text index bytes and asserting state malformed, then writing a cut-off JSON object and asserting state truncated; missing stop: both writes together; both writes are one row; one index state is not a multi-phase test; index_diag_to_dict_zero records a state outside the closed set and is neither malformed nor truncated; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_absent_codex",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_absent_codex calling doctor_report(agents=[\"codex\"], env={}, home=home, quick_checks=False) with one rollout and no index, asserting state absent, index_entries None, and sessions_on_disk 1; missing stop: that absent codex index with those counts; one index state is not this count pair; the claude empty-projects absent home is not this pytest; index_diag_to_dict_absent is state absent with sessions_on_disk 2 and is not sessions_on_disk 1; a CLI exit is not an API report; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_codex_subtree_states",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_codex_subtree_states calling doctor_report three times on a codex named-threads registry: an indexed rollout is ok with index_entries 1, an extra unindexed rollout stays ok, and a claimed id with no rollout is stale-divergent; missing stop: all three phases together; all three phases are one row; one index state is not a multi-phase test; the state-database phases are not this registry; index_diag_to_dict_absent is one absent dict and is not these three phases; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_codex_state_db",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_codex_state_db calling doctor_report twice: a state database with one registered rollout is ok with index_entries 1, and an unregistered rollout becomes stale-divergent; missing stop: both phases together; both phases are one row; one index state is not a multi-phase test; the named-threads registry phases are not this database; the orphan-edge phase is not this pytest; helper _mk_codex_state_db is not this test; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_codex_state_db_orphans_and_malformed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_codex_state_db_orphans_and_malformed calling doctor_report twice: an edge to a missing thread is stale-divergent, and replacing the database bytes with non-database bytes is malformed; missing stop: both phases together; both phases are one row; one index state is not a multi-phase test; the registered-rollout ok phase is not this pytest; the cut-off JSON truncated write is not this database; helper _mk_codex_state_db is not this test; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_sidecars_not_sessions",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_sidecars_not_sessions calling doctor_report(agents=[\"claude\"], env={}, home=home, quick_checks=False) on one session file plus an agent sidecar and a nested jsonl, asserting sessions_on_disk 1 and state ok; missing stop: that count and state together; one index state is not this count; count_files_walk_sorted counts nested files and is not this sessions_on_disk 1; GAP-doctor-index-health says index_health stops at sesslint.indexes.discover_index_files; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_json_shape_pinned",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_json_shape_pinned calling doctor_report(env={}, home=home, quick_checks=False) and asserting every root has an index key, and when the index is present its keys are exactly index_entries, sessions_on_disk, and state, and state is in the six-word set ok, stale-divergent, malformed, truncated, unverified-format, absent; missing stop: that shape on every root; one key is not the whole pytest; the schema state enum is not this shape test; index_diag_to_dict_absent is one constructed dict and does not walk every root; index_diag_to_dict_zero records a state outside that six-word set, so it is not this success mode; GAP-doctor-doctor-report says doctor_report stops at sesslint.adapters.supported_adapters; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.doctor_report is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_index_state_words_are_closed_enum",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_index_state_words_are_closed_enum calling load_doctor_schema and asserting the roots index state enum set equals ok, stale-divergent, malformed, truncated, unverified-format, absent; missing stop: that six-word schema enum; the shape test is not this schema enum; one word is not the whole set; this is not a CLI run; a CLI exit is not this schema load; index_diag_to_dict_zero records a state outside that set and does not read the schema enum; GAP-doctor-load-schema says load_doctor_schema stops at sesslint._resources.schema_path; parity/vectors/doctor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, so that older corpus is not this row; sesslint.doctor.load_doctor_schema is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_doctor_report_lists_roots",
    "test_doctor_absent_root",
    "test_doctor_no_filenames_no_payloads",
    "test_doctor_quick_verdicts",
    "test_doctor_config_none",
    "test_doctor_json_schema",
    "test_doctor_cli_exit_0",
    "test_doctor_cli_json",
    "test_doctor_agent_filter",
    "test_doctor_deterministic",
    "test_doctor_file_count_bound",
    "test_doctor_index_stale_divergent",
    "test_doctor_index_ok_and_absent",
    "test_doctor_index_malformed_and_truncated",
    "test_doctor_index_absent_codex",
    "test_doctor_index_codex_subtree_states",
    "test_doctor_index_codex_state_db",
    "test_doctor_index_codex_state_db_orphans_and_malformed",
    "test_doctor_index_sidecars_not_sessions",
    "test_doctor_index_json_shape_pinned",
    "test_doctor_index_state_words_are_closed_enum",
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
fn pinned_cli_test_doctor_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 384);
}

#[test]
fn pinned_cli_test_doctor_row_count_equals_twenty_one() {
    assert_eq!(ROWS.len(), 21);
    assert_eq!(PINNED_TEST_COUNT, 21);
}

#[test]
fn every_pinned_cli_test_doctor_test_has_one_disposition() {
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
