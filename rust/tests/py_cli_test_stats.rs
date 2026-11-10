//! Dispositions for the twelve `def test_` functions in pinned
//! `tests/cli/test_stats.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (172 splitlines). The module
//! covers exact counters for one four-event file, tool-call hashing whose raw
//! name is absent from `to_json` plus `render_human`, a recursive directory
//! walk of two session files plus one non-session text file, a directory
//! `ValueError` when recursive is omitted, a missing-path `FileNotFoundError`,
//! non-text bytes counted without raising, recursive counters for
//! `fixtures/checks`, two recursive `to_json` results that match, `main`
//! `stats --json` against the stats schema, human `main` `stats` stdout, three
//! `main` `stats` exit paths, and two payload absences in `to_json` plus
//! `render_human`. Exactly twelve test functions, in module order. None is
//! parametrized. Helpers `_claude_records` and `_write_jsonl` are not tests.
//! Each row is the whole function. A single counter is not the exact-counter
//! test. An API `stats_paths` result is not a CLI run. One call is not the
//! three-exit pytest. The API `ValueError` is not the directory exit 0. The
//! tool-name absence is not the payload-value pytest. The JSON schema sweep is
//! not the human stdout pytest. `parity/vectors/cli/vectors.json` has 33
//! vectors at this pin. None is one of these rows.
//! `parity/vectors/stats/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and its parity card recorded 0
//! covered and 12 not_applicable. This integration test crate links
//! `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`] only. It
//! cannot call `sesslint.cli.main` or `sesslint.stats.stats_paths` without a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 12;
const PINNED_SPLITLINES: usize = 172;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A single counter is not the exact-counter test. An API
/// `stats_paths` result is not a CLI run. One call is not the three-exit
/// pytest. The API `ValueError` is not the directory exit 0. The tool-name
/// absence is not the payload-value pytest. The JSON schema sweep is not the
/// human stdout pytest. `not_applicable` names the missing stop.
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
        name: "test_stats_single_file_exact_counters",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_single_file_exact_counters: stats_paths of one four-event file asserts files_processed 1, files_undetected 0, files_unreadable 0, events_total 4, by_kind message 4, by_actor user 2 and assistant 2, by_adapter claude-code-jsonl 1, file_bytes total equal to that file's size, and events_per_file max 4; missing stop: that whole counter set on that one file; one counter is not this pytest; a single counter is not the exact-counter test; events_total 4 is not files_processed 1; by_kind message 4 is not by_actor user 2 or assistant 2; by_adapter claude-code-jsonl 1 is not events_per_file max 4; file_bytes total is the file size and is not a pinned integer; the call passes one file and omits format, recursive, max_files, and max_bytes; this is an API stats_paths result and is not a CLI run; the human stdout row is not this pytest; the schema sweep is not this pytest; helpers _claude_records and _write_jsonl are not tests; this function is not parametrized; check_exit_constants stores the help lines 0 a clean session exits 0, 1 a session with findings exits 1, and 2 an internal tool error exits 2, and those lines are not these counters; create_parser_subcommand_names lists stats and stops at GAP-cli-init-create-parser, so the name is not stats_paths; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable, so that older corpus is not a source of Covered and those ids are not cli vectors; dist_sorted_copy expects max 4, p50 3, p95 4, and total 10 for four integers and is not events_per_file of a session file; count_events_tool_checkpoint expects events_total 3 with one tool_call, one checkpoint, and one compaction_boundary, not four message events; session_stats_files_total expects files_total 9; stats_paths_load_events_gap pins files_processed 0, files_undetected 1, files_unreadable 0, and events_total 0 on one synthetic session with explicit limits and format, and its rust mode is load_events_unavailable, so those counters are not this success; module_constants lists stats_paths and STATS_SCHEMA_VERSION and does not call stats_paths; GAP-stats-scan-defaults says a call that omits max_files or max_bytes stops with sesslint.scan.DEFAULT_MAX_FILES is not available before root checks, which is not this counter set; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_tool_call_hashing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_tool_call_hashing: one file holds a parent message record and one tool-use record, stats_paths is called with format claude-code-jsonl, tool_calls_total is 1, by_tool_hash has one entry, that hash is 16 hex characters, and the raw tool name is absent from to_json plus render_human; missing stop: that whole hashing result together with the absence; the tool name and its input are not repeated here; tool_calls_total 1 is not the absence; one 16-hex hash is not the absence; the raw-name absence is this pytest and is not test_stats_no_payload_values; this call omits max_files and max_bytes; this is an API stats_paths result and is not a CLI run; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable; tool_hash_read hashes one tool name to 16 hex characters and does not call stats_paths or inspect to_json plus render_human; count_events_tool_checkpoint expects tool_calls_total 1 beside one checkpoint and one compaction_boundary and does not assert a raw name is absent from to_json plus render_human; session_stats_output_minimize_gap stops at sesslint.report.minimize_path is not available and does not emit output, so it cannot show the absence; those ids are not cli vectors; GAP-stats-scan-defaults stops an omitted-limits call before root checks; GAP-stats-minimize-path and GAP-stats-load-events are not this success; create_parser_subcommand_names lists stats and is not this call; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_directory_walk",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_directory_walk: a directory holds two session files of three and five events plus one non-session text file, and recursive stats_paths asserts files_processed 2, files_undetected 1, and events_total 8; missing stop: that whole walk; the text file is not quoted here; one session file is not this pytest; files_processed 2 is not events_total 8; files_undetected 1 is not the text file; this pytest does not assert files_unreadable; the call omits max_files and max_bytes; this is an API stats_paths result and is not the CLI directory exit 0; test_stats_cli_exit_2_paths is that CLI exit and is not these counters; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; removed_flag_hint_recursive_short, removed_flag_hint_recursive_long, and removed_flag_hint_first_flag say -r or --recursive was removed because directories are always recursive now, and those hints are not this walk; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable, so that older corpus is not a source of Covered; iter_files_excluded_and_order and iter_files_max_files_cap walk fixtures/walk_tree and return paths, not events_total 8; stats_paths_load_events_gap is one undetected synthetic file with explicit limits, not two sessions plus a text file; those ids are not cli vectors; GAP-stats-scan-defaults stops this omitted-limits call before a directory walk; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_dir_without_recursive_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_dir_without_recursive_raises: stats_paths of a directory without recursive raises ValueError matching directory; missing stop: that ValueError; the pytest does not assert the rest of the message and does not pass max_files or max_bytes; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; this API ValueError is not the directory exit 0 in test_stats_cli_exit_2_paths; an API stats_paths result is not a CLI run; removed_flag_hint_recursive_short, removed_flag_hint_recursive_long, and removed_flag_hint_first_flag say directories are always recursive now and are removed-flag hints, not this ValueError; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable; stats_paths_directory_requires_recursive expects ValueError for fixtures/synthetic-dir with recursive false and explicit max_files 4 and max_bytes 32, which is not a temporary directory with limits omitted; stats_paths_missing_limits_directory is that same fixture with limits omitted and its rust mode is scan_default_unavailable under GAP-stats-scan-defaults, so Rust does not raise the ValueError; neither id is a cli vector; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_missing_path_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_missing_path_raises: stats_paths of a missing path raises FileNotFoundError; missing stop: that FileNotFoundError; the pytest does not assert a message; max_files and max_bytes are omitted; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; this exception is not the unreadable-count success and is not a CLI exit 2; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable; stats_paths_missing_path_pin_contract expects FileNotFoundError for fixtures/synthetic-absent.jsonl with limits omitted, and its rust mode is scan_default_unavailable, so Rust stops at sesslint.scan.DEFAULT_MAX_FILES is not available before the missing-path check; stats_paths_missing_path_explicit_limits expects the same exception type with max_files 4 and max_bytes 32, which this pytest does not pass; those ids are not cli vectors; GAP-cli-init-dispatch-runtime is not this API call; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_unreadable_counts_not_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_unreadable_counts_not_raises: a file of non-text bytes is passed to stats_paths, files_processed is 0, and files_unreadable plus files_undetected equals 1; missing stop: that whole non-raising count; the byte run is not copied here; the pytest does not assert which of the two buckets is 1 and does not assert events_total; files_processed 0 alone is not this pytest; the sum of 1 is not a choice of bucket; this is not the missing-path FileNotFoundError; the call omits max_files and max_bytes; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; this is an API stats_paths result and is not a CLI run; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable; stats_paths_load_events_gap pins files_processed 0, files_undetected 1, and files_unreadable 0 for a synthetic session that is not non-text bytes, and its rust mode is load_events_unavailable, so it is not this sum; that id is not a cli vector; GAP-stats-scan-defaults stops this omitted-limits call before a byte file can be counted; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_compaction_and_checkpoint",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_compaction_and_checkpoint: recursive stats_paths of fixtures/checks asserts events_total 187, by_kind checkpoint 10, by_kind compaction_boundary 7, checkpoints 10, compaction_boundaries 7, tool_calls_total 16, and files_processed 47; missing stop: that whole counter set; all of those counters are one row; one counter is not this pytest; events_total 187 is not files_processed 47; by_kind checkpoint 10 is not by_kind compaction_boundary 7; checkpoints 10 is the same row as by_kind checkpoint 10 and neither stands alone; compaction_boundaries 7 is the same row as by_kind compaction_boundary 7; tool_calls_total 16 is not the one-tool-use hashing pytest; the call omits max_files and max_bytes; tmp_path is unused; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; this is an API stats_paths result and is not a CLI run; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable; count_events_tool_checkpoint expects events_total 3, one checkpoint, one compaction_boundary, and tool_calls_total 1, not this fixture corpus; session_stats_files_total expects files_total 9; those ids are not cli vectors; GAP-stats-scan-defaults stops this omitted-limits call before a fixture walk; GAP-stats-load-events is not these counters; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_deterministic: a six-event file is written, then two recursive stats_paths calls return equal to_json; missing stop: that equality of the two to_json results; one call is not this pytest; equal to_json is not equal render_human, which this pytest does not compare; this is not the human CLI stdout and is not the schema sweep; the calls omit max_files and max_bytes; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; this is an API stats_paths result and is not a CLI run; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable; session_stats_output_minimize_gap pins a human prefix and to_dict keys and its rust mode is minimize_path_unavailable, so it does not emit to_json and does not compare two calls; that id is not a cli vector; GAP-stats-minimize-path says to_json returns sesslint.report.minimize_path is not available and does not emit output; GAP-stats-scan-defaults stops each omitted-limits call before a document exists; no cli vector compares two stats documents; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_json_schema",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_json_schema: main stats --json of one three-event file exits 0, schema_version equals the loaded schema const and STATS_SCHEMA_VERSION, every required key is present, files.total equals processed plus undetected plus unreadable, and the temporary path is absent from the JSON; missing stop: that whole schema sweep; one key is not this pytest; schema_version alone is not every required key; the files.total sum is not the path absence; the temporary path is not repeated here; this CLI run is not an API stats_paths result; this is not test_stats_cli_human_output; the JSON schema sweep is not the human pytest; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; check_exit_constants records the help line 0 a clean session exits 0 and is not this stats --json; main_removed_formats_json exits 2 for argv --json formats and is not stats --json; create_parser_subcommand_names lists stats and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run; parity/vectors/cli.stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, configure_subcommand_declarations lists --json, and GAP-cli-stats-discover-session-roots says Rust stats run() returns Display sesslint.api.discover_session_roots is not available before emit_text and does not return 0 or 2, so that declaration is not this exit 0 and that id is not a cli vector; parity/vectors/stats/vectors.json at that same older pin recorded 0 covered and 12 not_applicable; module_constants stores STATS_SCHEMA_VERSION sesslint.stats/v1 and does not load a schema or call main; load_stats_schema_gap and get_stats_schema_path_gap raise ModuleNotFoundError for sesslint._resources under GAP-stats-schema-path, which is not exit 0 JSON; session_stats_output_minimize_gap lists to_dict keys and does not emit JSON; those ids are not cli vectors; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_cli_human_output",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_cli_human_output: main stats of one four-event file, without --json, exits 0, stdout contains SessLint corpus statistics and Events: 4, and stdout does not contain the message text; missing stop: that whole human success including the absence; the message text is not quoted here; the heading alone is not Events: 4; Events: 4 alone is not the absence; the JSON schema sweep is not this pytest; an API stats_paths result is not this CLI run; test_stats_single_file_exact_counters is not this stdout; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; check_exit_constants records the help line 0 a clean session exits 0 and is not this run; create_parser_subcommand_names lists stats and is not main(); GAP-cli-init-dispatch-runtime says Rust stops before command.run; parity/vectors/cli.stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, configure_subcommand_declarations lists a human default format, and GAP-cli-stats-discover-session-roots stops before emit_text and does not return 0, so that older card is not this stdout and that id is not a cli vector; parity/vectors/stats/vectors.json at that same older pin recorded 0 covered and 12 not_applicable; session_stats_output_minimize_gap pins the human prefix SessLint corpus statistics and its rust mode does not emit output, so it is not main() and does not assert Events: 4 or the message-text absence; that id is not a cli vector; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_cli_exit_2_paths",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_cli_exit_2_paths, one row for three calls: stats with no path exits 2, stats of a directory exits 0, and stats of a file with --agent claude exits 2; the captured streams are drained and not asserted; missing stop: that whole three-call sequence; one call is not this pytest; the no-path exit 2 is not the directory exit 0; the directory exit 0 is not the --agent conflict exit 2; the API ValueError is not the directory exit 0; an API stats_paths result is not a CLI run; this function is not parametrized; a two-event file is written for the third call and its records are not copied here; helpers _claude_records and _write_jsonl are not tests; check_exit_constants and check_exit_epilog record the help line 2 an internal tool error exits 2, the note (also usage error / invalid flags / I/O failure), and the line 0 a clean session exits 0, and those lines are not these three runs; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not stats; removed_flag_hint_recursive_short, removed_flag_hint_recursive_long, and removed_flag_hint_first_flag say directories are always recursive now and are not main() of a directory; create_parser_subcommand_names lists stats and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, configure_subcommand_declarations marks path required and lists --agent choice claude, and GAP-cli-stats-discover-session-roots says Rust run() returns Display sesslint.api.discover_session_roots is not available before the agent/path checks and does not return 0 or 2, so that declaration is not the three exits and that id is not a cli vector; parity/vectors/stats/vectors.json at that same older pin recorded 0 covered and 12 not_applicable, and its directory ValueError vectors are not this exit 0; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_stats_no_payload_values",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stats_no_payload_values: three records are written, the first message is replaced, stats_paths is called with format claude-code-jsonl, and to_json plus render_human contains neither the replaced message token nor another message text; missing stop: both absences together; both absences are one row; one absence is not this pytest; the replaced token is not the other message text; neither string is quoted here; the tool-name absence is not this pytest; test_stats_tool_call_hashing is not this row; the human CLI absence of one message is not these two API absences; the call omits max_files and max_bytes; this function is not parametrized; helpers _claude_records and _write_jsonl are not tests; this is an API stats_paths result and is not a CLI run; parity/vectors/stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its parity card recorded 0 covered and 12 not_applicable; session_stats_output_minimize_gap does not emit to_json or render_human; tool_hash_read does not inspect message text; those ids are not cli vectors; GAP-stats-scan-defaults stops this omitted-limits call before either absence can be shown; GAP-stats-minimize-path stops before to_json or render_human emits output; sesslint.stats.stats_paths is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_stats_single_file_exact_counters",
    "test_stats_tool_call_hashing",
    "test_stats_directory_walk",
    "test_stats_dir_without_recursive_raises",
    "test_stats_missing_path_raises",
    "test_stats_unreadable_counts_not_raises",
    "test_stats_compaction_and_checkpoint",
    "test_stats_deterministic",
    "test_stats_json_schema",
    "test_stats_cli_human_output",
    "test_stats_cli_exit_2_paths",
    "test_stats_no_payload_values",
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
fn pinned_cli_test_stats_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 172);
}

#[test]
fn pinned_cli_test_stats_row_count_equals_twelve() {
    assert_eq!(ROWS.len(), 12);
    assert_eq!(PINNED_TEST_COUNT, 12);
}

#[test]
fn every_pinned_cli_test_stats_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 12);
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
