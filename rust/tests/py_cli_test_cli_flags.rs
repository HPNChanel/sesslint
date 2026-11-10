//! Dispositions for the 9 `def test_` functions in pinned `tests/cli/test_cli_flags.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (232 splitlines). Exactly nine
//! test functions, in module order. None is parametrized. `_run_cli` is a helper,
//! not a test. Each row is the whole function. A nested loop is one matrix, not
//! one cell. One argv is not the whole pytest. A parser acceptance of one flag
//! is not a main() exit run.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli` or `sesslint.api`
//! without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. A parser probe, an exit-code constant, or one argv is not the whole
//! pytest. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 9;
const PINNED_SPLITLINES: usize = 232;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A parser probe, an exit-code constant, or one argv is not the
/// whole pytest. `not_applicable` names the missing stop.
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
        name: "test_global_flag_preservation_subcommands",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_global_flag_preservation_subcommands calling create_parser and requiring parse_args of --color always check file.jsonl to keep color always, parse_args of --no-color check file.jsonl to keep no_color True, parse_args of --color never --no-color scan some_dir to keep color never and no_color True, parse_args of --no-color repair file.jsonl -o out.jsonl to keep no_color True, parse_args of --color never --no-color verify --manifest m.json to keep color never and no_color True, parse_args of check file.jsonl --profile p_check --adapter canonical to accept profile p_check and adapter canonical, and parse_args of repair file.jsonl -o out.jsonl --policy salvage --include-content to accept policy salvage and include_content True; one argv is not this pytest; create_parser_subcommand_names lists check, scan, repair, and verify among subcommand names and does not parse these flags; removed_flag_hint_salvage is the removed --salvage-unsupported hint whose text says use --policy salvage and is not acceptance of --policy salvage together with --include-content; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; create_parser is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_subcommand_flag_override",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_subcommand_flag_override calling create_parser and requiring parse_args of --color always check file.jsonl --color never to set color never, parse_args of --color always scan some_dir --color never to set color never, parse_args of repair file.jsonl -o out.jsonl --policy salvage to accept policy salvage, and parse_args of --color always verify --color never --manifest manifest.json to set color never; one argv is not this pytest; root --color always surviving into a subcommand is a different pytest; removed_flag_hint_salvage is the removed --salvage-unsupported hint and is not this --policy salvage acceptance; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; create_parser is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_range_validation_max_files_max_bytes",
        disposition: Disposition::NotApplicable(
            "no cli vector is the whole test_cli_range_validation_max_files_max_bytes matrix calling create_parser and, for check and scan and for --max-files and --max-bytes, rejecting 0, -1, and -100 with SystemExit code 2 and stderr containing positive integer (> 0); the row is the whole matrix and one cell is not this pytest; check_exit_constants is the exit-code constant table, including the line that an internal tool error exits 2 and the note that a usage error, invalid flags, or I/O failure also exits 2, and is not these SystemExit cells; verbose_settings_provenance records max_files = 3 and is not a rejection of 0, -1, or -100; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; create_parser is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_range_validation_confidence_margin",
        disposition: Disposition::NotApplicable(
            "no cli vector is the whole test_cli_range_validation_confidence_margin matrix calling create_parser and, for check and bundle and for --confidence-min and --margin-min, rejecting 0, 0.0, 1, 1.0, -0.1, 1.1, nan, and inf with SystemExit code 2 and stderr containing strictly between 0.0 and 1.0; the row is the whole matrix and one cell is not this pytest; the scan rejection matrix is a different pytest; check_exit_constants is the exit-code constant table and is not these SystemExit cells; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; create_parser is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_main_exit_code_on_range_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_main_exit_code_on_range_error writing a sample jsonl under tmp_path and requiring main, through _run_cli, to return 2 for check --max-files 0, check --max-bytes -10, check --confidence-min 2.0, and check --margin-min 0.0 on that path; all four calls are this pytest; a parser acceptance of one flag is not a main() exit run, and the parse_args range matrices are different pytests; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json are main on removed subcommands exiting 2 and are not these four range errors; check_exit_constants is the exit-code constant for an internal tool error exiting 2 and is not these four calls; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_scan_parser_accepts_threshold_flags",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_parser_accepts_threshold_flags calling create_parser and requiring parse_args of scan some_dir --confidence-min 0.7 --margin-min 0.2 to accept confidence_min 0.7 and margin_min 0.2; a parser acceptance of one flag is not a main() exit run, and this acceptance is not the scan detection exits; create_parser_subcommand_names lists scan among subcommand names and does not parse these flags; the scan out-of-range rejection matrix is a different failure mode; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; create_parser is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_scan_threshold_flags_reject_out_of_range",
        disposition: Disposition::NotApplicable(
            "no cli vector is the whole test_scan_threshold_flags_reject_out_of_range matrix calling create_parser and, for scan --confidence-min and scan --margin-min, rejecting 0, 0.0, 1, 1.0, -0.1, 1.1, nan, and inf with SystemExit code 2 and stderr containing strictly between 0.0 and 1.0; the row is the whole matrix and one cell is not this pytest; the check and bundle matrix is a different pytest; accepting --confidence-min 0.7 and --margin-min 0.2 is a different success mode; check_exit_constants is the exit-code constant table and is not these SystemExit cells; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; create_parser is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_scan_threshold_flags_reach_detection",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_threshold_flags_reach_detection copying fixtures/cli/check_basic/healthy.jsonl into a directory as a.jsonl, patching detect_claude_code to 0.60, detect_openai_agents to 0.10, and detect_canonical to 0.10, then requiring main scan of that directory to exit 0, main scan with --confidence-min 0.7 to exit 0, and main scan with --confidence-min 0.7 and --fail-on-unsupported to exit 1; all three runs are this pytest; a parser acceptance of one flag is not a main() exit run; check_exit_constants lines for a clean session exiting 0 and a session with findings exiting 1 are the exit-code constant table and are not these three runs; the check directory branch is a different pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_check_dir_branch_threshold_flags_reach_detection",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_dir_branch_threshold_flags_reach_detection copying fixtures/cli/check_basic/healthy.jsonl into a directory as a.jsonl, patching detect_claude_code to 0.60, detect_openai_agents to 0.10, and detect_canonical to 0.10, then requiring main check of that directory to exit 0, main check with --confidence-min 0.7 to exit 0, and main check with --confidence-min 0.7 and --fail-on-unsupported to exit 1; all three runs are this pytest; the scan test is not this pytest; a parser acceptance of one flag is not a main() exit run; check_exit_constants lines for a clean session exiting 0 and a session with findings exiting 1 are the exit-code constant table and are not these three runs; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_global_flag_preservation_subcommands",
    "test_subcommand_flag_override",
    "test_cli_range_validation_max_files_max_bytes",
    "test_cli_range_validation_confidence_margin",
    "test_cli_main_exit_code_on_range_error",
    "test_scan_parser_accepts_threshold_flags",
    "test_scan_threshold_flags_reject_out_of_range",
    "test_scan_threshold_flags_reach_detection",
    "test_check_dir_branch_threshold_flags_reach_detection",
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
fn pinned_cli_test_cli_flags_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 232);
}

#[test]
fn pinned_cli_test_cli_flags_row_count_equals_nine() {
    assert_eq!(ROWS.len(), 9);
    assert_eq!(PINNED_TEST_COUNT, 9);
}

#[test]
fn every_pinned_cli_test_cli_flags_test_has_one_disposition() {
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
