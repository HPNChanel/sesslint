//! Dispositions for the eight `def test_` functions in pinned
//! `tests/cli/test_output_protection.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (128 splitlines). The module
//! covers a parent-directory check, scan, and stats that must not replace the
//! child source, a verify of a copied `fixtures/verify/ok` bundle that must
//! not replace `manifest.json` or `plan.json`, a triage that must not replace
//! its state-copy database, a check that must not replace a hardlink alias
//! through `-o` or `--write-baseline`, a discovered Codex store that must not
//! be the report destination for check, stats, or triage, a three-phase
//! config and baseline protection, a new report inside the scan root that
//! exits 0 with `totals.healthy` equal to 1, and a seal ledger that must not
//! be the report destination for `-o` or `--write-baseline` whether or not it
//! already exists. Exactly eight test functions, in module order. Several are
//! parametrized. A parametrized function is one row, and every parameter cell
//! belongs to that row. `healthy` is not a test. A single parameter cell is
//! not the whole pytest. An exit 2 that preserves bytes is not the safe
//! new-report success. `parity/vectors/cli/vectors.json` has 33 vectors at
//! this pin. None is one of these rows. `parity/vectors/cli._output/vectors.json`
//! is pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and its
//! `guard_destination` rows are single guards, not these `main()` matrices.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` without
//! a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 8;
const PINNED_SPLITLINES: usize = 128;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest, including every parameter cell. A parametrized function is one
/// row. A single parameter cell is not the whole pytest. An exit 2 that
/// preserves bytes is not the safe new-report success. `not_applicable`
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
        name: "test_scan_cannot_replace_its_child",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cannot_replace_its_child, one row for command check, scan, and stats: the healthy helper writes a synthetic session at sessions/source.jsonl, sesslint.cli.main is called with [command, that parent directory, --json, -o, that child], the returned exit code is 2, and the child bytes stay equal to the bytes read before the call; missing stop: that whole three-command refusal with unchanged child bytes; the pytest does not assert stderr text; a single command cell is not this pytest; check is not scan; scan is not stats; an exit 2 that preserves bytes is not the safe new-report success; healthy is not a test; check_exit_constants and check_exit_epilog record the help line 2  an internal tool error exits 2 and the note (also usage error / invalid flags / I/O failure) and are not this run; create_parser_subcommand_names lists check, scan, and stats and stops at GAP-cli-init-create-parser, so the name list is not main(); removed_flag_hint_out says --out was removed in favor of -o/--output and is not this destination; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not this parent-directory scan; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli._registry/vectors.json at this pin has dispatch_scan_alias_and_missing with scan_name check, which is a dispatch lookup and is not these three main() calls, and that id is not a cli vector; parity/vectors/cli._output/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, guard_rejects_existing_file_inside_input_directory is one guard_destination whose destination is sessions/artifact.json and whose display is Error: --output must not replace an artifact inside an input directory, and guard_error_order_input_path_before_inside_directory expects Error: --output/--write-baseline must not be an input path when both the directory and sessions/source.jsonl are inputs, so that older corpus is not this three-command main() row and those ids are not cli vectors; guard_rejects_output_same_as_input refuses a destination that is the input file itself and is not a directory scan; parity/vectors/api/vectors.json at this pin has GAP-api-scan_path saying check_dir stops at sesslint.scan.scan_path is not available, so that corpus is not this main() row and those ids are not cli vectors; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verify_preserves_auxiliary_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_preserves_auxiliary_evidence, one row for -o of manifest.json and -o of plan.json: every file in fixtures/verify/ok is copied, sesslint.cli.main is called with [verify, source.jsonl, output.jsonl, --manifest, manifest.json, --plan, plan.json, --json, -o, the chosen target], the returned exit code is 2, and the name-to-bytes map of the copy stays equal; missing stop: that whole two-target verify refusal together with the unchanged copy; the pytest does not assert stderr text; one target is not this pytest; manifest.json is not plan.json; an exit 2 that preserves bytes is not the safe new-report success; healthy is not a test and this function does not call it; fixture bytes are not repeated here; check_exit_epilog is a help note and is not this verify; create_parser_subcommand_names lists verify and is not main(); main_removed_formats_json exits 2 with a removed-formats envelope and does not copy fixtures/verify/ok; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.verify/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-cli-verify-api-verify says when both paths are set Rust run stops with Display sesslint.api.verify is not available (no import, no emit_text, no seal, no exit 0 or 1), so that older corpus is not this main() row and those ids are not cli vectors; parity/vectors/verify/vectors.json at this pin has GAP-verify-cli saying CLI argv, capsys, exit codes, and main() integration are not byte-compared here, and GAP-verify-end-to-end says fixture directories are not vector-compared and Rust verify() returns sesslint.report.parse_manifest is not available, so that corpus is not this copied bundle and those ids are not cli vectors; parity/vectors/api/vectors.json at this pin has GAP-api-verify saying verify() stops at sesslint.verify.verify is not available, which is not this CLI row and those ids are not cli vectors; cli._output guards do not pass verify, --manifest, and --plan; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_triage_preserves_state_copy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_triage_preserves_state_copy: triage of one rollout passes --state-copy and -o of the same sqlite database, sesslint.cli.main returns 2, and the database bytes stay unchanged; missing stop: that whole triage refusal with unchanged database bytes; the pytest does not assert stderr text; this function is not parametrized; an exit 2 that preserves bytes is not the safe new-report success; the identity, the SQL, and the fixture bytes are not repeated here; healthy is not a test; create_parser_subcommand_names lists triage and is not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not triage; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.triage/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, configure_subcommand_declarations lists --state-copy, and GAP-cli-triage-latest-session says Rust run() returns Display sesslint.discovery.latest_session is not available immediately after evaluating the first import name (no stderr, no exit 2, no triage, no emit_text), so that declaration is not this main() row and those ids are not cli vectors; guard_rejects_output_same_as_input refuses a destination that is an input file and does not pass --state-copy; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_alias_and_baseline_cannot_replace_source",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_alias_and_baseline_cannot_replace_source, one row for -o and --write-baseline: the healthy helper writes a source, a hardlink alias is created, sesslint.cli.main is called with [check, that source, option, that alias] and no --json, the returned exit code is 2, and the source bytes, the alias bytes, and the original bytes stay equal; missing stop: that whole two-option hardlink refusal; the pytest does not assert stderr text; one option is not this pytest; -o is not --write-baseline; an exit 2 that preserves bytes is not the safe new-report success; healthy is not a test; check_exit_constants is a help line and is not this check; main_removed_baseline exits 2 for argv [baseline] and its hint mentions --baseline and --write-baseline, and removed_command_hint_baseline is that same removed-command hint, so neither is check of a hardlink alias; parity/vectors/cli._registry/vectors.json at this pin has removed_commands_migration_text whose baseline entry mentions --write-baseline, and removed_flags_migration_text maps --out to -o/--output, and those migration strings are not this main() row and those ids are not cli vectors; parity/vectors/cli._output/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and guard_error_order_alias_before_input_path is one guard_destination whose destination is alias.jsonl and whose display is Error: --output/--write-baseline must not be a link alias, so that one guard is not both option cells and does not assert the source, the alias, and the original bytes stay equal, and that id is not a cli vector; parity/vectors/cli._common/vectors.json at that older pin has GAP-common-write-baseline-set saying _write_baseline_arg stops at WRITE_BASELINE_UNAVAILABLE, which is not this check; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_discovered_store_cannot_be_report_destination",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovered_store_cannot_be_report_destination, one row for check, stats, and triage: CODEX_HOME contains one rollout, check and stats are [command, --agent, codex, -o, that rollout], triage also passes --latest, there is no positional path, each sesslint.cli.main returns 2, and the rollout bytes stay unchanged; missing stop: that whole three-command discovered-store refusal; the pytest does not assert stderr text; one command is not this pytest; check is not stats; stats is not triage; triage's --latest is not the check or stats argv; the rollout name is not repeated here; an exit 2 that preserves bytes is not the safe new-report success; healthy is not a test; create_parser_subcommand_names lists the three commands and is not main(); GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.stats/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-cli-stats-discover-session-roots says Rust stats run() returns Display sesslint.api.discover_session_roots is not available before the agent/path checks and does not return 0 or 2; parity/vectors/cli.check/vectors.json at that older pin has GAP-cli-check-run-stops saying an agent and a single directory Display sesslint.api.check_dir is not available and run vectors are omitted; GAP-cli-triage-latest-session stops before triage; parity/vectors/discovery/vectors.json at that older pin has codex_rollout_shallow_accepted and codex_rollout_nested_accepted as candidate_in_layout on synthetic-store paths, which do not set CODEX_HOME and do not call main(); parity/vectors/api/vectors.json at this pin has discover_codex_env_archived and discover_env_both_agents calling discover_session_roots with CODEX_HOME and returning roots, which is not -o of a rollout and not unchanged rollout bytes, and those ids are not cli vectors; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_config_and_baseline_are_protected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_config_and_baseline_are_protected, one row for three phases in order: the healthy helper writes a source, sesslint.toml whose profile is neutral is the -o target of check and that call returns 2 with the config bytes unchanged, then check --write-baseline of baseline.json returns 0, then check --baseline of that file with -o of the same file returns 2 and the baseline bytes stay; the working directory is the temp directory; missing stop: that whole three-phase sequence; one phase is not this pytest; the exit-2 config refusal is not the exit-0 baseline write; the exit-0 baseline write is not the later exit-2 overwrite refusal; an exit 2 that preserves bytes is not the safe new-report success; the exit-0 phase is not test_new_report_inside_scan_root_is_safe; the pytest does not assert stderr text or the baseline document schema; healthy is not a test; main_removed_baseline and removed_command_hint_baseline mention --baseline and --write-baseline only inside the removed baseline subcommand hint and do not write baseline.json or preserve config bytes; parity/vectors/cli._registry/vectors.json at this pin repeats that migration text in removed_commands_migration_text and that id is not a cli vector; parity/vectors/cli._common/vectors.json at e91d50b2ecea57ef4dd900e3b0b87b14946e847e has GAP-common-write-baseline-set saying _write_baseline_arg stops at WRITE_BASELINE_UNAVAILABLE and GAP-common-load-baseline-set saying _load_baseline_arg stops at LOAD_BASELINE_UNAVAILABLE, which is not the exit-0 write followed by the exit-2 refusal; parity/vectors/baseline/vectors.json at that older pin has GAP-baseline-write-baseline saying write_baseline delegates to atomic_write_text and does not pin this CLI sequence, and its file_role rows are path classification, not these three main() calls; parity/vectors/cli.check/vectors.json at that older pin lists --baseline and --write-baseline in configure_subcommand_declarations and GAP-cli-check-run-stops says run vectors are omitted; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_new_report_inside_scan_root_is_safe",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_new_report_inside_scan_root_is_safe: the healthy helper writes a source inside a directory, sesslint.cli.main is called with [check, that directory, --json, -o, a new report.json], the returned exit code is 0, the written report has totals.healthy equal to 1, and the source bytes stay; missing stop: that whole exit-0 success; this success is not any exit-2 protection; an exit 2 that preserves bytes is not this row; the report does not exist before the call; there is no --seal, no --write-baseline, and no --baseline; the pytest does not assert stderr text; healthy is not a test; check_exit_constants records the help line 0  a clean session exits 0 and is not this directory check and not totals.healthy; create_parser_subcommand_names lists check and is not main(); main_removed_formats_json exits 2 and is not exit 0; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli._render/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and scan_buckets_padding_and_rollups embeds totals.healthy 1 inside format_scan_report_human, and GAP-render-render-json says the json report branch stops at sesslint.report.render_json, so that older corpus is not main() writing a new report and those ids are not cli vectors; parity/vectors/api/vectors.json at this pin has GAP-api-scan_path saying directory-mode check stops at sesslint.scan.scan_path is not available, so that corpus is not this exit-0 report and those ids are not cli vectors; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_seal_ledger_cannot_be_report_destination",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_seal_ledger_cannot_be_report_destination, one row for option -o and --write-baseline crossed with existing false and true: the healthy helper writes a source; when the ledger already exists, a prior check --seal returns 0, then the same --seal plus the option pointing at the ledger returns 2 and the ledger bytes stay; when the ledger does not exist, that combined command returns 2 and the ledger stays absent; missing stop: that whole four-cell refusal; one cell is not this pytest; -o is not --write-baseline; an existing ledger is not an absent ledger; the prior exit 0 is not the following exit 2; an exit 2 that preserves bytes is not the safe new-report success; the absent-ledger cell does not create the ledger; the pytest does not assert stderr text; healthy is not a test; create_parser_subcommand_names lists the seal subcommand and that name is not check --seal; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and do not pass --seal; parity/vectors/__main__/vectors.json at this pin has non_frozen_unparsed_check with argv [check] and exit 2, which is usage text for a missing command argument, not check --seal, and GAP-__main__-unparsed-command says Rust main__::main stops at sesslint.cli.check.configure is not available, and that id is not a cli vector; parity/vectors/cli._seal/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and maybe_append_seal_absent_returns_none expects result none and ledger_unchanged true, which is not the four-cell main() matrix; parity/vectors/seal/vectors.json at that older pin compares seal hash-chain entries and GAP-seal-ledger-lock says append_seal stops at locking before append, not this destination guard; parity/vectors/cli.check/vectors.json at that older pin lists --seal in configure_subcommand_declarations and GAP-cli-check-run-stops says run vectors are omitted; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_scan_cannot_replace_its_child",
    "test_verify_preserves_auxiliary_evidence",
    "test_triage_preserves_state_copy",
    "test_alias_and_baseline_cannot_replace_source",
    "test_discovered_store_cannot_be_report_destination",
    "test_config_and_baseline_are_protected",
    "test_new_report_inside_scan_root_is_safe",
    "test_seal_ledger_cannot_be_report_destination",
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
fn pinned_cli_test_output_protection_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 128);
}

#[test]
fn pinned_cli_test_output_protection_row_count_equals_eight() {
    assert_eq!(ROWS.len(), 8);
    assert_eq!(PINNED_TEST_COUNT, 8);
}

#[test]
fn every_pinned_cli_test_output_protection_test_has_one_disposition() {
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
