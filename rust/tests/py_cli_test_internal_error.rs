//! Dispositions for the eight `def test_` functions in pinned
//! `tests/cli/test_internal_error.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (174 splitlines). The module
//! covers a patched `run_all_checks` crash on `check --json`, that same crash
//! in human mode, a patched `planner.plan` crash on `repair --output --json`,
//! that planner crash in human mode, a patched `verify.verify` crash on
//! `verify` of the fixture twice with `--manifest` and `--json`, that verify
//! crash in human mode, `repair --profile bogus_profile --dry-run`, and
//! `check --profile bogus_profile` raised as `SystemExit`. Exactly eight test
//! functions, in module order. None is parametrized. `ERR_ID_PATTERN` is not
//! a test. The fixture path `fixtures/determinism/repeat/repeat_session.json`
//! is the input. Each row is the whole function. JSON mode is not human mode.
//! Check is not repair. Repair is not verify. A returned exit 2 is not a
//! `SystemExit`. `parity/vectors/cli/vectors.json` has 33 vectors at this pin.
//! None is one of these rows. `parity/vectors/cli._common/vectors.json` is
//! pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and
//! `GAP-common-internal-error-json` says `_handle_internal_error` JSON mode
//! stops at `BUILD_INTERNAL_ERROR_ENVELOPE_UNAVAILABLE`; that older corpus is
//! not these rows. This integration test crate links
//! `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`] only. It
//! cannot call `sesslint.cli.main` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 8;
const PINNED_SPLITLINES: usize = 174;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. JSON mode is not human mode. Check is not repair. Repair is not
/// verify. A returned exit 2 is not a `SystemExit`. The help line about an
/// internal tool error is not a patched crash. An envelope constructor is not
/// `main`. `not_applicable` names the missing stop.
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
        name: "test_internal_error_json_mode",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_internal_error_json_mode patching sesslint.repair.executor.run_all_checks to RuntimeError with Simulated engine crash, calling sesslint.cli.main on [check, fixtures/determinism/repeat/repeat_session.json, --json], and asserting the returned exit code is 2, stdout JSON has verdict error, code INTERNAL_ERROR, error_id matching ^ERR-[0-9a-fA-F]{8}$ (ERR- plus eight hex digits), message containing that crash text, and stdout has no Traceback (most recent call last):; missing stop: that whole patched check --json envelope; stderr is not asserted; JSON mode is not human mode; check is not repair; repair is not verify; a returned exit 2 is not a SystemExit; ERR_ID_PATTERN is not a test; check_exit_constants and check_exit_epilog record the help line 2  an internal tool error exits 2 and are not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, and main_removed_init_hooks exit 2 for removed subcommands, not this patched check; main_removed_formats_json exits 2 with code ERROR and verdict error for removed formats, not INTERNAL_ERROR and not this crash text; create_parser_subcommand_names lists subcommands and is not this run; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli._common/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, handle_internal_error_human_no_args, handle_internal_error_human_other_hex, and handle_internal_error_human_json_false call _handle_internal_error directly with synthetic-engine-fault and a fixed hex, handle_internal_error_usage_reraises reraises CliError, and GAP-common-internal-error-json says json mode returns BUILD_INTERNAL_ERROR_ENVELOPE_UNAVAILABLE, so that older corpus is not this row and those ids are not cli vectors; parity/vectors/api/vectors.json at this pin has build_internal_error_envelope_empty_id, build_internal_error_envelope_spaced_id, and build_internal_error_envelope_supplied, whose message is Something unexpected broke, and GAP-api-secrets-token-hex says an omitted error_id stops at secrets.token_hex, so those envelopes are not this main() run and are not cli vectors; parity/vectors/repair.executor/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and module_all_export_order only lists the name run_all_checks, so that older corpus is not this RuntimeError patch; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_internal_error_human_mode",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_internal_error_human_mode patching sesslint.repair.executor.run_all_checks to RuntimeError with Simulated engine crash, calling sesslint.cli.main on [check, fixtures/determinism/repeat/repeat_session.json] without --json, and asserting the returned exit code is 2, stderr contains Operational error [ERR- and that crash text, stdout is empty, and stdout has no Traceback (most recent call last):; missing stop: that whole human-mode check crash; the JSON envelope is not this pytest; JSON mode is not human mode; check is not repair; repair is not verify; a returned exit 2 is not a SystemExit; this row does not parse stdout and does not require a traceback check on stderr; check_exit_constants and check_exit_epilog record the help line 2  an internal tool error exits 2 and are not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, and main_removed_init_hooks exit 2 with empty stdout for removed subcommands, not this patched check; main_removed_formats_json is a JSON envelope with code ERROR, not this human mode; create_parser_subcommand_names lists subcommands and is not this run; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli._common/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, and handle_internal_error_human_no_args, handle_internal_error_human_other_hex, and handle_internal_error_human_json_false are direct _handle_internal_error calls whose stderr is Operational error [ERR- plus a fixed hex and synthetic-engine-fault, not main() on the fixture with Simulated engine crash, so that older corpus is not this row and those ids are not cli vectors; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_internal_error_repair_command",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_internal_error_repair_command patching sesslint.repair.planner.plan to RuntimeError with Simulated planner crash, calling sesslint.cli.main on [repair, fixtures/determinism/repeat/repeat_session.json, --output, tmp_path/out.json, --json], and asserting the returned exit code is 2, stdout JSON has verdict error, code INTERNAL_ERROR, error_id matching ^ERR-[0-9a-fA-F]{8}$ (ERR- plus eight hex digits), message containing that planner text, and the output file is absent; missing stop: that whole patched repair --json envelope together with the absent output file; this function does not assert a traceback absence; JSON mode is not human mode; check is not repair; repair is not verify; a returned exit 2 is not a SystemExit; the engine-crash check envelope is not this planner text; check_exit_constants and check_exit_epilog record the help line 2  an internal tool error exits 2 and are not this run; main_removed_formats_json exits 2 with code ERROR and verdict error and does not assert an absent repair output file; main_removed_formats, main_removed_baseline, main_removed_validate_session, and main_removed_init_hooks exit 2 for removed subcommands, not this patched repair; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/repair.planner/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-planner-register-all says plan stops at sesslint.repair.recipes_conservative.register_all on the success path, so that older corpus is not this RuntimeError and those ids are not cli vectors; parity/vectors/api/vectors.json build_internal_error_envelope_supplied has message Something unexpected broke and is not this main() run; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_internal_error_repair_human_mode",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_internal_error_repair_human_mode patching sesslint.repair.planner.plan to RuntimeError with Simulated planner crash, calling sesslint.cli.main on [repair, fixtures/determinism/repeat/repeat_session.json, --output, tmp_path/out.json] without --json, and asserting the returned exit code is 2, stderr contains Operational error [ERR- and that planner text, stdout is empty and has no Traceback (most recent call last):, and the output file is absent; missing stop: that whole human-mode repair crash together with the absent output file; the JSON envelope is not this pytest; JSON mode is not human mode; check is not repair; repair is not verify; a returned exit 2 is not a SystemExit; the engine-crash human check is not this planner text; check_exit_constants and check_exit_epilog record the help line 2  an internal tool error exits 2 and are not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, and main_removed_init_hooks exit 2 for removed subcommands and do not assert an absent repair output file; main_removed_formats_json is JSON mode with code ERROR, not this human repair; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/repair.planner/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and GAP-planner-register-all says plan stops at sesslint.repair.recipes_conservative.register_all on the success path, so that older corpus is not this RuntimeError and those ids are not cli vectors; parity/vectors/cli._common/vectors.json human _handle_internal_error rows use synthetic-engine-fault and a fixed hex, not main() repair of the fixture, and that older corpus is not this row; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_internal_error_verify_json_mode",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_internal_error_verify_json_mode patching sesslint.verify.verify to RuntimeError with Simulated verify engine crash, calling sesslint.cli.main on [verify, fixtures/determinism/repeat/repeat_session.json, fixtures/determinism/repeat/repeat_session.json, --manifest, fixtures/determinism/repeat/repeat_session.json, --json], and asserting the returned exit code is 2, stdout JSON has verdict error, code INTERNAL_ERROR, error_id matching ^ERR-[0-9a-fA-F]{8}$ (ERR- plus eight hex digits), message containing that verify text, and stdout has no Traceback (most recent call last):; missing stop: that whole verify --json envelope; tmp_path is unused; JSON mode is not human mode; check is not repair; repair is not verify; a returned exit 2 is not a SystemExit; the check and repair envelopes are not this verify text; check_exit_epilog records the help line 2  an internal tool error exits 2 and is not this run; main_removed_formats_json exits 2 with code ERROR, not INTERNAL_ERROR and not verify of the fixture twice; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/verify/vectors.json at this pin has GAP-verify-cli saying CLI argv, capsys, exit codes, and main() integration are not byte-compared here, and GAP-verify-end-to-end says verify() stops at sesslint.report.parse_manifest, so that corpus is not this patched crash and those ids are not cli vectors; parity/vectors/api/vectors.json GAP-api-verify says verify() stops at sesslint.verify.verify is not available and build_internal_error_envelope_supplied is message Something unexpected broke, not this main() run; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_internal_error_verify_human_mode",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_internal_error_verify_human_mode patching sesslint.verify.verify to RuntimeError with Simulated verify engine crash, calling sesslint.cli.main on [verify, fixtures/determinism/repeat/repeat_session.json, fixtures/determinism/repeat/repeat_session.json, --manifest, fixtures/determinism/repeat/repeat_session.json] without --json, and asserting the returned exit code is 2, stderr contains Operational error [ERR- and that verify text, and stdout is empty and has no Traceback (most recent call last):; missing stop: that whole human-mode verify crash; tmp_path is unused; the JSON envelope is not this pytest; JSON mode is not human mode; check is not repair; repair is not verify; a returned exit 2 is not a SystemExit; the planner human crash is not this verify text; check_exit_constants and check_exit_epilog record the help line 2  an internal tool error exits 2 and are not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, and main_removed_init_hooks exit 2 for removed subcommands, not verify of the fixture twice; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/verify/vectors.json at this pin has GAP-verify-cli saying CLI argv, capsys, exit codes, and main() integration are not byte-compared here, so that corpus is not this patched crash and those ids are not cli vectors; parity/vectors/cli._common/vectors.json human _handle_internal_error rows use synthetic-engine-fault and a fixed hex, not main() verify of the fixture, and that older corpus at e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not this row; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_invalid_profile_repair_command_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_invalid_profile_repair_command_exits_2 calling sesslint.cli.main on [repair, fixtures/determinism/repeat/repeat_session.json, --profile, bogus_profile, --dry-run] with no patch, and asserting the returned exit code is 2, stderr contains the exact phrase Error: Unknown profile 'bogus_profile', and neither stdout nor stderr contains Traceback (most recent call last):; missing stop: that exact unknown-profile repair phrase on a returned exit 2; this is not a patched crash; a returned exit 2 is not a SystemExit; check is not repair; the check profile SystemExit is not this pytest; JSON mode is not this human repair run; no cli vector mentions profile; check_exit_epilog mentions invalid flags in help text and is not this bogus_profile run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not repair --profile bogus_profile --dry-run; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/repair.planner/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not this CLI phrase; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_invalid_profile_check_command_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_invalid_profile_check_command_exits_2 calling sesslint.cli.main on [check, fixtures/determinism/repeat/repeat_session.json, --profile, bogus_profile] inside pytest.raises(SystemExit), and asserting SystemExit code is 2, stderr contains Unknown profile 'bogus_profile' without requiring the Error: prefix, and neither stdout nor stderr contains Traceback (most recent call last):; missing stop: that SystemExit; a returned exit 2 is not a SystemExit; the repair profile test is not this pytest; this is not a patched crash; check is not repair; there is no --dry-run and no --json; the exact Error: Unknown profile phrase is not required here; no cli vector mentions profile; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json return exit 2 for removed subcommands and are not this SystemExit; check_exit_constants records a help line that an internal tool error exits 2 and is not this raise; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_internal_error_json_mode",
    "test_internal_error_human_mode",
    "test_internal_error_repair_command",
    "test_internal_error_repair_human_mode",
    "test_internal_error_verify_json_mode",
    "test_internal_error_verify_human_mode",
    "test_invalid_profile_repair_command_exits_2",
    "test_invalid_profile_check_command_exits_2",
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
fn pinned_cli_test_internal_error_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 174);
}

#[test]
fn pinned_cli_test_internal_error_row_count_equals_eight() {
    assert_eq!(ROWS.len(), 8);
    assert_eq!(PINNED_TEST_COUNT, 8);
}

#[test]
fn every_pinned_cli_test_internal_error_test_has_one_disposition() {
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
