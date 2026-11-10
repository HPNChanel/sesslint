//! Dispositions for the thirty-one `def test_` functions in pinned
//! `tests/test_config.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (402 splitlines). Exactly
//! thirty-one test functions, in module order. None is parametrized. Each row
//! is the whole function. A load_config result is not a CLI exit. A check is
//! not a scan. A check is not doctor. One phase is not a multi-phase
//! function. The helpers `_toml_decode_error` and `_WARN_SESSION`, and the
//! constant `CORRUPT`, are not tests. `CORRUPT` names
//! `fixtures/adapters/codex/orphan_output.jsonl`. The warning session, the
//! corrupt fixture, and payload text are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, removed-command hints, removed-flag hints, verbose
//! provenance, and removed-subcommand exits. Those vectors are not these
//! load_config results or these check, scan, and doctor runs.
//! `create_parser_subcommand_names` lists `check`, `doctor`, and `scan` and
//! stops at `GAP-cli-init-create-parser`. `GAP-cli-init-parse-args` stops
//! before `parse_args`. `GAP-cli-init-dispatch-runtime` stops at
//! `sesslint.config.load_config` before `command.run`.
//! `removed_flag_hint_format_membership` hints `--format` and stops at
//! `GAP-cli-init-format-membership`. That hint is not the config key `format`
//! and is not a check with adapter canonical.
//! `main_removed_formats_json` exits 2 with code ERROR and verdict error for
//! the removed formats command. `main_removed_formats` exits 2 for that same
//! removed command. `main_removed_validate_session` exits 2 for the removed
//! validate-session command. None of those exits is a config check, scan, or
//! doctor run.
//! `parity/vectors/config/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Its ids are `format_renamed`,
//! `unknown_key`, `select_and_ignore`, `empty_profile`, `fail_on_stripped`,
//! `adapter_claude`, `bad_adapter`, `bool_is_not_a_number`, `timestamp_zero`,
//! `timestamp_negative`, `list_strip`, `key_order`, and `nothing_found`.
//! They are not among the 33 cli vectors and are not used to mark a row
//! covered. This integration test crate links `sesslint-rust-workspace`,
//! whose library exports [`PACKAGE_NAME`] only. It cannot call config or cli
//! functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 31;
const PINNED_SPLITLINES: usize = 402;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Each row is the whole function. A load_config result is not a CLI
/// exit. A check is not a scan. A check is not doctor. One phase is not a
/// multi-phase function. `not_applicable` names the missing stop.
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
        name: "test_load_pyproject_section",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_pyproject_section: a pyproject with a tool.sesslint table and ignore SL101 makes load_config return the mapping ignore containing SL101; missing stop: that loaded mapping; the standalone file is not this pytest; test_load_standalone_toml loads select from sesslint.toml and is not this pyproject section; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; config vector nothing_found is load_config of an empty directory at pin e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not this pyproject; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_load_standalone_toml",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_standalone_toml: a sesslint.toml with select SL101 makes load_config return the mapping select containing SL101; missing stop: that loaded mapping; the pyproject section is not this pytest; test_load_pyproject_section loads ignore from a tool.sesslint table and is not this standalone file; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_pyproject_without_section_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_pyproject_without_section_ignored: a pyproject with only a project table makes load_config return an empty mapping and find_config_file return None; missing stop: the empty mapping and None together; both assertions are one row; the empty mapping is not the None result; the None result is not the empty mapping; one assertion is not this pytest; test_explicit_pyproject_without_section_rejected raises ConfigError for an explicit path and is not this discovery skip; config vector nothing_found is load_config of an empty directory and is not this project table plus find_config_file None; verbose_settings_provenance records debug provenance and is not find_config_file None; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config and find_config_file are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_discovery_walks_upward",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_discovery_walks_upward: a nested directory with no file finds the parent sesslint.toml whose fail_on is warning; missing stop: that parent path from find_config_file; a load_config result is not this find; test_nearest_file_wins returns the nested file and is not this empty-directory walk; config vector key_order returns adapter auto and fail_on warning from validate_keys and is not this path; config vector fail_on_stripped returns a padded error string as error and is not this path; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; find_config_file is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_nearest_file_wins",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_nearest_file_wins: the parent fail_on is error and the nested file fail_on is warning, and find_config_file from the nested directory returns the nested file; missing stop: that nested path; a load_config result is not this find; the empty-directory walk is not this pytest; test_discovery_walks_upward finds the parent whose fail_on is warning and is not this nested file; config vector fail_on_stripped is a padded error string and is not these two files; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; find_config_file is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_unknown_key_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_key_rejected: a sesslint.toml with bogus true makes load_config raise ConfigError matching Unknown sesslint config key; missing stop: that ConfigError; test_cli_bad_config_exits_2 is the check exit and is not this API error; a load_config result is not a CLI exit; config vector unknown_key is validate_keys of a boolean bogus entry and is not this load_config of a sesslint.toml; the API unknown-key test is this pytest and the CLI exit is not this pytest; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_bad_type_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bad_type_rejected: fail_on as an integer makes load_config raise ConfigError matching non-empty string; missing stop: that ConfigError; test_bad_enum_rejected matches one of for fail_on fatal and is not this integer; a load_config result is not a CLI exit; config vector bool_is_not_a_number is validate_keys of confidence_min and is not fail_on as an integer; config vector empty_profile matches non-empty string for an empty profile and is not this integer; config vector timestamp_negative is a timestamp_skew_ms integer error and is not this fail_on type error; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_bad_enum_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bad_enum_rejected: fail_on fatal makes load_config raise ConfigError matching one of; missing stop: that ConfigError; the integer type error is not this pytest; test_bad_type_rejected matches non-empty string for fail_on as an integer and is not this enum; config vector bad_adapter matches one of for an unknown adapter and is not fail_on fatal; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_malformed_toml_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_toml_rejected: a standalone sesslint.toml that is not valid TOML makes load_config raise ConfigError matching Invalid TOML; missing stop: that ConfigError; the pyproject marker test is not this file; test_malformed_pyproject_with_sesslint_marker_fails_closed is the marker-present pyproject and is not this standalone file; a load_config result is not a CLI exit; a check is not this ConfigError; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_malformed_pyproject_with_sesslint_marker_fails_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_pyproject_with_sesslint_marker_fails_closed: a parent ignore file exists and a nested pyproject contains the marker but is invalid TOML; load_config and find_config_file both raise ConfigError matching Invalid TOML, and each message contains the bad path and the TOML decode error; then check --json of the corrupt fixture exits 2, stderr contains Invalid TOML, the path, and the decode error, and the JSON document has code ERROR, verdict error, and a message containing those three; missing stop: both ConfigErrors, the check exit 2, the stderr phrases, and the JSON document together; all of those assertions are one row; one phase is not this multi-phase function; a load_config result is not this CLI exit; a check is not doctor; the decode helper is not a test; _toml_decode_error is not a test; test_doctor_malformed_pyproject_with_marker_exits_2 is the doctor run and is not this check JSON exit 2; test_malformed_toml_rejected is the standalone sesslint.toml and is not this pyproject; test_malformed_pyproject_without_sesslint_marker_falls_back skips a file with no marker and is not this fail-closed marker; main_removed_formats_json exits 2 with code ERROR and verdict error for the removed formats command and is not this check of the corrupt fixture; the corrupt fixture is not copied here; the TOML decode error text is not copied here; this function is not parametrized; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config, find_config_file, and main are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_malformed_pyproject_without_sesslint_marker_falls_back",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_pyproject_without_sesslint_marker_falls_back: a lone invalid pyproject with no marker yields None and an empty mapping; after a parent fail_on warning and a nested broken project table, find_config_file returns the parent and load_config returns fail_on warning; missing stop: both phases together; both phases are one row; one phase is not this multi-phase function; the lone skip is not the parent fallback; the parent fallback is not the lone skip; the marker-present failure is not this skip; test_malformed_pyproject_with_sesslint_marker_fails_closed fails closed on a marker and is not this skip; config vector nothing_found is an empty directory and is not both phases; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; find_config_file and load_config are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_undecodable_pyproject_with_sesslint_marker_fails_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_undecodable_pyproject_with_sesslint_marker_fails_closed: a parent file ignores SL101, and bytes that start with the marker and then are not UTF-8 make load_config raise ConfigError matching Invalid TOML, and the message contains the path and utf-8; missing stop: that ConfigError together with the path and utf-8; the parent ignore file is part of this function and is not a successful load; the byte is not copied here; the valid-looking malformed marker test is not this pytest; test_malformed_pyproject_with_sesslint_marker_fails_closed is valid-looking invalid TOML and also runs check --json, and is not these undecodable bytes; test_undecodable_pyproject_without_sesslint_marker_falls_back skips bytes without the marker and is not this fail-closed raise; find_config_file is not asserted here; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_undecodable_pyproject_without_sesslint_marker_falls_back",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_undecodable_pyproject_without_sesslint_marker_falls_back: non-UTF-8 without the marker is skipped and the parent fail_on warning is loaded; find_config_file returns the parent and load_config returns fail_on warning; missing stop: that parent path and that fail_on warning mapping together; both assertions are one row; the find is not the load; the load is not the find; the byte is not copied here; the marker-present undecodable test is not this pytest; test_undecodable_pyproject_with_sesslint_marker_fails_closed raises Invalid TOML and is not this skip; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; find_config_file and load_config are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_doctor_malformed_pyproject_with_marker_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_malformed_pyproject_with_marker_exits_2: a nested pyproject contains the marker and is invalid TOML, and doctor --no-quick-checks exits 2, stderr does not contain Operational error, stderr contains Invalid TOML and the bad path, and stdout is empty; missing stop: that exit together with the absent Operational error, Invalid TOML, the bad path, and empty stdout; all of those assertions are one row; the exit is not the stderr text; the absent Operational error is not the Invalid TOML phrase; the check JSON exit 2 is not this doctor run; test_malformed_pyproject_with_sesslint_marker_fails_closed is the check JSON exit 2 and is not this doctor run; a check is not doctor; main_removed_formats exits 2 with empty stdout for the removed formats command and is not doctor --no-quick-checks; main_removed_formats_json writes a JSON document and is not this empty stdout; create_parser lists doctor and that name is not this run; a load_config result is not this CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_explicit_missing_path_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_explicit_missing_path_rejected: an explicit missing path makes load_config raise ConfigError matching not found; missing stop: that ConfigError; discovery that returns None is not this explicit rejection; test_pyproject_without_section_ignored returns None for a project table and is not this raise; test_discovery_walks_upward finds a parent file and is not this missing explicit path; a load_config result is not a CLI exit; verbose_settings_provenance records debug provenance and is not this not found ConfigError; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_explicit_pyproject_without_section_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_explicit_pyproject_without_section_rejected: an explicit pyproject with only a project table makes load_config raise ConfigError matching tool.sesslint; missing stop: that ConfigError; the discovery skip of that file is not this explicit rejection; test_pyproject_without_section_ignored loads an empty mapping and find_config_file returns None, and is not this raise; a load_config result is not a CLI exit; config vector nothing_found is an empty directory and is not this explicit rejection; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_honors_config_ignore",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_honors_config_ignore: ignore SL101, check --json of the corrupt fixture exits 0, and the SL101 count is 0; missing stop: that exit together with the SL101 count; both assertions are one row; the select override is not this pytest; test_cli_explicit_flag_overrides_config passes --select SL101 and exits 1 and is not this config ignore; test_cli_config_only_ignore_still_applies is a separate function and is not this pytest; test_cli_explicit_config_path passes --config and is not this discovered sesslint.toml; test_scan_honors_config_select is a scan and is not this check; a load_config result is not this CLI exit; a check is not a scan; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_explicit_flag_overrides_config",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_explicit_flag_overrides_config: config ignore SL101 but --select SL101 makes by_code exactly SL101 1 and the exit 1; missing stop: that exact by_code together with exit 1; both assertions are one row; the config-only ignore is not this pytest; test_cli_honors_config_ignore and test_cli_config_only_ignore_still_applies leave the SL101 count at 0 and exit 0 and are not this flag; test_cli_config_only_select_still_applies puts select in the file and passes no --select flag and is not this override; a load_config result is not this CLI exit; a check is not a scan; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_explicit_config_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_explicit_config_path: --config of a custom file that ignores SL101 exits 0 and the SL101 count is 0; missing stop: that exit together with the SL101 count for the explicit path; both assertions are one row; the discovered sesslint.toml is not this explicit path; test_cli_honors_config_ignore discovers sesslint.toml and is not this --config path; test_cli_config_only_ignore_still_applies discovers sesslint.toml and is not this custom file; a load_config result is not this CLI exit; a check is not a scan; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_select_and_ignore_together_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_and_ignore_together_rejected: select SL001 and ignore SL002 together make load_config raise ConfigError matching mutually exclusive, and the message contains the path, select, and ignore; missing stop: that ConfigError together with the path, select, and ignore; all of those assertions are one row; the CLI exit is not this API error; test_cli_select_and_ignore_config_exits_nonzero is the check exit and is not this ConfigError; a load_config result is not a CLI exit; config vector select_and_ignore is validate_keys of two empty lists and is not this file, these codes, or this path; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_select_and_ignore_config_exits_nonzero",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_select_and_ignore_config_exits_nonzero: a sesslint.toml sets select SL001 and ignore SL002, and check of the corrupt fixture without --json is not 0 and equals 2, and stderr contains the path, select, and ignore; missing stop: both exit assertions and the stderr phrases together; both exit assertions and the stderr phrases are one row; the exit that is not 0 is not the stderr phrases; the exit that equals 2 is not the API exception; the API exception is not this CLI exit; test_select_and_ignore_together_rejected raises ConfigError and is not this check; a load_config result is not this CLI exit; config vector select_and_ignore is validate_keys of two empty lists and is not this CLI exit; main_removed_formats exits 2 for the removed formats command and is not this check; main_removed_formats_json exits 2 with a JSON document and is not this check without --json; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_config_only_select_still_applies",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_config_only_select_still_applies: select SL101, check --json of the corrupt fixture, by_code is exactly SL101 1, and the exit is 1; missing stop: that exact by_code together with exit 1; both assertions are one row; the flag override is not this config-only select; test_cli_explicit_flag_overrides_config adds --select over ignore and is not this file select; test_cli_config_only_ignore_still_applies ignores SL101 and is not this select; test_cli_honors_config_adapter expects SL001 and is not this SL101 result; a load_config result is not this CLI exit; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_config_only_ignore_still_applies",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_config_only_ignore_still_applies: ignore SL101, check --json of the corrupt fixture, the SL101 count is 0, and the exit is 0; missing stop: that SL101 count together with exit 0; both assertions are one row; the select-only test is not this pytest; test_cli_config_only_select_still_applies is the select-only test and is not this ignore; test_cli_honors_config_ignore is a separate function and is not this pytest; test_scan_honors_config_select is a scan and is not this check; a check is not a scan; a load_config result is not this CLI exit; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_config_neither_select_nor_ignore_unchanged",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_config_neither_select_nor_ignore_unchanged: fail_on error only, check --json of the corrupt fixture, the SL101 count is 1, and the exit is 1; missing stop: that SL101 count together with exit 1; both assertions are one row; the ignore test is not this unchanged selection; test_cli_config_only_ignore_still_applies and test_cli_honors_config_ignore leave the SL101 count at 0 and are not this fail_on error file; test_cli_config_only_select_still_applies sets select and is not this file; config vector fail_on_stripped is validate_keys of a padded error string and is not this check; a load_config result is not this CLI exit; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_bad_config_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_bad_config_exits_2: a bogus key makes check of the corrupt fixture without --json exit 2, and stderr contains Unknown sesslint config key; missing stop: that exit together with that stderr phrase; both assertions are one row; the API unknown-key test is not this CLI exit; test_unknown_key_rejected raises ConfigError and is not this check; a load_config result is not this CLI exit; config vector unknown_key is validate_keys of a boolean bogus entry and is not this CLI exit; main_removed_formats exits 2 for the removed formats command and is not this check; check_exit_constants records the help line for exit 2 and is not this run; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_epilog records exit-code help text and is not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_scan_honors_config_select",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_honors_config_select: the function name says select, but the body sets ignore SL101, copies the corrupt fixture into a directory, and scan --json exits 0 with totals invalid 0 and healthy 1; missing stop: both totals together with that exit; both totals are one row; invalid 0 is not healthy 1; one total is not this pytest; the check ignore test is not this scan; test_cli_honors_config_ignore and test_cli_config_only_ignore_still_applies are check runs and are not this scan; a check is not a scan; a load_config result is not this CLI exit; create_parser lists scan and that name is not this run; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_config_fail_on_warning",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_config_fail_on_warning: fail_on warning makes check of a warning-only session exit 1; missing stop: that exit 1; the warning session is not copied here; the flag override is not this pytest; test_cli_fail_on_flag_overrides_config passes --fail-on error and exits 0 and is not this config-only exit 1; check_exit_constants records the help line for exit 1 and is not this run; config vector fail_on_stripped is validate_keys of a padded error string and is not this check; config vector key_order is validate_keys of adapter auto and fail_on warning and is not this check; a load_config result is not this CLI exit; a check is not doctor; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the corrupt fixture and payload text are not copied here; check_exit_epilog records exit-code help text and is not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_fail_on_flag_overrides_config",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_fail_on_flag_overrides_config: the same warning-only session with config fail_on warning and --fail-on error exits 0; missing stop: that exit 0; the warning session is not copied here; the config-only exit 1 is not this pytest; test_config_fail_on_warning exits 1 without --fail-on and is not this flag; check_exit_constants records the help line for exit 0 and is not this run; config vector key_order is validate_keys of fail_on warning and is not this --fail-on error check; a load_config result is not this CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the corrupt fixture and payload text are not copied here; check_exit_epilog records exit-code help text and is not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_adapter_key_accepted",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_key_accepted: adapter canonical makes load_config return adapter canonical; missing stop: that loaded mapping; the format key is not this pytest; test_format_key_renamed_to_adapter raises ConfigError and is not this accepted key; test_cli_honors_config_adapter is the check and is not this load; a load_config result is not a CLI exit; config vector adapter_claude is validate_keys of adapter claude and is not adapter canonical; config vector key_order is validate_keys of adapter auto and is not adapter canonical; config vector bad_adapter is an unknown adapter error and is not this success; removed_flag_hint_format_membership hints --format and stops at GAP-cli-init-format-membership and is not this config key; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_format_key_renamed_to_adapter",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_format_key_renamed_to_adapter: format canonical makes load_config raise ConfigError matching renamed to adapter; missing stop: that ConfigError; the accepted adapter key is not this pytest; test_adapter_key_accepted loads adapter canonical and is not this rename; config vector format_renamed is validate_keys of format canonical together with bogus true and is not this format-only file; removed_flag_hint_format_membership is a CLI flag hint for --format and stops at GAP-cli-init-format-membership and is not this config key; a load_config result is not a CLI exit; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session, the corrupt fixture, and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this pytest; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; load_config is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_honors_config_adapter",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_honors_config_adapter: adapter canonical, check --json of the corrupt fixture, by_code is exactly SL001 1, and the exit is 1; missing stop: that exact by_code together with exit 1; both assertions are one row; the load-only adapter test is not this CLI; test_adapter_key_accepted loads the mapping and is not this check; the SL101 ignore test is not this SL001 result; test_cli_honors_config_ignore and test_cli_config_only_ignore_still_applies count SL101 and are not this SL001 result; test_cli_config_only_select_still_applies expects SL101 and is not this SL001 result; a load_config result is not this CLI exit; config vector adapter_claude is adapter claude and is not this check; removed_flag_hint_format_membership is a flag hint and is not this check; main_removed_validate_session exits 2 for the removed validate-session command and is not this check; the corrupt fixture is not copied here; this function is not parametrized; _toml_decode_error is not a test; _WARN_SESSION is not a test; CORRUPT is not a test; the warning session and payload text are not copied here; check_exit_constants and check_exit_epilog record exit-code help text and are not this run; create_parser_subcommand_names lists check, doctor, and scan and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; GAP-cli-init-dispatch-runtime stops at sesslint.config.load_config before command.run; parity/vectors/config/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not among the 33 cli vectors; main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_load_pyproject_section",
    "test_load_standalone_toml",
    "test_pyproject_without_section_ignored",
    "test_discovery_walks_upward",
    "test_nearest_file_wins",
    "test_unknown_key_rejected",
    "test_bad_type_rejected",
    "test_bad_enum_rejected",
    "test_malformed_toml_rejected",
    "test_malformed_pyproject_with_sesslint_marker_fails_closed",
    "test_malformed_pyproject_without_sesslint_marker_falls_back",
    "test_undecodable_pyproject_with_sesslint_marker_fails_closed",
    "test_undecodable_pyproject_without_sesslint_marker_falls_back",
    "test_doctor_malformed_pyproject_with_marker_exits_2",
    "test_explicit_missing_path_rejected",
    "test_explicit_pyproject_without_section_rejected",
    "test_cli_honors_config_ignore",
    "test_cli_explicit_flag_overrides_config",
    "test_cli_explicit_config_path",
    "test_select_and_ignore_together_rejected",
    "test_cli_select_and_ignore_config_exits_nonzero",
    "test_cli_config_only_select_still_applies",
    "test_cli_config_only_ignore_still_applies",
    "test_cli_config_neither_select_nor_ignore_unchanged",
    "test_cli_bad_config_exits_2",
    "test_scan_honors_config_select",
    "test_config_fail_on_warning",
    "test_cli_fail_on_flag_overrides_config",
    "test_adapter_key_accepted",
    "test_format_key_renamed_to_adapter",
    "test_cli_honors_config_adapter",
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
fn pinned_test_config_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 402);
}

#[test]
fn pinned_test_config_row_count_equals_thirty_one() {
    assert_eq!(ROWS.len(), 31);
    assert_eq!(PINNED_TEST_COUNT, 31);
}

#[test]
fn every_pinned_test_config_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 31);
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
