//! Dispositions for the 12 `def test_` functions in pinned
//! `tests/cli/test_env_precedence.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (160 splitlines). Exactly twelve
//! test functions, in module order. None is parametrized. Helpers `_run`,
//! `_write_config`, `_adapter_id`, and `_profile_id` are not tests. The autouse
//! fixture `_clean_env` is not a test: it clears `SESSLINT_CONFIG`,
//! `SESSLINT_PROFILE`, `SESSLINT_ADAPTER`, and `SESSLINT_FORMAT`, and changes
//! directory to the temporary path so the repository config is not discovered.
//! That setup belongs to every row and is not its own row. Each row is the whole
//! function. One precedence layer is not another. An exit in {0, 1} is not a
//! single exit code.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` without a
//! `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. One precedence layer is not another. An exit in {0, 1} is not a
//! single exit code. The JSON adapter-id check is not the SARIF-key pytest.
//! The check SARIF run is not the doctor rejection. `not_applicable` names the
//! missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 12;
const PINNED_SPLITLINES: usize = 160;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One precedence layer is not another. An exit in {0, 1} is not a
/// single exit code. The JSON adapter-id check is not the SARIF-key pytest.
/// The check SARIF run is not the doctor rejection. `not_applicable` names the
/// missing stop.
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
        name: "test_config_beats_default_adapter",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_config_beats_default_adapter calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json, after _write_config writes adapter = canonical into sesslint.toml in the temporary directory, requiring an exit in {0, 1} and coverage.adapter.id canonical; missing stop: that config-over-default adapter id canonical together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the env-over-config adapter run and the cli-over-env adapter run are different pytests; the config-over-default profile run is a different layer; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; main_removed_validate_session mentions check --adapter canonical in a removed-command hint and does not run this check; verbose_settings_provenance records config file none and is not this sesslint.toml; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_env_beats_config_adapter",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_env_beats_config_adapter calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json, after _write_config writes adapter = canonical and SESSLINT_ADAPTER is set to claude-code-jsonl, requiring an exit in {0, 1} and coverage.adapter.id claude-code-jsonl; missing stop: that env-over-config adapter id claude-code-jsonl together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the config-over-default adapter run and the cli-over-env adapter run are different pytests; the env-over-config profile run is a different layer; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; removed_flag_hint_format_membership is a --format claude-code-jsonl hint and is not SESSLINT_ADAPTER; verbose_settings_provenance records max_files = 3 from env SESSLINT_X and is not SESSLINT_ADAPTER; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_beats_env_adapter",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_beats_env_adapter calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --adapter claude-code-jsonl and --json, after _write_config writes adapter = canonical and SESSLINT_ADAPTER is set to canonical, requiring an exit in {0, 1} and coverage.adapter.id claude-code-jsonl; missing stop: that cli-over-env adapter id claude-code-jsonl together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the config-over-default adapter run and the env-over-config adapter run are different pytests; the cli-over-env profile run is a different layer; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; removed_flag_hint_format_membership tells the caller to use --adapter and does not run check --adapter claude-code-jsonl; verbose_settings_provenance records flag = True from cli and is not this --adapter win; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_config_beats_default_profile",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_config_beats_default_profile calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json, after _write_config writes profile = claude-strict, requiring an exit in {0, 1} and coverage.profile.id claude-strict; missing stop: that config-over-default profile id claude-strict together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the env-over-config profile run and the cli-over-env profile run are different pytests; the config-over-default adapter run is a different layer; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; verbose_settings_provenance records policy = None from config:synthetic and is not profile claude-strict; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_env_beats_config_profile",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_env_beats_config_profile calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json, after _write_config writes profile = neutral and SESSLINT_PROFILE is set to claude-strict, requiring an exit in {0, 1} and coverage.profile.id claude-strict; missing stop: that env-over-config profile id claude-strict together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the config-over-default profile run and the cli-over-env profile run are different pytests; the env-over-config adapter run is a different layer; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; verbose_settings_provenance records max_files = 3 from env SESSLINT_X and is not SESSLINT_PROFILE; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_beats_env_profile",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_beats_env_profile calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --profile neutral and --json, with SESSLINT_PROFILE set to claude-strict and with no config file, requiring an exit in {0, 1} and coverage.profile.id neutral; missing stop: that cli-over-env profile id neutral together with an exit in {0, 1}; there is no config file in this test; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the config-over-default profile run and the env-over-config profile run are different pytests; the cli-over-env adapter run is a different layer; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; verbose_settings_provenance records config = synthetic-config.toml from cli and is not --profile neutral; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_env_output_format_applies",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_env_output_format_applies calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with no --json flag, with SESSLINT_FORMAT set to json, requiring an exit in {0, 1} and the parsed coverage.adapter.id claude-code-jsonl; missing stop: that SESSLINT_FORMAT json check whose stdout parses with coverage.adapter.id claude-code-jsonl together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the --format sarif override is a different pytest; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; removed_flag_hint_format_membership, removed_flag_hint_format_eq, removed_flag_hint_format_bare, and removed_flag_hint_output_format are removed --format hint probes and are not SESSLINT_FORMAT json on check; the env adapter override is a different layer; verbose_settings_provenance records zeta = json from cli and is not SESSLINT_FORMAT; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_format_beats_env_output_format",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_format_beats_env_output_format calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --format sarif, with SESSLINT_FORMAT set to json, requiring an exit in {0, 1} and stdout containing the SARIF schema key \"$schema\"; missing stop: that --format sarif stdout containing the SARIF schema key together with an exit in {0, 1}; the JSON adapter-id check is not this pytest; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the doctor rejection of SESSLINT_FORMAT sarif is a different pytest; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; removed_flag_hint_format_membership is a --format claude-code-jsonl hint whose text says --format now selects the output format, and is not this --format sarif check; removed_flag_hint_output_format is the removed --output-format hint and is not this run; verbose_settings_provenance records zeta = json from cli and is not this --format win; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_config_path_from_env",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_config_path_from_env calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --json, after _write_config writes adapter = canonical under the conf directory and SESSLINT_CONFIG is set to that path, requiring an exit in {0, 1} and coverage.adapter.id canonical; missing stop: that SESSLINT_CONFIG-selected adapter id canonical together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the cwd sesslint.toml config-over-default adapter run is a different pytest; the --config win over SESSLINT_CONFIG is a different pytest; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; verbose_settings_provenance records config file none and config = synthetic-config.toml from cli and is not SESSLINT_CONFIG; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_config_beats_env_config",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_config_beats_env_config calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with --config pointing at cli.toml and --json, after _write_config writes adapter = canonical to env.toml and adapter = claude-code-jsonl to cli.toml and SESSLINT_CONFIG is set to env.toml, requiring an exit in {0, 1} and coverage.adapter.id claude-code-jsonl; missing stop: that --config win whose adapter id is claude-code-jsonl together with an exit in {0, 1}; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the SESSLINT_CONFIG-only adapter id canonical is a different pytest; the --adapter win is a different layer; an exit in {0, 1} is not a single exit code; check_exit_constants stores separate lines for a clean session exiting 0 and a session with findings exiting 1 and is not this run; verbose_settings_provenance records config = synthetic-config.toml from cli and is not env.toml overridden by cli.toml; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_invalid_env_adapter_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_invalid_env_adapter_exits_2 calling sesslint.cli.main through _run on check of fixtures/cli/check_basic/healthy.jsonl with no format flag, with SESSLINT_ADAPTER set to bogus, requiring exit 2 and stderr containing SESSLINT_ADAPTER; missing stop: that exit 2 whose stderr contains SESSLINT_ADAPTER; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the SESSLINT_FORMAT rejection on doctor is a different pytest; an exit in {0, 1} is not a single exit code and is not this exit 2; check_exit_constants stores the line that an internal tool error exits 2 and the note that a usage error, invalid flags, or I/O failure also exits 2, and is not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not this bogus SESSLINT_ADAPTER; verbose_settings_provenance records max_files = 3 from env SESSLINT_X and is not SESSLINT_ADAPTER bogus; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_env_format_rejected_on_command_without_choice",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_env_format_rejected_on_command_without_choice calling sesslint.cli.main through _run on doctor --no-quick-checks, with SESSLINT_FORMAT set to sarif, requiring exit 2 and stderr containing SESSLINT_FORMAT; missing stop: that doctor exit 2 whose stderr contains SESSLINT_FORMAT; the check SARIF run is not this pytest; the autouse fixture _clean_env clears SESSLINT_CONFIG, SESSLINT_PROFILE, SESSLINT_ADAPTER, and SESSLINT_FORMAT and changes directory to the temporary path so the repository config is not discovered, and that setup belongs to this row; one precedence layer is not another; the bogus SESSLINT_ADAPTER exit 2 is a different pytest; an exit in {0, 1} is not a single exit code and is not this exit 2; check_exit_constants stores the line that an internal tool error exits 2 and is not this run; create_parser_subcommand_names lists doctor among subcommand names and does not run doctor --no-quick-checks; removed_command_hint_formats and removed_flag_hint_show_limits mention sesslint doctor in hint text and are not this invocation; main_removed_formats exits 2 for the removed formats command and mentions doctor in that hint, and is not this doctor run; removed_flag_hint_format_membership is a --format claude-code-jsonl hint and is not SESSLINT_FORMAT sarif; verbose_settings_provenance records zeta = json from cli and is not SESSLINT_FORMAT sarif; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_config_beats_default_adapter",
    "test_env_beats_config_adapter",
    "test_cli_beats_env_adapter",
    "test_config_beats_default_profile",
    "test_env_beats_config_profile",
    "test_cli_beats_env_profile",
    "test_env_output_format_applies",
    "test_cli_format_beats_env_output_format",
    "test_config_path_from_env",
    "test_cli_config_beats_env_config",
    "test_invalid_env_adapter_exits_2",
    "test_env_format_rejected_on_command_without_choice",
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
fn pinned_cli_test_env_precedence_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 160);
}

#[test]
fn pinned_cli_test_env_precedence_row_count_equals_twelve() {
    assert_eq!(ROWS.len(), 12);
    assert_eq!(PINNED_TEST_COUNT, 12);
}

#[test]
fn every_pinned_cli_test_env_precedence_test_has_one_disposition() {
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
