//! Dispositions for the twelve `def test_` functions in pinned
//! `tests/cli/test_completion.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (149 splitlines). The module
//! covers generated completion scripts for `COMPLETION_SHELLS` (`bash`, `zsh`,
//! `fish`, `powershell`, read from pinned `sesslint.completion`), live
//! subcommand coverage against `PINNED_COMMANDS`, flags and choices,
//! deterministic generation, an unknown-shell `ValueError`, the PowerShell
//! script shape and sorted flag-map command keys, `main` completion runs, a
//! parser `SystemExit`, and zsh bracket escapes. Exactly twelve test functions,
//! in module order. None is parametrized. Helper `_live_subcommands` is not a
//! test. The tuple `PINNED_COMMANDS` is not a test. Each row is the whole
//! function. A nested loop is one matrix, not one cell. A `generate_completion`
//! string check is not a `main()` exit run. A parser `SystemExit` is not a
//! `ValueError`. One command in one shell is not the whole pytest. One flag is
//! not the whole pytest. One phrase is not the whole pytest. One shell is not
//! the whole pytest. `parity/vectors/completion/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and its gaps say
//! `generate_completion(parser=None)` is not byte-compared; that older corpus
//! is not these rows. This integration test crate links
//! `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`] only. It
//! cannot call `sesslint.cli.main`, `sesslint.cli.create_parser`, or
//! `sesslint.completion.generate_completion` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 12;
const PINNED_SPLITLINES: usize = 149;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A `generate_completion` string check is not a `main()` exit run. A
/// parser `SystemExit` is not a `ValueError`. One command in one shell is not
/// the whole pytest. One flag is not the whole pytest. One phrase is not the
/// whole pytest. One shell is not the whole pytest. The completion corpus at
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not these rows.
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
        name: "test_pinned_commands_present_in_all_shells",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_pinned_commands_present_in_all_shells calling generate_completion for every shell in COMPLETION_SHELLS (bash, zsh, fish, powershell) and asserting each script contains every PINNED_COMMANDS name (bundle, check, completion, diff, doctor, export, hook, mcp, outcome, repair, scan, seal, stats, triage, verify, version, watch); missing stop: that matrix of every command in every shell script; a nested loop is one matrix, not one cell; one command in one shell is not the whole pytest; create_parser_subcommand_names lists those names with gap_id GAP-cli-init-create-parser and is not generated scripts; a generate_completion string check is not a main() exit run; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its gaps say generate_completion(parser=None) is not byte-compared, so that older corpus is not this row; sesslint.completion.generate_completion is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_every_live_subcommand_covered",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_every_live_subcommand_covered asserting the live create_parser subcommand set equals PINNED_COMMANDS (bundle, check, completion, diff, doctor, export, hook, mcp, outcome, repair, scan, seal, stats, triage, verify, version, watch) and that every live name appears in the generate_completion script for every shell in COMPLETION_SHELLS (bash, zsh, fish, powershell); missing stop: both halves together; both halves are one row; a nested loop is one matrix, not one cell; one command in one shell is not the whole pytest; create_parser_subcommand_names lists those names with gap_id GAP-cli-init-create-parser and does not check shell scripts; helper _live_subcommands is not this test; a generate_completion string check is not a main() exit run; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its gaps say generate_completion(parser=None) is not byte-compared, so that older corpus is not this row; sesslint.cli.create_parser and sesslint.completion.generate_completion are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_flags_and_choices_present",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_flags_and_choices_present calling generate_completion for every shell in COMPLETION_SHELLS (bash, zsh, fish, powershell) and asserting each script contains --adapter, --format, --profile, --json, --output, --policy, and the choices claude-code-jsonl, openai-agents, canonical, conservative, claude-strict, neutral, and openai-strict; missing stop: that flag and choice matrix in every shell script; a nested loop is one matrix, not one cell; one flag is not the whole pytest; removed_flag_hint_format_membership records a removed --format hint for claude-code-jsonl and is not these completion scripts; a generate_completion string check is not a main() exit run; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its gaps say generate_completion(parser=None) and live profile choices are not byte-compared, so that older corpus is not this row; sesslint.completion.generate_completion is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_generation_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_generation_deterministic calling generate_completion twice for every shell in COMPLETION_SHELLS (bash, zsh, fish, powershell) and asserting the two texts are equal; missing stop: that double call for every shell; one shell is not the whole pytest; a single script snapshot is not two calls; a generate_completion string check is not a main() exit run; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its gaps say generate_completion(parser=None) is not byte-compared, so that older corpus is not this row; sesslint.completion.generate_completion is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_rejects_unknown_shell",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_rejects_unknown_shell calling generate_completion(\"elvish\") and asserting ValueError matching Unsupported shell; missing stop: that ValueError for elvish; a parser SystemExit is not this ValueError; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e, records no elvish vector, and its gaps say generate_completion(parser=None) is not byte-compared, so that older corpus is not this pytest; sesslint.completion.generate_completion is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_powershell_script_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_powershell_script_shape calling generate_completion(\"powershell\") and asserting the script contains Register-ArgumentCompleter, -Native -CommandName sesslint, CompletionResult, GetNewClosure, $sesslintFlagMap, $sesslintChoiceMap, 'check' = @(, 'scan' = @(, 'check --adapter' = @('auto', 'check --profile' = @('claude-strict', 'neutral', 'openai-strict'), and Parameters.ContainsKey('Native'); missing stop: every listed shape together; one phrase is not the whole pytest; a generate_completion string check is not a main() exit run; the powershell main() exit run is not this pytest; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its gaps say generate_completion(parser=None) is not byte-compared, so that older corpus is not this row; sesslint.completion.generate_completion is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_powershell_script_is_deterministic_sorted",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_powershell_script_is_deterministic_sorted calling generate_completion(\"powershell\"), keeping flag-map rows that start with four spaces and a quote and contain \" = @(\", dropping keys that contain \" -\" (command-plus-flag rows), and asserting the remaining command keys equal their sorted order; missing stop: that sorted command-key order; one phrase is not the whole pytest; the powershell shape phrases are not this order check; a generate_completion string check is not a main() exit run; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its gaps say generate_completion(parser=None) is not byte-compared, so that older corpus is not this row; sesslint.completion.generate_completion is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_completion_command",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_completion_command calling sesslint.cli.main on [\"completion\", \"bash\"] asserting exit 0 and stdout contains complete and sesslint; missing stop: that bash completion main run; a generate_completion string check is not this main() exit run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not completion bash exit 0; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_completion_rejects_unknown_shell",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_completion_rejects_unknown_shell calling create_parser().parse_args([\"completion\", \"elvish\"]) and asserting SystemExit code 2; missing stop: that parser SystemExit; the ValueError from generate_completion(\"elvish\") is not this pytest; a parser SystemExit is not a ValueError; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not parse_args of completion elvish; GAP-cli-init-parse-args records that Rust stops because argparse.ArgumentParser.parse_args is not available; sesslint.cli.create_parser is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_completion_powershell",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_completion_powershell calling sesslint.cli.main on [\"completion\", \"powershell\"] asserting exit 0 and stdout contains Register-ArgumentCompleter and sesslint; missing stop: that powershell completion main run; the bash main run is not this pytest; a generate_completion string check is not this main() exit run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not completion powershell exit 0; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_zsh_completion_escapes_brackets",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_zsh_completion_escapes_brackets calling generate_completion(\"zsh\") and asserting the script contains the escaped bracket phrases \\[lossy\\: follows links\\] and \\[tool.sesslint\\]; missing stop: both escaped phrases in the zsh script; one phrase is not the whole pytest; a generate_completion string check is not a main() exit run; parity/vectors/completion/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and its gaps say generate_completion(parser=None) is not byte-compared, so that older corpus is not this row; sesslint.completion.generate_completion is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_completion_all_supported_shells",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_completion_all_supported_shells calling sesslint.cli.main on [\"completion\", shell] for every shell in COMPLETION_SHELLS (bash, zsh, fish, powershell) asserting each returns 0 and stdout contains sesslint; missing stop: that main run for every shell; one shell is not the whole pytest; the bash main run is not this pytest; the powershell main run is not this pytest; a generate_completion string check is not this main() exit run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not completion exit 0; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_pinned_commands_present_in_all_shells",
    "test_every_live_subcommand_covered",
    "test_flags_and_choices_present",
    "test_generation_deterministic",
    "test_rejects_unknown_shell",
    "test_powershell_script_shape",
    "test_powershell_script_is_deterministic_sorted",
    "test_cli_completion_command",
    "test_cli_completion_rejects_unknown_shell",
    "test_cli_completion_powershell",
    "test_zsh_completion_escapes_brackets",
    "test_cli_completion_all_supported_shells",
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
fn pinned_cli_test_completion_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 149);
}

#[test]
fn pinned_cli_test_completion_row_count_equals_twelve() {
    assert_eq!(ROWS.len(), 12);
    assert_eq!(PINNED_TEST_COUNT, 12);
}

#[test]
fn every_pinned_cli_test_completion_test_has_one_disposition() {
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
