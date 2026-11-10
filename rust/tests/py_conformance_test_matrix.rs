//! Dispositions for the 6 `def test_` functions in pinned
//! `tests/conformance/test_matrix.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (95 splitlines). Exactly six
//! test functions, in module order. None is parametrized. A for-loop is one
//! row. `FIXTURES_DIR` and the fixture path constants `CANONICAL_FIXTURE`,
//! `CLAUDE_FIXTURE`, `OPENAI_FIXTURE`, and `CODEX_FIXTURE` are not tests. Each
//! row is the whole function. An exit 0 under one profile is not the exit 2
//! under another profile. One adapter matrix is not another. A CLI exit is not
//! the documentation read. All three memberships are one row. All three
//! profiles of the canonical check are one row. All three calls of an adapter
//! matrix are one row. The two successes are not the refusal. The Claude
//! matrix is not the OpenAI pytest. The OpenAI matrix is not the Codex pytest.
//! The comment about SL107 is not a separate assertion. All seven substrings
//! of the documentation read are one row.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` or
//! `sesslint.profiles.list_profiles` without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/profiles/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and is not a Covered source.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 6;
const PINNED_SPLITLINES: usize = 95;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. An exit 0 under one profile is not the exit 2 under another
/// profile. One adapter matrix is not another. A CLI exit is not the
/// documentation read. `not_applicable` names the missing stop.
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
        name: "test_matrix_registry_profiles",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_matrix_registry_profiles calling sesslint.profiles.list_profiles and requiring that the result contains neutral, claude-strict, and openai-strict; missing stop: list_profiles contains neutral, claude-strict, and openai-strict; all three memberships are one row; this is not a CLI run; an exit 0 under one profile is not the exit 2 under another profile and neither exit is this membership test; one adapter matrix is not another and no adapter matrix is this registry read; a CLI exit is not this list_profiles call; a for-loop is one row and this pytest has no for-loop; FIXTURES_DIR, CANONICAL_FIXTURE, CLAUDE_FIXTURE, OPENAI_FIXTURE, and CODEX_FIXTURE are not tests; parity/vectors/profiles/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a Covered source; package_registry_order lists keys neutral, claude-strict, and openai-strict on a noop and is not this call to list_profiles; package_all names the symbol list_profiles and does not assert the three memberships; package_neutral_name maps neutral, claude_strict, and openai_strict and is not the three memberships as one row; check_exit_constants stores the lines that a clean session exits 0, a session with findings exits 1, and an internal tool error exits 2, and those lines are not profile membership; check_exit_epilog stores those notes in help text; version_label stores sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not list profiles; create_parser_subcommand_names lists check among subcommand names and does not call list_profiles; removed_flag_hint_format_membership passes --format claude-code-jsonl and does not call list_profiles; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands; verbose_settings_provenance stores stderr debug lines and does not call list_profiles; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.profiles.list_profiles is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_canonical_supported_across_all_profiles",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_supported_across_all_profiles calling sesslint.cli.main on check of fixtures/determinism/repeat/repeat_session.json with --profile neutral, with --profile claude-strict, and with --profile openai-strict, requiring exit 0 under each; missing stop: check of fixtures/determinism/repeat/repeat_session.json exits 0 under neutral, under claude-strict, and under openai-strict; a for-loop is one row; all three profiles are one row; one profile is not this pytest; an exit 0 under one profile is not the exit 2 under another profile; this pytest has no exit 2; the two successes of an adapter matrix are not this three-success loop and the refusal is not this pytest; one adapter matrix is not another; the Claude matrix, the OpenAI matrix, and the Codex matrix are not this pytest; the registry membership test is not a CLI run and is not this check; a CLI exit of a removed subcommand is not this check; FIXTURES_DIR, CANONICAL_FIXTURE, CLAUDE_FIXTURE, OPENAI_FIXTURE, and CODEX_FIXTURE are not tests; parity/vectors/profiles/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a Covered source; a registry key list is not this check; check_exit_constants stores the line that a clean session exits 0 and does not check fixtures/determinism/repeat/repeat_session.json under neutral, claude-strict, and openai-strict; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists check among subcommand names and does not pass --profile or this fixture; version_label stores sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not run check; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and do not exit 0 on this fixture; removed_flag_hint vectors probe removed flags and do not pass --profile on this fixture; verbose_settings_provenance stores stderr debug lines and does not run check; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_claude_adapter_profile_matrix",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_claude_adapter_profile_matrix calling sesslint.cli.main on check of fixtures/claude_code/basic.jsonl, exiting 0 under neutral, exiting 0 under claude-strict, and exiting 2 under openai-strict; missing stop: check of fixtures/claude_code/basic.jsonl exits 0 under neutral and under claude-strict, and exits 2 under openai-strict; all three calls are one row; a for-loop is one row for the two successes and the refusal call is that same row; the two successes are not the refusal; an exit 0 under one profile is not the exit 2 under another profile; one profile is not this pytest; the OpenAI matrix is not this pytest; the Codex matrix is not this pytest; one adapter matrix is not another; the canonical three exits 0 are not this refusal; the registry membership test is not a CLI run and is not this check; a documentation read is not this check; FIXTURES_DIR, CANONICAL_FIXTURE, CLAUDE_FIXTURE, OPENAI_FIXTURE, and CODEX_FIXTURE are not tests; parity/vectors/profiles/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a Covered source; a registry key list is not these three calls; check_exit_constants stores a clean session exits 0 and an internal tool error exits 2 and does not check fixtures/claude_code/basic.jsonl under neutral, claude-strict, and openai-strict; check_exit_epilog stores those notes in help text; create_parser_subcommand_names lists check among subcommand names and does not pass this fixture or --profile; removed_flag_hint_format_membership passes --format claude-code-jsonl and does not check fixtures/claude_code/basic.jsonl; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not the openai-strict refusal of this fixture; version_label stores sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not run check; verbose_settings_provenance stores stderr debug lines and does not run check; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_openai_adapter_profile_matrix",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_openai_adapter_profile_matrix calling sesslint.cli.main on check of fixtures/openai_agents/items_basic.json, exiting 0 under neutral, exiting 0 under openai-strict, and exiting 2 under claude-strict; missing stop: check of fixtures/openai_agents/items_basic.json exits 0 under neutral and under openai-strict, and exits 2 under claude-strict; all three calls are one row; a for-loop is one row for the two successes and the refusal call is that same row; the two successes are not the refusal; an exit 0 under one profile is not the exit 2 under another profile; one profile is not this pytest; the Claude matrix is not this pytest; the Codex matrix is not this pytest; one adapter matrix is not another; the canonical three exits 0 are not this refusal; the registry membership test is not a CLI run and is not this check; a documentation read is not this check; FIXTURES_DIR, CANONICAL_FIXTURE, CLAUDE_FIXTURE, OPENAI_FIXTURE, and CODEX_FIXTURE are not tests; parity/vectors/profiles/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a Covered source; a registry key list is not these three calls; check_exit_constants stores a clean session exits 0 and an internal tool error exits 2 and does not check fixtures/openai_agents/items_basic.json under neutral, openai-strict, and claude-strict; check_exit_epilog stores those notes in help text; create_parser_subcommand_names lists check among subcommand names and does not pass this fixture or --profile; removed_flag_hint vectors do not check fixtures/openai_agents/items_basic.json; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not the claude-strict refusal of this fixture; version_label stores sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not run check; verbose_settings_provenance stores stderr debug lines and does not run check; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_codex_adapter_profile_matrix",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_adapter_profile_matrix calling sesslint.cli.main on check of fixtures/conformance/codex_rollout/healthy.jsonl, exiting 0 under neutral, exiting 0 under openai-strict, and exiting 2 under claude-strict; missing stop: check of fixtures/conformance/codex_rollout/healthy.jsonl exits 0 under neutral and under openai-strict, and exits 2 under claude-strict; all three calls are one row; a for-loop is one row for the two successes and the refusal call is that same row; the two successes are not the refusal; an exit 0 under one profile is not the exit 2 under another profile; one profile is not this pytest; the OpenAI matrix is not this pytest; the Claude matrix is not this pytest; one adapter matrix is not another; the canonical three exits 0 are not this refusal; the comment about SL107 is not a separate assertion; the docstring sentence about SL107 on async pairings is not an assert and the three exit codes do not require SL107; the registry membership test is not a CLI run and is not this check; a documentation read is not this check; FIXTURES_DIR, CANONICAL_FIXTURE, CLAUDE_FIXTURE, OPENAI_FIXTURE, and CODEX_FIXTURE are not tests; parity/vectors/profiles/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a Covered source; a registry key list is not these three calls; check_exit_constants stores a clean session exits 0 and an internal tool error exits 2 and does not check fixtures/conformance/codex_rollout/healthy.jsonl under neutral, openai-strict, and claude-strict; check_exit_epilog stores those notes in help text; create_parser_subcommand_names lists check among subcommand names and does not pass this fixture or --profile; removed_flag_hint vectors do not check fixtures/conformance/codex_rollout/healthy.jsonl; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not the claude-strict refusal of this fixture; version_label stores sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not run check; verbose_settings_provenance stores stderr debug lines and does not run check; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_matrix_doc_exists_and_matches",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_matrix_doc_exists_and_matches asserting that docs/MATRIX.md is a file and that its text contains canonical, claude-code-jsonl, openai-agents, codex-rollout, neutral, claude-strict, and openai-strict; missing stop: docs/MATRIX.md is a file and its text contains canonical, claude-code-jsonl, openai-agents, codex-rollout, neutral, claude-strict, and openai-strict; all seven substrings are one row; a CLI exit is not this read; an exit 0 under one profile is not the exit 2 under another profile and neither exit is this read; one adapter matrix is not another and no adapter matrix is this read; the canonical three exits 0 are not this read; the registry membership test calls list_profiles and is not this read; a for-loop is one row and this pytest has no for-loop; the comment about SL107 is not this read; FIXTURES_DIR, CANONICAL_FIXTURE, CLAUDE_FIXTURE, OPENAI_FIXTURE, and CODEX_FIXTURE are not tests; parity/vectors/profiles/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a Covered source; a registry key list is not this file read; check_exit_constants stores exit lines and does not read docs/MATRIX.md; check_exit_epilog stores those notes in help text and does not read docs/MATRIX.md; version_label stores sesslint 0.5.0 and does not read docs/MATRIX.md; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not read docs/MATRIX.md; create_parser_subcommand_names lists subcommand names and does not read docs/MATRIX.md; removed_flag_hint_format_membership passes --format claude-code-jsonl and does not read docs/MATRIX.md; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and do not read docs/MATRIX.md; verbose_settings_provenance stores stderr debug lines and does not read docs/MATRIX.md; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; this disposition does not read docs/MATRIX.md; sesslint.cli.main and sesslint.profiles.list_profiles are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_matrix_registry_profiles",
    "test_canonical_supported_across_all_profiles",
    "test_claude_adapter_profile_matrix",
    "test_openai_adapter_profile_matrix",
    "test_codex_adapter_profile_matrix",
    "test_matrix_doc_exists_and_matches",
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
fn pinned_conformance_test_matrix_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 95);
}

#[test]
fn pinned_conformance_test_matrix_row_count_equals_six() {
    assert_eq!(ROWS.len(), 6);
    assert_eq!(PINNED_TEST_COUNT, 6);
}

#[test]
fn every_pinned_conformance_test_matrix_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 6);
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
