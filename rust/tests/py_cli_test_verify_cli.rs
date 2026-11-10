//! Dispositions for the 7 `def test_` functions in pinned
//! `tests/cli/test_verify_cli.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (139 splitlines). Exactly seven
//! test functions, in module order. None is parametrized. The module constant
//! `FIXTURES_DIR` is not a test. Each row is the whole function. Flag form is
//! not positional form. Human phrases are not a JSON ok field. A SystemExit 2
//! is not a returned exit 1. All three assertions of the ok set are one row.
//! All three phrases of a human run are one row. The ok set is not the tampered
//! flag-form pytest. The JSON ok test is not the human PASSED run. The human
//! PASSED run is not the positional json pytest. The JSON ok false test is not
//! the human FAILED run. The flag-form missing-flag test is not the positional
//! missing-repaired pytest.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` without a
//! `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. Flag form is not positional form. Human phrases are not a JSON ok
//! field. A SystemExit 2 is not a returned exit 1. `not_applicable` names the
//! missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 7;
const PINNED_SPLITLINES: usize = 139;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Flag form is not positional form. Human phrases are not a JSON ok
/// field. A SystemExit 2 is not a returned exit 1. `not_applicable` names the
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
        name: "test_verify_cli_ok_set",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_cli_ok_set calling sesslint.cli.main on verify of fixtures/verify/ok with flag form --source source.jsonl --plan plan.json --repaired output.jsonl --manifest manifest.json, requiring exit 0, JSON ok is true, and the keys checks and assurance are present; missing stop: that exit 0 whose JSON ok is true and whose keys checks and assurance are present; all three assertions are one row; flag form is not positional form; human phrases are not a JSON ok field; the positional human run on fixtures/verify/ok exits 0 with stdout containing Verification: PASSED, Checks:, and source_hash: matched, and the JSON ok test is not this human run; the positional arguments plus --json exit 0 with JSON ok true and do not require the keys checks and assurance; the same flag form on fixtures/verify/tampered_output exits 1 and JSON ok is false, and the ok set is not that pytest; a SystemExit 2 is not a returned exit 1 and is not this returned exit 0; check_exit_constants stores the line that a clean session exits 0 and the note that verification passed or a dry-run plan generated, and that note is not a JSON ok field and does not require the keys checks and assurance; check_exit_epilog stores those notes in help text; create_parser_subcommand_names lists verify among subcommand names and does not pass --source --plan --repaired --manifest; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not verify fixtures/verify/ok; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verify_cli_tampered_output",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_cli_tampered_output calling sesslint.cli.main on verify of fixtures/verify/tampered_output with the same flag form --source source.jsonl --plan plan.json --repaired output.jsonl --manifest manifest.json, requiring exit 1 and JSON ok is false; missing stop: that exit 1 whose JSON ok is false; the ok set is not this pytest; flag form is not positional form; human phrases are not a JSON ok field; the ok set uses that flag form on fixtures/verify/ok and exits 0 with JSON ok true and the keys checks and assurance present; the positional human run on fixtures/verify/tampered_output exits 1 with stdout containing Verification: FAILED, Checks:, and output_hash, and the JSON ok false test is not that human run; a SystemExit 2 is not a returned exit 1; the flag-form missing-flag pytest raises SystemExit code 2 from verify --source fake.jsonl and does not return exit 1; check_exit_constants stores the line that a session with findings exits 1 and the note that verification failed or repair refused, and that note is not a JSON ok field; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists verify among subcommand names and does not pass --source --plan --repaired --manifest on fixtures/verify/tampered_output; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verify_cli_missing_flag_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_cli_missing_flag_exits_2 calling sesslint.cli.main on verify --source fake.jsonl with no other flags and raising SystemExit code 2; missing stop: that SystemExit whose code is 2 from verify --source fake.jsonl with no other flags; a SystemExit 2 is not a returned exit 1; flag form is not positional form; the positional missing-repaired pytest raises SystemExit code 2 from positional source plus --manifest without the repaired path on fixtures/verify/ok, and that pytest is not this flag-form missing-flag test; the tampered flag form returns exit 1 and JSON ok is false and does not raise SystemExit; the ok set returns exit 0; check_exit_constants stores the line that an internal tool error exits 2 and the note that a usage error, invalid flags, or I/O failure also exits 2, and does not raise SystemExit from verify --source fake.jsonl; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists verify among subcommand names and does not call verify --source fake.jsonl; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and do not raise SystemExit from verify --source fake.jsonl; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verify_cli_positional_syntax",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_cli_positional_syntax calling sesslint.cli.main on verify with positional source.jsonl and repaired output.jsonl plus --manifest manifest.json, with no --plan, on fixtures/verify/ok, requiring exit 0 and stdout contains Verification: PASSED, Checks:, and source_hash: matched; missing stop: that exit 0 whose stdout contains Verification: PASSED, Checks:, and source_hash: matched; all three phrases are one row; human phrases are not a JSON ok field; the JSON ok test is not this human run; the same positional arguments plus --json exit 0 and JSON ok is true, and that pytest does not require Verification: PASSED, Checks:, or source_hash: matched; flag form is not positional form; the flag-form ok set passes --source --plan --repaired --manifest and requires JSON ok true with the keys checks and assurance; a SystemExit 2 is not a returned exit 1 and is not this returned exit 0; check_exit_constants stores the line that a clean session exits 0 and the note that verification passed or a dry-run plan generated, and that note is not the stdout phrase Verification: PASSED and does not require Checks: or source_hash: matched; check_exit_epilog stores that note in help text and does not render this human verify run; create_parser_subcommand_names lists verify among subcommand names and does not pass positional source and repaired paths; parser_shell_metadata describes an offline vendor-neutral session integrity checker and conservative repair tool and does not print Verification: PASSED; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verify_cli_positional_with_json_flag",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_cli_positional_with_json_flag calling sesslint.cli.main on verify with positional source.jsonl and repaired output.jsonl plus --manifest manifest.json and --json, with no --plan, on fixtures/verify/ok, requiring exit 0 and JSON ok is true; missing stop: that exit 0 whose JSON ok is true; the human PASSED run is not this pytest; human phrases are not a JSON ok field; the positional human run on the same paths without --json exits 0 and stdout contains Verification: PASSED, Checks:, and source_hash: matched; flag form is not positional form; the flag-form ok set passes --source --plan --repaired --manifest and also requires the keys checks and assurance, which this pytest does not assert; the tampered flag form exits 1 and JSON ok is false; a SystemExit 2 is not a returned exit 1 and is not this returned exit 0; main_removed_formats_json passes --json before the removed formats subcommand and exits 2, and it does not run verify; check_exit_constants stores the line that a clean session exits 0 and the note that verification passed or a dry-run plan generated, and that note is not a JSON ok field; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists verify among subcommand names and does not pass positional paths or --json; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verify_cli_positional_tampered_human_mode",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_cli_positional_tampered_human_mode calling sesslint.cli.main on verify with positional source.jsonl and repaired output.jsonl plus --manifest manifest.json, with no --plan and no --json, on fixtures/verify/tampered_output, requiring exit 1 and stdout contains Verification: FAILED, Checks:, and output_hash; missing stop: that exit 1 whose stdout contains Verification: FAILED, Checks:, and output_hash; all three phrases are one row; the JSON ok false test is not this human run; human phrases are not a JSON ok field; the flag form on fixtures/verify/tampered_output exits 1 and JSON ok is false and does not require Verification: FAILED, Checks:, or output_hash; flag form is not positional form; the positional human PASSED run on fixtures/verify/ok requires Verification: PASSED and source_hash: matched; a SystemExit 2 is not a returned exit 1; check_exit_constants stores the line that a session with findings exits 1 and the note that verification failed or repair refused, and that note is not the stdout phrase Verification: FAILED and does not require Checks: or output_hash; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists verify among subcommand names and does not pass positional paths on fixtures/verify/tampered_output; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verify_cli_positional_missing_repaired_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_cli_positional_missing_repaired_exits_2 calling sesslint.cli.main on verify with positional source.jsonl plus --manifest manifest.json, without the repaired path, on fixtures/verify/ok, and raising SystemExit code 2; missing stop: that SystemExit whose code is 2 from positional source plus --manifest without the repaired path on fixtures/verify/ok; the flag-form missing-flag test is not this pytest; flag form is not positional form; the flag-form missing-flag test is verify --source fake.jsonl with no other flags and also raises SystemExit code 2; a SystemExit 2 is not a returned exit 1; the positional human PASSED run includes the repaired path and exits 0 with Verification: PASSED, Checks:, and source_hash: matched; the positional --json run includes the repaired path and exits 0 with JSON ok true; check_exit_constants stores the line that an internal tool error exits 2 and the note that a usage error, invalid flags, or I/O failure also exits 2, and does not raise SystemExit from this positional argv; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists verify among subcommand names and does not omit the repaired path; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and do not raise this SystemExit; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_verify_cli_ok_set",
    "test_verify_cli_tampered_output",
    "test_verify_cli_missing_flag_exits_2",
    "test_verify_cli_positional_syntax",
    "test_verify_cli_positional_with_json_flag",
    "test_verify_cli_positional_tampered_human_mode",
    "test_verify_cli_positional_missing_repaired_exits_2",
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
fn pinned_cli_test_verify_cli_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 139);
}

#[test]
fn pinned_cli_test_verify_cli_row_count_equals_seven() {
    assert_eq!(ROWS.len(), 7);
    assert_eq!(PINNED_TEST_COUNT, 7);
}

#[test]
fn every_pinned_cli_test_verify_cli_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 7);
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
