//! Dispositions for the 21 `def test_` functions in pinned
//! `tests/test_adversarial_verify.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (562 splitlines). Exactly
//! twenty-one test functions, in module order. Four are parametrized:
//! malformed syntax has four cells, each non-dict root test has five cells,
//! and empty files has five cells. A parametrized function is one row
//! covering every cell. The helper `_make_base_bundle` is not a test. Each
//! row is the whole function. An API verify result is not a CLI exit. One
//! check is not a multi-check function. One cell is not the pytest.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.verify`,
//! `sesslint.cli`, or fingerprint functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin, including every cell. `parity/vectors/verify/vectors.json`
//! is pinned to the same commit and its cases are module and parse probes.
//! A parse rejection, one malformed file, or one check is not an entire
//! adversarial pytest. `parity/vectors/repair.fingerprint/vectors.json` is
//! pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and is not a Covered
//! source. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 21;
const PINNED_SPLITLINES: usize = 562;
const CLI_VECTOR_COUNT: usize = 33;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const VERIFY_VECTORS_REL: &str = "parity/vectors/verify/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest, including every cell. An API verify result is not a CLI exit. One
/// check is not a multi-check function. One cell is not the pytest.
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

macro_rules! not_applicable {
    ($unique:literal) => {
        Disposition::NotApplicable(concat!(
            $unique,
            " sesslint.cli vectors record parser metadata, removed-command hints, \
             removed-flag hints, exit-code constants, verbose settings, and main on \
             removed subcommands only; check_exit_constants stores a clean session \
             exits 0, a session with findings exits 1, and an internal tool error \
             exits 2, and notes that mention a dry-run plan generated, repair refused, \
             and a usage error, and those stored lines are not this pytest; \
             check_exit_epilog stores those notes in help text; version_label stores \
             sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral \
             session integrity checker and conservative repair tool and does not run \
             verify; create_parser_subcommand_names lists verify among subcommand \
             names and does not call main; removed_flag_hint_recursive_short stores a \
             hint for -r; removed_flag_hint_salvage stores a hint whose replacement \
             text names --policy salvage; removed_flag_hint_format_membership passes \
             --format claude-code-jsonl; removed_flag_hint_format_eq passes \
             --format=canonical and expects the hint to be absent; \
             verbose_settings_provenance stores stderr debug lines; \
             main_removed_formats, main_removed_baseline, \
             main_removed_validate_session, main_removed_init_hooks, and \
             main_removed_formats_json exit 2 for removed subcommands; a returned \
             exit 2 is not this flag-form verify; \
             parity/vectors/verify/vectors.json is pinned to this commit and its \
             cases are module and parse probes: module_all lists exports, \
             dataclass_serialization compares one Check and Verdict.to_json, \
             render_verify_human_formatting stores human render lines, and \
             parse_rejects_nan, parse_rejects_infinity, \
             parse_rejects_out_of_range_float, parse_rejects_deep_nesting, \
             parse_rejects_oversized_line, parse_rejects_nul_byte, \
             parse_rejects_oversized_file, parse_tolerates_headerless, and \
             parse_accepts_valid_jsonl are one parse call each; a parse rejection, \
             one malformed file, or one check is not an entire adversarial pytest; \
             GAP-verify-cli records that CLI argv, capsys, exit codes, and main \
             integration are not byte-compared; GAP-verify-end-to-end records that \
             verify on fixture bundles is not vector-compared; \
             GAP-verify-adversarial-matrix records that parametrized corrupt_file, \
             empty_target, and bad_root cells are not one vector per pytest; \
             GAP-verify-fs-hostile records that missing-path and directory-as-file \
             tests are not byte-compared; those gap strings are not vector ids; \
             rust/parity/vectors/repair.fingerprint/vectors.json is pinned to \
             e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a Covered source; \
             the helper _make_base_bundle is not a test; an API verify result is not \
             a CLI exit; one check is not a multi-check function; one cell is not the \
             pytest; sesslint.verify, sesslint.cli, and fingerprint functions are not \
             callable from this package without a Cargo.toml change"
        ))
    };
}

const ROWS: &[Row] = &[
    Row {
        name: "test_cli_declared_loss_null_exits_2_instead_of_1",
        disposition: not_applicable!(
            "no cli vector is test_cli_declared_loss_null_exits_2_instead_of_1 \
             calling sesslint.cli.main in flag form on verify, --source, --plan, \
             --repaired, and --manifest after declared_loss is set to null and \
             asserting the returned exit code is 1; missing stop: that flag-form \
             verify and that exit code 1; the comment about exit 2 is not the \
             assertion; the API null test is not this CLI exit; an API verify \
             result is not a CLI exit;"
        ),
    },
    Row {
        name: "test_simultaneous_failure_checks_1_2_3_4",
        disposition: not_applicable!(
            "no verify vector is test_simultaneous_failure_checks_1_2_3_4 replacing \
             the source bytes, replacing the plan fingerprint, and replacing the \
             output bytes, then verify returning ok false, seven checks, \
             source_hash, plan_fingerprint, output_hash, and transformation_audit \
             all false, with the names loss_audit, assurance_audit, and \
             idempotence present; missing stop: that whole four-check failure; all \
             of those assertions are one row; the seven-failure test is not this \
             pytest; one check is not a multi-check function; a parse rejection is \
             not this verify call;"
        ),
    },
    Row {
        name: "test_simultaneous_failure_all_7_checks",
        disposition: not_applicable!(
            "no verify vector is test_simultaneous_failure_all_7_checks replacing \
             the source bytes, replacing the plan fingerprint, replacing the \
             output with fixtures/verify/non_idempotent/output.jsonl, setting \
             declared_loss to one falsified entry, and setting assurance to clean, \
             then verify returning ok false, seven checks, and source_hash, \
             plan_fingerprint, output_hash, transformation_audit, loss_audit, \
             assurance_audit, and idempotence all false; missing stop: those seven \
             false checks together; all of those assertions are one row; the \
             four-check test is not this pytest; the registry-reset case is not \
             this pytest; one check is not a multi-check function; the fixture \
             bytes are not this stop;"
        ),
    },
    Row {
        name: "test_malformed_syntax_in_each_file",
        disposition: not_applicable!(
            "no verify vector is test_malformed_syntax_in_each_file across all four \
             cells source, plan, output, and manifest, each writing truncated \
             syntax and verify returning a Verdict whose ok is false and whose \
             check count is 7; missing stop: those four cells together; all four \
             cells are one row; one file is not this pytest; one cell is not the \
             pytest; a parse rejection of one session line is not this four-file \
             verify; the truncated bytes are not this stop;"
        ),
    },
    Row {
        name: "test_non_dict_root_in_manifest",
        disposition: not_applicable!(
            "no verify vector is test_non_dict_root_in_manifest across all five \
             cells, an array, a string, an integer, true, and null, each written \
             to the manifest and each returning a Verdict whose ok is false; \
             missing stop: those five roots together; all five cells are one row; \
             the pytest does not assert the check count; one root is not this \
             pytest; the plan test is not this pytest; one cell is not the pytest;"
        ),
    },
    Row {
        name: "test_non_dict_root_in_plan",
        disposition: not_applicable!(
            "no verify vector is test_non_dict_root_in_plan across the same five \
             roots, an array, a string, an integer, true, and null, each written \
             to the plan and each returning a Verdict whose ok is false; missing \
             stop: those five plan roots together; all five cells are one row; the \
             pytest does not assert the check count; one root is not this pytest; \
             the manifest test is not this pytest; one cell is not the pytest;"
        ),
    },
    Row {
        name: "test_empty_files_total_function",
        disposition: not_applicable!(
            "no verify vector is test_empty_files_total_function across all five \
             cells source, plan, output, manifest, and all four files together, \
             each returning a Verdict whose ok is false and whose check count is \
             7; missing stop: those five empty-file cells together; all five cells \
             are one row; one cell is not this pytest; one file is not this \
             pytest;"
        ),
    },
    Row {
        name: "test_inaccessible_file_raises_filenotfound",
        disposition: not_applicable!(
            "no verify vector is test_inaccessible_file_raises_filenotfound raising \
             FileNotFoundError four times, once for a missing source, once for a \
             missing plan, once for a missing output, and once for a missing \
             manifest; missing stop: those four raises together; four \
             FileNotFoundError raises are one row; one path is not this pytest; \
             the directory raise is not this pytest;"
        ),
    },
    Row {
        name: "test_directory_passed_as_file_raises_isadirectoryerror",
        disposition: not_applicable!(
            "no verify vector is \
             test_directory_passed_as_file_raises_isadirectoryerror passing only \
             the source path as a directory and verify raising IsADirectoryError; \
             missing stop: that source-directory raise; the four missing-file \
             raises are not this pytest; the test does not pass a directory as the \
             plan, output, or manifest;"
        ),
    },
    Row {
        name: "test_permuted_dict_keys_passes_audit",
        disposition: not_applicable!(
            "no verify vector is test_permuted_dict_keys_passes_audit reversing \
             event-object keys, updating the output fingerprint, then asserting \
             transformation_audit ok is true and verdict ok is true; missing stop: \
             both assertions together; both assertions are one row; the event-order \
             swap is not this pytest; one check is not this pair;"
        ),
    },
    Row {
        name: "test_permuted_event_order_fails_audit",
        disposition: not_applicable!(
            "no verify vector is test_permuted_event_order_fails_audit swapping two \
             event lines, updating the output fingerprint, then asserting \
             transformation_audit ok is false and its detail contains \
             events-mismatch; missing stop: both assertions together; both \
             assertions are one row; the key reversal is not this pytest; one \
             check is not this pair;"
        ),
    },
    Row {
        name: "test_tampered_manifest_source_hash",
        disposition: not_applicable!(
            "no verify vector is test_tampered_manifest_source_hash setting \
             input_fingerprint to 64 zeros, then asserting source_hash ok is false \
             and its detail contains mismatch; missing stop: both assertions \
             together; both assertions are one row; the plan-fingerprint tamper is \
             not this pytest; the output-hash tamper is not this pytest; one check \
             is not a multi-check function;"
        ),
    },
    Row {
        name: "test_tampered_plan_fingerprint",
        disposition: not_applicable!(
            "no verify vector is test_tampered_plan_fingerprint setting the plan \
             fingerprint to 64 ones, then asserting plan_fingerprint ok is false \
             and its detail contains plan-tampered; missing stop: both assertions \
             together; both assertions are one row; the source-hash tamper is not \
             this pytest; the output-hash tamper is not this pytest; \
             repair.fingerprint vectors are a different pin and are not this \
             verify failure;"
        ),
    },
    Row {
        name: "test_tampered_output_hash",
        disposition: not_applicable!(
            "no verify vector is test_tampered_output_hash setting \
             output_fingerprint to 64 twos, then asserting output_hash ok is false \
             and its detail contains mismatch; missing stop: both assertions \
             together; both assertions are one row; the source-hash tamper is not \
             this pytest; the plan-fingerprint tamper is not this pytest; one \
             check is not a multi-check function;"
        ),
    },
    Row {
        name: "test_modified_loss_totals_fails_check_5",
        disposition: not_applicable!(
            "no verify vector is test_modified_loss_totals_fails_check_5 setting \
             declared_loss to one discarded-suffix entry, then asserting loss_audit \
             ok is false and its detail contains mismatch; missing stop: both \
             assertions together; both assertions are one row; the falsified \
             assurance check is not this pytest; a null declared_loss is not this \
             entry; one check is not a multi-check function;"
        ),
    },
    Row {
        name: "test_falsified_assurance_level_fails_check_6",
        disposition: not_applicable!(
            "no verify vector is test_falsified_assurance_level_fails_check_6 \
             setting assurance to clean, then asserting assurance_audit ok is \
             false and its detail contains mismatch; missing stop: both assertions \
             together; both assertions are one row; the loss-totals check is not \
             this pytest; the seven-failure test that also sets assurance to clean \
             is not this single check;"
        ),
    },
    Row {
        name: "test_manifest_declared_loss_null_must_not_crash",
        disposition: not_applicable!(
            "no verify vector is test_manifest_declared_loss_null_must_not_crash \
             calling API verify after declared_loss is set to null and asserting \
             ok is false and loss_audit ok is false; missing stop: both assertions \
             together; both assertions are one row; the CLI exit 1 is not this API \
             result; an API verify result is not a CLI exit; the integer \
             declared_loss test is not this null case;"
        ),
    },
    Row {
        name: "test_manifest_declared_loss_integer_must_not_crash",
        disposition: not_applicable!(
            "no verify vector is \
             test_manifest_declared_loss_integer_must_not_crash setting \
             declared_loss to an integer, then asserting ok is false and \
             loss_audit ok is false; missing stop: both assertions together; both \
             assertions are one row; the null case is not this pytest; the \
             loss_totals non-integer case is not this pytest;"
        ),
    },
    Row {
        name: "test_manifest_loss_totals_invalid_values_must_not_crash",
        disposition: not_applicable!(
            "no verify vector is \
             test_manifest_loss_totals_invalid_values_must_not_crash removing \
             declared_loss and placing a non-integer in loss_totals, then \
             asserting ok is false and loss_audit ok is false; missing stop: both \
             assertions together; both assertions are one row; the integer \
             declared_loss case is not this pytest; the value is named only as a \
             non-integer;"
        ),
    },
    Row {
        name: "test_indented_single_document_session_parsing",
        disposition: not_applicable!(
            "no verify vector is test_indented_single_document_session_parsing \
             calling _parse_session_events on one indented document and returning \
             a header whose session id equals the id in that document and one \
             event; missing stop: that header equality and that one event \
             together; both assertions are one row; this is not a verify call; \
             parse_accepts_valid_jsonl is a compact JSONL probe and is not this \
             indented document; parse_tolerates_headerless has no header and is \
             not this document; the payload is not this stop;"
        ),
    },
    Row {
        name: "test_idempotence_falsely_converged_when_check4_skipped",
        disposition: not_applicable!(
            "no verify vector is \
             test_idempotence_falsely_converged_when_check4_skipped clearing the \
             recipe registry, breaking the source, and using the non-idempotent \
             fixture as the output, then asserting transformation_audit ok is \
             false and idempotence ok is false; missing stop: both assertions \
             together; both assertions are one row; the seven-failure test is not \
             this registry-reset case; the broken line and the fixture bytes are \
             not this stop;"
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_cli_declared_loss_null_exits_2_instead_of_1",
    "test_simultaneous_failure_checks_1_2_3_4",
    "test_simultaneous_failure_all_7_checks",
    "test_malformed_syntax_in_each_file",
    "test_non_dict_root_in_manifest",
    "test_non_dict_root_in_plan",
    "test_empty_files_total_function",
    "test_inaccessible_file_raises_filenotfound",
    "test_directory_passed_as_file_raises_isadirectoryerror",
    "test_permuted_dict_keys_passes_audit",
    "test_permuted_event_order_fails_audit",
    "test_tampered_manifest_source_hash",
    "test_tampered_plan_fingerprint",
    "test_tampered_output_hash",
    "test_modified_loss_totals_fails_check_5",
    "test_falsified_assurance_level_fails_check_6",
    "test_manifest_declared_loss_null_must_not_crash",
    "test_manifest_declared_loss_integer_must_not_crash",
    "test_manifest_loss_totals_invalid_values_must_not_crash",
    "test_indented_single_document_session_parsing",
    "test_idempotence_falsely_converged_when_check4_skipped",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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

fn vector_slice<'a>(json: &'a str, id: &str, corpus: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("{corpus} vectors.json is missing id {id}"));
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
fn pinned_test_adversarial_verify_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 562);
}

#[test]
fn pinned_test_adversarial_verify_row_count_equals_twenty_one() {
    assert_eq!(ROWS.len(), 21);
    assert_eq!(PINNED_TEST_COUNT, 21);
    assert_eq!(PINNED_NAMES.len(), 21);
}

#[test]
fn every_pinned_test_adversarial_verify_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 21);
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
                assert!(
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
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
    let json = read_vectors(CLI_VECTORS_REL);
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
        let slice = vector_slice(&json, vector_id, "cli");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}

#[test]
fn verify_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 21);

    let json = read_vectors(VERIFY_VECTORS_REL);
    // `parity/vectors/verify/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "verify vectors python_commit spacing does not match {needle}"
    );
    assert!(json.contains("\"module\": \"sesslint.verify\""));

    let ids = vector_ids(&json);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing verify vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "verify");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
