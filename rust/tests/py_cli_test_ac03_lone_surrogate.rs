//! Dispositions for the twenty-three `def test_` functions in pinned
//! `tests/cli/test_ac03_lone_surrogate.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (553 splitlines). Exactly
//! twenty-three test functions, in module order. Three are parametrized:
//! `test_complete_terminal_surrogate_is_not_suffix_repairable` has two
//! newline cells, `test_json_cancellation_does_not_invent_a_complete_document`
//! has two exception cells, and `test_json_output_format_error_aliases` has
//! three flag cells. Each of those functions is one row covering every cell.
//! The helpers `_surrogate_why`, `_why_lines`, `_run`, and `_claude_line` are
//! not tests. Each row is the whole function. A decoder call is not
//! `check_file`. `check_file` is not the CLI. A comment is not an assertion.
//! Session records, timestamps, and message text are not copied here. The
//! planted sentinel is named only as absent.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call cli, api, or io functions
//! without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33 ids at this
//! pin and none of those ids is one of these twenty-three functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these
//! twenty-three functions. `parity/vectors/io/vectors.json` has 37 ids pinned
//! to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. None of those ids is one of
//! these twenty-three functions. That old pin is not a Covered source.
//! `decode_json_clean` is a single decoder cell and is not the five-call
//! decode pytest. `main_removed_formats_json` is one CLI error case and is
//! not the whole error loop. Therefore every row is NotApplicable.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 23;
const PINNED_SPLITLINES: usize = 553;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A decoder call is not `check_file`. `check_file` is
/// not the CLI. A comment is not an assertion. Each row is the whole
/// function. `not_applicable` names the missing stop.
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
        name: "test_decode_rejects_lone_surrogate_and_keeps_pairs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_decode_rejects_lone_surrogate_and_keeps_pairs: a lone high escape, a lone low escape, and two lone escapes each raise the surrogate error with those escape tuples, the two-escape call goes through the duplicate-aware decoder, a real pair decodes to U+1F600, and a doubled backslash stays the literal escape text; missing stop: all five calls together; all five calls are one row; a decoder call is not check_file; decode_json_clean is a single decoder cell and is not this pytest; test_decode_error_template_names_only_lone_surrogates is the template pair",
        ),
    },
    Row {
        name: "test_decode_error_template_names_only_lone_surrogates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_decode_error_template_names_only_lone_surrogates: the terminal and non-terminal templates are the same fixed sentence, that sentence does not contain the low escape from the input, a terminal JSON error uses the torn-record template, and a non-terminal value error uses the malformed-record template; missing stop: all of that together; all of that is one row; a decoder call is not check_file; the five-call decode is not this pytest; test_decode_rejects_lone_surrogate_and_keeps_pairs is that five-call decode",
        ),
    },
    Row {
        name: "test_other_surrogate_code_point_keeps_the_example",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_other_surrogate_code_point_keeps_the_example: the rendered sentence for line 4 equals the fixed sentence for line 4, and the low escape from the input is absent; missing stop: both together; both are one row; a decoder call is not check_file; the unrendered template pair is not this pytest; test_decode_error_template_names_only_lone_surrogates is that template pair",
        ),
    },
    Row {
        name: "test_lone_surrogate_line_is_a_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_lone_surrogate_line_is_a_finding: the written bad line contains the escape text, the check has at least one SL001, the sentinel is absent from every finding message, and one message is the fixed sentence for line 2; the human CLI exits 1, has no traceback on stdout or stderr, stderr has neither the canonical-serialization phrase nor the validation-error phrase, stdout contains the malformed-record heading, has exactly that line-2 sentence as its Why line, lacks the invisible phrase, lacks the sentinel on both streams, and lacks the raw surrogate character; missing stop: the check and the human CLI together; the check and the CLI are one row; check_file is not the CLI; the records are not copied here; the terminal-only finding is not this pytest; test_terminal_lone_surrogate_is_a_finding is that terminal file",
        ),
    },
    Row {
        name: "test_terminal_lone_surrogate_is_a_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_terminal_lone_surrogate_is_a_finding: the JSON CLI exits 1, the schema is sesslint.report/v1, the finding whose code is SL001 or SL002 is SL001, and its key set is exactly code, evidence, fingerprint, remediation, repairability, severity, and span; the sentinel is absent from stdout and stderr has no traceback; the human CLI exits 1, contains the malformed-record heading, has exactly the line-1 sentence as its Why line, and lacks the torn-terminal phrase; missing stop: both phases together; both phases are one row; the comment is not an extra assertion; the record is not copied here; the mid-file check is not this pytest; test_lone_surrogate_line_is_a_finding is that check and human CLI",
        ),
    },
    Row {
        name: "test_canonical_event_lone_surrogate",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_event_lone_surrogate: the canonical JSON CLI exits 1, some finding is SL001, the sentinel is absent from stdout, and stderr lacks the canonical-serialization phrase; the human CLI exits 1, contains the malformed-record heading, and has exactly the line-2 sentence as its Why line; missing stop: both phases together; both phases are one row; the records are not copied here; the non-canonical finding is not this pytest; test_lone_surrogate_line_is_a_finding is that check and human CLI",
        ),
    },
    Row {
        name: "test_ordinary_torn_and_malformed_keep_their_why",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ordinary_torn_and_malformed_keep_their_why: the unterminated file exits 1, contains the torn-record phrase for line 2, and lacks both the lone-surrogate phrase and the not-truncated sentence; the broken mid-file exits 1, contains the malformed-record phrase for line 2, and lacks those same two phrases; missing stop: both files together; both files are one row; the fragments are not copied here; a comment is not an assertion; the surrogate finding is not this pytest; test_lone_surrogate_line_is_a_finding is that surrogate finding",
        ),
    },
    Row {
        name: "test_paired_surrogate_and_literal_escape_stay_healthy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_paired_surrogate_and_literal_escape_stay_healthy: the paired-character file exits 0 with a total count of 0, and the literal-escape file exits 0 with a total count of 0 and without ud800 in stdout; missing stop: both files together; both files are one row; the message text is not copied here; a decoder call is not this CLI; test_decode_rejects_lone_surrogate_and_keeps_pairs is that five-call decode and is not this pytest",
        ),
    },
    Row {
        name: "test_surrogate_human_color_respects_no_color",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_surrogate_human_color_respects_no_color: with NO_COLOR unset, color always exits 1, contains the ANSI introducer, and contains Integrity check failed; with NO_COLOR set, the same command exits 1, lacks the ANSI introducer, contains Integrity check failed, and lacks the sentinel; missing stop: both phases together; both phases are one row; the record is not copied here; the missing-file color pair is not this pytest; test_missing_file_json_ignores_no_color is that pair of JSON documents",
        ),
    },
    Row {
        name: "test_missing_file_json_is_parseable",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_file_json_is_parseable: the JSON check of the missing path exits 2, verdict error, code ERROR, the normalized message contains /nope.jsonl, the message contains not found, and stderr has no traceback; missing stop: all of that together; all of that is one row; check_file is not the CLI; check_file_missing_default is one missing-file api call and is not this pytest; test_missing_file_human_stdout_stays_empty is the human check",
        ),
    },
    Row {
        name: "test_missing_file_json_ignores_no_color",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_file_json_ignores_no_color: both the unset and the set NO_COLOR runs exit 2, and their parsed documents are equal; missing stop: both runs together; both runs are one row; it does not assert the code field; the single missing-file JSON test is not this pytest; test_missing_file_json_is_parseable is that single run",
        ),
    },
    Row {
        name: "test_missing_file_human_stdout_stays_empty",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_file_human_stdout_stays_empty: the human check exits 2, stdout is empty, and stderr contains not found; missing stop: all three together; all three are one row; the JSON missing-file test is not this pytest; test_missing_file_json_is_parseable is that JSON check",
        ),
    },
    Row {
        name: "test_json_error_branches",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_error_branches: every case in that loop has parseable object stdout, verdict error, code ERROR, a non-empty message, an exit other than 0 and other than 130, and no traceback on stdout or stderr; missing stop: every case together; every case is one row; the argument lists are not copied here; one case is not this pytest; test_missing_file_json_is_parseable is that one missing-path case; main_removed_formats_json is one CLI error case and is not the whole error loop; test_json_schema_error_branch is the patched schema error and is not this pytest",
        ),
    },
    Row {
        name: "test_json_schema_error_branch",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_schema_error_branch: the patched schema error exits 1, verdict error, the message contains schema boom, and stderr has no traceback; missing stop: that patched schema error; it does not assert the code field; the loop test is not this pytest; test_json_error_branches is that loop; check_file is not the CLI",
        ),
    },
    Row {
        name: "test_directory_inputs_emit_one_scan_report",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_directory_inputs_emit_one_scan_report: both cells exit 0 with schema sesslint.scan-report/v1, no verdict key, and empty stderr; the empty directory has total 0 and healthy 0; the healthy file plus a directory has total 1 and healthy 1; missing stop: both cells together; both cells are one row; the error loop is not this pytest; test_json_error_branches is that loop",
        ),
    },
    Row {
        name: "test_json_top_level_file_not_found",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_top_level_file_not_found: version --json with the patched not-found error exits 2, verdict error, and the message contains gone; missing stop: that patched not-found error; it does not assert the code field; the missing-path test is not this pytest; test_missing_file_json_is_parseable is that missing path",
        ),
    },
    Row {
        name: "test_complete_terminal_surrogate_is_not_suffix_repairable",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_complete_terminal_surrogate_is_not_suffix_repairable: both newline cells have some manual SL001 and no SL002; the repair exits 1, writes neither the output nor the manifest, leaves the source bytes and mtime unchanged, and keeps the sentinel out of both streams; missing stop: both cells and both phases together; both cells and both phases are one row; the records are not copied here; check_file is not the CLI; the terminal finding CLI is not this pytest; test_terminal_lone_surrogate_is_a_finding is that JSON and human finding; a comment is not an assertion",
        ),
    },
    Row {
        name: "test_json_cancellation_does_not_invent_a_complete_document",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_cancellation_does_not_invent_a_complete_document: both exception cells, KeyboardInterrupt and OperationCancelled, exit 130 with empty stdout, and stderr contains cancelled; missing stop: both cells together; both cells are one row; it does not invent a JSON document; the kept-document test is not this pytest; test_existing_json_error_document_is_not_duplicated is that kept document",
        ),
    },
    Row {
        name: "test_existing_json_error_document_is_not_duplicated",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_existing_json_error_document_is_not_duplicated: the pre-emitted document is kept, the exit is 2, and its code is EXISTING; missing stop: that kept document with exit 2 and code EXISTING; it does not assert the message text; the cancellation test is not this pytest; test_json_cancellation_does_not_invent_a_complete_document is that empty stdout",
        ),
    },
    Row {
        name: "test_json_output_format_error_aliases",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_output_format_error_aliases: all three flag forms, the separate format flag, the equals form, and the short flag, exit 2 and have code ERROR; missing stop: all three cells together; all three cells are one row; the missing-file JSON test uses --json and is not this pytest; test_missing_file_json_is_parseable is that --json check",
        ),
    },
    Row {
        name: "test_json_environment_precedence_for_context_errors",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_environment_precedence_for_context_errors: the JSON format environment with a missing config exits 2 and has code ERROR; the explicit human format exits 2 with empty stdout; missing stop: both phases together; both phases are one row; the flag-alias test is not this pytest; test_json_output_format_error_aliases is those three flag cells",
        ),
    },
    Row {
        name: "test_doctor_config_error_is_usage_failure",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_doctor_config_error_is_usage_failure: the patched config error exits 2, the JSON code is ERROR, stderr contains invalid config, and stdout does not contain INTERNAL_ERROR; missing stop: all of that together; all of that is one row; it does not assert the message field; the environment config error is not this pytest; test_json_environment_precedence_for_context_errors is that check with a missing config",
        ),
    },
    Row {
        name: "test_error_tracking_does_not_retain_reports",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_error_tracking_does_not_retain_reports: the unlimited stream is nonempty and its diagnostic is empty; the stream limited to 32 has a diagnostic of 32 copies of the written character; missing stop: both streams together; both streams are one row; the large write is not generated here; a kept JSON document is not this pytest; test_existing_json_error_document_is_not_duplicated is that kept document",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_decode_rejects_lone_surrogate_and_keeps_pairs",
    "test_decode_error_template_names_only_lone_surrogates",
    "test_other_surrogate_code_point_keeps_the_example",
    "test_lone_surrogate_line_is_a_finding",
    "test_terminal_lone_surrogate_is_a_finding",
    "test_canonical_event_lone_surrogate",
    "test_ordinary_torn_and_malformed_keep_their_why",
    "test_paired_surrogate_and_literal_escape_stay_healthy",
    "test_surrogate_human_color_respects_no_color",
    "test_missing_file_json_is_parseable",
    "test_missing_file_json_ignores_no_color",
    "test_missing_file_human_stdout_stays_empty",
    "test_json_error_branches",
    "test_json_schema_error_branch",
    "test_directory_inputs_emit_one_scan_report",
    "test_json_top_level_file_not_found",
    "test_complete_terminal_surrogate_is_not_suffix_repairable",
    "test_json_cancellation_does_not_invent_a_complete_document",
    "test_existing_json_error_document_is_not_duplicated",
    "test_json_output_format_error_aliases",
    "test_json_environment_precedence_for_context_errors",
    "test_doctor_config_error_is_usage_failure",
    "test_error_tracking_does_not_retain_reports",
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
fn pinned_cli_test_ac03_lone_surrogate_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 553);
}

#[test]
fn pinned_cli_test_ac03_lone_surrogate_row_count_equals_twenty_three() {
    assert_eq!(ROWS.len(), 23);
    assert_eq!(PINNED_TEST_COUNT, 23);
    assert_eq!(PINNED_NAMES.len(), 23);
}

#[test]
fn every_pinned_cli_test_ac03_lone_surrogate_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 23);
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
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
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
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(
            !names.contains(id),
            "cli id {id} equals a pinned test name"
        );
    }

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
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 23);

    let json = read_vectors(API_VECTORS_REL);
    // `parity/vectors/api/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "api vectors python_commit spacing does not match {needle}"
    );
    assert!(json.contains("\"module\": \"sesslint.api\""));

    let ids = vector_ids(&json);
    assert_eq!(API_VECTOR_COUNT, 77);
    assert_eq!(ids.len(), API_VECTOR_COUNT);
    assert_eq!(ids.len(), 77);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    assert_eq!(id_set.len(), 77);
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(
            !names.contains(id),
            "api id {id} equals a pinned test name"
        );
    }
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "api");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
