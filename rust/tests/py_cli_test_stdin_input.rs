//! Dispositions for the nineteen `def test_` functions in pinned
//! `tests/cli/test_stdin_input.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (254 splitlines). Exactly
//! nineteen test functions, in module order. None is parametrized. The class
//! `_FakeStdin` and the helper `_feed_stdin` are not tests. Each row is the
//! whole function. `check_bytes` is not the CLI. `scan_bytes` is not
//! `scan_path`. A comment is not an assertion. Fixture bytes from the Codex,
//! scan, and repair fixtures are not copied here. The one-line schema
//! document and the document that contains an embedded NUL are not copied
//! here. The unused expected-output path is not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call cli, api, scan, or source
//! functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33 ids at this
//! pin and none of those ids is one of these nineteen functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these nineteen
//! functions. `module_all` lists `check_bytes`, `check_file`, and `scan_bytes`
//! among exports. `check_file_missing_default` is a missing-path `check_file`
//! call. `repair_plan_path_exclusive` is one dry-run repair call.
//! `removed_command_hint_dash_only` is a removed-command hint.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `parity/vectors/source/vectors.json` has 13 ids at that old pin.
//! `parity/vectors/adapters/vectors.json` has 1 id at that old pin. Those old
//! pins are not a Covered source, and none of those ids equals one of these
//! nineteen functions. `fingerprint_bytes_empty` and
//! `fingerprint_file_synthetic_default_chunk` are individual fingerprint calls
//! on that old pin. `supported_adapters` is that one adapters id.
//! `aggregate_by_code_exact` is an aggregate on that old pin. Therefore every
//! row is NotApplicable. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 19;
const PINNED_SPLITLINES: usize = 254;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `check_bytes` is not the CLI. `scan_bytes` is not
/// `scan_path`. A comment is not an assertion. Each row is the whole
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
        name: "test_check_bytes_matches_check_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_bytes_matches_check_file: the finding codes are equal, the assurance values are equal, and the source fingerprints are equal. All three are one row. It does not assert the code list. The scan comparison is not this pytest. missing stop: all three together; a comment is not an assertion; check_bytes is not the CLI; test_scan_bytes_matches_scan_path is that scan comparison; module_all lists check_bytes and check_file among exports and is not this comparison; check_file_missing_default is a missing-path check_file call and is not this pytest",
        ),
    },
    Row {
        name: "test_scan_bytes_matches_scan_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_bytes_matches_scan_path: the first-file verdicts are equal, the finding codes are equal, the path is <stdin>, and the root path is <stdin>. All of that is one row. It does not assert the verdict string. The check comparison is not this pytest. missing stop: all of that together; scan_bytes is not scan_path; the codes compared are the first file; test_check_bytes_matches_check_file is that check comparison; module_all lists scan_bytes among exports and is not this comparison; aggregate_by_code_exact is an aggregate on the old pin and is not this pytest",
        ),
    },
    Row {
        name: "test_fingerprint_bytes_matches_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fingerprint_bytes_matches_file: the fingerprint of the written bytes equals the fingerprint of the file. That equality is one row. It does not assert the fingerprint value. The check fingerprint comparison is not this pytest. missing stop: that equality; the one-line schema document is not copied here; test_check_bytes_matches_check_file is that check fingerprint comparison; fingerprint_bytes_empty is one fingerprint call on the old pin and is not this equality; fingerprint_file_synthetic_default_chunk is one file fingerprint on the old pin and is not this pytest",
        ),
    },
    Row {
        name: "test_check_bytes_fail_closed_variants",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_bytes_fail_closed_variants: the word garbage has empty findings, assurance A0, and a limitation that starts with Unsupported: format-undetected; a document with an embedded NUL has codes exactly SL001; empty bytes have codes exactly SL001; whitespace has codes exactly SL001. All four inputs are one row. The oversize test is not this pytest. missing stop: all four inputs together; the embedded-NUL document is not copied here; check_bytes is not the CLI; test_check_bytes_oversize_structured_result is that oversize test; test_cli_check_stdin_garbage_is_unsupported_by_default is the CLI garbage run and is not this pytest; test_check_bytes_virtual_path_in_findings asserts a path and is not these codes",
        ),
    },
    Row {
        name: "test_check_bytes_oversize_structured_result",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_bytes_oversize_structured_result: 128 bytes with a 64-byte limit has empty findings, assurance A0, and a limitation that starts with Skipped: file-too-large. All of that is one row. The scan oversize test is not this pytest. missing stop: all of that together; the limit is max_input_bytes on check_bytes; check_bytes is not the CLI; test_scan_bytes_oversize_skipped is that scan oversize test; test_cli_check_stdin_oversize_structured is the CLI oversize run and is not this pytest; test_check_bytes_fail_closed_variants is the four fail-closed inputs and is not this oversize result",
        ),
    },
    Row {
        name: "test_scan_bytes_oversize_skipped",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_bytes_oversize_skipped: the verdict is skipped, the skipped reason is file-too-large, the skipped total is 1, and the findings are empty. All of that is one row. The check oversize test is not this pytest. missing stop: all of that together; the limit is max_input_bytes on scan_bytes; scan_bytes is not scan_path; test_check_bytes_oversize_structured_result is that check oversize test; test_scan_bytes_matches_scan_path compares verdicts and does not assert the verdict string; module_all lists scan_bytes among exports and is not this skip",
        ),
    },
    Row {
        name: "test_check_bytes_virtual_path_in_findings",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_bytes_virtual_path_in_findings: the first finding source path is <pipe>. That path is one row. It does not assert the code. The NUL code assertion is not this pytest. missing stop: that path; it does not assert the code; the embedded-NUL document is not copied here; check_bytes is not the CLI; test_check_bytes_fail_closed_variants is that NUL code assertion",
        ),
    },
    Row {
        name: "test_cli_check_stdin_healthy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_stdin_healthy: the CLI exits 0 and stdout contains Valid Codex rollout session. Both are one row. It does not assert a fingerprint. The JSON match test is not this pytest. missing stop: both together; it does not pass the adapter flag; the Codex fixture bytes are not copied here; check_bytes is not the CLI; test_cli_check_stdin_json_matches_file is that JSON match test; test_cli_check_stdin_format_override passes the adapter flag and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_stdin_json_matches_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_stdin_json_matches_file: both exits are 0, the finding codes are equal, and the source fingerprints are equal. All of that is one row. It does not assert the code list. The human healthy check is not this pytest. missing stop: all of that together; it does not assert the code list; the Codex fixture bytes are not copied here; check_bytes is not the CLI; test_cli_check_stdin_healthy is that human healthy check; test_check_bytes_matches_check_file is the API comparison and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_check_stdin_garbage_is_unsupported_by_default",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_stdin_garbage_is_unsupported_by_default: the JSON check exits 0, assurance is A0, findings are empty, the limitation starts with Unsupported: format-undetected, and stderr contains unsupported (format-undetected); the fail-on-unsupported run exits 1. Both phases are one row. The skip-undetected test is not this pytest. missing stop: both phases together; check_bytes is not the CLI; test_cli_check_stdin_skip_undetected_json is that skip-undetected test; test_check_bytes_fail_closed_variants is the API garbage input and is not this CLI; test_cli_scan_stdin_garbage is the scan garbage run and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_stdin_mixed_paths_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_stdin_mixed_paths_rejected: the CLI exits 2 and stderr contains stdin without regard to case. Both are one row. The single-stdin healthy check is not this pytest. missing stop: both together; the command passes - and a second path; it does not assert the fed byte; test_cli_check_stdin_healthy is that single-stdin healthy check; removed_command_hint_dash_only is a removed-command hint and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_check_stdin_skip_undetected_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_stdin_skip_undetected_json: the CLI exits 0, skipped is true, and the path is <stdin>. All three are one row. It does not assert assurance. The default garbage test is not this pytest. missing stop: all three together; it does not assert assurance; test_cli_check_stdin_garbage_is_unsupported_by_default is that default garbage test; test_check_bytes_virtual_path_in_findings asserts a finding path and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_check_stdin_format_override",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_stdin_format_override: the adapter flag exits 0 and stdout contains Valid Codex rollout session. Both are one row. The default healthy check does not pass that flag and is not this pytest. missing stop: both together; the flag is --adapter codex-rollout; the Codex fixture bytes are not copied here; test_cli_check_stdin_healthy is that default healthy check; supported_adapters is the one adapters id on the old pin and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_check_stdin_oversize_structured",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_stdin_oversize_structured: the CLI exits 0, assurance is A0, findings are empty, and the limitation starts with Skipped: file-too-large. All of that is one row. The API oversize test is not this CLI. missing stop: all of that together; the command passes --max-file-bytes 64 on 128 bytes; a docstring is not an assertion; check_bytes is not the CLI; test_check_bytes_oversize_structured_result is that API oversize test; test_scan_bytes_oversize_skipped is the scan oversize test and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_scan_stdin_healthy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_stdin_healthy: the CLI exits 0 and stdout contains healthy. Both are one row. The check healthy test is not this pytest. missing stop: both together; it does not assert a verdict string; the scan fixture bytes are not copied here; scan_bytes is not scan_path; test_cli_check_stdin_healthy is that check healthy test; test_scan_bytes_matches_scan_path compares first-file verdicts and is not this CLI",
        ),
    },
    Row {
        name: "test_cli_scan_stdin_garbage",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_stdin_garbage: the JSON schema version is sesslint.report/v1, the session id is stdin, the CLI exits 0, and stderr contains unsupported; the fail-on-unsupported run exits 1. Both phases are one row. The check garbage test is not this pytest. missing stop: both phases together; stderr contains unsupported without regard to case; scan_bytes is not scan_path; test_cli_check_stdin_garbage_is_unsupported_by_default is that check garbage test; test_scan_bytes_oversize_skipped is the scan oversize skip and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_repair_stdin_roundtrip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_stdin_roundtrip: the stdin repair exits 0, the output exists, the manifest exists, the file repair exits 0, and the output bytes are equal. All of that is one row. It does not assert the bytes. The dry-run repair is not this pytest. missing stop: all of that together; a comment is not an assertion; the unused expected-output path is not this comparison; the repair fixture bytes are not copied here; test_cli_repair_stdin_dry_run is that dry-run repair; test_cli_repair_stdin_requires_output refuses a repair without --output and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_repair_stdin_requires_output",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_stdin_requires_output: the CLI exits 2 and stderr contains --output. Both are one row. The dry-run repair is not this pytest. missing stop: both together; the command is repair - with no --output and no --dry-run; test_cli_repair_stdin_dry_run is that dry-run repair; test_cli_repair_stdin_roundtrip passes --output and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_repair_stdin_dry_run",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_repair_stdin_dry_run: the CLI exits 0 and stdout contains Plan fingerprint:. Both are one row. The roundtrip writes an output and is not this pytest. missing stop: both together; it does not assert an output path; the repair fixture bytes are not copied here; test_cli_repair_stdin_roundtrip is that roundtrip; test_cli_repair_stdin_requires_output exits 2 and is not this pytest; repair_plan_path_exclusive is one dry-run repair call and is not this CLI",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_check_bytes_matches_check_file",
    "test_scan_bytes_matches_scan_path",
    "test_fingerprint_bytes_matches_file",
    "test_check_bytes_fail_closed_variants",
    "test_check_bytes_oversize_structured_result",
    "test_scan_bytes_oversize_skipped",
    "test_check_bytes_virtual_path_in_findings",
    "test_cli_check_stdin_healthy",
    "test_cli_check_stdin_json_matches_file",
    "test_cli_check_stdin_garbage_is_unsupported_by_default",
    "test_cli_check_stdin_mixed_paths_rejected",
    "test_cli_check_stdin_skip_undetected_json",
    "test_cli_check_stdin_format_override",
    "test_cli_check_stdin_oversize_structured",
    "test_cli_scan_stdin_healthy",
    "test_cli_scan_stdin_garbage",
    "test_cli_repair_stdin_roundtrip",
    "test_cli_repair_stdin_requires_output",
    "test_cli_repair_stdin_dry_run",
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
fn pinned_cli_test_stdin_input_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 254);
}

#[test]
fn pinned_cli_test_stdin_input_row_count_equals_nineteen() {
    assert_eq!(ROWS.len(), 19);
    assert_eq!(PINNED_TEST_COUNT, 19);
    assert_eq!(PINNED_NAMES.len(), 19);
}

#[test]
fn every_pinned_cli_test_stdin_input_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 19);
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
    assert_eq!(not_applicable, 19);

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
