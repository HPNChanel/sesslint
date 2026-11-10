//! Dispositions for the fourteen test functions in pinned
//! `tests/test_field_regressions.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (395 splitlines). Exactly
//! fourteen test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helpers `_HDR` and `_ev` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these fourteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids and module
//! `sesslint.api`. None of those 77 is one of these fourteen names.
//! `parity/vectors/checks/vectors.json`,
//! `parity/vectors/checks.identity/vectors.json`,
//! `parity/vectors/io/vectors.json`, `parity/vectors/canonical/vectors.json`,
//! `parity/vectors/scan/vectors.json`, `parity/vectors/discovery/vectors.json`,
//! `parity/vectors/sarif/vectors.json`, and
//! `parity/vectors/repair.writeback/vectors.json` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! That old pin is not a Covered source. A check vector that only emits SL001
//! is not the whole pytest. The name says SL302 only when the body asserts
//! SL302. `test_check_non_utf8_is_sl001_not_sl302` and
//! `test_check_nul_byte_is_sl001` assert that SL302 is absent.
//! `test_empty_file_with_forced_format_is_invalid` asserts an error count and
//! does not assert SL302. `test_whitespace_only_with_forced_format_is_invalid`
//! asserts SL001 membership and does not assert SL302.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `check_file`, `main`, or
//! `probe_text_encoding` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 14;
const PINNED_SPLITLINES: usize = 395;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these fourteen functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A check vector that only emits SL001 is not the whole pytest.
/// The name says SL302 only when the body asserts SL302.
/// `not_applicable` names the missing stop and the nearest different test.
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
        name: "test_sl003_identical_when_only_seq_differs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sl003_identical_when_only_seq_differs: check_file with format canonical has one SL003 whose severity is warning, whose evidence is present, and whose variant is identical-duplicate; the docstring is not an assertion; missing stop: that one hit, that warning severity, that present evidence, and that identical-duplicate variant together; The conflicting SL003 is not this; test_sl003_conflicting_still_fires is that conflicting SL003",
        ),
    },
    Row {
        name: "test_sl003_vendor_byte_identical_lines",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sl003_vendor_byte_identical_lines: check_file has one SL003 whose evidence is present, whose variant is identical-duplicate, and whose severity is warning; the docstring is not an assertion; missing stop: that one hit, that present evidence, that identical-duplicate variant, and that warning severity together; The conflicting SL003 is not this; test_sl003_conflicting_still_fires is that conflicting SL003",
        ),
    },
    Row {
        name: "test_sl003_conflicting_still_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sl003_conflicting_still_fires: check_file with format canonical has one SL003 whose severity is error, whose evidence is present, and whose variant is conflicting-duplicate; the docstring is not an assertion; missing stop: that one hit, that error severity, that present evidence, and that conflicting-duplicate variant together; The identical-seq SL003 is not this; test_sl003_identical_when_only_seq_differs is that identical-seq SL003",
        ),
    },
    Row {
        name: "test_orphan_result_drop_resolves_by_id",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_orphan_result_drop_resolves_by_id: repair with an output path, salvage policy, and acknowledge-side-effects returns 0; two ids are absent from the written id list; the written id list has five elements and the first element is None; the docstring is not an assertion; the comment is not an assertion; missing stop: that zero return, those two absent ids, that length of five, and that leading None together; The non-UTF-8 check is not this; test_check_non_utf8_is_sl001_not_sl302 is that non-UTF-8 check",
        ),
    },
    Row {
        name: "test_check_non_utf8_is_sl001_not_sl302",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_non_utf8_is_sl001_not_sl302: check_file codes include SL001 and do not include SL302; it does not assert a severity or a count; the docstring is not an assertion; missing stop: that SL001 membership and that SL302 absence together; The NUL-byte SL001 is not this; test_check_nul_byte_is_sl001 is that NUL-byte SL001",
        ),
    },
    Row {
        name: "test_check_nul_byte_is_sl001",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_nul_byte_is_sl001: check_file codes include SL001 and do not include SL302; it does not assert a severity or a count; missing stop: that SL001 membership and that SL302 absence together; The non-UTF-8 check is not this; test_check_non_utf8_is_sl001_not_sl302 is that non-UTF-8 check",
        ),
    },
    Row {
        name: "test_probe_text_encoding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_probe_text_encoding: probe_text_encoding returns None for the clean path, nul for the nul path, and utf8 for the bad path; it does not assert a finding code or a severity; missing stop: that None, that nul, and that utf8 together; The NUL-byte SL001 is not this; test_check_nul_byte_is_sl001 is that NUL-byte SL001",
        ),
    },
    Row {
        name: "test_empty_file_with_forced_format_is_invalid",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_empty_file_with_forced_format_is_invalid: check_file with format claude-code-jsonl has SL001 among its codes and an error severity count of at least 1; it does not assert SL302; missing stop: that SL001 membership and that error count together; The whitespace-only file is not this; test_whitespace_only_with_forced_format_is_invalid is that whitespace-only file",
        ),
    },
    Row {
        name: "test_whitespace_only_with_forced_format_is_invalid",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_whitespace_only_with_forced_format_is_invalid: check_file with format claude-code-jsonl has SL001 among its codes; it does not assert a severity, a count, or SL302; missing stop: that SL001 membership together; The empty file is not this; test_empty_file_with_forced_format_is_invalid is that empty file",
        ),
    },
    Row {
        name: "test_check_json_skip_undetected_emits_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_json_skip_undetected_emits_json: check with json and skip-undetected returns 0, and the parsed stdout object has ok true, skipped true, skipped_reason format-undetected, and findings empty; the comment is not an assertion; missing stop: that zero return, that ok flag, that skipped flag, that format-undetected reason, and that empty findings list together; The SARIF output is not this; test_check_sarif_skip_undetected_emits_sarif is that SARIF output",
        ),
    },
    Row {
        name: "test_check_sarif_skip_undetected_emits_sarif",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_sarif_skip_undetected_emits_sarif: check with format sarif and skip-undetected returns 0, and the parsed stdout object has version 2.1.0 and contains runs; it does not assert ok, skipped, skipped_reason, or findings; missing stop: that zero return, that version, and that runs key together; The JSON output is not this; test_check_json_skip_undetected_emits_json is that JSON output",
        ),
    },
    Row {
        name: "test_scan_excludes_git_dir_and_own_artifacts",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_excludes_git_dir_and_own_artifacts: a json scan has one file path and that path ends with sess.jsonl; it does not assert a finding code or a severity; missing stop: that one path and that sess.jsonl suffix together; The reparse identity equality is not this; test_reparse_identity_hashes_normalizes_synthetic_ids is that reparse identity equality",
        ),
    },
    Row {
        name: "test_reparse_identity_hashes_normalizes_synthetic_ids",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reparse_identity_hashes_normalizes_synthetic_ids: reparse_identity_hashes of the original list equals reparse_identity_hashes of the reparsed list; it does not assert a finding code or a return code; the docstring is not an assertion; the comments are not assertions; missing stop: that equality together; The vendor write-back is not this; test_codex_vendor_writeback_e2e is that vendor write-back",
        ),
    },
    Row {
        name: "test_codex_vendor_writeback_e2e",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_vendor_writeback_e2e: repair with an output path returns 0; the manifest adapter_id is codex-rollout; the first output object type is session_meta; verify with the manifest returns 0; the docstring is not an assertion; the comments are not assertions; missing stop: that repair return, that adapter id, that session_meta type, and that verify return together; The reparse identity equality is not this; test_reparse_identity_hashes_normalizes_synthetic_ids is that reparse identity equality",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_sl003_identical_when_only_seq_differs",
    "test_sl003_vendor_byte_identical_lines",
    "test_sl003_conflicting_still_fires",
    "test_orphan_result_drop_resolves_by_id",
    "test_check_non_utf8_is_sl001_not_sl302",
    "test_check_nul_byte_is_sl001",
    "test_probe_text_encoding",
    "test_empty_file_with_forced_format_is_invalid",
    "test_whitespace_only_with_forced_format_is_invalid",
    "test_check_json_skip_undetected_emits_json",
    "test_check_sarif_skip_undetected_emits_sarif",
    "test_scan_excludes_git_dir_and_own_artifacts",
    "test_reparse_identity_hashes_normalizes_synthetic_ids",
    "test_codex_vendor_writeback_e2e",
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

fn assert_python_commit_one_space(json: &str, corpus: &str) {
    // The corpus stores one space after the colon.
    let commit = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&commit),
        "{corpus} vectors python_commit spacing does not match {commit}"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "{corpus} python_commit has no space after the colon"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":  \"{PIN}\"")),
        "{corpus} python_commit has more than one space after the colon"
    );
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_test_field_regressions_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 395);
}

#[test]
fn pinned_test_field_regressions_row_count_equals_fourteen() {
    assert_eq!(ROWS.len(), 14);
    assert_eq!(PINNED_TEST_COUNT, 14);
    assert_eq!(PINNED_NAMES.len(), 14);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_field_regressions_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 14);
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
    assert_python_commit_one_space(&json, "cli");
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
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
    assert_eq!(not_applicable, 14);

    let json = read_vectors(API_VECTORS_REL);
    assert_python_commit_one_space(&json, "api");
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
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
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
