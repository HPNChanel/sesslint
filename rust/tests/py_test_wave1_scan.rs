//! Dispositions for the nine test functions in pinned
//! `tests/test_wave1_scan.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (164 splitlines). Exactly
//! nine test functions, in module order. Two are parametrized:
//! `test_bad_timestamp_tolerance_rejected` is one row over the cells -1,
//! True, and 1.5, and `test_stdin_invalid_limit_is_usage_error` is one row
//! over the commands check and scan. Each row is the whole function. A
//! docstring is not an assertion. A comment is not an assertion. The helper
//! `_session` is not a test.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these nine names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these nine names. An API vector that calls one
//! function is not this whole pytest.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. None of those ids is one of
//! these tests. That old pin is not a Covered source. A scan vector that
//! only applies one cap is not the whole pytest.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `scan_path`, `aggregate_scan`,
//! `check`, `check_file`, or `main` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 9;
const PINNED_SPLITLINES: usize = 164;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. Two of these nine functions are parametrized and each
/// is still one row. Each row is the whole function. A docstring is not an
/// assertion. A comment is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A scan vector that only applies one cap is not the whole pytest and is not
/// a Covered source.
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
        name: "test_unknown_input_has_no_synthetic_integrity_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_input_has_no_synthetic_integrity_error: scan_path reports unsupported total 1, the first file findings are empty, and the skipped reason is format-undetected; check exits 0; that check stdout omits a healthy-session claim, includes an unsupported-input claim, and omits a no-repair claim; that check stderr omits a bundle claim; check with fail-on-unsupported exits 1; scan with fail-on-unsupported exits 1; missing stop: that unsupported total, those empty findings, that skipped reason, that exit 0, those stdout conditions, that stderr condition, and those two fail-on-unsupported exits together; The vendor-scope row is not this; test_vendor_scope_excludes_memory_and_tool_results is that vendor-scope row",
        ),
    },
    Row {
        name: "test_vendor_scope_excludes_memory_and_tool_results",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_vendor_scope_excludes_memory_and_tool_results: a recursive scan with vendor layout claude has total 2 and every file verdict is healthy; missing stop: that total and those healthy verdicts together; The unknown-input row is not this; test_unknown_input_has_no_synthetic_integrity_error is that unknown-input row",
        ),
    },
    Row {
        name: "test_newest_and_since_select_before_cumulative_caps",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_newest_and_since_select_before_cumulative_caps: a recursive scan with newest 1 and since 2026-01-02 has healthy 1 and skipped 2, the healthy path ends with 2.jsonl, and skipped reason totals are before-since 1 and newest-cap-exceeded 1; missing stop: that healthy total, that skipped total, that path ending, and those two reason totals together; The file-limit skip is not this; test_file_limit_skips_without_malformed_finding_and_can_be_raised is that file-limit skip",
        ),
    },
    Row {
        name: "test_file_limit_skips_without_malformed_finding_and_can_be_raised",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_file_limit_skips_without_malformed_finding_and_can_be_raised: scan_path one byte below the file length has skipped reason file-too-large and no findings; check at that byte cap has a limitation that names a skip; scan_path at the file length has healthy 1; check_file one byte below the file length has a limitation that names a file-too-large skip, no findings, and assurance A0; missing stop: that skipped reason, those empty scan findings, that skip limitation, that healthy total, that file-too-large limitation, those empty report findings, and that assurance together; The newest-and-since selection is not this; test_newest_and_since_select_before_cumulative_caps is that newest-and-since selection",
        ),
    },
    Row {
        name: "test_finding_samples_do_not_change_counts_or_cached_results",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_finding_samples_do_not_change_counts_or_cached_results: the first of two cached incremental scans, each recursive with max findings per code 3, has warning count at least 30, and the second file is a cache hit; for each result the wire findings whose code is SL009 number 3, the SL009 finding-group count is 30, and the aggregate by-code count for SL009 is 30; missing stop: that warning count, that cache hit, those finding lengths, those group counts, and those aggregate counts together; The snapshot digest is not this; test_check_digest_binds_parsed_snapshot_during_write is that snapshot digest",
        ),
    },
    Row {
        name: "test_check_digest_binds_parsed_snapshot_during_write",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_digest_binds_parsed_snapshot_during_write: check_file source fingerprint equals the sha256 of the bytes taken before load rewrites the file, and the report findings are empty; missing stop: that fingerprint and those empty findings together; The finding-sample count is not this; test_finding_samples_do_not_change_counts_or_cached_results is that finding-sample count",
        ),
    },
    Row {
        name: "test_bad_timestamp_tolerance_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bad_timestamp_tolerance_rejected: this row is one row over the cells -1, True, and 1.5, and each cell makes check_file raise ValueError matching timestamp_skew_ms; missing stop: those three cells and those ValueError raises together; The tolerance configuration is not this; test_timestamp_tolerance_configuration is that tolerance configuration",
        ),
    },
    Row {
        name: "test_timestamp_tolerance_configuration",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_timestamp_tolerance_configuration: check with a config file and json output exits 0, and the limitation names a file-too-large skip; missing stop: that exit 0 and that limitation together; The bad tolerance value is not this; test_bad_timestamp_tolerance_rejected is that bad tolerance value",
        ),
    },
    Row {
        name: "test_stdin_invalid_limit_is_usage_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stdin_invalid_limit_is_usage_error: this row is one row over the commands check and scan; each command on standard input with max-file-bytes -1 yields status 2, from a return or from SystemExit, and stderr names max_file_bytes; missing stop: those two commands, that status 2, and that stderr name together; The file-limit skip is not this; test_file_limit_skips_without_malformed_finding_and_can_be_raised is that file-limit skip",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_unknown_input_has_no_synthetic_integrity_error",
    "test_vendor_scope_excludes_memory_and_tool_results",
    "test_newest_and_since_select_before_cumulative_caps",
    "test_file_limit_skips_without_malformed_finding_and_can_be_raised",
    "test_finding_samples_do_not_change_counts_or_cached_results",
    "test_check_digest_binds_parsed_snapshot_during_write",
    "test_bad_timestamp_tolerance_rejected",
    "test_timestamp_tolerance_configuration",
    "test_stdin_invalid_limit_is_usage_error",
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
fn pinned_test_wave1_scan_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 164);
}

#[test]
fn pinned_test_wave1_scan_row_count_equals_nine() {
    assert_eq!(ROWS.len(), 9);
    assert_eq!(PINNED_TEST_COUNT, 9);
    assert_eq!(PINNED_NAMES.len(), 9);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_wave1_scan_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 9);
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
    assert_eq!(not_applicable, 9);

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
