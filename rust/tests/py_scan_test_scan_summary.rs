//! Dispositions for the nineteen test functions in pinned
//! `tests/scan/test_scan_summary.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (226 splitlines). Exactly
//! nineteen test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helpers `_finding` and `_files` are not tests.
//! `FIXTURES_DIR` is not a test.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these nineteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these nineteen names.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `aggregate_by_code_exact`, `aggregate_by_code_sort_order`,
//! `aggregate_worst_files_exact`, `aggregate_worst_files_excludes_healthy`,
//! `aggregate_top_one`, `aggregate_top_zero`, `aggregate_top_negative`,
//! `aggregate_group_by_none`, `aggregate_group_by_invalid`, and
//! `aggregate_deterministic` are on that old pin.
//! `aggregate_top_one` and `aggregate_top_zero` are two vectors. They are not
//! the whole top-limits pytest. That old pin is not a Covered source.
//! `session_link_wire_round_trip` on that old pin is not a summary pytest.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `aggregate_scan`,
//! `ScanReport`, `format_scan_report_human`, `check_dir`, or `main` without
//! a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 19;
const PINNED_SPLITLINES: usize = 226;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these nineteen functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A summary helper tested alone is not a CLI pytest, and a CLI pytest is not
/// the helper.
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
        name: "test_aggregate_by_code_exact",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_by_code_exact: aggregate_scan of the shared file helper returns by_code rows (code, severity, count, files) equal to SL203, error, 3, 2 then SL302, error, 1, 1 then SL101, warning, 1, 1; the docstring is not an assertion; missing stop: those three rows together; The sort-order helper is not this; test_aggregate_by_code_sort_order is that sort-order helper",
        ),
    },
    Row {
        name: "test_aggregate_by_code_sort_order",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_by_code_sort_order: aggregate_scan of one invalid file returns by_code codes SL001 then SL006 then SL007; the comment about severity rank and count is not an assertion; missing stop: that code order together; The exact by-code helper is not this; test_aggregate_by_code_exact is that exact by-code helper",
        ),
    },
    Row {
        name: "test_aggregate_worst_files_exact",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_worst_files_exact: aggregate_scan of the shared file helper returns two worst_files rows, the first with error_count 3 and warning_count 0 and the second with error_count 2 and warning_count 1; the docstring is not an assertion; missing stop: those two count pairs in that order together; The healthy-exclusion helper is not this; test_aggregate_worst_files_excludes_healthy is that healthy-exclusion helper",
        ),
    },
    Row {
        name: "test_aggregate_worst_files_excludes_healthy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_worst_files_excludes_healthy: aggregate_scan of only healthy files returns an empty worst_files tuple and an empty by_code tuple; the docstring is not an assertion; missing stop: those two empty tuples together; The exact worst-files helper is not this; test_aggregate_worst_files_exact is that exact worst-files helper",
        ),
    },
    Row {
        name: "test_aggregate_top_limits_and_zero",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_top_limits_and_zero: aggregate_scan with top 1 has worst_files length 1, and aggregate_scan with top 0 has an empty worst_files tuple; the docstring is not an assertion; it does not assert which row remains; missing stop: that length and that empty tuple together; The CLI top-zero pytest is not this helper; test_scan_cli_top_zero_hides_worst is that CLI top-zero pytest",
        ),
    },
    Row {
        name: "test_aggregate_top_negative_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_top_negative_rejected: aggregate_scan with top -1 raises ValueError matched to the top-bound text; missing stop: that rejection together; The CLI negative-top pytest is not this helper; test_scan_cli_top_negative_exit_2 is that CLI negative-top pytest",
        ),
    },
    Row {
        name: "test_aggregate_group_by_none",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_group_by_none: aggregate_scan with group_by none returns an empty by_code tuple and a worst_files length of 2; the docstring is not an assertion; missing stop: that empty tuple and that length together; The CLI group-by-none pytest is not this helper; test_scan_cli_group_by_none_hides_by_code is that CLI group-by-none pytest",
        ),
    },
    Row {
        name: "test_aggregate_group_by_invalid_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_group_by_invalid_rejected: aggregate_scan with an unknown group_by value raises ValueError matched to the group-by token; missing stop: that rejection together; The group-by-none helper is not this; test_aggregate_group_by_none is that group-by-none helper",
        ),
    },
    Row {
        name: "test_aggregate_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_deterministic: two aggregate_scan calls on the same files compare equal; the docstring is not an assertion; it does not assert field values; missing stop: that equality together; The content-free dict helper is not this; test_summary_to_dict_content_free is that content-free dict helper",
        ),
    },
    Row {
        name: "test_summary_to_dict_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_summary_to_dict_content_free: each by_code dict has sorted keys code, count, files, and severity, and each worst_files dict has sorted keys error_count, the path key, and warning_count; the docstring is not an assertion; it does not assert values; missing stop: those two key lists together; The CLI json pytest is not this helper; test_scan_cli_json_summary is that CLI json pytest",
        ),
    },
    Row {
        name: "test_scan_report_summary_omitted_when_none",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_report_summary_omitted_when_none: a report dict with no summary lacks the summary key, and a report dict with a summary has that key whose sorted keys are by_code and worst_files; the docstring is not an assertion; missing stop: that absent key and those present keys together; The CLI json pytest is not this helper; test_scan_cli_json_summary is that CLI json pytest",
        ),
    },
    Row {
        name: "test_scan_cli_json_summary",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cli_json_summary: json scan with top 3 has exit code 0 or 1, the document contains summary, worst_files length is at most 3, and each by_code row key set is code, count, files, and severity; the docstring is not an assertion; missing stop: that exit pair, that summary, that length bound, and that key set together; The omitted-summary report helper is not this CLI pytest; test_scan_report_summary_omitted_when_none is that omitted-summary report helper",
        ),
    },
    Row {
        name: "test_scan_cli_human_summary_block",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cli_human_summary_block: a human scan returns exit code 1, the by-code heading is present, the worst-files heading is present, and the worst-files heading index is greater than the by-code heading index; the docstring is not an assertion; the comment about file rows is not an assertion; missing stop: that exit, those two headings, and that order together; The human-renderer helper is not this CLI pytest; test_human_renderer_summary_only_when_present is that human-renderer helper",
        ),
    },
    Row {
        name: "test_scan_cli_group_by_none_hides_by_code",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cli_group_by_none_hides_by_code: a human scan with group_by none returns exit code 1, the by-code heading is absent, and the worst-files heading is present; missing stop: that exit, that absence, and that presence together; The group-by-none helper is not this CLI pytest; test_aggregate_group_by_none is that group-by-none helper",
        ),
    },
    Row {
        name: "test_scan_cli_top_zero_hides_worst",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cli_top_zero_hides_worst: a human scan with top 0 returns exit code 1, the by-code heading is present, and the worst-files heading is absent; missing stop: that exit, that presence, and that absence together; The top-limit helper is not this CLI pytest; test_aggregate_top_limits_and_zero is that top-limit helper",
        ),
    },
    Row {
        name: "test_scan_cli_both_disabled_no_block",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cli_both_disabled_no_block: a human scan with group_by none and top 0 returns exit code 1 and both headings are absent, and a json scan with those flags returns exit code 1 and the document lacks the summary key; the docstring is not an assertion; missing stop: those two exits, those two absences, and that missing key together; The top-zero CLI pytest is not this; test_scan_cli_top_zero_hides_worst is that top-zero CLI pytest",
        ),
    },
    Row {
        name: "test_scan_cli_top_negative_exit_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cli_top_negative_exit_2: scan with top -1 returns exit code 2 and stderr contains the top-bound text; missing stop: that exit and that stderr text together; The negative-top helper is not this CLI pytest; test_aggregate_top_negative_rejected is that negative-top helper",
        ),
    },
    Row {
        name: "test_human_renderer_summary_only_when_present",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_human_renderer_summary_only_when_present: the human formatter on a report without a summary lacks the by-code heading, and the same formatter on a report with a summary has the by-code heading and the worst-files heading; the docstring is not an assertion; missing stop: that absence and those two presences together; The CLI human pytest is not this helper; test_scan_cli_human_summary_block is that CLI human pytest",
        ),
    },
    Row {
        name: "test_check_dir_report_has_no_summary_by_default",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_dir_report_has_no_summary_by_default: check_dir returns a report whose summary is None and whose dict lacks the summary key; the docstring is not an assertion; missing stop: that None and that absent key together; The omitted-summary report helper is not this; test_scan_report_summary_omitted_when_none is that omitted-summary report helper",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_aggregate_by_code_exact",
    "test_aggregate_by_code_sort_order",
    "test_aggregate_worst_files_exact",
    "test_aggregate_worst_files_excludes_healthy",
    "test_aggregate_top_limits_and_zero",
    "test_aggregate_top_negative_rejected",
    "test_aggregate_group_by_none",
    "test_aggregate_group_by_invalid_rejected",
    "test_aggregate_deterministic",
    "test_summary_to_dict_content_free",
    "test_scan_report_summary_omitted_when_none",
    "test_scan_cli_json_summary",
    "test_scan_cli_human_summary_block",
    "test_scan_cli_group_by_none_hides_by_code",
    "test_scan_cli_top_zero_hides_worst",
    "test_scan_cli_both_disabled_no_block",
    "test_scan_cli_top_negative_exit_2",
    "test_human_renderer_summary_only_when_present",
    "test_check_dir_report_has_no_summary_by_default",
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
fn pinned_scan_test_scan_summary_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 226);
}

#[test]
fn pinned_scan_test_scan_summary_row_count_equals_nineteen() {
    assert_eq!(ROWS.len(), 19);
    assert_eq!(PINNED_TEST_COUNT, 19);
    assert_eq!(PINNED_NAMES.len(), 19);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_scan_test_scan_summary_test_has_one_disposition() {
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
    assert_eq!(not_applicable, 19);

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
