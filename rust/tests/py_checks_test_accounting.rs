//! Dispositions for the fourteen `def test_` functions in pinned
//! `tests/checks/test_accounting.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (205 splitlines). Exactly
//! fourteen test functions, in module order. None is parametrized. The helpers
//! `_ev`, `_contrib`, and `_marker` are not tests. Each row is the whole
//! function. Two phases in one function are one row. A direct
//! `check_accounting` call is not `check_file`. A clean fixture is not a
//! divergent fixture. A docstring is not an assertion. Event timestamps and
//! session lines are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these fourteen functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these fourteen
//! functions.
//! `parity/vectors/checks.accounting/vectors.json` has seven ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `module_dunder_all`,
//! `no_usage_slots_empty_findings`, `contribution_two_then_cumulative_two_empty`,
//! `marker_own_contribution_inside_expected_sum_empty`,
//! `key_only_in_window_no_mismatch`,
//! `bool_float_negative_ignored_nonneg_match_empty`, and
//! `compaction_next_cumulative_baseline_unchecked_empty`. That corpus is not a
//! Covered source. Similar names are not these fourteen functions.
//! `parity/vectors/profiles.profile/vectors.json` and
//! `parity/vectors/checks/vectors.json` are pinned to that same old commit and
//! are not Covered sources. Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `check_accounting`,
//! `check_file`, `run_all_checks`, or `sesslint.api` without a `Cargo.toml`
//! change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 14;
const PINNED_SPLITLINES: usize = 205;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A direct `check_accounting` call is not `check_file`. A clean
/// fixture is not a divergent fixture. A docstring is not an assertion. Two
/// phases in one function are one row. `not_applicable` names the missing stop
/// and the nearest different test.
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
        name: "test_no_usage_events_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_usage_events_clean: two events without usage produce an empty finding list; missing stop: that empty finding list; that empty list is the row; test_contributions_without_marker_no_finding is the bare-contribution test and is not this pytest",
        ),
    },
    Row {
        name: "test_consistent_markers_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_consistent_markers_clean: three events whose markers match the window sums produce an empty finding list; missing stop: that empty finding list; that empty list is the row; test_marker_own_contribution_counts is the own-contribution test and is not this pytest",
        ),
    },
    Row {
        name: "test_divergent_marker_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_divergent_marker_fires: exactly one SL204 warning, repairability manual, record id m2, expected_total 20, observed_total 106, mismatched_key_count 1, and both window indexes 1; missing stop: those assertions together; all of those are one row; test_fixture_divergent_fires asserts only the count, the warning, and the two totals, and is not this pytest",
        ),
    },
    Row {
        name: "test_contributions_without_marker_no_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_contributions_without_marker_no_finding: two bare contributions produce an empty finding list; missing stop: that empty finding list; that empty list is the row; test_no_usage_events_clean is the no-usage test and is not this pytest",
        ),
    },
    Row {
        name: "test_marker_own_contribution_counts",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_marker_own_contribution_counts: the marker's own contribution is inside a consistent window and the finding list is empty; missing stop: that empty finding list; that empty list is the row; test_divergent_marker_fires is the divergent marker and is not this pytest",
        ),
    },
    Row {
        name: "test_compaction_resets_epoch",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_compaction_resets_epoch: a compaction boundary, an unchecked continued cumulative, and a consistent later delta produce an empty finding list; missing stop: that empty finding list; that empty list is the row; test_post_compaction_delta_divergence_fires is the post-compaction divergence and is not this pytest",
        ),
    },
    Row {
        name: "test_post_compaction_delta_divergence_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_post_compaction_delta_divergence_fires: one finding whose expected_total is 16; missing stop: that expected_total 16; that finding is the row; it does not assert severity or the other evidence keys; test_compaction_resets_epoch is the clean compaction test and is not this pytest",
        ),
    },
    Row {
        name: "test_zero_baseline_first_marker_checked",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_zero_baseline_first_marker_checked: both phases are one row; a first marker that matches the window sum is silent, then the same marker shortened to cumulative 9 fires one finding whose expected_total is 12; missing stop: those two phases together; both phases are one row; test_non_int_counters_ignored is the non-integer test and is not this pytest",
        ),
    },
    Row {
        name: "test_non_int_counters_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_int_counters_ignored: the body uses a float cumulative and a bool value, then a consistent marker, and the finding list is empty; missing stop: that empty finding list; the body is the row; the docstring names str and negative, but those values are not in the body; a docstring is not an assertion; test_two_markers_both_diverge is the two-marker test and is not this pytest",
        ),
    },
    Row {
        name: "test_two_markers_both_diverge",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_two_markers_both_diverge: two findings whose record ids are m1 and m2; missing stop: both record ids; both findings are one row; test_divergent_marker_fires is the single divergent marker and is not this pytest",
        ),
    },
    Row {
        name: "test_fixture_consistent_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_consistent_clean: check_file of sl204_usage_consistent.jsonl has no SL204; missing stop: that absence of SL204; that check_file is the row; it does not assert that every finding is absent; test_consistent_markers_clean is the in-memory clean test and is not this pytest",
        ),
    },
    Row {
        name: "test_fixture_divergent_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_divergent_fires: check_file of sl204_usage_divergent.jsonl has exactly one SL204 warning, expected_total 20, and observed_total 106; missing stop: those assertions together; all of those are one row; it does not assert repairability, record id, mismatched key count, or window indexes; test_divergent_marker_fires is the in-memory divergent test and is not this pytest",
        ),
    },
    Row {
        name: "test_fixture_postcompact_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_postcompact_clean: check_file of sl204_usage_postcompact.jsonl has no SL204; missing stop: that absence of SL204; that check_file is the row; test_fixture_consistent_clean is the consistent fixture and is not this pytest",
        ),
    },
    Row {
        name: "test_gated_by_rule_selection",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_gated_by_rule_selection: both phases are one row; run_all_checks with select SL204 finds SL204, and run_all_checks with ignore SL204 finds no SL204; missing stop: those two phases together; both phases are one row; test_divergent_marker_fires is a direct check_accounting call and is not this pytest",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_no_usage_events_clean",
    "test_consistent_markers_clean",
    "test_divergent_marker_fires",
    "test_contributions_without_marker_no_finding",
    "test_marker_own_contribution_counts",
    "test_compaction_resets_epoch",
    "test_post_compaction_delta_divergence_fires",
    "test_zero_baseline_first_marker_checked",
    "test_non_int_counters_ignored",
    "test_two_markers_both_diverge",
    "test_fixture_consistent_clean",
    "test_fixture_divergent_fires",
    "test_fixture_postcompact_clean",
    "test_gated_by_rule_selection",
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
fn pinned_checks_test_accounting_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 205);
}

#[test]
fn pinned_checks_test_accounting_row_count_equals_fourteen() {
    assert_eq!(ROWS.len(), 14);
    assert_eq!(PINNED_TEST_COUNT, 14);
    assert_eq!(PINNED_NAMES.len(), 14);
}

#[test]
fn every_pinned_checks_test_accounting_test_has_one_disposition() {
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
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 14);

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
