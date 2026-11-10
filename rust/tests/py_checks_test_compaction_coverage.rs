//! Dispositions for the fifteen `def test_` functions in pinned
//! `tests/checks/test_compaction_coverage.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (204 splitlines). Exactly
//! fifteen test functions, in module order. None is parametrized. Helpers
//! `_ev` and `_sl205` are not tests. Each row is the whole function. Two
//! phases in one function are one row. A direct `check_compaction_coverage`
//! call is not `check_file`. A silent list is not a finding. A docstring is
//! not an assertion. Timestamps are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check or api functions
//! without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33
//! parser-metadata vectors at this pin and none is one of these functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for
//! envelopes, directory limits, discovery, module constants, plan and repair
//! rejection, thresholds, and validate_session. None of those 77 is one of
//! these fifteen functions. Therefore every row is `NotApplicable`.
//! `parity/vectors/checks.checkpoint/vectors.json` has ten ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `empty_input_silent`,
//! `constants_and_all`, `fingerprint_sl201_aba`,
//! `checkpoint_before_run_start_silent`, `same_hash_divergence_silent`,
//! `pointerless_compaction_silent`, `duplicated_leaf_silent`,
//! `parent_cycle_silent`, `root_parent_contiguous_silent`, and
//! `codex_rollout_continuation_silent`. That corpus is not a Covered source.
//! `pointerless_compaction_silent`, `duplicated_leaf_silent`, and
//! `parent_cycle_silent` are not these pytest functions. `checks.runner` and
//! `profiles.profile` are the same old pin and are not Covered sources.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 15;
const PINNED_SPLITLINES: usize = 204;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A direct `check_compaction_coverage` call is not
/// `check_file`. A silent list is not a finding. A docstring is not an
/// assertion. Two phases in one function are one row. `not_applicable` names
/// the missing stop.
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
        name: "test_no_boundaries_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_boundaries_clean: two message events and no boundary produce an empty finding list; missing stop: that empty finding list; the empty list is the row; a silent list is not a finding; the pointerless boundary is not this pytest; test_pointerless_boundary_silent is that boundary",
        ),
    },
    Row {
        name: "test_valid_coverage_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_valid_coverage_clean: a leaf that precedes the boundary on a contiguous chain produces an empty finding list; missing stop: that empty finding list; the empty list is the row; a silent list is not a finding; the missing-leaf test is not this pytest; test_missing_leaf_fires is that test",
        ),
    },
    Row {
        name: "test_missing_leaf_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_leaf_fires: exactly one SL205 warning, repairability manual, missing true, non_contiguous false, covered_through_id ghost, and boundary_id b1; missing stop: all of those together; all of those are one row; the fixture missing-leaf test asserts only one SL205 and missing true, and is not this pytest; test_fixture_missing_leaf is that check_file; a direct check_compaction_coverage call is not check_file",
        ),
    },
    Row {
        name: "test_leaf_at_or_after_boundary_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_leaf_at_or_after_boundary_fires: one finding, missing false, and non_contiguous true; missing stop: those three together; it does not assert the covered id; the broken-ancestor test asserts only non_contiguous true and is not this pytest; test_broken_ancestor_chain_fires is that test",
        ),
    },
    Row {
        name: "test_broken_ancestor_chain_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_broken_ancestor_chain_fires: one finding whose non_contiguous is true; missing stop: that non_contiguous finding; it does not assert missing false; the ancestor-after-boundary test places the ancestor after the boundary and is not this pytest; test_ancestor_after_boundary_fires is that test",
        ),
    },
    Row {
        name: "test_ancestor_after_boundary_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ancestor_after_boundary_fires: one finding whose non_contiguous is true because the ancestor is after the boundary; missing stop: that non_contiguous finding; the broken-parent test is not this pytest; test_broken_ancestor_chain_fires is that test",
        ),
    },
    Row {
        name: "test_pointerless_boundary_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_pointerless_boundary_silent: a boundary without a coverage pointer produces an empty finding list; missing stop: that empty finding list; the empty list is the row; a silent list is not a finding; the comment about unverifiable is not an extra assertion; the no-boundary test is not this pytest; test_no_boundaries_clean is that test",
        ),
    },
    Row {
        name: "test_duplicate_leaf_id_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_duplicate_leaf_id_silent: a duplicated leaf id produces an empty finding list; missing stop: that empty finding list; the docstring mentions SL003, but the body does not assert SL003; the empty list is the row; a docstring is not an assertion; a silent list is not a finding; the cycle test is not this pytest; test_cycle_in_chain_no_finding is that test",
        ),
    },
    Row {
        name: "test_cycle_in_chain_no_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cycle_in_chain_no_finding: a parent cycle produces an empty finding list; missing stop: that empty finding list; the docstring mentions SL005, but the body does not assert SL005; the empty list is the row; a docstring is not an assertion; a silent list is not a finding; the duplicate-id test is not this pytest; test_duplicate_leaf_id_silent is that test",
        ),
    },
    Row {
        name: "test_multiple_boundaries_each_checked",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multiple_boundaries_each_checked: one finding whose boundary_id is b2; missing stop: that boundary id; it does not assert missing true; the single missing-leaf test is not this pytest; test_missing_leaf_fires is that test",
        ),
    },
    Row {
        name: "test_fixture_valid_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_valid_clean: check_file of sl205_valid_coverage.jsonl has no SL205; missing stop: that absent SL205; it does not assert that every finding is absent; a direct check_compaction_coverage call is not check_file; the in-memory valid test is not this pytest; test_valid_coverage_clean is that call",
        ),
    },
    Row {
        name: "test_fixture_missing_leaf",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_missing_leaf: check_file of sl205_missing_leaf.jsonl has exactly one SL205 and missing true; missing stop: that one SL205 and missing true; it does not assert severity, repairability, non_contiguous, or the ids; a direct check_compaction_coverage call is not check_file; the in-memory missing-leaf test is not this pytest; test_missing_leaf_fires is that call",
        ),
    },
    Row {
        name: "test_fixture_noncontig",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_noncontig: check_file of sl205_noncontig.jsonl has exactly one SL205 and non_contiguous true; missing stop: that one SL205 and non_contiguous true; a direct check_compaction_coverage call is not check_file; the in-memory non-contiguous tests are not this pytest; test_ancestor_after_boundary_fires is the nearest of test_leaf_at_or_after_boundary_fires, test_broken_ancestor_chain_fires, and test_ancestor_after_boundary_fires",
        ),
    },
    Row {
        name: "test_fixture_pointerless",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_pointerless: check_file of sl205_pointerless.jsonl has no SL205; missing stop: that absent SL205; a direct check_compaction_coverage call is not check_file; the in-memory pointerless test is not this pytest; test_pointerless_boundary_silent is that call",
        ),
    },
    Row {
        name: "test_gated_by_rule_selection",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_gated_by_rule_selection: both phases are one row; run_all_checks with select SL205 finds SL205, and run_all_checks with ignore SL205 finds no SL205; missing stop: both phases together; a docstring is not an assertion; a direct check_compaction_coverage call is not this pytest; test_missing_leaf_fires is that call",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_no_boundaries_clean",
    "test_valid_coverage_clean",
    "test_missing_leaf_fires",
    "test_leaf_at_or_after_boundary_fires",
    "test_broken_ancestor_chain_fires",
    "test_ancestor_after_boundary_fires",
    "test_pointerless_boundary_silent",
    "test_duplicate_leaf_id_silent",
    "test_cycle_in_chain_no_finding",
    "test_multiple_boundaries_each_checked",
    "test_fixture_valid_clean",
    "test_fixture_missing_leaf",
    "test_fixture_noncontig",
    "test_fixture_pointerless",
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
fn pinned_test_compaction_coverage_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 204);
}

#[test]
fn pinned_test_compaction_coverage_row_count_equals_fifteen() {
    assert_eq!(ROWS.len(), 15);
    assert_eq!(PINNED_TEST_COUNT, 15);
    assert_eq!(PINNED_NAMES.len(), 15);
}

#[test]
fn every_pinned_test_compaction_coverage_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 15);
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
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(
            !names.contains(id),
            "cli id {id} is one of the fifteen functions"
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
    assert_eq!(not_applicable, 15);

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
            "api id {id} is one of the fifteen functions"
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
