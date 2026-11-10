//! Dispositions for the six `def test_` functions in pinned
//! `tests/repair/test_step_coordinates.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (147 splitlines). Exactly
//! six test functions. One is parametrized over four cells. The helpers
//! `_line`, `_msg`, `_stage`, and `_ids` are not tests. `HEADER`, `M0`,
//! `M1`, `M2`, `M3`, and `INTERLEAVED` are not tests. A parametrized function
//! is one row covering every cell, not one row per cell. A docstring is not
//! an assertion. A header fragment is not a whole pytest. Session lines and
//! record ids are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call repair, planner, executor,
//! api, or cli functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `Disposition::Covered` exists only so a later
//! whole-pytest vector can be claimed. `parity/vectors/cli/vectors.json` has
//! 33 ids at this pin and none of those ids is one of these six functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for module
//! `sesslint.api`. None of those 77 is one of these six functions.
//!
//! `parity/vectors/repair.executor/vectors.json` has 17 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `source_positions_duplicate_origin` expects the message that repair
//! duplicated source event 1. It is not the one-pass repair.
//! `relocate_step_removed_target` expects a step 7 drop-record message. It
//! is not the `_relocate_step` call. That old pin is not a Covered source.
//!
//! `parity/vectors/repair.planner/vectors.json` has 17 ids,
//! `parity/vectors/repair.errors/vectors.json` has 25 ids,
//! `parity/vectors/repair.fingerprint/vectors.json` has 7 ids,
//! `parity/vectors/repair/vectors.json` has 1 id, and
//! `parity/vectors/cli.repair/vectors.json` has 1 id, all on that old pin.
//! `repair_refused_default` and `repair_refused_custom_code` construct
//! `RepairRefused`. `output_invalid_default` constructs `OutputInvalid`.
//! None of those old-pin corpora is a Covered source.
//!
//! Therefore every row is NotApplicable. `not_applicable` names the missing
//! stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 6;
const PINNED_SPLITLINES: usize = 147;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A header fragment is not a whole pytest. A docstring
/// is not an assertion. A parametrized function is one row covering every
/// cell. `not_applicable` names the missing stop.
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
        name: "test_every_duplicate_group_is_repaired_in_one_pass",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_every_duplicate_group_is_repaired_in_one_pass: one row covers four cells, two-adjacent-pairs, interleaved, triple, and spread-triple. Each cell repairs, the manifest is present, the output ids equal the four original message ids in source order, and the repaired file has no SL003 finding. It does not assert recipe names. The triple-recipe test is not this repair. missing stop: that present manifest, that id order, and that absent SL003 together across all four cells; it does not assert recipe names; test_group_of_three_is_dropped_not_collapsed is the triple-recipe test and is not this repair; test_salvage_drop_before_duplicate_group is the salvage repair and is not this one-pass repair; source_positions_duplicate_origin expects the message that repair duplicated source event 1 and is not this one-pass repair",
        ),
    },
    Row {
        name: "test_group_of_three_is_dropped_not_collapsed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_group_of_three_is_dropped_not_collapsed: plan_repair recipes are exactly identical-duplicate-drop then seq-renumber. It does not call repair and it does not check output ids. A docstring about a leftover copy is not an assertion. The one-pass repair is not this plan. missing stop: those two recipe names together; it does not call repair and it does not check output ids; a docstring about a leftover copy is not an assertion; test_every_duplicate_group_is_repaired_in_one_pass is the one-pass repair and is not this plan; test_truncated_duplicate_group_is_refused is the refusal and is not this plan",
        ),
    },
    Row {
        name: "test_truncated_duplicate_group_is_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_truncated_duplicate_group_is_refused: the source repeats one message forty times between two neighbors. plan.steps is empty and plan.blocked is exactly one pair, SL003 with reason precondition-failed:sl003_identical_duplicate. It does not assert an evidence cap of 32. The docstring is not an assertion. The triple-recipe plan is not this refusal. missing stop: that empty step list and that one blocked pair together; it does not assert an evidence cap of 32; the docstring is not an assertion; test_group_of_three_is_dropped_not_collapsed is the triple-recipe plan and is not this refusal",
        ),
    },
    Row {
        name: "test_salvage_drop_before_duplicate_group",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_salvage_drop_before_duplicate_group: salvage plan_repair with acknowledge_side_effects has recipes exactly orphan-result-drop, identical-duplicate-drop, then seq-renumber. The later repair with the same policy and acknowledgement has output ids equal to the four original message ids in source order. The plain triple plan is not this salvage repair. missing stop: those three recipe names and that repaired id order together; test_group_of_three_is_dropped_not_collapsed is the plain triple plan and is not this salvage repair",
        ),
    },
    Row {
        name: "test_step_whose_target_an_earlier_step_removed_fails_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_step_whose_target_an_earlier_step_removed_fails_closed: the first planned step has record_indexes exactly 1 and 3. That step is repeated with seq 1, the fingerprint is recomputed, and execute raises RepairRefused matching the sentence fragment derives for this source now. The output is absent. The relocation call is not this execute. A constructed RepairRefused is not this. missing stop: those indexes, that repeated step, that refusal, and that absent output together; test_relocation_refuses_an_already_removed_source_coordinate is the relocation call and is not this execute; repair_refused_default constructs RepairRefused and is not this; repair_refused_custom_code constructs RepairRefused and is not this; relocate_step_removed_target expects a step 7 drop-record message and is not this execute",
        ),
    },
    Row {
        name: "test_relocation_refuses_an_already_removed_source_coordinate",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_relocation_refuses_an_already_removed_source_coordinate: _relocate_step is called on the first planned step with a map that keeps coordinates 0, 1, and 2, sends 4 to 3, and a length of 5. It raises OutputInvalid matching the substring which an earlier step removed. relocate_step_removed_target is a step 7 message and is not this call. The execute refusal is not this. missing stop: that map, that length, and that OutputInvalid together; test_step_whose_target_an_earlier_step_removed_fails_closed is the execute refusal and is not this call; relocate_step_removed_target expects a step 7 drop-record message and is not this call; output_invalid_default constructs OutputInvalid and is not this call",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_every_duplicate_group_is_repaired_in_one_pass",
    "test_group_of_three_is_dropped_not_collapsed",
    "test_truncated_duplicate_group_is_refused",
    "test_salvage_drop_before_duplicate_group",
    "test_step_whose_target_an_earlier_step_removed_fails_closed",
    "test_relocation_refuses_an_already_removed_source_coordinate",
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
fn pinned_repair_test_step_coordinates_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 147);
}

#[test]
fn pinned_repair_test_step_coordinates_row_count_equals_six() {
    assert_eq!(ROWS.len(), 6);
    assert_eq!(PINNED_TEST_COUNT, 6);
    assert_eq!(PINNED_NAMES.len(), 6);
}

#[test]
fn every_pinned_repair_test_step_coordinates_test_has_one_disposition() {
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
    // `parity/vectors/cli/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "cli vectors python_commit spacing does not match {needle}"
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
    assert_eq!(not_applicable, 6);

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
