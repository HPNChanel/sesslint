//! Dispositions for the fourteen test functions in pinned
//! `tests/repair/test_t04_recipes.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (229 splitlines). Exactly
//! fourteen test functions, in module order. None is parametrized. Each row is
//! the whole function. A docstring is not an assertion. Helpers `_ev`,
//! `_write`, and `_dup_events` are not tests. `_HDR`, `FIXTURES_DIR`, and
//! `VENDOR_TORN` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these fourteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these fourteen names.
//! `parity/vectors/repair.recipes_conservative/vectors.json` has 12 ids pinned
//! to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `duplicate_collapse_refusal_checkpoint_or_boundary` and
//! `duplicate_collapse_refusal_mixed_kinds` call
//! `apply_identical_duplicate_collapse`. They are not
//! `apply_identical_duplicate_drop` and they are not these pytests. That old
//! pin is not a Covered source.
//! `parity/vectors/repair.planner/vectors.json` has 17 ids,
//! `parity/vectors/repair.errors/vectors.json` has 25 ids,
//! `parity/vectors/repair/vectors.json` has 1 id, and
//! `parity/vectors/cli.repair/vectors.json` has 1 id, all on that old pin.
//! Those corpora are not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `api.plan`, `api.repair`,
//! `apply_identical_duplicate_drop`, `apply_seq_renumber`, or `planner.plan`
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 14;
const PINNED_SPLITLINES: usize = 229;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these fourteen functions is parametrized. Each
/// row is the whole function. A docstring is not an assertion. The corpus
/// pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered
/// source. `duplicate_collapse_refusal_checkpoint_or_boundary` and
/// `duplicate_collapse_refusal_mixed_kinds` call
/// `apply_identical_duplicate_collapse`. They are not
/// `apply_identical_duplicate_drop` and they are not these pytests.
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
        name: "test_nonadjacent_dup_plans_drop_plus_renumber",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_nonadjacent_dup_plans_drop_plus_renumber: api.plan contains identical-duplicate-drop, the last recipe is seq-renumber, that last step target_finding_fp equals SYNTHETIC_STEP_FP, target_index is None, lossy is false, and blocked is empty; it does not assert the full recipe order; missing stop: that drop membership, that last renumber, that synthetic fingerprint, that absent index, that not-lossy flag, and that empty blocked together; The adjacent collapse is not this plan; test_adjacent_dup_still_collapses is that adjacent collapse",
        ),
    },
    Row {
        name: "test_adjacent_dup_still_collapses",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adjacent_dup_still_collapses: api.plan contains identical-duplicate-collapse, does not contain identical-duplicate-drop, and the last recipe is seq-renumber; it does not assert the synthetic fingerprint; missing stop: that collapse membership, that absent drop, and that last renumber together; The nonadjacent plan is not this collapse; test_nonadjacent_dup_plans_drop_plus_renumber is that nonadjacent plan",
        ),
    },
    Row {
        name: "test_conflicting_dup_blocked_manual",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_conflicting_dup_blocked_manual: api.plan raises RepairRefused; it does not assert a message, a blocked list, or the word manual; the name and the docstring are not the assertion; missing stop: that RepairRefused together; The drop-precondition test is not this plan call; test_drop_fails_closed_on_conflicting_variant is that drop-precondition test",
        ),
    },
    Row {
        name: "test_drop_removes_only_later_identicals",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_drop_removes_only_later_identicals: api.repair keeps three events whose ids are the first event, the kept duplicate, and the following event, in that order; the filter keeps lines that contain seq; it does not assert the seq values; missing stop: those three ids in that order together; The contiguous-seq repair is not this id check; test_renumbered_seq_contiguous is that contiguous-seq repair",
        ),
    },
    Row {
        name: "test_renumbered_seq_contiguous",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_renumbered_seq_contiguous: the same repair yields seq values equal to a range over the kept events; it does not assert the ids; missing stop: that contiguous seq range together; The id-order repair is not this seq check; test_drop_removes_only_later_identicals is that id-order repair",
        ),
    },
    Row {
        name: "test_no_renumber_without_drops",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_renumber_without_drops: a two-event plan has no seq-renumber step; it does not assert that the step list is empty; missing stop: that absent seq-renumber together; The one-event plan is not this two-event plan; test_seq_renumber_absent_when_no_steps is that one-event plan",
        ),
    },
    Row {
        name: "test_no_renumber_on_vendor_input",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_renumber_on_vendor_input: the torn-tail vendor fixture is copied and planned; there is at least one step and no seq-renumber; it does not assert the recipe names; missing stop: that at least one step and that absent seq-renumber together; The clean two-event plan is not this vendor plan; test_no_renumber_without_drops is that clean two-event plan",
        ),
    },
    Row {
        name: "test_repair_output_idempotent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_output_idempotent: repair then plan of the output has empty steps and empty blocked; it does not assert findings; the docstring is not an assertion; missing stop: that empty step tuple and that empty blocked tuple together; The determinism comparison is not this second plan; test_plan_determinism_with_synthetic_step is that determinism comparison",
        ),
    },
    Row {
        name: "test_seq_renumber_step_idempotent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_seq_renumber_step_idempotent: a PlanStep with seq 0, recipe seq-renumber, target_finding_fp a single hyphen, and target_index None is applied twice; the two results are equal, and the seq values become 0 then 1; the input seq values are 5 and 9; missing stop: that equal second apply and those two seq values together; The plan-level idempotence is not this recipe call; test_repair_output_idempotent is that plan-level idempotence",
        ),
    },
    Row {
        name: "test_drop_fails_closed_on_conflicting_variant",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_drop_fails_closed_on_conflicting_variant: apply_identical_duplicate_drop raises PreconditionFailed for variant conflicting-duplicate, target_index 1, record indexes 1 and 2, and four copies of one event; it does not assert a message; missing stop: that PreconditionFailed together; The content-drift refusal is not this variant; test_drop_fails_closed_on_content_drift is that content-drift refusal",
        ),
    },
    Row {
        name: "test_drop_fails_closed_on_content_drift",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_drop_fails_closed_on_content_drift: apply_identical_duplicate_drop raises PreconditionFailed for variant identical-duplicate, target_index 0, and record indexes 0, 1, and 2, when the third event content differs; it does not assert a message; missing stop: that PreconditionFailed together; The conflicting-variant refusal is not this drift; test_drop_fails_closed_on_conflicting_variant is that conflicting-variant refusal",
        ),
    },
    Row {
        name: "test_plan_determinism_with_synthetic_step",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_determinism_with_synthetic_step: two api.plan to_dict dumps with sort_keys are equal; it does not assert the bytes; missing stop: that equal dump together; The repair-output second plan is not this comparison; test_repair_output_idempotent is that repair-output second plan",
        ),
    },
    Row {
        name: "test_seq_renumber_absent_when_no_steps",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_seq_renumber_absent_when_no_steps: a one-event plan has no seq-renumber step; the docstring says relink-only, but the body does not build a relink plan; a docstring is not an assertion; missing stop: that absent seq-renumber together; The two-event plan is not this one-event plan; The planner call with empty findings is not this api.plan; test_no_renumber_without_drops is that two-event plan; test_planner_input_format_default_off is that planner call",
        ),
    },
    Row {
        name: "test_planner_input_format_default_off",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_planner_input_format_default_off: planner.plan with empty findings and empty events has no seq-renumber step; it does not pass input_format; missing stop: that absent seq-renumber together; The one-event api.plan is not this planner call; test_seq_renumber_absent_when_no_steps is that one-event api.plan",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_nonadjacent_dup_plans_drop_plus_renumber",
    "test_adjacent_dup_still_collapses",
    "test_conflicting_dup_blocked_manual",
    "test_drop_removes_only_later_identicals",
    "test_renumbered_seq_contiguous",
    "test_no_renumber_without_drops",
    "test_no_renumber_on_vendor_input",
    "test_repair_output_idempotent",
    "test_seq_renumber_step_idempotent",
    "test_drop_fails_closed_on_conflicting_variant",
    "test_drop_fails_closed_on_content_drift",
    "test_plan_determinism_with_synthetic_step",
    "test_seq_renumber_absent_when_no_steps",
    "test_planner_input_format_default_off",
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
fn pinned_repair_test_t04_recipes_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 229);
}

#[test]
fn pinned_repair_test_t04_recipes_row_count_equals_fourteen() {
    assert_eq!(ROWS.len(), 14);
    assert_eq!(PINNED_TEST_COUNT, 14);
    assert_eq!(PINNED_NAMES.len(), 14);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_repair_test_t04_recipes_test_has_one_disposition() {
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
