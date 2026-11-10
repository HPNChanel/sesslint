//! Dispositions for the nine test functions in pinned
//! `tests/repair/test_plan_vetting.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (167 splitlines). Exactly
//! nine test functions, in module order. Two are parametrized. A parametrized
//! function is one row covering every cell, not one row per cell. Helpers
//! `_stage`, `_reseal`, and `_forge` are not tests. `HEADER`, `MSG0`, `MSG1`,
//! `MSG2`, `DUPLICATE`, `TORN_MIDDLE`, and `REFUSAL` are not tests. A header
//! fragment is not a whole pytest.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these nine names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these nine names. `discover_agents_reordered` is
//! discovery order. It is not reordered repair steps.
//! `parity/vectors/repair.vetting/vectors.json` has 20 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Its hash-mismatch and
//! events-hash vectors are not the stale-source pytest and not the
//! renamed-file pytest. `vet_plan_invalid_policy` is not a forged step.
//! That old pin is not a Covered source.
//! `parity/vectors/repair.errors/vectors.json` ids
//! `plan_source_mismatch_default`, `plan_source_mismatch_custom_code`,
//! `repair_refused_default`, and `repair_refused_custom_code` construct
//! exceptions. They do not call `apply_plan`. That corpus is on the old pin,
//! which is not a Covered source.
//! `parity/vectors/repair.fingerprint/vectors.json` ids
//! `plan_fp_extra_fingerprint_policy_omitted` and
//! `plan_fp_extra_fingerprint_policy_conservative` recompute a fingerprint.
//! They are not an apply. That old pin is not a Covered source.
//! `parity/vectors/repair.executor/vectors.json` id
//! `execute_fingerprint_import_seam` is not an apply. That old pin is not a
//! Covered source.
//! `parity/vectors/repair/vectors.json` has 1 id and
//! `parity/vectors/cli.repair/vectors.json` has 1 id, both on that old pin.
//! Those two corpora are not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `apply_plan`, `plan_repair`,
//! or cli functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 9;
const PINNED_SPLITLINES: usize = 167;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A parametrized function is one row covering every cell.
/// A header fragment is not a whole pytest. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// `discover_agents_reordered` is discovery order. It is not reordered repair
/// steps. `not_applicable` names the missing stop and the nearest different test.
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
        name: "test_exported_plan_applies",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_exported_plan_applies: plan_repair converted to a dict is applied, the manifest is present, and the action kinds equal the exported step recipes in order; missing stop: that present manifest and that recipe-kind equality together; It does not assert the recipe names; The subset apply is not this full apply; test_subset_of_derived_steps_applies is that subset apply",
        ),
    },
    Row {
        name: "test_subset_of_derived_steps_applies",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_subset_of_derived_steps_applies: the exported recipes are exactly identical-duplicate-collapse then seq-renumber; the applied plan is the resealed first step; the manifest is present and the action kinds are exactly identical-duplicate-collapse; missing stop: those two recipe names, that first-step subset, and that one action kind together; The full apply is not this subset; test_exported_plan_applies is that full apply",
        ),
    },
    Row {
        name: "test_forged_step_is_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_forged_step_is_refused: one row for four cells finding, index, params, and recipe; each raises RepairRefused matching the sentence fragment derives for this source now; the output is absent and the source bytes stay unchanged; it does not raise PlanSourceMismatch; missing stop: those four refusals, that absent output, and those unchanged source bytes together; All four cells are one row; The CLI forged-plan test is not this API call; test_cli_refuses_forged_plan is that CLI forged-plan test",
        ),
    },
    Row {
        name: "test_misdeclared_loss_is_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_misdeclared_loss_is_refused: one row for three cells hidden, zero, and inflated; the plan uses policy salvage and acknowledge_side_effects; the first step loss is torn-record with count 1; each forged apply raises RepairRefused matching derives for this source now, passes acknowledge_side_effects, and leaves the output absent; it does not assert the source bytes; missing stop: that derived loss, those three refusals, and that absent output together; All three cells are one row; The honest declared-loss apply is not this refusal; test_declared_loss_is_the_planner_derivation is that honest declared-loss apply",
        ),
    },
    Row {
        name: "test_declared_loss_is_the_planner_derivation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_declared_loss_is_the_planner_derivation: the exported salvage plan is applied, the manifest is present, and declared_loss equals the one-element tuple torn-record:1; it does not raise; missing stop: that present manifest and that declared-loss tuple together; The misdeclared refusal is not this apply; test_misdeclared_loss_is_refused is that misdeclared refusal",
        ),
    },
    Row {
        name: "test_reordered_steps_are_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_reordered_steps_are_refused: the two steps are swapped, their seq values become 0 and 1, the plan is resealed, and apply raises RepairRefused matching derives for this source now; it does not assert an absent output; missing stop: that swap and that refusal together; The subset apply is not this reorder; discover_agents_reordered is discovery order and is not this; test_subset_of_derived_steps_applies is that subset apply",
        ),
    },
    Row {
        name: "test_plan_for_changed_source_is_stale",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_for_changed_source_is_stale: after the export, the source bytes are extended and apply raises PlanSourceMismatch; it does not match the refusal sentence and it does not raise RepairRefused; missing stop: that extended source and that PlanSourceMismatch together; The renamed-file refusal is not this stale source; A constructed PlanSourceMismatch is not this apply; test_plan_for_another_file_name_is_refused is that renamed-file refusal",
        ),
    },
    Row {
        name: "test_plan_for_another_file_name_is_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_for_another_file_name_is_refused: a plan from one file applied to a same-bytes copy with a different name raises RepairRefused matching same name and bytes; it does not raise PlanSourceMismatch; missing stop: that different name and that refusal together; The stale-source test is not this renamed copy; test_plan_for_changed_source_is_stale is that stale source",
        ),
    },
    Row {
        name: "test_cli_refuses_forged_plan",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_refuses_forged_plan: the CLI repair command passes --plan and --output, exits 1, stderr contains REPAIR_REFUSED, and the output is absent; it does not assert the refusal sentence and it does not check stdout; missing stop: that exit 1, that stderr token, and that absent output together; The API forged-step test is not this CLI; test_forged_step_is_refused is that API forged-step test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_exported_plan_applies",
    "test_subset_of_derived_steps_applies",
    "test_forged_step_is_refused",
    "test_misdeclared_loss_is_refused",
    "test_declared_loss_is_the_planner_derivation",
    "test_reordered_steps_are_refused",
    "test_plan_for_changed_source_is_stale",
    "test_plan_for_another_file_name_is_refused",
    "test_cli_refuses_forged_plan",
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
fn pinned_repair_test_plan_vetting_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 167);
}

#[test]
fn pinned_repair_test_plan_vetting_row_count_equals_nine() {
    assert_eq!(ROWS.len(), 9);
    assert_eq!(PINNED_TEST_COUNT, 9);
    assert_eq!(PINNED_NAMES.len(), 9);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_repair_test_plan_vetting_test_has_one_disposition() {
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
