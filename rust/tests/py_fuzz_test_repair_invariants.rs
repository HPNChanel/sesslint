//! Dispositions for the 4 `def test_` functions in pinned
//! `tests/fuzz/test_repair_invariants.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (249 splitlines). This
//! integration test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `api.repair`, `api.apply_plan`, or the
//! repair executor.
//!
//! The pinned module exercises N4 repair-safety invariants: a Hypothesis property
//! over conservative terminal-tail repair, a dual-policy malformed-line refusal or
//! salvage-loss check, a parametrized four-cell matrix over public execution
//! surfaces, and artifact immutability across plan and bundle boundaries.
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest, including the full example budget or parametrization matrix. One torn
//! record, one refusal, or one execution surface is not the whole pytest.
//! `not_applicable` names the missing stop. This package has no Hypothesis and
//! cannot run those property sweeps.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 4;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One torn record, one refusal, or one execution surface is not the
/// whole pytest. `not_applicable` names the missing stop.
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
        name: "test_conservative_torn_tail_preserves_every_unique_decodable_record",
        disposition: Disposition::NotApplicable(
            "no cli vector is the entire Hypothesis @given TEXTS property with @settings max_examples=20 deadline None derandomize True conservative api.repair on synthetic canonical bytes with torn terminal JSON object prefix asserting manifest declared_loss empty decoded output equals generated events and unique event ids unchanged",
        ),
    },
    Row {
        name: "test_untargeted_malformed_line_refuses_or_salvage_loss_matches_physical_difference",
        disposition: Disposition::NotApplicable(
            "no cli vector couples conservative api.repair SesslintError refusal without output artifact and salvage policy with acknowledge_side_effects declared_loss torn-record physical splitline count delta and decoded event equality in one untargeted malformed-line scenario",
        ),
    },
    Row {
        name: "test_resealed_tampered_plan_is_refused_at_every_public_execution_boundary",
        disposition: Disposition::NotApplicable(
            "no cli vector parametrizes surface api and executor with input_kind canonical and vendor four cells applying fingerprint-valid forged torn-terminal-record-discard RepairPlan expecting RepairRefused unchanged source bytes and absent output plus manifest sidecar",
        ),
    },
    Row {
        name: "test_repair_keeps_source_plan_bundle_and_existing_artifact_aliases_immutable",
        disposition: Disposition::NotApplicable(
            "no cli vector runs api.plan_repair api.build_bundle api.apply_plan then api.apply_plan with output_path each of source hard-linked alias output plan.json bundle.json expecting RepairRefused while plan bundle source and artifact byte snapshots stay identical",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_conservative_torn_tail_preserves_every_unique_decodable_record",
    "test_untargeted_malformed_line_refuses_or_salvage_loss_matches_physical_difference",
    "test_resealed_tampered_plan_is_refused_at_every_public_execution_boundary",
    "test_repair_keeps_source_plan_bundle_and_existing_artifact_aliases_immutable",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
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

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
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
fn every_pinned_fuzz_repair_invariants_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
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
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
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
        let slice = vector_slice(&json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
