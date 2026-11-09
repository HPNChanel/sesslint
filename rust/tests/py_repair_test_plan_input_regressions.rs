//! Dispositions for the two `def test_` functions in pinned
//! `tests/repair/test_plan_input_regressions.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (37 splitlines). T-05
//! minimized fuzz failures: malformed plan containers must fail before any
//! write. This integration test crate links `sesslint-rust-workspace`, whose
//! library exports [`PACKAGE_NAME`] only. It cannot call `api.plan_repair`,
//! `load_plan`, or `api.apply_plan`.
//!
//! `test_malformed_plan_container_refused` is one disposition row for the full
//! `@pytest.mark.parametrize` matrix over five `(field, value)` cells
//! (`steps=None`, `steps=[None]`, `blocked=None`, `loss_accounting=None`,
//! `profile=None`); one parametrized cell is not the whole pytest.
//! `test_unknown_plan_profile_is_typed_and_content_free` sets an unknown plan
//! profile token, expects `RepairRefused` matching `Unsupported repair plan
//! profile`, requires that token to stay out of the refusal text, and requires
//! an empty output directory.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 2;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One parametrized cell alone is not the full matrix pytest.
/// `not_applicable` names the missing stop.
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
        name: "test_malformed_plan_container_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector runs api.plan_repair on fixtures/repair_cli/basic/source.jsonl to_dict then mutates doc across the full five-cell parametrize matrix steps None steps list containing None blocked None loss_accounting None profile None and expects ValueError from load_plan for every cell; one matrix cell is not the whole pytest and sesslint.cli vectors do not record that entire malformed-container refusal stop and api.plan_repair load_plan are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_unknown_plan_profile_is_typed_and_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector runs api.plan_repair on fixtures/repair_cli/basic/source.jsonl to_dict sets profile to an unknown plan profile token that must stay out of the typed refusal then api.apply_plan with output_path under tmp_path expecting RepairRefused matching Unsupported repair plan profile with that unknown profile token absent from the exception text and list tmp_path.iterdir empty; sesslint.cli vectors do not record that entire typed content-free refusal stop and api.plan_repair api.apply_plan are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_malformed_plan_container_refused",
    "test_unknown_plan_profile_is_typed_and_content_free",
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
fn every_pinned_repair_test_plan_input_regressions_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 2);
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
