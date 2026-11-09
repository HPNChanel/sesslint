//! Dispositions for the two `def test_` functions in pinned
//! `tests/repair/test_snapshot_consistency.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (91 splitlines). B19: planning
//! and write-back bind one read of the source; a writer that completes a torn
//! tail between planning parse and hash, or between planning and apply, must not
//! drop the now-complete record as torn. Helper `_completed_record` is not a
//! test. This integration test crate links `sesslint-rust-workspace`, whose
//! library exports [`PACKAGE_NAME`] only. It cannot call `api.plan_repair`,
//! `executor.load_source_for_format`, `run_all_checks`, `planner_plan`, or
//! `executor.execute` without a `Cargo.toml` change.
//!
//! `test_tail_completed_during_planning_is_refused` writes fixture bytes plus a
//! torn half of a late append, monkeypatches `load_source_for_format` to finish
//! that append on first load, expects `PlanSourceMismatch` from
//! `api.plan_repair` with `FORMAT_CLAUDE_CODE`, then requires source bytes equal
//! the fixture plus the completed append.
//!
//! `test_write_back_keeps_line_the_current_bytes_no_longer_flag` loads findings
//! from the torn file including an `SL002` stream finding, plans without
//! `source_hash`, completes the source before execute, then either
//! `executor.execute` raises `SesslintError` with absent output or the output
//! ends with the completed late record; both outcomes are one disposition row.
//! One execute-outcome branch alone is not the whole pytest.
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
const PINNED_SPLITLINES: usize = 91;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One execute-outcome branch alone is not the whole write-back pytest.
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
        name: "test_tail_completed_during_planning_is_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector writes fixtures claude_code basic session bytes plus torn half of a late append to session.jsonl monkeypatches executor.load_source_for_format to finish that append on first load runs api.plan_repair with FORMAT_CLAUDE_CODE expecting PlanSourceMismatch then asserts source bytes equal fixture plus completed append; sesslint.cli vectors do not record that entire planning source-binding refusal stop and api.plan_repair executor.load_source_for_format are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_write_back_keeps_line_the_current_bytes_no_longer_flag",
        disposition: Disposition::NotApplicable(
            "no cli vector writes fixture bytes plus torn late append loads with executor.load_source_for_format asserts SL002 among stream_findings merges stream_findings with run_all_checks builds plan via planner_plan without source_hash asserting plan.steps completes source before executor.execute then either execute raises SesslintError with absent output or output bytes end with completed late record and in both branches source bytes stay the completed file; one execute outcome branch is not the whole pytest and sesslint.cli vectors do not record that entire write-back stale-finding stop and executor.load_source_for_format run_all_checks planner_plan executor.execute are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_tail_completed_during_planning_is_refused",
    "test_write_back_keeps_line_the_current_bytes_no_longer_flag",
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
fn pinned_snapshot_consistency_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 91);
}

#[test]
fn every_pinned_repair_test_snapshot_consistency_test_has_one_disposition() {
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
