//! Dispositions for the 5 `def test_` functions in pinned
//! `tests/privacy/test_run_state_evidence.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (171 splitlines). Each row is
//! the whole pinned function, not one redacted field or one checkpoint. Helpers
//! and imports are not tests. `rust/parity/vectors/report/vectors.json` is
//! pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`; this map does not claim
//! Covered from that corpus. This integration test crate links
//! `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`] only. It
//! cannot call `sesslint.api.check_file`, `sesslint.api.check_dir`,
//! `sesslint.cli.main`, or `sesslint.report.render_json` without a `Cargo.toml`
//! change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 5;
const PINNED_SPLITLINES: usize = 171;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. `not_applicable` names the missing stop.
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
        name: "test_run_state_evidence_fixture_survival_and_zero_leakage",
        disposition: Disposition::NotApplicable(
            "no cli vector is api.check_file on openai_agents run_state_evidence fixture asserting two findings SL009 and SL201 set equality full SL201 run_state evidence projection keys shapes truncated flag two checkpoint records SL009 secret_family without raw credential bytes in finding serialization render_json with structural len tokens and zero raw run_state payload values in report JSON; sesslint.cli vectors record parser and exit metadata only",
        ),
    },
    Row {
        name: "test_cli_json_run_state_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is main check with json on run_state_evidence fixture asserting exit one two findings SL201 run_state projection in parsed stdout and zero raw run_state payload values anywhere in CLI stdout",
        ),
    },
    Row {
        name: "test_healthy_run_state_checkpoint_fixture_remains_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is api.check_file on openai_agents run_state_checkpoint healthy fixture asserting zero findings and zero total counts",
        ),
    },
    Row {
        name: "test_dynamic_secrets_and_pii_strictly_redacted",
        disposition: Disposition::NotApplicable(
            "no cli vector is tmp_path authored session with live credential and contact fields in run_state checkpoints and items api.check_file three findings SL009 and SL201 render_json and tests.utils.privacy assert_no_pii on full rendered report JSON",
        ),
    },
    Row {
        name: "test_scan_run_state_evidence_preservation",
        disposition: Disposition::NotApplicable(
            "no cli vector is api.check_dir recursive on openai_agents tree with one run_state_evidence file result invalid verdict two findings SL201 run_state shapes secret_token len projection and scan report to_json zero raw run_state payload leakage; api.check_dir is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_run_state_evidence_fixture_survival_and_zero_leakage",
    "test_cli_json_run_state_evidence",
    "test_healthy_run_state_checkpoint_fixture_remains_clean",
    "test_dynamic_secrets_and_pii_strictly_redacted",
    "test_scan_run_state_evidence_preservation",
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
fn pinned_run_state_evidence_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 171);
}

#[test]
fn pinned_run_state_evidence_row_count_equals_five() {
    assert_eq!(ROWS.len(), 5);
    assert_eq!(PINNED_TEST_COUNT, 5);
}

#[test]
fn every_pinned_run_state_evidence_test_has_one_disposition() {
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
