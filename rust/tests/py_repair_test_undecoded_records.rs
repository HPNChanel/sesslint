//! Dispositions for the four `def test_` functions in pinned
//! `tests/repair/test_undecoded_records.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (101 splitlines). B22: canonical
//! emission must account for every undecoded source record. Helpers `_source` and
//! `_plan` are not tests. This integration test crate links `sesslint-rust-workspace`,
//! whose library exports [`PACKAGE_NAME`] only. It cannot call `api.repair`,
//! `api.apply_plan`, `executor.execute`, `load_source_for_format`, `run_all_checks`,
//! `derive_plan`, or `compute_plan_fingerprint` without a `Cargo.toml` change.
//!
//! `test_unrepaired_bad_line_refuses_canonical_emission` is parametrized over vendor
//! false and true and supplied false and true (four cells as one row). It builds a
//! source with one complete event written twice and one undecoded non-JSON line,
//! derives a plan with steps and blocked SL001, then expects `api.repair` with
//! emit canonical to raise `SesslintError` matching undecoded while source bytes
//! stay unchanged and neither output nor its manifest sidecar exist.
//!
//! `test_direct_executor_also_refuses_unrepaired_bad_line` uses canonical source
//! only and expects `executor.execute` with the derived plan to raise matching
//! undecoded.
//!
//! `test_salvage_excision_accounts_for_bad_line` calls `api.repair` with salvage
//! policy and `acknowledge_side_effects` true, expects manifest `declared_loss` of
//! the single label torn-record:1, and expects one surviving event id between
//! header and trailing blank in output.
//!
//! `test_salvage_subset_cannot_omit_excision` edits a salvage plan dict by removing
//! the torn-record-excision step, rewriting step seq values, and recomputing the
//! fingerprint, then expects `api.apply_plan` to raise matching undecoded.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. One parametrized matrix cell alone is not the whole first pytest.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 4;
const PINNED_SPLITLINES: usize = 101;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One parametrized matrix cell alone is not the whole first pytest.
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
        name: "test_unrepaired_bad_line_refuses_canonical_emission",
        disposition: Disposition::NotApplicable(
            "no cli vector is the full two-by-two parametrized matrix over canonical versus vendor adapter format and automatic versus exported derived plan builds a tmp_path source with one complete event duplicated and one undecoded non-JSON line derives a plan with executable steps and SL001 blocked runs api.repair with emit canonical and plan supplied or omitted expecting SesslintError matching undecoded then asserts source bytes unchanged and neither repaired output nor its manifest sidecar exist; one matrix cell alone is not this pytest and sesslint.cli vectors record parser metadata removed-command hints and exit-code constants only; api.repair load_source_for_format run_all_checks and derive_plan are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_direct_executor_also_refuses_unrepaired_bad_line",
        disposition: Disposition::NotApplicable(
            "no cli vector builds canonical tmp_path source with duplicated complete event and undecoded non-JSON line derives conservative plan via helper then expects executor.execute with that plan to raise SesslintError matching undecoded; sesslint.cli vectors do not record that executor undecoded refusal stop and executor.execute load_source_for_format run_all_checks and derive_plan are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_salvage_excision_accounts_for_bad_line",
        disposition: Disposition::NotApplicable(
            "no cli vector runs api.repair on canonical undecoded-line source with policy salvage and acknowledge_side_effects true expecting manifest declared_loss tuple of torn-record:1 and output whose parsed event ids between header line and trailing blank are exactly the one surviving record; sesslint.cli vectors do not record salvage repair manifest loss accounting or undecoded excision stops and api.repair is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_salvage_subset_cannot_omit_excision",
        disposition: Disposition::NotApplicable(
            "no cli vector serializes salvage derived plan to dict removes torn-record-excision step rewrites remaining step seq integers recomputes plan fingerprint then calls api.apply_plan with acknowledge_side_effects true expecting SesslintError matching undecoded; sesslint.cli vectors do not record apply_plan refusal when excision is omitted from an otherwise valid salvage fingerprint and api.apply_plan compute_plan_fingerprint load_source_for_format and derive_plan are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_unrepaired_bad_line_refuses_canonical_emission",
    "test_direct_executor_also_refuses_unrepaired_bad_line",
    "test_salvage_excision_accounts_for_bad_line",
    "test_salvage_subset_cannot_omit_excision",
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
fn pinned_undecoded_records_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 101);
}

#[test]
fn every_pinned_repair_test_undecoded_records_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 4);
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
