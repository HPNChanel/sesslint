//! Dispositions for the 5 `def test_` functions in pinned `tests/checks/test_runner.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (73 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `load_canonical`, `run_all_checks`,
//! `repair.executor.run_all_checks`, or `verify._run_detector_checks`.
//!
//! `covered` names one id in `checks.runner/vectors.json` (or a sibling ledger)
//! whose construct is the same function and the same success or failure mode as
//! that entire pinned test. One `run_all_checks` vector that omits the executor
//! alias, verify delegate, `load_canonical` of `graph_healthy.json`,
//! `return_coverage` success, or `claude-strict` profile gating is not
//! coverage. `not_applicable` records runner integration wiring no isolated
//! vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 5;
const RUNNER_VECTOR_COUNT: usize = 8;
const RUNNER_VECTORS_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const RUNNER_VECTORS_REL: &str = "parity/vectors/checks.runner/vectors.json";
const RUNNER_COVERAGE_REL: &str = "parity/vectors/checks.runner/coverage.json";
const VERIFY_COVERAGE_REL: &str = "parity/vectors/verify/coverage.json";
const VERIFY_VECTORS_REL: &str = "parity/vectors/verify/vectors.json";
const EXECUTOR_COVERAGE_REL: &str = "parity/vectors/repair.executor/coverage.json";
const RUNNER_MANIFEST_REL: &str = "parity/vectors/checks.runner/manifest.json";

/// `covered` names a vector id in `checks.runner/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
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

/// Vector id and construct type for the eight `checks.runner` vectors.
const RUNNER_VECTORS: &[(&str, &str)] = &[
    ("module_all_export", "module_all"),
    ("import_paths_pin_order", "import_paths"),
    ("empty_neutral_no_findings", "run_all_checks"),
    ("return_coverage_empty_stop", "run_all_checks"),
    ("version_gated_skips_detectors", "run_all_checks"),
    ("cap_exceeded_skips_detectors", "run_all_checks"),
    ("graph_healthy_fixture_silent", "run_all_checks"),
    ("profile_name_neutral_builtin", "run_all_checks"),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_executor_reexports_shared_runner",
        disposition: Disposition::NotApplicable(
            "assert repair.executor.run_all_checks is checks.runner.run_all_checks; module_all_export in checks.runner and module_all_export_order in repair.executor only list the run_all_checks name and GAP-runner-executor-alias states parity vectors exercise sesslint.checks.runner.run_all_checks only, so no vector records Python callable identity",
        ),
    },
    Row {
        name: "test_verify_delegates_to_shared_runner",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/checks/graph_healthy.json then _run_detector_checks with profile_name neutral and source_path s.jsonl must equal run_all_checks with profile neutral, adapter canonical, and the same source_path; verify._run_detector_checks is outside this package, GAP-runner-verify-delegate is explicit, and graph_healthy_fixture_silent is a single runner call on synthetic events without the verify entry point or load_canonical of the fixture file",
        ),
    },
    Row {
        name: "test_runner_findings_byte_identical_across_entry_points",
        disposition: Disposition::NotApplicable(
            "load_canonical of graph_healthy.json then compare finding dicts from checks.runner.run_all_checks and repair.executor.run_all_checks with source_path x; no vector pairs those two entry points, module_all_export does not assert alias parity, and graph_healthy_fixture_silent records rust_assertion profiles_unavailable instead of byte-identical finding dicts across imports",
        ),
    },
    Row {
        name: "test_runner_is_pure_and_deterministic",
        disposition: Disposition::NotApplicable(
            "deep-copied to_canonical_dict snapshot, two run_all_checks calls with return_coverage true on graph_healthy events must yield equal finding and coverage dicts without mutating the input; return_coverage_empty_stop records rust_assertion coverage_unavailable on the successful Python path, graph_healthy_fixture_silent does not use return_coverage, and no vector records input purity or repeat-run equality",
        ),
    },
    Row {
        name: "test_runner_profile_gating_parity",
        disposition: Disposition::NotApplicable(
            "profile claude-strict with return_coverage true must make runner and executor alias produce equal findings and coverage dicts on graph_healthy events; profile_name_neutral_builtin is profile neutral with rust_assertion builtin_unavailable, no vector names claude-strict, and no vector compares executor alias coverage on a non-neutral profile",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_executor_reexports_shared_runner",
    "test_verify_delegates_to_shared_runner",
    "test_runner_findings_byte_identical_across_entry_points",
    "test_runner_is_pure_and_deterministic",
    "test_runner_profile_gating_parity",
];

const COVERAGE_TEST_PATHS: &[&str] = &[
    "tests/checks/test_runner.py::test_executor_reexports_shared_runner",
    "tests/checks/test_runner.py::test_verify_delegates_to_shared_runner",
    "tests/checks/test_runner.py::test_runner_findings_byte_identical_across_entry_points",
    "tests/checks/test_runner.py::test_runner_is_pure_and_deterministic",
    "tests/checks/test_runner.py::test_runner_profile_gating_parity",
];

fn expected_covered_ids(_name: &str) -> Option<&'static [&'static str]> {
    None
}

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\n      \"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("checks.runner vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_coverage_rows_not_applicable(coverage_json: &str, module_label: &str) {
    for path in COVERAGE_TEST_PATHS {
        let needle = format!("\"test\": \"{path}\"");
        assert!(
            coverage_json.contains(&needle),
            "{module_label} coverage.json is missing row {path}"
        );
        let row_start = coverage_json
            .find(&needle)
            .unwrap_or_else(|| panic!("{module_label} coverage row start for {path}"));
        let row_tail = &coverage_json[row_start..];
        let row_end = row_tail
            .find("\n    }")
            .map(|offset| row_start + offset)
            .unwrap_or(coverage_json.len());
        let row = &coverage_json[row_start..row_end];
        assert!(
            row.contains("\"status\": \"not_applicable\""),
            "{module_label} coverage row for {path} is not not_applicable"
        );
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_checks_test_runner_has_one_disposition() {
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
            Disposition::Covered {
                vector_id,
                needles,
            } => {
                let expected = expected_covered_ids(row.name)
                    .unwrap_or_else(|| panic!("{} is not a fully covered pin test", row.name));
                assert!(
                    expected.contains(&vector_id),
                    "{} vector id {}",
                    row.name,
                    vector_id
                );
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert!(!needles.is_empty(), "{}", row.name);
                assert!(
                    needles
                        .iter()
                        .any(|needle| needle.starts_with("\"type\": \"")),
                    "{} covered row is missing a construct type needle",
                    row.name
                );
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(
                    expected_covered_ids(row.name).is_none(),
                    "{} is not_applicable but lists covered ids",
                    row.name
                );
                assert!(!reason.is_empty(), "{}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn runner_integration_tests_are_not_applicable_in_parity_ledgers() {
    let runner_path = vectors_path(RUNNER_VECTORS_REL);
    let runner_json = fs::read_to_string(&runner_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", runner_path.display()));
    assert!(
        runner_json.contains(&format!("\"python_commit\": \"{RUNNER_VECTORS_COMMIT}\"")),
        "checks.runner vectors are pinned to {RUNNER_VECTORS_COMMIT}"
    );
    assert!(runner_json.contains("\"module\": \"sesslint.checks.runner\""));
    assert!(runner_json.contains("GAP-runner-executor-alias"));
    assert!(runner_json.contains("GAP-runner-verify-delegate"));
    assert!(runner_json.contains("GAP-runner-coverage"));

    let ids = vector_ids(&runner_json);
    let expected_ids: Vec<&str> = RUNNER_VECTORS.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, expected_ids);
    assert_eq!(ids.len(), RUNNER_VECTOR_COUNT);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct) in RUNNER_VECTORS {
        let slice = vector_slice(&runner_json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
    }

    let manifest_path = vectors_path(RUNNER_MANIFEST_REL);
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", manifest_path.display()));
    assert!(manifest.contains(&format!("\"vector_count\": {RUNNER_VECTOR_COUNT}")));
    assert!(manifest.contains("GAP-runner-executor-alias"));
    assert!(manifest.contains("GAP-runner-verify-delegate"));

    let runner_coverage_path = vectors_path(RUNNER_COVERAGE_REL);
    let runner_coverage = fs::read_to_string(&runner_coverage_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", runner_coverage_path.display()));
    assert!(runner_coverage.contains("\"not_applicable_count\": 5"));
    assert!(runner_coverage.contains("\"covered_count\": 0"));
    assert_coverage_rows_not_applicable(&runner_coverage, "checks.runner");

    let verify_coverage_path = vectors_path(VERIFY_COVERAGE_REL);
    let verify_coverage = fs::read_to_string(&verify_coverage_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", verify_coverage_path.display()));
    assert!(
        verify_coverage.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "verify coverage is pinned to {PIN}"
    );
    assert_coverage_rows_not_applicable(&verify_coverage, "verify");

    let verify_vectors_path = vectors_path(VERIFY_VECTORS_REL);
    let verify_vectors = fs::read_to_string(&verify_vectors_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", verify_vectors_path.display()));
    assert!(verify_vectors.contains("GAP-verify-runner-integration"));

    let executor_coverage_path = vectors_path(EXECUTOR_COVERAGE_REL);
    let executor_coverage = fs::read_to_string(&executor_coverage_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", executor_coverage_path.display()));
    assert_coverage_rows_not_applicable(&executor_coverage, "repair.executor");

    for row in ROWS {
        let Disposition::Covered {
            vector_id,
            needles,
        } = row.disposition
        else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&runner_json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
