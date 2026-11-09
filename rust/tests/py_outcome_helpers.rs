//! Dispositions for pinned `tests/outcome/helpers.py` (no `def test_` names).
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (99 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. The module is a pytest support library: builders
//! `at`, `contract`, `due`, `snapshot`, `run`, `item`, and `cond` wrap
//! `sesslint.outcome` for synthetic OutcomeGuard contracts and snapshots. A
//! column-0 scan and an indented scan both find zero `def test_` functions.
//!
//! `covered` would name one parity vector whose construct is the same function
//! and the same success or failure mode as that entire pinned test name.
//! `not_applicable` records pytest builder wiring no vector records. The sibling
//! `tests/outcome/test_outcome_*.py` modules are mapped by their own RX-TST
//! cards; this file claims no builder coverage.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 0;
const VECTORS_REL: &str = "parity/vectors/outcome/vectors.json";
const MANIFEST_REL: &str = "parity/vectors/outcome/manifest.json";
const COVERAGE_REL: &str = "parity/vectors/outcome/coverage.json";

/// `covered` names a vector id in `outcome/vectors.json`. `not_applicable`
/// records a pytest helper or builder mode no vector records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
    Covered {
        vector_id: &'static str,
        needles: &'static [&'static str],
    },
    #[allow(dead_code)]
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[];

const PINNED_NAMES: &[&str] = &[];

const PYTEST_BUILDERS: &[&str] = &[
    "def at(",
    "def contract(",
    "def due(",
    "def snapshot(",
    "def run(",
    "def item(",
    "def cond(",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_outcome_helpers_test_has_one_disposition() {
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
                assert!(!reason.is_empty(), "{}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, 0);
}

#[test]
fn outcome_pytest_builders_are_outside_committed_vectors() {
    let outcome_vectors_path = vectors_path(VECTORS_REL);
    let vectors = fs::read_to_string(&outcome_vectors_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", outcome_vectors_path.display()));
    assert!(
        vectors.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "outcome vectors are pinned to {PIN}"
    );
    assert!(vectors.contains("\"module\":\"sesslint.outcome\""));
    assert!(vectors.contains("\"schema\":\"sesslint.parity-module-vectors/v1\""));
    assert!(
        !vectors.contains("tests/outcome/helpers.py"),
        "module verify vectors do not name tests/outcome/helpers.py"
    );
    assert!(
        !vectors.contains("fixtures/outcome/orders"),
        "ORDERS path from helpers.py is not embedded in verify vectors"
    );

    let manifest_path = vectors_path(MANIFEST_REL);
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", manifest_path.display()));
    assert!(
        manifest.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "outcome manifest is pinned to {PIN}"
    );
    assert!(manifest.contains("\"module\": \"sesslint.outcome\""));
    assert!(
        !manifest.contains("tests/outcome/helpers.py"),
        "manifest python_sha256 does not list helpers.py"
    );
    assert!(manifest.contains("tests/outcome/test_outcome_contract.py"));
    assert!(manifest.contains("tests/outcome/test_outcome_engine.py"));
    assert!(manifest.contains("tests/outcome/test_outcome_snapshot.py"));

    let coverage_path = vectors_path(COVERAGE_REL);
    let coverage = fs::read_to_string(&coverage_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", coverage_path.display()));
    assert!(
        !coverage.contains("tests/outcome/helpers.py"),
        "coverage.json rows name only test_outcome_*.py modules"
    );
    assert!(coverage.contains("\"test_file\": \"tests/outcome/test_outcome_engine.py\""));

    for builder in PYTEST_BUILDERS {
        assert!(
            !vectors.contains(builder),
            "verify vectors do not record pytest helper {builder}"
        );
    }
}
