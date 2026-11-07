//! Dispositions for the 1 indented `def test_` name in pinned `tests/conftest.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (36 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. The module defines Hypothesis profiles, shared test
//! constants, and pytest fixtures only.
//!
//! A column-0 scan finds no `def test_`. The single indented name
//! `test_tool_version` is a `@pytest.fixture`, not a test function. The
//! `default_limits` fixture name does not start with `test_`.
//!
//! `covered` would name one parity vector whose construct is the same function
//! and the same success or failure mode as that entire pinned name.
//! `not_applicable` records pytest, Hypothesis, or harness constant setup no
//! vector records. Reaching those modules from this package would require a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 1;

/// `covered` names a vector id whose construct matches that entire pinned name.
/// `not_applicable` records a mode no vector has.
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

const ROWS: &[Row] = &[Row {
    name: "test_tool_version",
    disposition: Disposition::NotApplicable(
        "pytest fixture test_tool_version returns TEST_TOOL_VERSION 0.1.0+test; no parity vector records a pytest fixture or that harness tool-version string",
    ),
}];

const PINNED_NAMES: &[&str] = &["test_tool_version"];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("vectors.json is missing id {id}"));
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
fn every_pinned_conftest_test_has_one_disposition() {
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
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn conftest_harness_setup_is_outside_committed_vectors() {
    let io_path = vectors_path("parity/vectors/io/vectors.json");
    let io = fs::read_to_string(&io_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", io_path.display()));
    assert!(
        io.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "io vectors are pinned to {PIN}"
    );
    assert!(io.contains("\"module\": \"sesslint.io\""));
    assert!(
        !io.contains("register_profile"),
        "io vectors do not record Hypothesis settings.register_profile"
    );
    assert!(
        !io.contains("load_profile"),
        "io vectors do not record Hypothesis settings.load_profile"
    );
    let constants = vector_slice(&io, "constants_default");
    assert!(constants.contains("\"type\": \"io_constants\""));
    assert!(constants.contains("8388608"));
    assert!(
        !constants.contains("1000000"),
        "DEFAULT_TEST_LIMITS max_line_bytes 1000000 is not constants_default"
    );

    let report_path = vectors_path("parity/vectors/report/vectors.json");
    let report = fs::read_to_string(&report_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", report_path.display()));
    assert!(
        report.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "report vectors are pinned to {PIN}"
    );
    assert!(report.contains("\"module\": \"sesslint.report\""));
    assert!(
        !report.contains("0.1.0+test"),
        "report vectors do not record TEST_TOOL_VERSION"
    );
    assert!(
        !report.contains("test-harness-conformance"),
        "report vectors do not record TEST_LIMITATION"
    );
    let assurance_constants = vector_slice(&report, "module_constants");
    assert!(assurance_constants.contains("\"A1\""));
    assert!(
        !assurance_constants.contains("\"type\": \"pytest.fixture\""),
        "module_constants lists Assurance levels; it is not the test_tool_version fixture"
    );

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let json = if io.contains(&format!("\"id\": \"{vector_id}\"")) {
            &io
        } else if report.contains(&format!("\"id\": \"{vector_id}\"")) {
            &report
        } else {
            panic!("{} names missing vector {vector_id}", row.name);
        };
        let slice = vector_slice(json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
