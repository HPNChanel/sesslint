//! Dispositions for the 8 `def test_` functions in pinned `tests/test_harness.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (103 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` would name one parity vector whose construct is the same function
//! and the same success or failure mode as that entire pinned test.
//! `not_applicable` records a `tests.harness.conformance` call no vector has.
//! A single code row is not a registry-wide detection sweep. A shared count is
//! not coverage. Reaching `api.check_file` or `api.check_dir` from this package
//! would require a `Cargo.toml` change; these rows do not call the checks or
//! scan crates.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 8;

/// `covered` names a vector id whose construct matches that entire pinned test.
/// `not_applicable` records a mode no vector has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum Disposition {
    Covered {
        vector_id: &'static str,
        construct_type: &'static str,
        needles: &'static [&'static str],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

struct Catalog {
    rel: &'static str,
    module: &'static str,
    count: usize,
}

const CATALOGS: &[Catalog] = &[
    Catalog {
        rel: "parity/vectors/codes/vectors.json",
        module: "sesslint.codes",
        count: 46,
    },
    Catalog {
        rel: "parity/vectors/canonical/vectors.json",
        module: "sesslint.canonical",
        count: 12,
    },
    Catalog {
        rel: "parity/vectors/determinism/vectors.json",
        module: "sesslint.determinism",
        count: 8,
    },
    Catalog {
        rel: "parity/vectors/discovery/vectors.json",
        module: "sesslint.discovery",
        count: 12,
    },
];

const ABSENT_CONSTRUCTS: &[&str] = &[
    "discover_cases",
    "assert_case",
    "run_case",
    "canonical_bytes",
    "to_canonical_json",
    "assert_deterministic",
];

const ROWS: &[Row] = &[
    // len(CASES) >= 8. A file that happens to hold 8 or 12 vectors is another count.
    Row {
        name: "test_harness_discovers_minimum_cases",
        disposition: Disposition::NotApplicable(
            "len(CASES) >= 8 after discover_cases on the fixtures root; no vector calls discover_cases, and a shared count is not that check",
        ),
    },
    // code_registry_row is one code. finding all_export_order only lists the name ALL_CODES.
    Row {
        name: "test_all_registered_codes_observed_through_public_detection",
        disposition: Disposition::NotApplicable(
            "run_case on every check_file and scan case until observed codes equal ALL_CODES; one code_registry_row is not that registry-wide detection sweep, and finding all_export_order only lists the name ALL_CODES",
        ),
    },
    Row {
        name: "test_conformance_case_matches_expected",
        disposition: Disposition::NotApplicable(
            "assert_case succeeds for every discovered golden case; no vector calls assert_case in that success mode",
        ),
    },
    // The gap names canonical_bytes. The construct types are parsers, canonical_json_bytes, and repeat_hash.
    Row {
        name: "test_conformance_case_report_is_deterministic",
        disposition: Disposition::NotApplicable(
            "canonical_bytes(to_canonical_json(run_case(case))) identical across 3 runs; no vector calls those functions, and canonical_json_bytes plus repeat_hash are different constructs",
        ),
    },
    Row {
        name: "test_assert_case_fails_on_tampered_counts",
        disposition: Disposition::NotApplicable(
            "assert_case raises AssertionError matching Counts mismatch when counts.total is 999; no vector records that tampered-count failure",
        ),
    },
    // The tampered finding uses SL001. code_registry_row_sl001 is a registry lookup.
    Row {
        name: "test_assert_case_fails_on_tampered_findings",
        disposition: Disposition::NotApplicable(
            "assert_case raises AssertionError matching Findings mismatch for one SL001 finding at line 9999; code_registry_row_sl001 is a different construct",
        ),
    },
    Row {
        name: "test_discover_cases_missing_input_raises",
        disposition: Disposition::NotApplicable(
            "discover_cases raises FileNotFoundError matching Missing input fixture for an orphan expected file; candidate_in_layout does not call discover_cases",
        ),
    },
    Row {
        name: "test_discover_cases_nonexistent_root",
        disposition: Disposition::NotApplicable(
            "discover_cases on a missing directory returns an empty list; candidate_in_layout is a different function and success mode",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_harness_discovers_minimum_cases",
    "test_all_registered_codes_observed_through_public_detection",
    "test_conformance_case_matches_expected",
    "test_conformance_case_report_is_deterministic",
    "test_assert_case_fails_on_tampered_counts",
    "test_assert_case_fails_on_tampered_findings",
    "test_discover_cases_missing_input_raises",
    "test_discover_cases_nonexistent_root",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in json.lines() {
        // Vector ids sit at six spaces. Nested JSON keys named id are deeper.
        let Some(rest) = line.strip_prefix("      \"id\": \"") else {
            continue;
        };
        let end = rest.find('"').expect("vector id is a JSON string");
        ids.push(&rest[..end]);
    }
    ids
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

fn type_needle(construct: &str) -> String {
    format!("\"type\": \"{construct}\"")
}

fn read_catalog(catalog: &Catalog) -> String {
    let path = vectors_path(catalog.rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{} vectors are pinned to {PIN}",
        catalog.rel
    );
    assert!(
        json.contains(&format!("\"module\": \"{}\"", catalog.module)),
        "{}",
        catalog.rel
    );
    let ids = vector_ids(&json);
    assert_eq!(ids.len(), catalog.count, "{}", catalog.rel);
    assert_eq!(
        ids.iter().collect::<BTreeSet<_>>().len(),
        catalog.count,
        "{}",
        catalog.rel
    );
    for construct in ABSENT_CONSTRUCTS {
        assert!(
            !json.contains(&type_needle(construct)),
            "{} has construct {construct}",
            catalog.rel
        );
    }
    json
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_harness_test_has_one_disposition() {
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
                construct_type,
                needles,
            } => {
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert!(!construct_type.is_empty(), "{}", row.name);
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
fn nearest_vectors_do_not_match_pinned_harness_tests() {
    let mut loaded = Vec::new();
    for catalog in CATALOGS {
        loaded.push(read_catalog(catalog));
    }
    let codes = &loaded[0];
    let canonical = &loaded[1];
    let determinism = &loaded[2];
    let discovery = &loaded[3];

    let sl001 = vector_slice(codes, "code_registry_row_sl001");
    assert!(sl001.contains(&type_needle("code_registry_row")));
    assert!(!sl001.contains("check_file"));
    assert!(!sl001.contains("scan"));

    assert!(canonical.contains("canonical_bytes"));
    assert!(canonical.contains("to_canonical_json"));
    assert!(canonical.contains(&type_needle("parse_session_header")));
    assert!(!canonical.contains(&type_needle("canonical_bytes")));
    assert!(!canonical.contains(&type_needle("to_canonical_json")));

    assert!(determinism.contains(&type_needle("canonical_json_bytes")));
    assert!(determinism.contains(&type_needle("repeat_hash")));
    assert!(!determinism.contains(&type_needle("canonical_bytes")));

    assert!(discovery.contains(&type_needle("candidate_in_layout")));
    assert_eq!(vector_ids(discovery).len(), 12);

    let finding_path = vectors_path("parity/vectors/finding/vectors.json");
    let finding = fs::read_to_string(&finding_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", finding_path.display()));
    assert!(finding.contains(&format!("\"python_commit\": \"{PIN}\"")));
    assert!(finding.contains("\"module\": \"sesslint.finding\""));
    let exports = vector_slice(&finding, "all_export_order");
    assert!(exports.contains(&type_needle("ALL")));
    assert!(exports.contains("\"ALL_CODES\""));
    assert!(!exports.contains(&type_needle("run_case")));
    assert!(!exports.contains("check_file"));
    for construct in ABSENT_CONSTRUCTS {
        assert!(
            !finding.contains(&type_needle(construct)),
            "finding vectors have construct {construct}"
        );
    }
}
