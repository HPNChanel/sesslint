//! Dispositions for the 7 `def test_` functions in pinned `tests/test_codes.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (192 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names a vector id in `codes/vectors.json` whose construct is the
//! same check as that pinned test. `not_applicable` records a `sesslint.codes`
//! check no vector has; reaching that module from this package would require a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 7;
const CODES_VECTOR_COUNT: usize = 46;
const VECTORS_REL: &str = "parity/vectors/codes/vectors.json";

/// `covered` names a vector id in `codes/vectors.json`. `not_applicable` records
/// a check this package cannot reach without a `Cargo.toml` change, or a mode
/// absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum Disposition {
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
    // `code_registry_row` looks up one code. A row count of 35 is not the size check.
    Row {
        name: "test_registry_has_exact_35_codes",
        disposition: Disposition::NotApplicable(
            "registry key set and length 35; no codes vector is that registry-size check",
        ),
    },
    Row {
        name: "test_code_enum_matches_registry",
        disposition: Disposition::NotApplicable(
            "Code enum values versus registry keys; no codes vector compares those sets",
        ),
    },
    // One get_code_info("SL203") row is not the 24-code name and summary sweep.
    Row {
        name: "test_verbatim_demand_names_and_summaries",
        disposition: Disposition::NotApplicable(
            "get_code_info name and summary for all 24 demand codes; get_code_info_sl203 is one code and code_registry_row is a different construct",
        ),
    },
    // True for every registered code, plus four distinct false inputs. No vector is that sweep.
    Row {
        name: "test_is_valid_code",
        disposition: Disposition::NotApplicable(
            "is_valid_code is true for every registered code and false for SL000, SL999, INVALID, and the empty string; no vector records that sweep",
        ),
    },
    // The pinned call is get_code_info("NONEXISTENT"). The unknown-code vector uses SL999.
    Row {
        name: "test_get_code_info_unknown_raises_finding_error",
        disposition: Disposition::NotApplicable(
            "get_code_info on NONEXISTENT raises FindingError; the only unknown-code vector uses SL999",
        ),
    },
    Row {
        name: "test_no_vendor_strings_in_codes_module",
        disposition: Disposition::NotApplicable(
            "source scan of codes.py for vendor terms; no codes vector reads module text",
        ),
    },
    // Severity_from_str and Repairability_from_str parse one token. They do not read the schema.
    Row {
        name: "test_codes_and_taxonomies_match_finding_schema_anti_drift",
        disposition: Disposition::NotApplicable(
            "finding schema enum lockstep; no codes vector compares that schema document",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_registry_has_exact_35_codes",
    "test_code_enum_matches_registry",
    "test_verbatim_demand_names_and_summaries",
    "test_is_valid_code",
    "test_get_code_info_unknown_raises_finding_error",
    "test_no_vendor_strings_in_codes_module",
    "test_codes_and_taxonomies_match_finding_schema_anti_drift",
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
        .unwrap_or_else(|| panic!("codes vectors.json is missing id {id}"));
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
fn every_pinned_codes_test_has_one_disposition() {
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
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn covered_vector_ids_are_present_in_codes_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "codes vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.codes\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), CODES_VECTOR_COUNT);
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
