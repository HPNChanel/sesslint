//! Dispositions for the 5 `def test_` functions in pinned
//! `tests/test_scan_schema.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (148 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.scan` or `tests.utils.schema`.
//!
//! `covered` names one id in `scan/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! One assertion inside `_validate_scan_dict_strictly`, a shared
//! `schema_version`, or a `skipped_reason` string is not coverage. A different
//! report dict is not coverage. `not_applicable` records a `load_scan_schema`,
//! `assert_schema`, `ScanReport`, or `skipped_reason_totals` check this package
//! cannot reach without a `Cargo.toml` change outside owned_paths, or a mode no
//! vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 5;
const SCAN_VECTOR_COUNT: usize = 21;
const VECTORS_REL: &str = "parity/vectors/scan/vectors.json";

/// `covered` names a vector id in `scan/vectors.json`. `not_applicable`
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

/// Vector id and construct type (hand-parsed from `scan/vectors.json`).
const SCAN_VECTORS: &[(&str, &str)] = &[
    ("module_constants", "module_constants"),
    ("aggregate_by_code_exact", "aggregate_scan"),
    ("aggregate_by_code_sort_order", "aggregate_scan"),
    ("aggregate_worst_files_exact", "aggregate_scan"),
    ("aggregate_worst_files_excludes_healthy", "aggregate_scan"),
    ("aggregate_top_one", "aggregate_scan"),
    ("aggregate_top_zero", "aggregate_scan"),
    ("aggregate_top_negative", "aggregate_scan"),
    ("aggregate_group_by_none", "aggregate_scan"),
    ("aggregate_group_by_invalid", "aggregate_scan"),
    ("aggregate_deterministic", "aggregate_scan"),
    ("session_link_wire_round_trip", "session_link"),
    ("rollout_uuid_00", "rollout_uuid"),
    ("rollout_uuid_01", "rollout_uuid"),
    ("rollout_uuid_02", "rollout_uuid"),
    ("rollout_uuid_03", "rollout_uuid"),
    ("looks_pathy_00", "looks_pathy"),
    ("looks_pathy_01", "looks_pathy"),
    ("looks_pathy_02", "looks_pathy"),
    ("looks_pathy_03", "looks_pathy"),
    ("looks_pathy_04", "looks_pathy"),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_scan_schema_loads_and_self_consistent",
        disposition: Disposition::NotApplicable(
            "get_scan_schema_path, load_scan_schema, draft 2020-12 $schema, required subset checks on schema totals and file items, verdict enum equals VALID_VERDICTS, and finding code enum equals ALL_CODES with len 35; reaching sesslint.scan from this package would require a Cargo.toml change outside owned_paths, and module_constants records scan_schema_version only without loading schemas/sesslint.scan-report.v1.json",
        ),
    },
    Row {
        name: "test_scan_report_dict_validates",
        disposition: Disposition::NotApplicable(
            "_sample_report with five FileResult verdicts and one SL001 finding, to_dict, assert_schema on sesslint.scan-report.v1.json, and _validate_scan_dict_strictly; reaching ScanReport from this package would require a Cargo.toml change outside owned_paths, and no scan vector builds that report or calls assert_schema",
        ),
    },
    Row {
        name: "test_scan_report_json_round_trip_validates",
        disposition: Disposition::NotApplicable(
            "json.loads on _sample_report().to_json() then _validate_scan_dict_strictly; reaching ScanReport.to_json from this package would require a Cargo.toml change outside owned_paths, and no scan vector records that JSON round trip through assert_schema",
        ),
    },
    Row {
        name: "test_scan_report_skipped_reasons_aggregated",
        disposition: Disposition::NotApplicable(
            "ScanReport with four skipped files, skipped_reason_totals equals {\"a-reason\": 1, \"z-reason\": 2}, totals.skipped_reasons in to_dict, and _validate_scan_dict_strictly; reaching sesslint.scan from this package would require a Cargo.toml change outside owned_paths, and scan vectors record no skipped_reason or skipped_reason_totals construct",
        ),
    },
    Row {
        name: "test_scan_report_skipped_reasons_omitted_when_empty",
        disposition: Disposition::NotApplicable(
            "ScanReport with healthy totals only asserts skipped_reasons is absent from to_dict totals; reaching ScanReport from this package would require a Cargo.toml change outside owned_paths, and aggregate_scan vectors do not record ScanReport.to_dict omission behavior",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_scan_schema_loads_and_self_consistent",
    "test_scan_report_dict_validates",
    "test_scan_report_json_round_trip_validates",
    "test_scan_report_skipped_reasons_aggregated",
    "test_scan_report_skipped_reasons_omitted_when_empty",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
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
        .unwrap_or_else(|| panic!("scan vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
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
fn every_pinned_scan_schema_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(SCAN_VECTORS.len(), SCAN_VECTOR_COUNT);
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
                    needles
                        .iter()
                        .all(|needle| !needle.contains("schema_version")),
                    "{} needle is a shared schema_version",
                    row.name
                );
                assert!(
                    needles
                        .iter()
                        .all(|needle| !needle.contains("skipped_reason")),
                    "{} needle is only a skipped_reason string",
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
fn covered_vector_ids_are_present_in_scan_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "scan vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.scan\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = SCAN_VECTORS.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct) in SCAN_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
    }

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
