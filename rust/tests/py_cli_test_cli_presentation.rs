//! Dispositions for the 5 `def test_` functions in pinned `tests/cli/test_cli_presentation.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (131 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 5;
const CLI_VECTOR_COUNT: usize = 33;
const COVERED_COUNT: usize = 0;
const NOT_APPLICABLE_COUNT: usize = 5;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` whose construct matches the
/// entire pinned pytest, including scan human output and skipped-reason lines.
/// `not_applicable` records a renderer or CLI scan mode no vector records.
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
    Row {
        name: "test_ansi_table_width_alignment",
        disposition: Disposition::NotApplicable(
            "format_scan_report_human colored vs uncolored column-23 alignment: no cli vector",
        ),
    },
    Row {
        name: "test_cli_scan_command_color_alignment",
        disposition: Disposition::NotApplicable(
            "scan subcommand --color always/never stdout alignment: no cli vector for scan",
        ),
    },
    Row {
        name: "test_skipped_reasons_aggregate_line",
        disposition: Disposition::NotApplicable(
            "format_scan_report_human skipped-reason aggregate and cap hint: no cli vector",
        ),
    },
    Row {
        name: "test_skipped_reasons_line_no_hint_for_non_cap",
        disposition: Disposition::NotApplicable(
            "format_scan_report_human non-cap skip without budget hint: no cli vector",
        ),
    },
    Row {
        name: "test_skipped_reasons_line_absent_without_skips",
        disposition: Disposition::NotApplicable(
            "format_scan_report_human with no skipped files omits reasons line: no cli vector",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_ansi_table_width_alignment",
    "test_cli_scan_command_color_alignment",
    "test_skipped_reasons_aggregate_line",
    "test_skipped_reasons_line_no_hint_for_non_cap",
    "test_skipped_reasons_line_absent_without_skips",
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
fn every_pinned_cli_presentation_test_has_one_disposition() {
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
    assert_eq!(covered, COVERED_COUNT);
    assert_eq!(not_applicable, NOT_APPLICABLE_COUNT);
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
