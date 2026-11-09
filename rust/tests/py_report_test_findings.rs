//! Dispositions for the 2 `def test_` functions in pinned
//! `tests/report/test_findings.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (103 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `report/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! One example inside a sweep, a different input string, or a shared field such
//! as `python_all` is not coverage. `not_applicable` records a
//! `sesslint.report` call this package cannot reach without a `Cargo.toml`
//! change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 2;
const REPORT_VECTOR_COUNT: usize = 17;
const VECTORS_REL: &str = "parity/vectors/report/vectors.json";

/// `covered` names a vector id in `report/vectors.json`. `not_applicable`
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

/// Vector id, construct type, and whether the expected result is an error.
/// Report vectors record validation failures in `display`, not `"message"`.
const REPORT_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("compute_assurance_none_empty", "compute_assurance", false),
    ("compute_assurance_nonempty_a3", "compute_assurance", false),
    ("dump_report_gap", "dump_report", false),
    ("parse_report_json_string_gap", "parse_report", false),
    ("parse_report_bool_total", "parse_report", false),
    ("build_report_empty_gap", "build_report", false),
    ("render_human_healthy_header", "render_human", false),
    ("render_human_with_finding_gap", "render_human", false),
    ("minimize_path_under_home", "minimize_path", false),
    ("minimize_path_home_self", "minimize_path", false),
    ("minimize_path_passthrough_tilde", "minimize_path", false),
    ("minimize_path_passthrough_dotdot", "minimize_path", false),
    ("minimize_path_passthrough_home", "minimize_path", false),
    ("minimize_path_outside_gap", "minimize_path", false),
    ("compute_assurance_warning_a2", "compute_assurance", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_finding_block_structure",
        disposition: Disposition::NotApplicable(
            "make_finding with SL001 on session.jsonl line 42, build_report for sess_block_test with one finding, and render_human then assert finding block lines for code title, Span, Why, Fix, and Fingerprint; render_human_with_finding_gap is one render_human on sess_bad with claude-code-jsonl and gap_refusal_rationale, render_human_healthy_header has zero findings, and no report vector calls make_finding",
        ),
    },
    Row {
        name: "test_deterministic_finding_sort_order",
        disposition: Disposition::NotApplicable(
            "sorted on four handcrafted findings by finding_report_sort_key, build_report for sess_sort_test passes the scrambled list, and render_human checks fingerprint positions; module_exports lists finding_report_sort_key in python_all only, build_report_empty_gap is build_report with findings_count 0, and no report vector records FR-094 sort order or multi-finding render order",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_finding_block_structure",
    "test_deterministic_finding_sort_order",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are indented further.
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
        .unwrap_or_else(|| panic!("report vectors.json is missing id {id}"));
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
fn every_pinned_report_findings_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REPORT_VECTORS.len(), REPORT_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_report_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "report vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.report\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = REPORT_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in REPORT_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"message\":"),
            fails,
            "{id} error mode does not match the vector file"
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
