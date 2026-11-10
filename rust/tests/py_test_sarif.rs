//! Dispositions for the seven `def test_` functions in pinned
//! `tests/test_sarif.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (96 splitlines). Exactly
//! seven test functions, in module order. None is parametrized. Each row is
//! the whole function. A check is not a scan. A returned exit is not a
//! SystemExit. One field is not the whole document. The helper `_load_sarif`
//! and the constants `CORRUPT` and `HEALTHY` are not tests. `CORRUPT` is
//! `fixtures/adapters/codex/orphan_output.jsonl`. `HEALTHY` is
//! `fixtures/canonical/minimal.json`. Neither fixture is copied here.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, removed-command hints, removed-flag hints, verbose
//! provenance, and removed-subcommand exits. None of those vectors is one of
//! these seven functions. `check_exit_constants` records help text that an
//! internal tool error exits 2. That help text is not
//! `test_json_and_output_format_mutually_exclusive`.
//! `parity/vectors/sarif/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Its ids are `module_constants`,
//! `build_sarif_level_mapping`, `build_sarif_empty_registry`,
//! `render_sarif_relative_percent_encode`, `scan_report_sarif_gap`, and
//! `render_sarif_absolute_char_colon_pin`. They are not among the 33 cli
//! vectors and are not used to mark a row covered. `build_sarif_level_mapping`
//! is a library call at that other pin, so it does not cover
//! `test_build_sarif_level_mapping`. `build_sarif_empty_registry` records a
//! version, a rule count, sorted ids, and an empty results list for empty
//! findings. That library document is not `test_check_sarif_structure` and
//! not `test_check_sarif_clean_file_empty_results`. `scan_report_sarif_gap`
//! is a gap mode, not `test_scan_sarif_aggregates_findings`.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call sarif or cli functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 7;
const PINNED_SPLITLINES: usize = 96;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Each row is the whole function. A check is not a scan. A returned
/// exit is not a SystemExit. One field is not the whole document.
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
        name: "test_check_sarif_structure",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_sarif_structure: check of the corrupt fixture with --format sarif; the document version is 2.1.0, the run has 35 rules whose ids are sorted, there is one result, its ruleId is SL101, its level is error, its finding fingerprint is present, its artifact uri contains no backslash, and the exit is 1; missing stop: all of those together; all of those are one row; one field is not the whole document; the clean-file test is not this pytest; test_check_sarif_clean_file_empty_results is the healthy fixture with an empty results list and exit 0 and is not this corrupt structure",
        ),
    },
    Row {
        name: "test_check_sarif_clean_file_empty_results",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_sarif_clean_file_empty_results: check of the healthy fixture with --format sarif; the results list is empty and the exit is 0; missing stop: both together; both are one row; the empty results list is not the exit; the corrupt structure test is not this pytest; test_check_sarif_structure is the corrupt fixture structure and exit 1 and is not this clean file",
        ),
    },
    Row {
        name: "test_scan_sarif_aggregates_findings",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_sarif_aggregates_findings: the corrupt fixture is copied into a directory and scan --format sarif returns one result whose ruleId is SL101, and the exit is 1; missing stop: the copy, that one SL101 result, and exit 1 together; all three are one row; a check is not this scan; test_check_sarif_structure is a check of the corrupt fixture and is not this scan",
        ),
    },
    Row {
        name: "test_json_and_output_format_mutually_exclusive",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_and_output_format_mutually_exclusive: check of the corrupt fixture with both --json and --format sarif raises SystemExit 2; missing stop: that SystemExit; a returned exit is not a SystemExit; the structure test returns exit 1 and is not this raise; test_check_sarif_structure returns exit 1 and is not this SystemExit",
        ),
    },
    Row {
        name: "test_sarif_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sarif_deterministic: two check --format sarif runs of the corrupt fixture have equal stdout; missing stop: that equality; the function does not assert an exit code; both runs are one row; one run is not this pytest; the structure assertions are not this equality; test_check_sarif_structure asserts the document fields and exit 1 and is not this stdout equality",
        ),
    },
    Row {
        name: "test_sarif_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sarif_content_free: check of the corrupt fixture with --format sarif, and the dumped document contains none of the three words payload, tool_calls, and arguments; missing stop: all three absences together; all three absences are one row; one word is not this pytest; the function does not assert the version, the rule count, or the exit; the structure test is not this pytest; test_check_sarif_structure asserts the version, the rule count, and the exit and is not these three absences",
        ),
    },
    Row {
        name: "test_build_sarif_level_mapping",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_build_sarif_level_mapping: build_sarif of an empty finding list with tool version 0.0.0-test; SL003 maps to warning, SL101 maps to error, and every level is one of error, warning, or note; missing stop: all three together; all three are one row; one mapping is not this pytest; a CLI check is not this library call; the 35-rule CLI test is not this level map; test_check_sarif_structure is the 35-rule CLI check and is not this level map",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_check_sarif_structure",
    "test_check_sarif_clean_file_empty_results",
    "test_scan_sarif_aggregates_findings",
    "test_json_and_output_format_mutually_exclusive",
    "test_sarif_deterministic",
    "test_sarif_content_free",
    "test_build_sarif_level_mapping",
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
fn pinned_test_sarif_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 96);
}

#[test]
fn pinned_test_sarif_row_count_equals_seven() {
    assert_eq!(ROWS.len(), 7);
    assert_eq!(PINNED_TEST_COUNT, 7);
}

#[test]
fn every_pinned_test_sarif_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 7);
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
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        if !id_set.contains(vector_id) {
            continue;
        }
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
