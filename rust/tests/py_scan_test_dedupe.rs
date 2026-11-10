//! Disposition for `test_hardlink_deduplication` in pinned `tests/scan/test_dedupe.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (40 splitlines). Exactly one
//! test function, not parametrized. The row is the whole function, including the
//! `pytest.skip` branch when `os.link` raises `OSError` or `NotImplementedError`.
//! On link success the test writes a two-event jsonl to `file_a`, hardlinks
//! `file_b`, calls `check_dir` on the tmp directory with `recursive=True`, then
//! expects exactly two discovered files with one verdict healthy and one skipped
//! whose `skipped_reason` is `duplicate-hardlink`, and `totals.healthy` and
//! `totals.skipped` each equal 1. A healthy scan of one file alone is not this
//! pytest.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `api.check_dir` or perform the
//! hardlink tmp_path setup without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest, including the skip branch when hard links are unavailable.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 1;
const PINNED_SPLITLINES: usize = 40;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest, including the skip branch when hard links are unavailable.
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

const ROWS: &[Row] = &[Row {
    name: "test_hardlink_deduplication",
    disposition: Disposition::NotApplicable(
        "no cli vector is the full test that writes a two-event jsonl to file_a under tmp_path attempts os.link from file_a to file_b and pytest.skips when hard links raise OSError or NotImplementedError otherwise runs check_dir on tmp_path with recursive true expecting ScanReport.files length 2 with verdicts including healthy and skipped one skipped file whose skipped_reason is duplicate-hardlink and report.totals.healthy and report.totals.skipped each 1; sesslint.cli vectors record parser metadata removed-command hints and exit-code constants only and do not record recursive directory scan hardlink deduplication or duplicate-hardlink skip accounting; api.check_dir is not callable from this package without a Cargo.toml change",
    ),
}];

const PINNED_NAMES: &[&str] = &["test_hardlink_deduplication"];

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
fn pinned_dedupe_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 40);
}

#[test]
fn every_pinned_scan_test_dedupe_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 1);
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
