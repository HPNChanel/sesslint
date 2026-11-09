//! Dispositions for the 6 `def test_` functions in pinned `tests/cli/test_quiet_verbose.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (75 lines). Helper `_run` is
//! not a test. This integration test crate links `sesslint-rust-workspace`,
//! whose library exports [`PACKAGE_NAME`] only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 6;
const COVERED_COUNT: usize = 0;
const NOT_APPLICABLE_COUNT: usize = 6;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` whose construct is the same
/// function and the same success or failure mode as that entire pinned test,
/// including which stream changes and whether `-q` or `-v` is present.
/// `not_applicable` names the check stop no vector records.
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
        name: "test_quiet_drops_valid_banner",
        disposition: Disposition::NotApplicable(
            "CLI main(['check', PATH, '-q']) exit 0 with stdout omitting 'Valid Claude Code session'; stops before check -q Valid banner; removed_command_hint_baseline is a removed-command error with -q, not that stdout success",
        ),
    },
    Row {
        name: "test_valid_banner_without_quiet",
        disposition: Disposition::NotApplicable(
            "CLI main(['check', PATH]) exit 0 with 'Valid Claude Code session' on stdout and no -q; stops before check human Valid banner; no cli vector records that stdout",
        ),
    },
    Row {
        name: "test_quiet_suppresses_stderr_hints",
        disposition: Disposition::NotApplicable(
            "CLI main(['check', PATH, '--jobs', '2']) exit 0 with 'Note: --jobs is ignored' on stderr, then the same argv plus -q exit 0 without it; stops before check -q jobs-hint suppression; no cli vector records that stderr pair",
        ),
    },
    Row {
        name: "test_verbose_emits_debug_lines",
        disposition: Disposition::NotApplicable(
            "CLI main(['check', PATH, '-v']) exit 0 with 'debug:' and 'elapsed' on stderr; stops before check -v debug and elapsed lines; verbose_settings_provenance has debug provenance and no elapsed and no -v",
        ),
    },
    Row {
        name: "test_no_debug_lines_without_verbose",
        disposition: Disposition::NotApplicable(
            "CLI main(['check', PATH]) exit 0 with no 'debug:' on stderr and no -v; stops before check stderr without verbose debug lines; no cli vector records that absence",
        ),
    },
    Row {
        name: "test_json_stdout_bytes_identical_across_verbosity",
        disposition: Disposition::NotApplicable(
            "CLI main(['check', PATH, '--json']) exit 0 stdout bytes identical for no flag, -q, and -v; stops before check --json stdout identity across verbosity; no cli vector records that trio",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_quiet_drops_valid_banner",
    "test_valid_banner_without_quiet",
    "test_quiet_suppresses_stderr_hints",
    "test_verbose_emits_debug_lines",
    "test_no_debug_lines_without_verbose",
    "test_json_stdout_bytes_identical_across_verbosity",
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
fn pinned_quiet_verbose_row_count_equals_six() {
    assert_eq!(ROWS.len(), 6);
    assert_eq!(PINNED_TEST_COUNT, 6);
}

#[test]
fn every_pinned_quiet_verbose_test_has_one_disposition() {
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
    assert!(not_applicable > 0);
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
