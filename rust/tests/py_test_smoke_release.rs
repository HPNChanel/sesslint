//! Dispositions for the 3 `def test_` functions in pinned `tests/test_smoke_release.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (86 splitlines). This
//! integration test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 3;
const CLI_VECTOR_COUNT: usize = 33;
const COVERED_COUNT: usize = 0;
const NOT_APPLICABLE_COUNT: usize = 3;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const DISPATCH_GAP: &str = "GAP-cli-init-dispatch-runtime: Python _dispatch runs build_context, preflight, and command.run; Rust stops at sesslint.config.load_config and registry Command::run seams.";

/// `covered` names a vector id in `cli/vectors.json` whose construct is the same
/// function and the same success or failure mode as that entire pinned test.
/// `not_applicable` is a mode no single committed vector records (`version_label`
/// and removed-command hints are not `main(['version', '--json'])`; check error
/// vectors are not a healthy check or a mixed-directory scan).
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
        name: "test_smoke_version_json",
        disposition: Disposition::NotApplicable(
            "main version --json exit 0 with cli, schema_manifest, schema_report, schema_session, adapters, and profiles; version_label records human text only",
        ),
    },
    Row {
        name: "test_smoke_healthy_check",
        disposition: Disposition::NotApplicable(
            "main check --json on a healthy fixture with exit 0 and zero findings; no cli vector records that end-to-end check dispatch",
        ),
    },
    Row {
        name: "test_smoke_mixed_directory_scan",
        disposition: Disposition::NotApplicable(
            "main check --json on a mixed directory with exit 1 and scan-report totals; no cli vector records a recursive mixed-directory scan",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_smoke_version_json",
    "test_smoke_healthy_check",
    "test_smoke_mixed_directory_scan",
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
fn every_pinned_smoke_release_test_has_one_disposition() {
    assert_eq!(ROWS.len(), 3);
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
    assert!(json.contains(DISPATCH_GAP));

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
