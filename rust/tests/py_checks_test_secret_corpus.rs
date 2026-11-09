//! Dispositions for the 3 `def test_` functions in pinned
//! `tests/checks/test_secret_corpus.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (72 splitlines).
//! `test_secret_corpus_exact_labels_and_privacy` is parametrized over the full
//! consolidation corpus `ROWS` loaded from fixtures; each disposition row is the
//! entire function, not one corpus parameter row. One `secret_family` label match
//! or one canary absence check is not the full parametrized matrix sweep. This
//! integration test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 3;
const PINNED_SPLITLINES: usize = 72;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. `not_applicable` names the missing stop.
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
        name: "test_secret_corpus_exact_labels_and_privacy",
        disposition: Disposition::NotApplicable(
            "no cli vector is SecretScanTracker feed on every consolidation corpus row asserting sorted secret_family equals expected, monkeypatch emptying _FAMILY_LITERALS and _GATE_TOKEN_TAIL leaves findings unchanged, and api.check_bytes canonical report JSON plus repr exclude each row canaries; hygiene SecretScanTracker api.check_bytes and pytest monkeypatch are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_corpus_covers_every_family_and_label_class",
        disposition: Disposition::NotApplicable(
            "no cli vector loads the consolidation corpus and asserts row families equal SECRET_FAMILY_IDS, each family has categories positive near-miss placeholder truncated malformed, and positive and malformed rows have expected equal to that family only; SECRET_FAMILY_IDS and corpus row metadata are not exercised by sesslint.cli vectors",
        ),
    },
    Row {
        name: "test_secret_at_window_boundary_and_output_caps",
        disposition: Disposition::NotApplicable(
            "no cli vector is SecretScanTracker feed repeated MAX_SECRET_FINDINGS_PER_FILE plus two times on a window-boundary padded blob asserting findings length at most MAX, overflow evidence on at least one finding, and credential-shaped material absent from findings repr; SecretScanTracker feed and hygiene caps are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_secret_corpus_exact_labels_and_privacy",
    "test_corpus_covers_every_family_and_label_class",
    "test_secret_at_window_boundary_and_output_caps",
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
fn pinned_secret_corpus_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 72);
}

#[test]
fn pinned_secret_corpus_row_count_equals_three() {
    assert_eq!(ROWS.len(), 3);
    assert_eq!(PINNED_TEST_COUNT, 3);
}

#[test]
fn every_pinned_secret_corpus_test_has_one_disposition() {
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
