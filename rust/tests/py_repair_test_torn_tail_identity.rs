//! Dispositions for the two `def test_` functions in pinned
//! `tests/repair/test_torn_tail_identity.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (60 splitlines). The module
//! documents B37: a torn final line may salvage a record id from incomplete
//! bytes, but a complete event carrying that same id is a distinct record and
//! must be kept when conservative torn-terminal discard runs. Helpers
//! including `_msg` are not tests. This integration test crate links
//! `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`] only. It
//! cannot call `sesslint.api.plan_repair` or `sesslint.api.repair` without a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 2;
const PINNED_SPLITLINES: usize = 60;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One recipe step is not the whole pytest. `not_applicable` names the
/// missing stop.
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
        name: "test_canonical_torn_tail_keeps_event_with_same_id",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_torn_tail_keeps_event_with_same_id building tmp_path session.jsonl from synthesized canonical session header plus three helper-built message lines then appending torn terminal bytes that reopen a record sharing the last complete event id without finishing decode api.plan_repair asserting plan steps are torn-terminal-record-discard with target_index None then seq-renumber with target_index None api.repair to out.jsonl asserting manifest is not None manifest declared_loss is the empty tuple and repaired bytes equal the complete session without the torn suffix; conservative torn-terminal-record-discard must not drop the intact event that shares the salvaged torn id; one recipe step or cli sl002 repair success is not that entire integration row; api.plan_repair and api.repair are not callable from this package without a Cargo.toml change; sesslint.cli vectors record parser hints exit constants and removed-flag probes only",
        ),
    },
    Row {
        name: "test_vendor_torn_tail_keeps_line_with_same_id",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_vendor_torn_tail_keeps_line_with_same_id reading fixtures claude_code basic.jsonl normalizing CRLF to LF parsing json from the final complete line for its id writing src as complete bytes plus torn vendor-prefix bytes reusing that id api.repair to out.jsonl asserting manifest is not None and output bytes equal the normalized complete fixture; vendor torn tail identity repair is not a cli vector; api.repair is not callable from this package without a Cargo.toml change; sesslint.cli vectors record parser hints exit constants and removed-flag probes only",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_canonical_torn_tail_keeps_event_with_same_id",
    "test_vendor_torn_tail_keeps_line_with_same_id",
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
fn pinned_torn_tail_identity_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 60);
}

#[test]
fn pinned_torn_tail_identity_row_count_equals_two() {
    assert_eq!(ROWS.len(), 2);
    assert_eq!(PINNED_TEST_COUNT, 2);
}

#[test]
fn every_pinned_torn_tail_identity_test_has_one_disposition() {
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
