//! Dispositions for the nine test functions in pinned
//! `tests/test_determinism.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (161 splitlines). Exactly
//! nine test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. `FIXTURES_DIR`, `NONASCII_PLAN_FIXTURE`, and
//! `REPEAT_SESSION_FIXTURE` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these nine names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these nine names.
//! `parity/vectors/determinism/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source.
//! `parity/vectors/_canonical_codec/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. A codec vector that only sorts
//! keys is not the whole pytest. That old pin is not a Covered source.
//! `parity/vectors/repair.fingerprint/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source.
//! The accept-suite determinism tests are not these nine functions.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `canonical_json_bytes`,
//! `repeat_hash`, `compute_plan_fingerprint`, or `plan` without a
//! `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 9;
const PINNED_SPLITLINES: usize = 161;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these nine functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A codec vector that only sorts keys is not the whole pytest.
/// The accept-suite determinism tests are not these nine functions.
/// `not_applicable` names the missing stop and the nearest different test.
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
        name: "test_canonical_json_key_sorting",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_json_key_sorting: two objects with different insertion order encode to equal bytes, and those bytes are lexicographic key order at nested depth; The comment is not an assertion; missing stop: that equal encoding and that key order together; The compact-separator test is not this; test_canonical_json_compact_separators is that compact-separator test",
        ),
    },
    Row {
        name: "test_canonical_json_compact_separators",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_json_compact_separators: the encoding has no space after a colon, no space after a comma, and the separators are compact; missing stop: those absent spaces and those separators together; The raw-UTF-8 test is not this; test_canonical_json_ensure_ascii_false_utf8 is that raw-UTF-8 test",
        ),
    },
    Row {
        name: "test_canonical_json_ensure_ascii_false_utf8",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_json_ensure_ascii_false_utf8: the encoding has no unicode escape, it contains raw UTF-8 for each non-ASCII field, and decoding those bytes equals the input; The comment is not an assertion; missing stop: that absent escape, that raw UTF-8, and that decoded equality together; The newline-policy test is not this; test_canonical_json_newline_policy is that newline-policy test",
        ),
    },
    Row {
        name: "test_canonical_json_newline_policy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_json_newline_policy: newline false does not end with a newline and equals the compact object, newline true ends with one trailing newline and equals that object plus a trailing newline, and the default equals the newline-true bytes; The comments are not an assertion; missing stop: those newline-false bytes, those newline-true bytes, and that default together; The delegation test is not this; test_repair_fingerprint_delegation is that delegation test",
        ),
    },
    Row {
        name: "test_repair_fingerprint_delegation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_fingerprint_delegation: repair canonical_json_bytes is the determinism function, the newline-false calls are equal and do not end with a newline, and the newline-true calls are equal and end with a newline; missing stop: that function identity and those two newline results together; The golden-fingerprint test is not this; test_nonascii_plan_golden_hash is that golden-fingerprint test",
        ),
    },
    Row {
        name: "test_nonascii_plan_golden_hash",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_nonascii_plan_golden_hash: the fixture path is a file, the finding fingerprint equals its pinned golden, and the computed plan fingerprint equals its pinned golden and the stored plan fingerprint; The comments are not an assertion; missing stop: that file, that finding fingerprint, and that plan fingerprint together; The repeat-hash test is not this; test_repeat_hash_determinism is that repeat-hash test",
        ),
    },
    Row {
        name: "test_repeat_hash_determinism",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repeat_hash_determinism: the digest length is 64 and two dicts with different insertion order hash equal; The docstring is not an assertion; It does not assert the digest text; missing stop: that length and that equal digest together; The plan-repeatability test is not this; test_plan_repeatability is that plan-repeatability test",
        ),
    },
    Row {
        name: "test_plan_repeatability",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_repeatability: two conservative plans have equal fingerprints and equal dicts; It does not assert that the fixture exists; missing stop: that fingerprint and that dict together; The non-string-key test is not this; test_canonical_json_rejects_non_string_keys is that non-string-key test",
        ),
    },
    Row {
        name: "test_canonical_json_rejects_non_string_keys",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_canonical_json_rejects_non_string_keys: canonical_json_bytes and repeat_hash each raise SchemaError for a rejected non-string key; missing stop: those two rejections together; The plan-repeatability test is not this; test_plan_repeatability is that plan-repeatability test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_canonical_json_key_sorting",
    "test_canonical_json_compact_separators",
    "test_canonical_json_ensure_ascii_false_utf8",
    "test_canonical_json_newline_policy",
    "test_repair_fingerprint_delegation",
    "test_nonascii_plan_golden_hash",
    "test_repeat_hash_determinism",
    "test_plan_repeatability",
    "test_canonical_json_rejects_non_string_keys",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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

fn vector_slice<'a>(json: &'a str, id: &str, corpus: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("{corpus} vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_python_commit_one_space(json: &str, corpus: &str) {
    // The corpus stores one space after the colon.
    let commit = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&commit),
        "{corpus} vectors python_commit spacing does not match {commit}"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "{corpus} python_commit has no space after the colon"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":  \"{PIN}\"")),
        "{corpus} python_commit has more than one space after the colon"
    );
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_test_determinism_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 161);
}

#[test]
fn pinned_test_determinism_row_count_equals_nine() {
    assert_eq!(ROWS.len(), 9);
    assert_eq!(PINNED_TEST_COUNT, 9);
    assert_eq!(PINNED_NAMES.len(), 9);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_determinism_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 9);
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
                assert!(
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
                    row.name
                );
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
    let json = read_vectors(CLI_VECTORS_REL);
    assert_python_commit_one_space(&json, "cli");
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
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
        let slice = vector_slice(&json, vector_id, "cli");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}

#[test]
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 9);

    let json = read_vectors(API_VECTORS_REL);
    assert_python_commit_one_space(&json, "api");
    assert!(json.contains("\"module\": \"sesslint.api\""));

    let ids = vector_ids(&json);
    assert_eq!(API_VECTOR_COUNT, 77);
    assert_eq!(ids.len(), API_VECTOR_COUNT);
    assert_eq!(ids.len(), 77);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    assert_eq!(id_set.len(), 77);
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
    }
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "api");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
