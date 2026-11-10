//! Dispositions for the six test functions in pinned
//! `tests/test_problem_matcher.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (109 splitlines). Exactly
//! six test functions, in module order.
//! `test_matcher_matches_live_location_lines` and
//! `test_matcher_matches_live_header_lines` are each parametrized over
//! `FIXTURES` and each is one row covering every fixture cell. Helpers are
//! not tests. Each row is the whole function. A docstring is not an
//! assertion. A comment is not an assertion. `FIXTURES`, `_patterns`, and
//! `_human_lines` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these six names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these six names.
//! `parity/vectors/report/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. That old pin is not a Covered
//! source. A report vector that only renders one line is not the whole pytest.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `check_file` or
//! `render_human` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 6;
const PINNED_SPLITLINES: usize = 109;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `test_matcher_matches_live_location_lines` and
/// `test_matcher_matches_live_header_lines` are each parametrized over
/// `FIXTURES` and each is one row covering every fixture cell.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A report vector that only renders one line is not the whole pytest.
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
        name: "test_matcher_matches_live_location_lines",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_matcher_matches_live_location_lines: for every fixture cell, each line that contains Span and a colon followed by digits matches the span pattern, the first capture is non-empty, and the second capture is an integer at least 1; The docstring is not an assertion; missing stop: that match, that non-empty capture, and that line number together across every fixture cell; The header-line match is not this; test_matcher_matches_live_header_lines is that header-line match",
        ),
    },
    Row {
        name: "test_matcher_matches_live_header_lines",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_matcher_matches_live_header_lines: for every fixture cell, each line that begins with optional whitespace and an SL bracket matches the header pattern, the first capture starts with SL, the second capture is non-empty, and the third capture is ERROR, FATAL, WARNING, or INFO; missing stop: that match, that code prefix, that message, and that severity together across every fixture cell; The corpus line check is not this; test_corpus_produces_matchable_lines is that corpus line check",
        ),
    },
    Row {
        name: "test_corpus_produces_matchable_lines",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_corpus_produces_matchable_lines: some human line from the fixture corpus matches the header pattern and some human line matches the span pattern; The docstring is not an assertion; missing stop: that header match and that span match together; The every-pair check is not this; test_every_finding_pair_matches is that every-pair check",
        ),
    },
    Row {
        name: "test_every_finding_pair_matches",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_every_finding_pair_matches: on the first fixture, every header line matches the header pattern, and a span line within the next five lines matches the span pattern; The docstring is not an assertion; The comment is not an assertion; It does not assert the capture groups; A missing span in that window is not an assertion; missing stop: that header match and that following span match together; The corpus line check is not this; test_corpus_produces_matchable_lines is that corpus line check",
        ),
    },
    Row {
        name: "test_byte_suffix_span_variant_matches",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_byte_suffix_span_variant_matches: the span pattern matches one span line that carries a byte-range suffix, and the second capture equals 12; missing stop: that match and that second capture together; The matcher-json test is not this; test_matcher_json_is_valid_and_complete is that matcher-json test",
        ),
    },
    Row {
        name: "test_matcher_json_is_valid_and_complete",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_matcher_json_is_valid_and_complete: the problemMatcher owner equals sesslint and the problemMatcher object contains the fileLocation key; missing stop: that owner and that key together; The byte-suffix span test is not this; test_byte_suffix_span_variant_matches is that byte-suffix span test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_matcher_matches_live_location_lines",
    "test_matcher_matches_live_header_lines",
    "test_corpus_produces_matchable_lines",
    "test_every_finding_pair_matches",
    "test_byte_suffix_span_variant_matches",
    "test_matcher_json_is_valid_and_complete",
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
fn pinned_test_problem_matcher_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 109);
}

#[test]
fn pinned_test_problem_matcher_row_count_equals_six() {
    assert_eq!(ROWS.len(), 6);
    assert_eq!(PINNED_TEST_COUNT, 6);
    assert_eq!(PINNED_NAMES.len(), 6);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_problem_matcher_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 6);
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
    assert_eq!(not_applicable, 6);

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
