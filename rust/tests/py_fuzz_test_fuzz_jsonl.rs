//! Dispositions for the 4 `def test_` functions in pinned
//! `tests/fuzz/test_fuzz_jsonl.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (113 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! The pinned module is Hypothesis fuzz property tests over `sesslint.io`
//! `read_header` and `iter_events` on arbitrary byte streams and random UTF-8
//! line lists, plus a seed-corpus playback over `fixtures/fuzz/corpus/*.jsonl`.
//! `covered` names a vector id whose construct is the same function and the
//! same success or failure mode as that entire pinned test. `not_applicable`
//! records a property sweep or corpus glob no vector has. This package has no
//! proptest and cannot run those generated sweeps.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 4;
const IO_VECTOR_COUNT: usize = 35;
const VECTORS_REL: &str = "parity/vectors/io/vectors.json";

/// `covered` names a vector id in `io/vectors.json`. `not_applicable` records
/// behavior this package cannot reach without a `Cargo.toml` change, or a mode
/// absent from that vector file.
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
        name: "test_seed_corpus_playback",
        disposition: Disposition::NotApplicable(
            "glob every fixtures/fuzz/corpus/*.jsonl and list(iter_events(path)) expecting only SessionEvent or Finding; io vectors are single-path or stream constructs, not that entire seed-corpus playback",
        ),
    },
    Row {
        name: "test_fuzz_read_header_arbitrary_bytes",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given(st.binary(max_size=32768)) max_examples=50 totality over arbitrary byte streams with fail-closed SesslintError; no io vector is that generated sweep",
        ),
    },
    Row {
        name: "test_fuzz_iter_events_arbitrary_bytes",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given(st.binary(max_size=32768)) with ReaderLimits(4096, 20, 65536) and dual-stream determinism on SessionEvent ids or Finding code and fingerprint; no io vector is that generated sweep",
        ),
    },
    Row {
        name: "test_fuzz_iter_events_random_lines",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given(st.lists of text or json.dumps(dict)) max_examples=40 over UTF-8 line lists with Finding codes SL001, SL002, or SL302; no io vector is that generated sweep",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_seed_corpus_playback",
    "test_fuzz_read_header_arbitrary_bytes",
    "test_fuzz_iter_events_arbitrary_bytes",
    "test_fuzz_iter_events_random_lines",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn first_top_level_id(chunk: &str) -> Option<&str> {
    let needle = "      \"id\": \"";
    let tail = chunk.strip_prefix(needle).or_else(|| {
        let pos = chunk.find(needle)?;
        Some(&chunk[pos + needle.len()..])
    })?;
    let end = tail.find('"')?;
    Some(&tail[..end])
}

fn top_level_vector_ids(json: &str) -> Vec<&str> {
    let body = json
        .split_once("\"vectors\": [")
        .expect("io vectors.json has a vectors array")
        .1;
    body.split("\n    {")
        .filter_map(first_top_level_id)
        .collect()
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("io vectors.json is missing id {id}"));
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
fn every_pinned_fuzz_jsonl_test_has_one_disposition() {
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
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_io_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "io vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.io\""));

    let ids = top_level_vector_ids(&json);
    assert_eq!(ids.len(), IO_VECTOR_COUNT);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();

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
