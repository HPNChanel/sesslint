//! Dispositions for the 3 `def test_` functions in pinned
//! `tests/fuzz/test_fuzz_canonical.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (127 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! The pinned module is Hypothesis fuzz property tests over
//! `sesslint.adapters.canonical` `load_canonical` and `dump_canonical`.
//! `covered` names one id in `adapters.canonical/vectors.json` whose construct is
//! the same function and the same success or failure mode as that entire pinned
//! test. One example inside a sweep, a different input string, or a shared
//! field such as `schema_version` is not coverage. `not_applicable` records a
//! property sweep or mode no vector records. This package has no proptest and
//! cannot run those generated sweeps.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 3;
const ADAPTERS_CANONICAL_VECTOR_COUNT: usize = 44;
const VECTORS_REL: &str = "parity/vectors/adapters.canonical/vectors.json";

/// `covered` names a vector id in `adapters.canonical/vectors.json`.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from that
/// vector file.
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

const ROWS: &[Row] = &[
    Row {
        name: "test_fuzz_load_canonical_arbitrary_bytes",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given(st.binary(max_size=32768)) max_examples=50 totality on load_canonical with SesslintError fail-closed, Finding and SessionEvent typing, and dual-call finding fingerprint determinism; no adapters.canonical vector is that generated sweep",
        ),
    },
    Row {
        name: "test_fuzz_load_canonical_arbitrary_json_document",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given recursive JSON documents max_examples=50 over json.dumps UTF-8 bytes through load_canonical with list typing or SesslintError; no adapters.canonical vector is that generated sweep",
        ),
    },
    Row {
        name: "test_fuzz_canonical_valid_event_round_trip",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given fixed SessionEvent-shaped dicts through dump_canonical then load_canonical asserting one event and id seq kind actor ts parent_id equality; no adapters.canonical vector is that generated round-trip property",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_fuzz_load_canonical_arbitrary_bytes",
    "test_fuzz_load_canonical_arbitrary_json_document",
    "test_fuzz_canonical_valid_event_round_trip",
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
        .expect("adapters.canonical vectors.json has a vectors array")
        .1;
    body.split("\n    {")
        .filter_map(first_top_level_id)
        .collect()
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("adapters.canonical vectors.json is missing id {id}"));
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
fn every_pinned_fuzz_canonical_test_has_one_disposition() {
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
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn covered_vector_ids_are_present_in_adapters_canonical_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "adapters.canonical vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.adapters.canonical\""));

    let ids = top_level_vector_ids(&json);
    assert_eq!(ids.len(), ADAPTERS_CANONICAL_VECTOR_COUNT);
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
