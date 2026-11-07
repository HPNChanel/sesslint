//! Dispositions for the 3 `def test_` functions in pinned
//! `tests/fuzz/test_fuzz_graph.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (129 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.graph/vectors.json` whose construct is the
//! same function and the same success or failure mode as that entire pinned test.
//! One generated parent topology is not coverage. A two-node clean chain is not a
//! 500-node recursion contract. `not_applicable` records a Hypothesis property sweep
//! this package cannot run without proptest, a mode no vector records, or behavior
//! omitted from parity vectors.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 3;
const GRAPH_VECTOR_COUNT: usize = 20;
const VECTORS_REL: &str = "parity/vectors/checks.graph/vectors.json";

/// `covered` names a vector id in `checks.graph/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file.
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

/// Vector id, construct type, and whether `expected.findings_count` must be zero.
const GRAPH_VECTORS: &[(&str, &str, bool)] = &[
    ("module_dunder_all", "module_dunder_all", false),
    ("module_constants_max_limits", "module_constants", false),
    (
        "compute_graph_fingerprint_empty_ids",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "compute_graph_fingerprint_duplicate_ids_either_order",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "compute_graph_fingerprint_duplicate_ids_reversed",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "compute_graph_fingerprint_bool_true_vs_str_true",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "is_qualifying_parent_candidate_exact_id",
        "is_qualifying_parent_candidate",
        false,
    ),
    (
        "is_qualifying_parent_candidate_prefix_not_full_match",
        "is_qualifying_parent_candidate",
        false,
    ),
    (
        "find_qualifying_parent_candidates_no_earlier_match",
        "find_qualifying_parent_candidates",
        false,
    ),
    (
        "find_qualifying_parent_candidates_one_earlier_exact",
        "find_qualifying_parent_candidates",
        false,
    ),
    (
        "find_qualifying_parent_candidates_two_earlier_exact",
        "find_qualifying_parent_candidates",
        false,
    ),
    (
        "same_compaction_segment_boundary_between_false",
        "same_compaction_segment",
        false,
    ),
    (
        "same_compaction_segment_adjacent_seq_true",
        "same_compaction_segment",
        false,
    ),
    ("check_missing_parent_present_parent", "check_missing_parent", true),
    ("check_missing_parent_later_parent", "check_missing_parent", true),
    ("check_missing_parent_self_parent", "check_missing_parent", true),
    ("check_cycles_none", "check_cycles", true),
    ("check_components_one_component", "check_components", true),
    ("check_heads_single_tip", "check_heads", true),
    ("check_graph_clean_chain", "check_graph", true),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_fuzz_arbitrary_parent_topologies",
        disposition: Disposition::NotApplicable(
            "Hypothesis @given over node_count 5..60 and parent index lists, check_graph termination under one second, SL004..SL007 finding kinds, and fingerprint determinism; no checks.graph vector is that max_examples property sweep",
        ),
    },
    Row {
        name: "test_deep_parent_chain_recursion_resistance",
        disposition: Disposition::NotApplicable(
            "500-node linear parent chain through check_graph with elapsed under one second and zero SL004 or SL005 findings; check_graph_clean_chain is two events without that depth or perf contract",
        ),
    },
    Row {
        name: "test_tight_and_extended_cycles",
        disposition: Disposition::NotApplicable(
            "check_cycles on self-loop, 2-cycle, and 10-cycle topologies each expecting SL005; parity vectors omit cycle findings and check_cycles_none is acyclic only",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_fuzz_arbitrary_parent_topologies",
    "test_deep_parent_chain_recursion_resistance",
    "test_tight_and_extended_cycles",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn module_vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\n      \"id\": \"";
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
        .unwrap_or_else(|| panic!("checks.graph vectors.json is missing id {id}"));
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
fn every_pinned_fuzz_graph_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(GRAPH_VECTORS.len(), GRAPH_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_graph_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "checks.graph vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.graph\""));

    let ids = module_vector_ids(&json);
    let expected: Vec<&str> = GRAPH_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, zero_findings) in GRAPH_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        if zero_findings {
            assert!(
                slice.contains("\"findings_count\": 0"),
                "{id} is missing zero findings_count"
            );
        }
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
