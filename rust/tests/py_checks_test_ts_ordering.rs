//! Dispositions for the 12 column-0 `def test_` functions in pinned
//! `tests/checks/test_ts_ordering.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (201 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `check_ordering`, `run_all_checks`,
//! `load_canonical`, or `get_profile`.
//!
//! A column-0 scan finds all 12 tests. None are indented. Each of those names
//! has one disposition.
//!
//! `covered` names every id in `checks.ordering/vectors.json` whose
//! `ordering_events` constructs together are the same function and the same
//! success or failure as that entire pinned test. One example inside a
//! multi-assert sweep, or a different input, is not coverage. `not_applicable`
//! records a call this package cannot reach without a `Cargo.toml` change, or
//! a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 12;
const ORDERING_VECTOR_COUNT: usize = 9;
const VECTORS_REL: &str = "parity/vectors/checks.ordering/vectors.json";

/// `covered` names every vector id in `checks.ordering/vectors.json` that
/// together match one entire pinned test. `not_applicable` records behavior
/// this package cannot reach without a `Cargo.toml` change outside the owned
/// path, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
    Covered {
        vector_ids: &'static [&'static str],
        needles: &'static [&'static [&'static str]],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

/// Vector id, construct type, and whether `expected.ordering_error` is set.
/// Silent rows are `ordering_events` successes with `check_findings_len` 0.
const ORDERING_VECTORS: &[(&str, &str, bool)] = &[
    ("no_parent_id_silent", "ordering_events", false),
    ("missing_parent_id_silent", "ordering_events", false),
    ("duplicate_parent_id_silent", "ordering_events", false),
    ("epoch_sentinel_child_silent", "ordering_events", false),
    ("epoch_sentinel_parent_silent", "ordering_events", false),
    (
        "default_skew_two_second_edge_silent",
        "ordering_events",
        false,
    ),
    ("unparseable_ts_child_silent", "ordering_events", false),
    ("unparseable_ts_parent_silent", "ordering_events", false),
    ("negative_skew_error", "ordering_events", true),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_sl008_fixture_single_regression",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/checks/sl008_ts_regression.json then check_ordering returns one SL008 on evt-3 whose parent is evt-2, ts_delta_ms is -3000, child_index is 2, and parent_index is 1; negative_skew_error is timestamp_skew_ms -1 on evt-par-ord-p4 and evt-par-ord-c4 and yields an argument error, and no ordering_events vector records that fixture or an SL008 finding",
        ),
    },
    Row {
        name: "test_equal_timestamps_allowed",
        disposition: Disposition::NotApplicable(
            "check_ordering of a and child b, both at 2026-01-01T00:00:00Z, returns []; no ordering_events vector uses equal timestamps, and default_skew_two_second_edge_silent is a two-second regression on evt-par-ord-p2 and evt-par-ord-c2",
        ),
    },
    Row {
        name: "test_fractional_second_regression_detected",
        disposition: Disposition::NotApplicable(
            "check_ordering of a at 2026-01-01T00:00:00.500Z and b at 2026-01-01T00:00:00.250Z returns [] and the same events with timestamp_skew_ms 0 return one finding whose ts_delta_ms is -250; that two-assert sweep is not one vector, default_skew_two_second_edge_silent is a different two-second input, and no vector records the skew-0 finding",
        ),
    },
    Row {
        name: "test_forward_positional_reference_no_finding",
        disposition: Disposition::NotApplicable(
            "check_ordering of child at 2026-01-01T00:00:02Z before parent at 2026-01-01T00:00:01Z returns []; no ordering_events vector places the parent later in the event list",
        ),
    },
    Row {
        name: "test_epoch_sentinel_edges_skipped",
        disposition: Disposition::NotApplicable(
            "check_ordering of child b at 1970-01-01T00:00:00Z under parent a at 2026-01-01T00:00:00Z and the swapped parent-sentinel pair both return []; epoch_sentinel_child_silent and epoch_sentinel_parent_silent are different evt-par-ord inputs at 2024 timestamps with actor assistant and timestamp_skew_ms 0",
        ),
    },
    Row {
        name: "test_missing_and_ambiguous_parents_skipped",
        disposition: Disposition::NotApplicable(
            "check_ordering of b with parent ghost at 2025-01-01T00:00:00Z and of duplicate id p with child c at 2026-01-01T00:00:00Z both return []; missing_parent_id_silent and duplicate_parent_id_silent are different evt-par-ord inputs at 2024 timestamps, and no_parent_id_silent is a third input this test does not call",
        ),
    },
    Row {
        name: "test_unparseable_and_naive_ts_skipped",
        disposition: Disposition::NotApplicable(
            "check_ordering of parent a with ts not-a-timestamp and child b at 2001-01-01T00:00:00Z returns [] and a naive child ts 2001-01-01T00:00:00 also returns []; unparseable_ts_parent_silent is a different 2024 child with timestamp_skew_ms 0, unparseable_ts_child_silent puts not-a-timestamp on the child, and no vector records the naive timestamp",
        ),
    },
    Row {
        name: "test_multiple_regressions_deterministic",
        disposition: Disposition::NotApplicable(
            "check_ordering twice with timestamp_skew_ms 0 on a, b, and c returns one finding whose count is 2, record_id is b, and max_delta_ms is 2000, with equal fingerprints; no ordering_events vector records that aggregate finding, and negative_skew_error is a negative skew argument error",
        ),
    },
    Row {
        name: "test_sidechain_interleave_no_finding",
        disposition: Disposition::NotApplicable(
            "check_ordering of a1, b1 at 2026-01-01T00:00:05Z, and a2 at 2026-01-01T00:00:01Z returns []; no ordering_events vector is that sidechain interleave",
        ),
    },
    Row {
        name: "test_empty_and_single_event",
        disposition: Disposition::NotApplicable(
            "check_ordering of an empty list and of single event a at 2026-01-01T00:00:00Z both return []; no ordering_events vector is empty or a single event, and no_parent_id_silent is two null-parent events",
        ),
    },
    // run_all_checks and profile selection are outside the nine ordering_events vectors.
    Row {
        name: "test_runner_select_ignore_gating",
        disposition: Disposition::NotApplicable(
            "run_all_checks on a at 2026-01-01T00:00:04Z and b at 2026-01-01T00:00:01Z contains SL008, apply_rule_selection of get_profile neutral with ignore SL008 drops it, and select SL008 keeps only that code; run_all_checks and profile selection are not in the nine ordering_events vectors",
        ),
    },
    Row {
        name: "test_evidence_is_content_free",
        disposition: Disposition::NotApplicable(
            "check_ordering of a at 2026-01-01T00:00:04Z and b at 2026-01-01T00:00:01Z returns one finding whose evidence keys stay inside the content-free set; no ordering_events vector records an SL008 evidence object, and negative_skew_error is an argument error",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_sl008_fixture_single_regression",
    "test_equal_timestamps_allowed",
    "test_fractional_second_regression_detected",
    "test_forward_positional_reference_no_finding",
    "test_epoch_sentinel_edges_skipped",
    "test_missing_and_ambiguous_parents_skipped",
    "test_unparseable_and_naive_ts_skipped",
    "test_multiple_regressions_deterministic",
    "test_sidechain_interleave_no_finding",
    "test_empty_and_single_event",
    "test_runner_select_ignore_gating",
    "test_evidence_is_content_free",
];

fn expected_covered_ids(_name: &str) -> Option<&'static [&'static str]> {
    None
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are indented further.
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
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("checks.ordering vectors.json is missing id {id}"));
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
fn every_pinned_checks_test_ts_ordering_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(ORDERING_VECTORS.len(), ORDERING_VECTOR_COUNT);
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
            Disposition::Covered {
                vector_ids,
                needles,
            } => {
                let expected = expected_covered_ids(row.name)
                    .unwrap_or_else(|| panic!("{} is not a fully covered pin test", row.name));
                assert_eq!(vector_ids, expected, "{}", row.name);
                assert!(!vector_ids.is_empty(), "{}", row.name);
                assert_eq!(vector_ids.len(), needles.len(), "{}", row.name);
                for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
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
                        covered_ids.insert(*vector_id),
                        "duplicate covered vector {vector_id}"
                    );
                }
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(
                    expected_covered_ids(row.name).is_none(),
                    "{} is not_applicable but lists covered ids",
                    row.name
                );
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
fn covered_vector_ids_are_present_in_checks_ordering_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "checks.ordering vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.ordering\""));
    assert!(json.contains("\"check_ordering\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = ORDERING_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in ORDERING_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"ordering_error\":"),
            fails,
            "{id} error mode does not match the vector file"
        );
        if !fails {
            assert!(
                slice.contains("\"check_findings_len\": 0"),
                "{id} is missing a silent check_findings_len"
            );
            assert!(
                slice.contains("\"ordering_record_none\": true"),
                "{id} is missing ordering_record_none"
            );
        }
    }

    for row in ROWS {
        let Disposition::Covered {
            vector_ids,
            needles,
        } = row.disposition
        else {
            continue;
        };
        for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
            assert!(
                id_set.contains(vector_id),
                "{} names missing vector {vector_id}",
                row.name
            );
            let slice = vector_slice(&json, vector_id);
            for needle in *needles {
                assert!(
                    slice.contains(needle),
                    "{} vector {vector_id} is missing {needle}",
                    row.name
                );
            }
        }
    }
}
