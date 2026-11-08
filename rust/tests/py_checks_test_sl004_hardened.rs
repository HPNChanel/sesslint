//! Dispositions for the 10 `def test_` functions in pinned
//! `tests/checks/test_sl004_hardened.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The card names 10 tests;
//! the pin has 10. This integration test crate links `sesslint-rust-workspace`,
//! whose library exports [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.graph/vectors.json`,
//! `repair.recipes_conservative/vectors.json`,
//! `repair.preconditions/vectors.json`, `repair.planner/vectors.json`, or
//! `repair.executor/vectors.json` whose construct is the same function and
//! the same success or failure mode as that entire pinned test. One example
//! inside a sweep, a different event id, or a shared reason string is not
//! coverage. A Rust seam while the pin test succeeds is not coverage.
//! `not_applicable` records a `same_compaction_segment`,
//! `is_qualifying_parent_candidate`, `check_missing_parent`,
//! `find_qualifying_parent_candidates`, `plan`, `unique_parent_candidate`,
//! `apply_proven_unique_parent_restore`, or `execute` check this package
//! cannot reach without a `Cargo.toml` change, or a mode no vector records
//! as the full pin outcome. Pinned `same_compaction_segment` calls pass
//! event objects; `checks.graph` vectors pass seq endpoints, and the
//! event-object index path is the `PYTHON_EVENT_INDEX_UNREPRESENTABLE` gap.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 10;
const GRAPH_VECTOR_COUNT: usize = 20;
const GRAPH_VECTORS_REL: &str = "parity/vectors/checks.graph/vectors.json";
const RECIPES_VECTORS_REL: &str = "parity/vectors/repair.recipes_conservative/vectors.json";
const PRECONDITIONS_VECTORS_REL: &str = "parity/vectors/repair.preconditions/vectors.json";
const PLANNER_VECTORS_REL: &str = "parity/vectors/repair.planner/vectors.json";
const EXECUTOR_VECTORS_REL: &str = "parity/vectors/repair.executor/vectors.json";

/// `covered` names a vector id. `not_applicable` records behavior this package
/// cannot reach without a `Cargo.toml` change, or a mode absent from the
/// vector files named above.
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

/// Top-level `checks.graph` ids. Nested event `"id"` fields are indented further.
const GRAPH_VECTORS: &[(&str, &str)] = &[
    ("module_dunder_all", "module_dunder_all"),
    ("module_constants_max_limits", "module_constants"),
    (
        "compute_graph_fingerprint_empty_ids",
        "compute_graph_fingerprint",
    ),
    (
        "compute_graph_fingerprint_duplicate_ids_either_order",
        "compute_graph_fingerprint",
    ),
    (
        "compute_graph_fingerprint_duplicate_ids_reversed",
        "compute_graph_fingerprint",
    ),
    (
        "compute_graph_fingerprint_bool_true_vs_str_true",
        "compute_graph_fingerprint",
    ),
    (
        "is_qualifying_parent_candidate_exact_id",
        "is_qualifying_parent_candidate",
    ),
    (
        "is_qualifying_parent_candidate_prefix_not_full_match",
        "is_qualifying_parent_candidate",
    ),
    (
        "find_qualifying_parent_candidates_no_earlier_match",
        "find_qualifying_parent_candidates",
    ),
    (
        "find_qualifying_parent_candidates_one_earlier_exact",
        "find_qualifying_parent_candidates",
    ),
    (
        "find_qualifying_parent_candidates_two_earlier_exact",
        "find_qualifying_parent_candidates",
    ),
    (
        "same_compaction_segment_boundary_between_false",
        "same_compaction_segment",
    ),
    (
        "same_compaction_segment_adjacent_seq_true",
        "same_compaction_segment",
    ),
    (
        "check_missing_parent_present_parent",
        "check_missing_parent",
    ),
    ("check_missing_parent_later_parent", "check_missing_parent"),
    ("check_missing_parent_self_parent", "check_missing_parent"),
    ("check_cycles_none", "check_cycles"),
    ("check_components_one_component", "check_components"),
    ("check_heads_single_tip", "check_heads"),
    ("check_graph_clean_chain", "check_graph"),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_same_compaction_segment_zero_boundaries",
        disposition: Disposition::NotApplicable(
            "same_compaction_segment is true for messages at seq 0, 1, and 2 with no compaction boundary, once on event objects and once on indices 0 and 2; same_compaction_segment_adjacent_seq_true compares seq endpoints 5 and 6 beside a boundary at seq 5, and the event-object call is the PYTHON_EVENT_INDEX_UNREPRESENTABLE gap",
        ),
    },
    Row {
        name: "test_same_compaction_segment_strictly_between",
        disposition: Disposition::NotApplicable(
            "a compaction_boundary at seq 1 makes same_compaction_segment false for the span from seq 0 to seq 2, on both event objects and indices, while the two adjacent event-object pairs stay true; same_compaction_segment_boundary_between_false is only the false half for seq endpoints 0 and 3",
        ),
    },
    Row {
        name: "test_same_compaction_segment_boundary_at_endpoints",
        disposition: Disposition::NotApplicable(
            "compaction boundaries sitting on seq 0 and seq 2 leave both adjacent event-object pairs in one segment; same_compaction_segment_adjacent_seq_true is one boundary at seq 5 beside a message at seq 6, and those event-object calls are the PYTHON_EVENT_INDEX_UNREPRESENTABLE gap",
        ),
    },
    Row {
        name: "test_same_compaction_segment_dict_events_and_indices",
        disposition: Disposition::NotApplicable(
            "three dict events omit seq, so indices 0 and 2 are different segments and the adjacent index pairs are the same segment; checks.graph same_compaction_segment endpoints are seq values, and no vector records that three-outcome missing-seq sweep",
        ),
    },
    Row {
        name: "test_is_qualifying_parent_candidate_rules",
        disposition: Disposition::NotApplicable(
            "one test sweeps exact equality ok on branch main, self_candidate, a prefix no_full_match, cross_branch, and cross_segment; is_qualifying_parent_candidate_exact_id is only the ok case on ids p-par-001 and c-par-002 with null branches, is_qualifying_parent_candidate_prefix_not_full_match is only no_full_match with missing_parent_id null, and checks.graph records no self_candidate, cross_branch, or cross_segment reason",
        ),
    },
    Row {
        name: "test_adversarial_decoy_prefix_collision",
        disposition: Disposition::NotApplicable(
            "check_missing_parent returns one SL004 MANUAL finding with reason no_full_match, candidate_count 0, and no rejected decoys, plan blocks it as repairability-manual, unique_parent_candidate is false, and apply_proven_unique_parent_restore raises PreconditionFailed for zero candidates; every check_missing_parent vector has findings_count 0, find_qualifying_parent_candidates_no_earlier_match rejects id x-fqc-000, unique_parent_no_finding has no findings, plan_empty_conservative_success_gap has blocked_count 0, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_adversarial_decoy_cross_branch",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed for cross_branch, unique_parent_candidate is false on an SL004 finding whose reason is cross_branch, and plan blocks that finding as repairability-manual; no apply vector calls apply_proven_unique_parent_restore, checks.graph records no cross_branch reason, unique_parent_no_finding has no findings, unique_parent_orphan is one SL203 event, unique_parent_graph_seam is a gap, and plan_empty_conservative_success_gap has blocked_count 0",
        ),
    },
    Row {
        name: "test_adversarial_decoy_cross_segment",
        disposition: Disposition::NotApplicable(
            "check_missing_parent returns one SL004 MANUAL finding, find_qualifying_parent_candidates returns an empty qualifying list with reason cross_segment, and apply_proven_unique_parent_restore raises PreconditionFailed for cross_segment; check_missing_parent vectors have findings_count 0, checks.graph records no cross_segment reason, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_adversarial_decoy_duplicate_candidates",
        disposition: Disposition::NotApplicable(
            "find_qualifying_parent_candidates returns two qualifying indices and reason ambiguous for missing parent msg-parent-ambig, apply_proven_unique_parent_restore raises PreconditionFailed for ambiguous candidates, and unique_parent_candidate is false; find_qualifying_parent_candidates_two_earlier_exact is that finder shape for id p-fqc-020 only, unique_parent_orphan is one SL203 event, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_exact_match_helper_plan_is_refused_when_source_finding_disagrees",
        disposition: Disposition::NotApplicable(
            "find_qualifying_parent_candidates returns index 0 with reason ok for missing parent msg-parent-exact at target index 1, plan emits one proven-unique-parent-restore step, and execute raises RepairRefused for a plan the current source does not derive, leaving the output and manifest paths absent; find_qualifying_parent_candidates_one_earlier_exact is id p-fqc-010 at target index 2 with rejected id n-fqc-011, plan_empty_conservative_success_gap has step_count 0, execute_fingerprint_import_seam records fingerprint_unavailable and pin_exception PlanTampered, and execute_cap_257 is the 257-step cap",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_same_compaction_segment_zero_boundaries",
    "test_same_compaction_segment_strictly_between",
    "test_same_compaction_segment_boundary_at_endpoints",
    "test_same_compaction_segment_dict_events_and_indices",
    "test_is_qualifying_parent_candidate_rules",
    "test_adversarial_decoy_prefix_collision",
    "test_adversarial_decoy_cross_branch",
    "test_adversarial_decoy_cross_segment",
    "test_adversarial_decoy_duplicate_candidates",
    "test_exact_match_helper_plan_is_refused_when_source_finding_disagrees",
];

const TOP_LEVEL_ID_PREFIX: &str = "\n      \"id\": \"";

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn assert_top_level_catalog(json: &str, label: &str, rows: &[(&str, &str)]) {
    let mut cursor = 0usize;
    for &(id, construct) in rows {
        let marker = format!("{TOP_LEVEL_ID_PREFIX}{id}\"");
        let rel = json[cursor..]
            .find(&marker)
            .unwrap_or_else(|| panic!("{label} is missing top-level id {id}"));
        let start = cursor + rel;
        let after = start + marker.len();
        let next = json[after..]
            .find(TOP_LEVEL_ID_PREFIX)
            .map(|offset| after + offset)
            .unwrap_or(json.len());
        let slice = &json[start..next];
        let type_key = "\"type\": \"";
        let type_at = slice
            .find(type_key)
            .unwrap_or_else(|| panic!("{label} {id} is missing a construct type"));
        let tail = &slice[type_at + type_key.len()..];
        let end = tail.find('"').expect("construct type is a JSON string");
        assert_eq!(&tail[..end], construct, "{label} {id}");
        cursor = after;
    }
    assert_eq!(
        json.matches(TOP_LEVEL_ID_PREFIX).count(),
        rows.len(),
        "{label} top-level id count"
    );
}

fn read_vectors(rel: &str, module: &str) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(json.contains(&format!("\"module\": \"{module}\"")));
    json
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("{TOP_LEVEL_ID_PREFIX}{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("vectors.json is missing top-level id {id}"));
    let after = start + marker.len();
    let end = json[after..]
        .find(TOP_LEVEL_ID_PREFIX)
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
fn every_pinned_sl004_hardened_test_has_one_disposition() {
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
fn cited_sl004_hardened_vectors_are_present() {
    let graph = read_vectors(GRAPH_VECTORS_REL, "sesslint.checks.graph");
    assert_top_level_catalog(&graph, "checks.graph", GRAPH_VECTORS);
    for absent in ["cross_branch", "cross_segment", "self_candidate"] {
        assert!(
            !graph.contains(absent),
            "checks.graph unexpectedly records {absent}"
        );
    }
    let exact = vector_slice(&graph, "is_qualifying_parent_candidate_exact_id");
    assert!(exact.contains("\"v\": \"p-par-001\""));
    assert!(exact.contains("\"v\": \"c-par-002\""));
    assert!(exact.contains("\"reason\": \"ok\""));
    let prefix = vector_slice(
        &graph,
        "is_qualifying_parent_candidate_prefix_not_full_match",
    );
    assert!(prefix.contains("\"v\": \"p-pre-001x\""));
    assert!(prefix.contains("\"missing_parent_id\": null"));
    assert!(prefix.contains("\"reason\": \"no_full_match\""));
    let no_earlier = vector_slice(&graph, "find_qualifying_parent_candidates_no_earlier_match");
    assert!(no_earlier.contains("\"v\": \"x-fqc-000\""));
    assert!(no_earlier.contains("\"reason\": \"no_full_match\""));
    let one_earlier = vector_slice(
        &graph,
        "find_qualifying_parent_candidates_one_earlier_exact",
    );
    assert!(one_earlier.contains("\"missing_parent_id\": \"p-fqc-010\""));
    assert!(one_earlier.contains("\"target_idx\": 2"));
    assert!(one_earlier.contains("\"v\": \"n-fqc-011\""));
    assert!(one_earlier.contains("\"reason\": \"ok\""));
    assert!(!one_earlier.contains("msg-parent-exact"));
    let two_earlier = vector_slice(
        &graph,
        "find_qualifying_parent_candidates_two_earlier_exact",
    );
    assert!(two_earlier.contains("\"missing_parent_id\": \"p-fqc-020\""));
    assert!(two_earlier.contains("\"reason\": \"ambiguous\""));
    assert!(!two_earlier.contains("msg-parent-ambig"));
    for id in [
        "same_compaction_segment_boundary_between_false",
        "same_compaction_segment_adjacent_seq_true",
    ] {
        assert!(
            vector_slice(&graph, id).contains("\"kind\": \"seq\""),
            "{id} endpoints are seq values"
        );
    }
    let between = vector_slice(&graph, "same_compaction_segment_boundary_between_false");
    assert!(between.contains("\"v\": 0"));
    assert!(between.contains("\"v\": 3"));
    assert!(between.contains("\"same\": false"));
    let adjacent = vector_slice(&graph, "same_compaction_segment_adjacent_seq_true");
    assert!(adjacent.contains("\"v\": 5"));
    assert!(adjacent.contains("\"v\": 6"));
    assert!(adjacent.contains("\"same\": true"));
    for id in [
        "check_missing_parent_present_parent",
        "check_missing_parent_later_parent",
        "check_missing_parent_self_parent",
    ] {
        assert!(
            vector_slice(&graph, id).contains("\"findings_count\": 0"),
            "{id} is a clean check_missing_parent result"
        );
    }

    let recipes = read_vectors(RECIPES_VECTORS_REL, "sesslint.repair.recipes_conservative");
    let exports = vector_slice(&recipes, "module_all_export_order");
    assert!(exports.contains("apply_proven_unique_parent_restore"));
    assert!(
        !recipes.contains("\"fn\": \"apply_proven_unique_parent_restore\""),
        "recipes_conservative apply vectors must not be treated as the parent-restore refusals"
    );

    let preconditions = read_vectors(PRECONDITIONS_VECTORS_REL, "sesslint.repair.preconditions");
    for id in [
        "unique_parent_no_finding",
        "unique_parent_orphan",
        "unique_parent_graph_seam",
    ] {
        let slice = vector_slice(&preconditions, id);
        assert!(slice.contains("\"predicate\": \"unique_parent_candidate\""));
    }
    assert!(vector_slice(&preconditions, "unique_parent_no_finding").contains("\"value\": false"));
    assert!(vector_slice(&preconditions, "unique_parent_no_finding").contains("\"findings\": []"));
    assert!(vector_slice(&preconditions, "unique_parent_orphan").contains("\"code\": \"SL203\""));
    let seam = vector_slice(&preconditions, "unique_parent_graph_seam");
    assert!(seam.contains("\"mode\": \"gap\""));
    assert!(seam.contains("\"gap_id\": \"GAP-preconditions-parent-candidates\""));

    let planner = read_vectors(PLANNER_VECTORS_REL, "sesslint.repair.planner");
    let plan_empty = vector_slice(&planner, "plan_empty_conservative_success_gap");
    assert!(plan_empty.contains("\"step_count\": 0"));
    assert!(plan_empty.contains("\"blocked_count\": 0"));
    assert!(
        !planner.contains("repairability-manual"),
        "planner vectors do not record a repairability-manual block"
    );
    assert!(
        !planner.contains("SL004"),
        "planner vectors do not record an SL004 plan"
    );

    let executor = read_vectors(EXECUTOR_VECTORS_REL, "sesslint.repair.executor");
    let fingerprint_seam = vector_slice(&executor, "execute_fingerprint_import_seam");
    assert!(fingerprint_seam.contains("\"type\": \"execute_fingerprint_gap\""));
    assert!(fingerprint_seam.contains("\"mode\": \"fingerprint_unavailable\""));
    assert!(fingerprint_seam.contains("\"pin_exception\": \"PlanTampered\""));
    assert!(vector_slice(&executor, "execute_cap_257").contains("\"type\": \"execute_cap\""));
    assert!(vector_slice(&executor, "execute_cap_257").contains("257"));

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let slice = if graph.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&graph, vector_id)
        } else if recipes.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&recipes, vector_id)
        } else if preconditions.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&preconditions, vector_id)
        } else if planner.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&planner, vector_id)
        } else {
            vector_slice(&executor, vector_id)
        };
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
