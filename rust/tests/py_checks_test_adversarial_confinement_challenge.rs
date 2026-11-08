//! Dispositions for the 41 `def test_` functions in pinned
//! `tests/checks/test_adversarial_confinement_challenge.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (829 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.graph/vectors.json`,
//! `repair.recipes_conservative/vectors.json`,
//! `repair.preconditions/vectors.json`, or `repair.executor/vectors.json`
//! whose construct is the same function and the same success or failure mode
//! as that entire pinned test. One example inside a sweep, a different event
//! id, or a shared reason string is not coverage. A Rust seam while the pin
//! test succeeds is not coverage. `not_applicable` records a
//! `same_compaction_segment`, `is_qualifying_parent_candidate`,
//! `find_qualifying_parent_candidates`, `apply_proven_unique_parent_restore`,
//! `unique_parent_candidate`, or `execute` check this package cannot reach
//! without a `Cargo.toml` change, or a mode no vector records as the full pin
//! outcome. Pinned `same_compaction_segment` calls pass event objects;
//! `checks.graph` vectors pass seq endpoints, and the event-object index path
//! is the `PYTHON_EVENT_INDEX_UNREPRESENTABLE` gap.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 41;
const GRAPH_VECTOR_COUNT: usize = 20;
const GRAPH_VECTORS_REL: &str = "parity/vectors/checks.graph/vectors.json";
const RECIPES_VECTORS_REL: &str = "parity/vectors/repair.recipes_conservative/vectors.json";
const PRECONDITIONS_VECTORS_REL: &str = "parity/vectors/repair.preconditions/vectors.json";
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
        name: "test_boundary_endpoint_at_candidate_seq",
        disposition: Disposition::NotApplicable(
            "same_compaction_segment is true for a message at seq 10, a compaction_boundary also at seq 10, and a child at seq 20; same_compaction_segment_adjacent_seq_true compares seq endpoints 5 and 6",
        ),
    },
    Row {
        name: "test_boundary_endpoint_at_child_seq",
        disposition: Disposition::NotApplicable(
            "same_compaction_segment is true when the only boundary shares child seq 20 with candidate seq 10; same_compaction_segment_adjacent_seq_true compares seq endpoints 5 and 6",
        ),
    },
    Row {
        name: "test_boundary_endpoint_at_both_candidate_and_child_seq",
        disposition: Disposition::NotApplicable(
            "boundaries sitting on both endpoint seqs 5 and 15 leave the candidate and child in one segment; no checks.graph vector records two endpoint boundaries",
        ),
    },
    Row {
        name: "test_multiple_intervening_boundaries",
        disposition: Disposition::NotApplicable(
            "three compaction boundaries strictly between seq 0 and seq 4 make same_compaction_segment false and is_qualifying_parent_candidate false with reason cross_segment; same_compaction_segment_boundary_between_false is one boundary and checks.graph has no cross_segment reason",
        ),
    },
    Row {
        name: "test_boundary_negative_sequence_numbers",
        disposition: Disposition::NotApplicable(
            "a boundary at seq -20 between seq -50 and seq -5 is a different segment, and a boundary on the candidate seq -50 is the same segment; that pair of outcomes is absent from checks.graph",
        ),
    },
    Row {
        name: "test_boundary_large_sequence_gaps",
        disposition: Disposition::NotApplicable(
            "a boundary at seq 500000 between seq 1 and seq 1000000 is a different segment; same_compaction_segment_boundary_between_false uses seq endpoints 0 and 3",
        ),
    },
    Row {
        name: "test_boundary_out_of_list_order",
        disposition: Disposition::NotApplicable(
            "a compaction_boundary listed after the child, with seq 15 between seq 10 and seq 20, breaks the segment; same_compaction_segment_boundary_between_false lists its boundary first",
        ),
    },
    Row {
        name: "test_non_compaction_boundary_events_do_not_break_segment",
        disposition: Disposition::NotApplicable(
            "checkpoint, message, tool_call, and tool_result events between seq 0 and seq 5 stay one segment; same_compaction_segment_adjacent_seq_true has no intervening non-boundary kinds",
        ),
    },
    Row {
        name: "test_branch_none_vs_string",
        disposition: Disposition::NotApplicable(
            "is_qualifying_parent_candidate is false with reason cross_branch when the candidate branch is null and the child branch is main; checks.graph records no cross_branch reason",
        ),
    },
    Row {
        name: "test_branch_string_vs_none",
        disposition: Disposition::NotApplicable(
            "candidate branch main and child branch null is cross_branch; checks.graph records no cross_branch reason",
        ),
    },
    Row {
        name: "test_branch_both_none_is_same_group",
        disposition: Disposition::NotApplicable(
            "both branches null, ids cand and child, missing parent cand, qualifies true with reason ok; is_qualifying_parent_candidate_exact_id is ids p-par-001 and c-par-002",
        ),
    },
    Row {
        name: "test_branch_empty_string_vs_none",
        disposition: Disposition::NotApplicable(
            "an empty-string branch versus null is cross_branch; checks.graph records no cross_branch reason and no empty-string branch",
        ),
    },
    Row {
        name: "test_branch_both_empty_string",
        disposition: Disposition::NotApplicable(
            "both empty-string branches qualify with reason ok; is_qualifying_parent_candidate_exact_id uses null branches on ids p-par-001 and c-par-002",
        ),
    },
    Row {
        name: "test_branch_unicode_matching",
        disposition: Disposition::NotApplicable(
            "the same non-ascii branch string on candidate and child qualifies with reason ok; is_qualifying_parent_candidate_exact_id uses null branches",
        ),
    },
    Row {
        name: "test_branch_unicode_mismatch",
        disposition: Disposition::NotApplicable(
            "two different non-ascii branch strings are cross_branch; checks.graph records no cross_branch reason",
        ),
    },
    Row {
        name: "test_branch_casing_sensitivity",
        disposition: Disposition::NotApplicable(
            "branch Main versus main is cross_branch; checks.graph records no cross_branch reason",
        ),
    },
    Row {
        name: "test_branch_whitespace_sensitivity",
        disposition: Disposition::NotApplicable(
            "a branch with a trailing space versus main is cross_branch; checks.graph records no cross_branch reason",
        ),
    },
    Row {
        name: "test_branch_non_string_types",
        disposition: Disposition::NotApplicable(
            "integer branch 100 qualifies against the string 100, and integer branch 200 does not; no checks.graph vector records a non-string branch",
        ),
    },
    Row {
        name: "test_prefix_collision_candidate_shorter_than_missing",
        disposition: Disposition::NotApplicable(
            "candidate id msg-1 versus missing parent msg-10 is no_full_match on the default branch main; is_qualifying_parent_candidate_prefix_not_full_match uses a longer id and missing_parent_id null",
        ),
    },
    Row {
        name: "test_prefix_collision_candidate_longer_than_missing",
        disposition: Disposition::NotApplicable(
            "candidate id msg-10 versus missing parent msg-1 is no_full_match; is_qualifying_parent_candidate_prefix_not_full_match sets missing_parent_id null on ids p-pre-001x and c-pre-002",
        ),
    },
    Row {
        name: "test_id_casing_sensitivity",
        disposition: Disposition::NotApplicable(
            "EVT-ROOT versus missing parent evt-root is no_full_match; is_qualifying_parent_candidate_prefix_not_full_match is a longer id with missing_parent_id null",
        ),
    },
    Row {
        name: "test_id_whitespace_padding",
        disposition: Disposition::NotApplicable(
            "an id with a trailing space versus the unpadded missing parent is no_full_match; no checks.graph vector records whitespace inside an id",
        ),
    },
    Row {
        name: "test_hash_vs_id_mixup_rejected",
        disposition: Disposition::NotApplicable(
            "a missing parent equal to the candidate hash field, with a different candidate id, is no_full_match; no checks.graph vector carries a hash field",
        ),
    },
    Row {
        name: "test_hash_prefix_mixup_rejected",
        disposition: Disposition::NotApplicable(
            "a missing parent that is only a prefix of the candidate hash field is no_full_match; no checks.graph vector carries a hash field",
        ),
    },
    Row {
        name: "test_self_candidate_rejected",
        disposition: Disposition::NotApplicable(
            "the child passed as its own candidate is false with reason self_candidate; checks.graph records no self_candidate reason",
        ),
    },
    Row {
        name: "test_empty_or_none_candidate_id_rejected",
        disposition: Disposition::NotApplicable(
            "an empty candidate id with an empty missing parent is false with reason empty_candidate_id; checks.graph records no empty_candidate_id reason",
        ),
    },
    Row {
        name: "test_special_characters_in_ids",
        disposition: Disposition::NotApplicable(
            "one id containing colon, slash, hash, and query qualifies with reason ok, and a shorter prefix of that id is no_full_match, both on the default branch main; is_qualifying_parent_candidate_exact_id is only the success half on null branches",
        ),
    },
    Row {
        name: "test_multiple_identical_candidates_in_same_segment",
        disposition: Disposition::NotApplicable(
            "find_qualifying_parent_candidates returns three qualifying indices and reason ambiguous; find_qualifying_parent_candidates_two_earlier_exact qualifies indices 0 and 1 for id p-fqc-020",
        ),
    },
    Row {
        name: "test_duplicate_disambiguated_by_branch",
        disposition: Disposition::NotApplicable(
            "one of two same-id candidates qualifies at index 0 with reason ok and the other is rejected cross_branch; find_qualifying_parent_candidates_one_earlier_exact rejects a different id with no_full_match",
        ),
    },
    Row {
        name: "test_duplicate_disambiguated_by_compaction_segment",
        disposition: Disposition::NotApplicable(
            "the post-boundary copy at index 2 qualifies with reason ok and an earlier copy is rejected cross_segment; checks.graph records no cross_segment reason",
        ),
    },
    Row {
        name: "test_duplicate_candidates_both_cross_branch",
        disposition: Disposition::NotApplicable(
            "both same-id candidates are cross_branch, qualifying is empty, and confinement branch is false; checks.graph records no cross_branch reason",
        ),
    },
    Row {
        name: "test_candidate_after_child_in_event_list",
        disposition: Disposition::NotApplicable(
            "target_idx 0 leaves the later candidate unconsidered, with empty qualifying, empty rejected, and reason no_full_match; find_qualifying_parent_candidates_no_earlier_match rejects an earlier id and sets confinement branch and segment false",
        ),
    },
    Row {
        name: "test_candidate_before_child_in_list_with_inverted_seq",
        disposition: Disposition::NotApplicable(
            "candidate seq 100, a boundary at seq 50, and child seq 10 make same_compaction_segment false and is_qualifying_parent_candidate false with reason cross_segment; same_compaction_segment_boundary_between_false is same false for seq endpoints 0 and 3",
        ),
    },
    Row {
        name: "test_apply_refuses_cross_branch_tampered_step",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed for zero candidates with cross_branch; recipes_conservative apply vectors call other recipes, and the export list only names apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_apply_refuses_cross_segment_tampered_step",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed for a parent across a compaction boundary with cross_segment; no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_apply_refuses_prefix_tampered_step",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed when the step parent id is a prefix, reason no_full_match; no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_apply_refuses_ambiguous_tampered_step",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed for two ambiguous candidates; find_qualifying_parent_candidates_two_earlier_exact is a finder reason, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_apply_refuses_out_of_bounds_target_index",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed for target_index values -1, 2, and 999; suffix_discard_refusal_out_of_bounds is apply_terminal_suffix_discard at index 5",
        ),
    },
    Row {
        name: "test_precondition_refuses_when_no_parent_id_in_evidence_or_child",
        disposition: Disposition::NotApplicable(
            "unique_parent_candidate is false for an SL004 finding whose evidence parent_id is null and whose child parent_id is null; unique_parent_no_finding has no findings, unique_parent_orphan is one SL203 event, and unique_parent_graph_seam is a gap",
        ),
    },
    Row {
        name: "test_e2e_executor_fails_closed_on_coercion_attempt",
        disposition: Disposition::NotApplicable(
            "execute under conservative policy raises RepairRefused for a one-step cross-branch proven-unique-parent-restore plan and leaves the output path absent; execute_fingerprint_import_seam records fingerprint_unavailable and pin_exception PlanTampered, and execute_cap_257 is the 257-step cap",
        ),
    },
    Row {
        name: "test_hypothesis_candidate_qualification_oracle",
        disposition: Disposition::NotApplicable(
            "Hypothesis sweeps ids, branches, sequence numbers, and an optional boundary for 300 examples against four confinement predicates; no checks.graph vector is that property sweep",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_boundary_endpoint_at_candidate_seq",
    "test_boundary_endpoint_at_child_seq",
    "test_boundary_endpoint_at_both_candidate_and_child_seq",
    "test_multiple_intervening_boundaries",
    "test_boundary_negative_sequence_numbers",
    "test_boundary_large_sequence_gaps",
    "test_boundary_out_of_list_order",
    "test_non_compaction_boundary_events_do_not_break_segment",
    "test_branch_none_vs_string",
    "test_branch_string_vs_none",
    "test_branch_both_none_is_same_group",
    "test_branch_empty_string_vs_none",
    "test_branch_both_empty_string",
    "test_branch_unicode_matching",
    "test_branch_unicode_mismatch",
    "test_branch_casing_sensitivity",
    "test_branch_whitespace_sensitivity",
    "test_branch_non_string_types",
    "test_prefix_collision_candidate_shorter_than_missing",
    "test_prefix_collision_candidate_longer_than_missing",
    "test_id_casing_sensitivity",
    "test_id_whitespace_padding",
    "test_hash_vs_id_mixup_rejected",
    "test_hash_prefix_mixup_rejected",
    "test_self_candidate_rejected",
    "test_empty_or_none_candidate_id_rejected",
    "test_special_characters_in_ids",
    "test_multiple_identical_candidates_in_same_segment",
    "test_duplicate_disambiguated_by_branch",
    "test_duplicate_disambiguated_by_compaction_segment",
    "test_duplicate_candidates_both_cross_branch",
    "test_candidate_after_child_in_event_list",
    "test_candidate_before_child_in_list_with_inverted_seq",
    "test_apply_refuses_cross_branch_tampered_step",
    "test_apply_refuses_cross_segment_tampered_step",
    "test_apply_refuses_prefix_tampered_step",
    "test_apply_refuses_ambiguous_tampered_step",
    "test_apply_refuses_out_of_bounds_target_index",
    "test_precondition_refuses_when_no_parent_id_in_evidence_or_child",
    "test_e2e_executor_fails_closed_on_coercion_attempt",
    "test_hypothesis_candidate_qualification_oracle",
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
fn every_pinned_adversarial_confinement_test_has_one_disposition() {
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
fn cited_confinement_vectors_are_present() {
    let graph = read_vectors(GRAPH_VECTORS_REL, "sesslint.checks.graph");
    assert_top_level_catalog(&graph, "checks.graph", GRAPH_VECTORS);
    for absent in [
        "cross_branch",
        "cross_segment",
        "self_candidate",
        "empty_candidate_id",
    ] {
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
    assert!(prefix.contains("\"missing_parent_id\": null"));
    assert!(prefix.contains("\"reason\": \"no_full_match\""));
    for id in [
        "same_compaction_segment_boundary_between_false",
        "same_compaction_segment_adjacent_seq_true",
    ] {
        assert!(
            vector_slice(&graph, id).contains("\"kind\": \"seq\""),
            "{id} endpoints are seq values"
        );
    }
    assert!(vector_slice(
        &graph,
        "find_qualifying_parent_candidates_two_earlier_exact"
    )
    .contains("\"reason\": \"ambiguous\""));

    let recipes = read_vectors(RECIPES_VECTORS_REL, "sesslint.repair.recipes_conservative");
    let exports = vector_slice(&recipes, "module_all_export_order");
    assert!(exports.contains("apply_proven_unique_parent_restore"));
    assert!(
        !recipes.contains("\"fn\": \"apply_proven_unique_parent_restore\""),
        "recipes_conservative apply vectors must not be treated as the parent-restore refusals"
    );
    assert!(
        vector_slice(&recipes, "suffix_discard_refusal_out_of_bounds")
            .contains("\"fn\": \"apply_terminal_suffix_discard\"")
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
    assert!(vector_slice(&preconditions, "unique_parent_orphan").contains("\"code\": \"SL203\""));
    let seam = vector_slice(&preconditions, "unique_parent_graph_seam");
    assert!(seam.contains("\"mode\": \"gap\""));
    assert!(seam.contains("\"gap_id\": \"GAP-preconditions-parent-candidates\""));

    let executor = read_vectors(EXECUTOR_VECTORS_REL, "sesslint.repair.executor");
    let fingerprint_seam = vector_slice(&executor, "execute_fingerprint_import_seam");
    assert!(fingerprint_seam.contains("\"type\": \"execute_fingerprint_gap\""));
    assert!(fingerprint_seam.contains("\"mode\": \"fingerprint_unavailable\""));
    assert!(fingerprint_seam.contains("\"pin_exception\": \"PlanTampered\""));
    assert!(vector_slice(&executor, "execute_cap_257").contains("\"type\": \"execute_cap\""));

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
