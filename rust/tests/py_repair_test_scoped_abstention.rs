//! Dispositions for the 23 `def test_` functions in pinned
//! `tests/repair/test_scoped_abstention.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The card names 23 tests;
//! `lstrip` finds 23 `def test_` functions and none are indented. This
//! integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call repair or checks without a
//! `Cargo.toml` change.
//!
//! `covered` would name one id in a published `vectors.json` whose construct
//! is the same function and the same success or failure mode as that entire
//! pinned test, with `entire_test` true. One function inside a sweep is not
//! the whole test. One refusal inside a plan-and-execute test is not the
//! whole test. A payload-free rewrite of a test whose events carry payload
//! is not that test. A Rust seam while the pin succeeds is not coverage. A
//! plan, a fixture diff, a payload, and a kept `SessionEvent` copy are not
//! coverage. No published vector is that entire test, so every row is
//! `not_applicable`. SL001 and SL002 are not invented as covered ids.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 23;
const COVERED_COUNT: usize = 0;
const POLICY_MODULE: &str = "sesslint.policy.abstention";
const CONSERVATIVE_MODULE: &str = "sesslint.repair.recipes_conservative";
const SL002_MODULE: &str = "sesslint.repair.recipes_sl002";
const SALVAGE_MODULE: &str = "sesslint.repair.recipes_salvage";
const POLICY_VECTOR_COUNT: usize = 25;
const TORN_VECTOR_COUNT: usize = 25;
const RESTORE_VECTOR_COUNT: usize = 20;
const REMOVAL_VECTOR_COUNT: usize = 5;
const COLLAPSE_VECTOR_COUNT: usize = 14;
const REUNION_VECTOR_COUNT: usize = 6;
const SEQ_VECTOR_COUNT: usize = 3;
const SUFFIX_VECTOR_COUNT: usize = 9;
const EXCISION_VECTOR_COUNT: usize = 6;
const POLICY_REL: &str = "parity/vectors/policy.abstention/vectors.json";
const TORN_REL: &str = "parity/recipes/torn-terminal-record-discard/vectors.json";
const RESTORE_REL: &str = "parity/recipes/proven-unique-parent-restore/vectors.json";
const REMOVAL_REL: &str = "parity/recipes/duplicate-projection-removal/vectors.json";
const COLLAPSE_REL: &str = "parity/recipes/identical-duplicate-collapse/vectors.json";
const REUNION_REL: &str = "parity/recipes/compaction-projection-reunion/vectors.json";
const SEQ_REL: &str = "parity/recipes/seq-renumber/vectors.json";
const SUFFIX_REL: &str = "parity/recipes/terminal-suffix-discard/vectors.json";
const EXCISION_REL: &str = "parity/recipes/torn-record-excision/vectors.json";

/// `covered` would name one vector id whose construct is that entire pinned
/// test. `not_applicable` records a plan, execute, oracle, or region check
/// this package cannot reach without a `Cargo.toml` change, or a mode no
/// cited vector records as the full pin outcome.
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

/// Vector id and construct type. Policy vectors have no `fn` and no
/// `entire_test` field.
const POLICY_VECTORS: &[(&str, &str)] = &[
    (
        "extract_explicit_empty_string_with_read_payload",
        "extract_side_effects",
    ),
    ("extract_tool_result_default_none", "extract_side_effects"),
    ("extract_tool_call_read_none", "extract_side_effects"),
    ("extract_tool_call_bash_unknown", "extract_side_effects"),
    (
        "extract_payload_only_when_top_missing",
        "extract_side_effects",
    ),
    ("extract_top_wins_over_payload", "extract_side_effects"),
    ("region_pair_1_3_unclamped", "affected_region_all_indices"),
    ("region_clamp_total_len_4", "affected_region_all_indices"),
    (
        "should_sl203_only_reason_despite_side_effects",
        "should_abstain_from_repair",
    ),
    (
        "should_conservative_step_none_ignores_possible",
        "should_abstain_from_repair",
    ),
    (
        "should_salvage_no_ack_lists_possible",
        "should_abstain_from_repair",
    ),
    (
        "should_salvage_ack_no_abstain",
        "should_abstain_from_repair",
    ),
    (
        "should_custom_policy_no_sl203_no_abstain",
        "should_abstain_from_repair",
    ),
    ("must_sl203_only_reason", "must_abstain"),
    ("must_default_abstain_unknown_bash", "must_abstain"),
    ("must_allow_unknown_no_walk", "must_abstain"),
    ("must_message_event_no_abstain", "must_abstain"),
    ("ambiguous_dangling_call", "find_ambiguous_events"),
    ("ambiguous_orphan_result", "find_ambiguous_events"),
    ("ambiguous_reused_correlation", "find_ambiguous_events"),
    (
        "ambiguous_duplicate_results_same_hash_not_conflicting",
        "find_ambiguous_events",
    ),
    (
        "ambiguous_conflicting_result_hashes",
        "find_ambiguous_events",
    ),
    ("scope_missing_region_fn", "check_step_scope"),
    ("scope_disjoint_read_allowed", "check_step_scope"),
    ("scope_sl203_abstains_disjoint_region", "check_step_scope"),
];

const TORN_VECTORS: &[(&str, &str)] = &[
    ("recipe_torn_terminal_record_discard", "recipe_constant"),
    ("discard_named_last", "apply_ok"),
    ("reader_minted_keeps", "apply_ok"),
    ("shared_id_discards_last", "apply_ok"),
    ("shared_id_index_zero_keeps", "apply_ok"),
    ("bool_cut_keeps", "apply_ok"),
    ("bool_true_discards_index_one", "apply_ok"),
    ("bool_false_clears_singleton", "apply_ok"),
    ("bool_true_keeps_singleton", "apply_ok"),
    ("not_mapping_keeps", "apply_ok"),
    ("other_target_keeps", "apply_ok"),
    ("ignores_region_fallback", "apply_ok"),
    ("duplicate_cut_last_wins", "apply_ok"),
    ("float_cut_keeps", "apply_ok"),
    ("string_cut_keeps", "apply_ok"),
    ("list_cut_keeps", "apply_ok"),
    ("cut_past_end_keeps", "apply_ok"),
    ("negative_cut_keeps", "apply_ok"),
    ("target_mismatch_keeps", "apply_ok"),
    ("missing_cut_keeps", "apply_ok"),
    ("null_cut_keeps", "apply_ok"),
    ("empty_no_cut_keeps", "apply_ok"),
    ("empty_zero_is_not_pop", "apply_ok"),
    ("other_target_empty_is_not_pop", "apply_ok"),
    ("empty_pop", "apply_index_error"),
];

const RESTORE_VECTORS: &[(&str, &str)] = &[
    ("recipe_proven_unique_parent_restore", "recipe_constant"),
    ("restore_refusal_missing_index", "apply_refusal"),
    ("restore_refusal_empty_events", "apply_refusal"),
    ("restore_refusal_negative_index", "apply_refusal"),
    ("restore_refusal_index_out_of_bounds", "apply_refusal"),
    ("restore_refusal_param_index_out_of_bounds", "apply_refusal"),
    ("restore_refusal_negative_at_index", "apply_refusal"),
    (
        "restore_refusal_non_int_index_hides_at_index",
        "apply_refusal",
    ),
    ("restore_refusal_params_not_mapping", "apply_refusal"),
    ("restore_refusal_missing_parent", "apply_refusal"),
    ("restore_refusal_null_parent", "apply_refusal"),
    ("restore_refusal_empty_parent_string", "apply_refusal"),
    ("restore_refusal_empty_parent_param", "apply_refusal"),
    ("restore_refusal_empty_prefix", "apply_refusal"),
    ("restore_refusal_zero_parent_param", "apply_refusal"),
    ("restore_refusal_empty_parent_list", "apply_refusal"),
    ("restore_refusal_empty_parent_map", "apply_refusal"),
    (
        "restore_refusal_at_index_zero_missing_parent",
        "apply_refusal",
    ),
    (
        "restore_refusal_not_mapping_missing_parent",
        "apply_refusal",
    ),
    (
        "restore_refusal_param_index_zero_missing_parent",
        "apply_refusal",
    ),
];

const REMOVAL_VECTORS: &[(&str, &str)] = &[
    ("recipe_duplicate_projection_removal", "recipe_constant"),
    ("removal_refusal_missing_correlation_id", "apply_refusal"),
    ("removal_refusal_zero_results", "apply_refusal"),
    ("removal_refusal_one_result", "apply_refusal"),
    ("removal_refusal_fingerprints_differ", "apply_refusal"),
];

const COLLAPSE_VECTORS: &[(&str, &str)] = &[
    ("recipe_identical_duplicate_collapse", "recipe_constant"),
    ("collapse_refusal_needs_two", "apply_refusal"),
    ("collapse_refusal_one_event", "apply_refusal"),
    ("collapse_refusal_index_out_of_bounds", "apply_refusal"),
    ("collapse_refusal_negative_index", "apply_refusal"),
    ("collapse_refusal_param_skips_non_int", "apply_refusal"),
    ("collapse_refusal_fingerprints_differ", "apply_refusal"),
    ("collapse_refusal_missing_kind", "apply_refusal"),
    ("collapse_refusal_no_eligible_pair", "apply_refusal"),
    ("collapse_refusal_note_kind_mismatch", "apply_refusal"),
    ("collapse_refusal_scan_skips_boundary", "apply_refusal"),
    ("collapse_refusal_boundary_compaction", "apply_refusal"),
    ("collapse_refusal_boundary_checkpoint", "apply_refusal"),
    ("collapse_refusal_kind_mismatch", "apply_refusal"),
];

const REUNION_VECTORS: &[(&str, &str)] = &[
    ("recipe_compaction_projection_reunion", "recipe_constant"),
    ("reunion_refusal_missing_correlation_id", "apply_refusal"),
    ("reunion_refusal_unclean_pair", "apply_refusal"),
    ("reunion_refusal_zero_boundaries", "apply_refusal"),
    ("reunion_refusal_multiple_boundaries", "apply_refusal"),
    ("reunion_refusal_boundary_at_endpoint", "apply_refusal"),
];

const SEQ_VECTORS: &[(&str, &str, &str)] = &[
    ("recipe_seq_renumber", "recipe_constant", ""),
    (
        "seq_renumber_step_idempotent",
        "apply_idempotent",
        "apply_seq_renumber",
    ),
    (
        "affected_region_seq_renumber",
        "affected_region",
        "affected_region_seq_renumber",
    ),
];

const SUFFIX_VECTORS: &[(&str, &str)] = &[
    ("recipe_terminal_suffix_discard", "recipe_constant"),
    ("suffix_refusal_missing_cut", "apply_refusal"),
    ("suffix_refusal_negative_cut", "apply_refusal"),
    ("suffix_refusal_cut_equals_length", "apply_refusal"),
    ("suffix_refusal_empty_events_past_end", "apply_refusal"),
    ("suffix_refusal_param_cut_past_end", "apply_refusal"),
    ("suffix_refusal_checkpoint", "apply_refusal"),
    ("suffix_discard_refusal_empty_session", "apply_refusal"),
    ("suffix_discard_refusal_out_of_bounds", "apply_refusal"),
];

const EXCISION_VECTORS: &[(&str, &str, &str)] = &[
    ("recipe_torn_record_excision", "recipe_constant", ""),
    (
        "sl001_excisable_precondition",
        "sl001_excisable",
        "sl001_excisable",
    ),
    (
        "apply_torn_record_excision_refusals",
        "apply_refusals",
        "apply_torn_record_excision",
    ),
    (
        "apply_bool_span_and_line",
        "apply_refusals",
        "apply_torn_record_excision",
    ),
    (
        "apply_record_id_bool_is_not_int",
        "apply_mixed",
        "apply_torn_record_excision",
    ),
    (
        "sl001_bool_span_is_not_an_int",
        "sl001_excisable",
        "sl001_excisable",
    ),
];

const REUNION_ENTIRE_TRUE: &[&str] = &[
    "reunion_refusal_zero_boundaries",
    "reunion_refusal_multiple_boundaries",
    "reunion_refusal_boundary_at_endpoint",
];

const SUFFIX_ENTIRE_TRUE: &[&str] = &[
    "suffix_discard_refusal_empty_session",
    "suffix_discard_refusal_out_of_bounds",
];

const COVERED_PAIRS: &[(&str, &str)] = &[];

/// Identifiers that belong to the pinned tests and are absent from every
/// cited vector file.
const PIN_IDENTIFIERS: &[&str] = &[
    "call-dangle",
    "call-unk",
    "call-nocorr",
    "call-reused",
    "call-sl203",
    "reversed-pairing",
    "call-mutating",
    "side-effect-abstention",
    "dummy-unproven",
    "msg-summary",
    "call-pytest",
    "c-unk-outside",
    "SL203-refusal",
];

const ROWS: &[Row] = &[
    Row {
        name: "test_oracle_completed_mutating_call_not_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on call-1 and res-1 with payload side_effects possible returns empty indices and empty ids; ambiguous_duplicate_results_same_hash_not_conflicting returns empty indices for call-d, res-d1, and res-d2 with content_hash abc and side_effects none, policy.abstention has no entire_test field, and the stored events differ",
        ),
    },
    Row {
        name: "test_oracle_dangling_tool_call_is_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on call-dangle with correlation c-dangle and payload side_effects possible marks index 0 and id call-dangle; ambiguous_dangling_call stores call-a and corr-a with payload name bash and no side_effects possible, and policy.abstention has no entire_test field",
        ),
    },
    Row {
        name: "test_oracle_unknown_side_effects_is_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on call-unk and res-unk with side_effects unknown marks indices 0 and 1 and both ids; no policy.abstention vector stores that pair, extract_tool_call_bash_unknown is extract_side_effects, and the file has no entire_test field",
        ),
    },
    Row {
        name: "test_oracle_unpaired_correlation_id_is_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on call-nocorr and res-nocorr with correlation_id None marks both indices and both ids; ambiguous_orphan_result is one tool_result res-b with corr-b, and policy.abstention has no entire_test field",
        ),
    },
    Row {
        name: "test_oracle_reused_tool_call_id_is_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on call-reused-1, call-reused-2, and res-reused with correlation c-reused marks indices 0, 1, and 2; ambiguous_reused_correlation stores call-c1 and call-c2 with corr-c and no tool_result, and the file has no entire_test field",
        ),
    },
    Row {
        name: "test_oracle_multiple_tool_results_is_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on call-1, res-1a, and res-1b with payload outputs v1 and v2 marks indices 0, 1, and 2; ambiguous_conflicting_result_hashes stores call-e, res-e1, and res-e2 with content hashes abc and unknown, ambiguous_duplicate_results_same_hash_not_conflicting returns empty indices, and neither vector has entire_test",
        ),
    },
    Row {
        name: "test_oracle_sl203_subject_is_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on evt-0 and call-sl203 with an SL203 finding marks index 1 and id call-sl203; scope_sl203_abstains_disjoint_region is check_step_scope, must_sl203_only_reason is must_abstain, no find_ambiguous_events vector stores that finding, and the file has no entire_test field",
        ),
    },
    Row {
        name: "test_region_functions_totality_fuzz",
        disposition: Disposition::NotApplicable(
            "the test calls affected_region_identical_duplicate_collapse, affected_region_proven_unique_parent_restore, affected_region_compaction_projection_reunion, affected_region_duplicate_projection_removal, and affected_region_torn_terminal_record_discard and asserts AffectedRegion; one function inside that five-function sweep is not the whole test, torn-terminal rows are apply_torn_terminal_record_discard with entire_test false, and reunion rows with entire_test true are apply_compaction_projection_reunion refusals",
        ),
    },
    Row {
        name: "test_doubt_rule_missing_region_function",
        disposition: Disposition::NotApplicable(
            "check_step_scope with recipe_region_fn None on message id 1 returns disjoint false and side-effect-scope-unproven; scope_missing_region_fn has that reason and has_recipe_region_fn false, but its events are read-tool and bash-tool, and policy.abstention has no entire_test field",
        ),
    },
    Row {
        name: "test_doubt_rule_forced_exception_in_region_function",
        disposition: Disposition::NotApplicable(
            "check_step_scope with a region function that raises RuntimeError returns disjoint false and side-effect-scope-unproven; no published vector records that exception, and scope_missing_region_fn does not raise",
        ),
    },
    Row {
        name: "test_doubt_rule_unproven_region_flag",
        disposition: Disposition::NotApplicable(
            "check_step_scope with AffectedRegion unproven true returns disjoint false and side-effect-scope-unproven; the three check_step_scope vectors store unproven false, and policy.abstention has no entire_test field",
        ),
    },
    Row {
        name: "test_scenario_1_completed_mutating_call_elsewhere_disjoint_repair",
        disposition: Disposition::NotApplicable(
            "the source-derived plan and execute succeed with identical-duplicate-collapse and seq-renumber, and the events carry payload; the pin succeeds, collapse vectors are apply refusals with entire_test false, seq_renumber_step_idempotent is apply_seq_renumber on ids a and b with no entire_test field, and one recipe inside the plan is not the whole test",
        ),
    },
    Row {
        name: "test_scenario_2_dangling_call_in_truncated_region",
        disposition: Disposition::NotApplicable(
            "plan blocks with side-effect-scope-unproven, then execute raises RepairRefused before apply_torn_terminal_record_discard; the crafted step is not applied, torn-terminal vectors are entire_test false, and the recipe constant handle SL002 is not this test",
        ),
    },
    Row {
        name: "test_scenario_3_unknown_side_effects_on_relink_target",
        disposition: Disposition::NotApplicable(
            "plan blocks with side-effect-scope-unproven, then execute raises RepairRefused before apply_proven_unique_parent_restore, and the events carry payload side_effects unknown; restore vectors are entire_test false apply refusals for a missing index or a missing parent_id, and one refusal is not this plan",
        ),
    },
    Row {
        name: "test_scenario_4_ambiguous_call_adjacent_but_outside_region_boundary_pin",
        disposition: Disposition::NotApplicable(
            "the first plan and execute succeed with identical-duplicate-collapse and seq-renumber on events that carry payload, then an SL002 plan has no steps and blocks with side-effect-scope-unproven; the pin succeeds on the first half, apply_torn_terminal_record_discard is not called, and one plan inside the test is not the boundary pin",
        ),
    },
    Row {
        name: "test_scenario_5_sl203_anywhere_global_refusal_unchanged",
        disposition: Disposition::NotApplicable(
            "plan blocks every finding with SL203-refusal, then execute raises Abstained matching SL203 present, and the events carry payload; these sets do not record SL203-refusal, must_sl203_only_reason is must_abstain, and a plan is not coverage",
        ),
    },
    Row {
        name: "test_positive_e2e_realistic_tool_session_repaired",
        disposition: Disposition::NotApplicable(
            "plan and execute succeed with torn-terminal-record-discard and seq-renumber and the output keeps msg-summary, and the events carry payload; the pin succeeds, torn-terminal apply rows are entire_test false and do not store msg-summary, and a plan, a payload, and a kept SessionEvent copy are not coverage",
        ),
    },
    Row {
        name: "test_parent_restore_disjoint_from_intermediate_mutating_tool",
        disposition: Disposition::NotApplicable(
            "plan returns one proven-unique-parent-restore step, then execute raises RepairRefused, and the events carry payload; the plan succeeds, restore vectors are entire_test false apply refusals, and one refusal is not the whole test",
        ),
    },
    Row {
        name: "test_duplicate_projection_removal_disjoint_from_intermediate_mutating_tool",
        disposition: Disposition::NotApplicable(
            "plan returns duplicate-projection-removal and seq-renumber and blocks SL007, then execute succeeds, and the events carry payload; the pin succeeds, removal vectors are entire_test false apply refusals, and one recipe inside the plan is not the whole test",
        ),
    },
    Row {
        name: "test_multistep_conservative_repair_no_index_drift_in_executor",
        disposition: Disposition::NotApplicable(
            "plan returns two identical-duplicate-collapse steps and seq-renumber, then execute records three actions, and the events carry payload; the pin succeeds, and collapse vectors are entire_test false refusals",
        ),
    },
    Row {
        name: "test_recipe_without_affected_region_keeps_global_gating",
        disposition: Disposition::NotApplicable(
            "register_recipe of dummy-unproven-recipe with handles SL001, then plan blocks with side-effect-abstention, then execute raises RepairRefused before apply; these sets do not record that recipe, and sl001_excisable_precondition is sl001_excisable with assert_count 10, a different function",
        ),
    },
    Row {
        name: "test_reversed_tool_pairing_marked_ambiguous",
        disposition: Disposition::NotApplicable(
            "find_ambiguous_events on r1 then c1 with correlation c_rev marks both indices, both ids, and a reason containing reversed-pairing; no vector in these sets contains reversed-pairing, and policy.abstention has no entire_test field",
        ),
    },
    Row {
        name: "test_check_step_scope_syncs_ids_to_indices_for_side_effect_check",
        disposition: Disposition::NotApplicable(
            "check_step_scope with a region that lists only id call-mutating, on events whose tool_call payload side_effects is possible, returns disjoint false and side-effect-scope-unproven; scope_missing_region_fn stores read-tool and bash-tool and an index region, the events differ, and policy.abstention has no entire_test field",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_oracle_completed_mutating_call_not_ambiguous",
    "test_oracle_dangling_tool_call_is_ambiguous",
    "test_oracle_unknown_side_effects_is_ambiguous",
    "test_oracle_unpaired_correlation_id_is_ambiguous",
    "test_oracle_reused_tool_call_id_is_ambiguous",
    "test_oracle_multiple_tool_results_is_ambiguous",
    "test_oracle_sl203_subject_is_ambiguous",
    "test_region_functions_totality_fuzz",
    "test_doubt_rule_missing_region_function",
    "test_doubt_rule_forced_exception_in_region_function",
    "test_doubt_rule_unproven_region_flag",
    "test_scenario_1_completed_mutating_call_elsewhere_disjoint_repair",
    "test_scenario_2_dangling_call_in_truncated_region",
    "test_scenario_3_unknown_side_effects_on_relink_target",
    "test_scenario_4_ambiguous_call_adjacent_but_outside_region_boundary_pin",
    "test_scenario_5_sl203_anywhere_global_refusal_unchanged",
    "test_positive_e2e_realistic_tool_session_repaired",
    "test_parent_restore_disjoint_from_intermediate_mutating_tool",
    "test_duplicate_projection_removal_disjoint_from_intermediate_mutating_tool",
    "test_multistep_conservative_repair_no_index_drift_in_executor",
    "test_recipe_without_affected_region_keeps_global_gating",
    "test_reversed_tool_pairing_marked_ambiguous",
    "test_check_step_scope_syncs_ids_to_indices_for_side_effect_check",
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

fn assert_typed_fns(json: &str, label: &str, rows: &[(&str, &str, &str)]) {
    let pairs: Vec<(&str, &str)> = rows
        .iter()
        .map(|(id, construct, _)| (*id, *construct))
        .collect();
    assert_top_level_catalog(json, label, &pairs);
    for &(id, _, function) in rows {
        if function.is_empty() {
            let slice = vector_slice(json, id);
            assert!(
                !slice.contains("\"fn\":"),
                "{label} {id} unexpectedly records fn"
            );
            continue;
        }
        let slice = vector_slice(json, id);
        assert!(
            slice.contains(&format!("\"fn\": \"{function}\"")),
            "{label} {id}"
        );
    }
}

fn assert_absent(json: &str, label: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !json.contains(needle),
            "{label} unexpectedly contains {needle}"
        );
    }
}

fn read_vectors(rel: &str, module: &str, recipe: Option<&str>) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(json.contains(&format!("\"module\": \"{module}\"")), "{rel}");
    if let Some(recipe) = recipe {
        assert!(json.contains(&format!("\"recipe\": \"{recipe}\"")), "{rel}");
    }
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

fn assert_entire_test_counts(json: &str, label: &str, entire_true: usize, entire_false: usize) {
    assert_eq!(
        json.matches("\"entire_test\": true").count(),
        entire_true,
        "{label} entire_test true"
    );
    assert_eq!(
        json.matches("\"entire_test\": false").count(),
        entire_false,
        "{label} entire_test false"
    );
}

fn assert_apply_fn_and_payload_free(
    json: &str,
    label: &str,
    rows: &[(&str, &str)],
    recipe_fn: &str,
    apply_fn: &str,
) {
    for &(id, construct) in rows {
        let slice = vector_slice(json, id);
        let function = if construct == "recipe_constant" {
            recipe_fn
        } else {
            apply_fn
        };
        assert!(
            slice.contains(&format!("\"fn\": \"{function}\"")),
            "{label} {id}"
        );
        assert!(!slice.contains("payload"), "{label} {id} stores payload");
        assert!(
            slice.contains("\"entire_test\": false") || slice.contains("\"entire_test\": true"),
            "{label} {id} is missing entire_test"
        );
    }
}

fn assert_named_entire_true(json: &str, label: &str, ids: &[&str], function: &str) {
    for id in ids {
        let slice = vector_slice(json, id);
        assert_eq!(
            slice.matches("\"entire_test\": true").count(),
            1,
            "{label} {id}"
        );
        assert!(!slice.contains("\"entire_test\": false"), "{label} {id}");
        assert!(
            slice.contains(&format!("\"fn\": \"{function}\"")),
            "{label} {id}"
        );
        assert!(
            !slice.contains("\"type\": \"find_ambiguous_events\""),
            "{label} {id}"
        );
        assert!(
            !slice.contains("\"type\": \"check_step_scope\""),
            "{label} {id}"
        );
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_scoped_abstention_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(POLICY_VECTORS.len(), POLICY_VECTOR_COUNT);
    assert_eq!(TORN_VECTORS.len(), TORN_VECTOR_COUNT);
    assert_eq!(RESTORE_VECTORS.len(), RESTORE_VECTOR_COUNT);
    assert_eq!(REMOVAL_VECTORS.len(), REMOVAL_VECTOR_COUNT);
    assert_eq!(COLLAPSE_VECTORS.len(), COLLAPSE_VECTOR_COUNT);
    assert_eq!(REUNION_VECTORS.len(), REUNION_VECTOR_COUNT);
    assert_eq!(SEQ_VECTORS.len(), SEQ_VECTOR_COUNT);
    assert_eq!(SUFFIX_VECTORS.len(), SUFFIX_VECTOR_COUNT);
    assert_eq!(EXCISION_VECTORS.len(), EXCISION_VECTOR_COUNT);
    assert_eq!(COVERED_PAIRS.len(), COVERED_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    let mut covered_ids = BTreeSet::new();
    let mut covered_pairs = Vec::new();
    for row in ROWS {
        assert!(
            names.insert(row.name),
            "duplicate pinned test name {}",
            row.name
        );
        match row.disposition {
            Disposition::Covered { vector_id, needles } => {
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert_ne!(vector_id, "SL001", "{}", row.name);
                assert_ne!(vector_id, "SL002", "{}", row.name);
                assert!(!needles.is_empty(), "{}", row.name);
                assert!(
                    needles
                        .iter()
                        .any(|needle| needle.starts_with("\"type\": \"")),
                    "{} covered row is missing a construct type needle",
                    row.name
                );
                assert!(
                    needles.contains(&"\"entire_test\": true"),
                    "{} covered row is missing entire_test",
                    row.name
                );
                assert!(
                    needles.contains(&"\"assert_count\": 1"),
                    "{} covered row is missing assert_count",
                    row.name
                );
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                covered_pairs.push((row.name, vector_id));
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
    assert_eq!(covered, COVERED_COUNT);
    assert_eq!(not_applicable, PINNED_TEST_COUNT - COVERED_COUNT);
    assert_eq!(covered_pairs.as_slice(), COVERED_PAIRS);
}

#[test]
fn cited_scoped_abstention_vectors_are_not_entire_pin_tests() {
    let policy = read_vectors(POLICY_REL, POLICY_MODULE, None);
    assert_top_level_catalog(&policy, "policy", POLICY_VECTORS);
    assert!(!policy.contains("entire_test"), "policy");
    assert_eq!(
        policy
            .matches("\"type\": \"find_ambiguous_events\"")
            .count(),
        5,
        "policy"
    );
    assert_eq!(
        policy.matches("\"type\": \"check_step_scope\"").count(),
        3,
        "policy"
    );
    assert_eq!(policy.matches("\"unproven\": false").count(), 3, "policy");
    assert!(!policy.contains("\"unproven\": true"), "policy");
    assert_absent(&policy, "policy", PIN_IDENTIFIERS);
    let dangling = vector_slice(&policy, "ambiguous_dangling_call");
    assert!(dangling.contains("\"v\": \"call-a\""));
    assert!(dangling.contains("\"v\": \"corr-a\""));
    assert!(dangling.contains("\"v\": \"bash\""));
    assert!(!dangling.contains("\"v\": \"possible\""));
    assert!(!dangling.contains("\"v\": \"c-dangle\""));
    let reused = vector_slice(&policy, "ambiguous_reused_correlation");
    assert!(reused.contains("\"v\": \"call-c1\""));
    assert!(reused.contains("\"v\": \"call-c2\""));
    assert!(reused.contains("\"v\": \"corr-c\""));
    assert!(!reused.contains("\"v\": \"tool_result\""));
    let same_hash = vector_slice(
        &policy,
        "ambiguous_duplicate_results_same_hash_not_conflicting",
    );
    assert!(same_hash.contains("\"indices\": []"));
    assert!(same_hash.contains("\"v\": \"call-d\""));
    assert!(same_hash.contains("\"v\": \"abc\""));
    let conflicting = vector_slice(&policy, "ambiguous_conflicting_result_hashes");
    assert!(conflicting.contains("\"v\": \"call-e\""));
    assert!(conflicting.contains("\"v\": \"unknown\""));
    assert!(conflicting.contains("\"reasons\": []"));
    let missing_region = vector_slice(&policy, "scope_missing_region_fn");
    assert!(missing_region.contains("\"has_recipe_region_fn\": false"));
    assert!(missing_region.contains("\"ok\": false"));
    assert!(missing_region.contains("\"reason\": \"side-effect-scope-unproven\""));
    assert!(missing_region.contains("\"v\": \"read-tool\""));
    assert!(missing_region.contains("\"v\": \"bash-tool\""));
    assert!(missing_region.contains("\"unproven\": false"));
    assert!(!missing_region.contains("\"v\": \"1\""));
    assert!(vector_slice(&policy, "extract_tool_call_bash_unknown")
        .contains("\"type\": \"extract_side_effects\""));
    assert!(vector_slice(&policy, "must_sl203_only_reason").contains("\"type\": \"must_abstain\""));
    assert!(
        vector_slice(&policy, "scope_sl203_abstains_disjoint_region")
            .contains("\"type\": \"check_step_scope\"")
    );

    let torn = read_vectors(TORN_REL, SL002_MODULE, Some("torn-terminal-record-discard"));
    assert_top_level_catalog(&torn, "torn", TORN_VECTORS);
    assert_entire_test_counts(&torn, "torn", 0, TORN_VECTOR_COUNT);
    assert_apply_fn_and_payload_free(
        &torn,
        "torn",
        TORN_VECTORS,
        "RECIPE_TORN_TERMINAL_RECORD_DISCARD",
        "apply_torn_terminal_record_discard",
    );
    assert_absent(&torn, "torn", PIN_IDENTIFIERS);
    assert!(torn.contains(
        "tests/repair/test_scoped_abstention.py::test_scenario_2_dangling_call_in_truncated_region"
    ));
    assert!(torn.contains(
        "tests/repair/test_scoped_abstention.py::test_region_functions_totality_fuzz calls affected_region_torn_terminal_record_discard inside a five-function sweep"
    ));
    assert!(torn.contains("raise before this function runs"));
    let torn_recipe = vector_slice(&torn, "recipe_torn_terminal_record_discard");
    assert!(torn_recipe.contains("\"entire_test\": false"));
    assert!(torn_recipe.contains("\"SL002\""));
    assert!(!torn.contains("\"type\": \"find_ambiguous_events\""));
    assert!(!torn.contains("\"fn\": \"execute\""));

    let restore = read_vectors(
        RESTORE_REL,
        CONSERVATIVE_MODULE,
        Some("proven-unique-parent-restore"),
    );
    assert_top_level_catalog(&restore, "restore", RESTORE_VECTORS);
    assert_entire_test_counts(&restore, "restore", 0, RESTORE_VECTOR_COUNT);
    assert_apply_fn_and_payload_free(
        &restore,
        "restore",
        RESTORE_VECTORS,
        "RECIPE_PROVEN_UNIQUE_PARENT_RESTORE",
        "apply_proven_unique_parent_restore",
    );
    assert_absent(&restore, "restore", PIN_IDENTIFIERS);
    assert!(!restore.contains("zero candidates"), "restore");
    assert!(restore.contains(
        "tests/repair/test_scoped_abstention.py::test_scenario_3_unknown_side_effects_on_relink_target plans and executes"
    ));
    assert!(restore.contains(
        "tests/repair/test_scoped_abstention.py::test_parent_restore_disjoint_from_intermediate_mutating_tool plans and executes"
    ));
    assert!(restore.contains(
        "tests/repair/test_scoped_abstention.py::test_region_functions_totality_fuzz is a multi-function sweep"
    ));
    for &(id, construct) in RESTORE_VECTORS {
        if construct == "recipe_constant" {
            continue;
        }
        let slice = vector_slice(&restore, id);
        let missing_index = slice.contains("missing or invalid target_index");
        let missing_parent = slice.contains("missing parent_id");
        assert!(
            missing_index != missing_parent,
            "{id} should record one early refusal"
        );
    }

    let removal = read_vectors(
        REMOVAL_REL,
        CONSERVATIVE_MODULE,
        Some("duplicate-projection-removal"),
    );
    assert_top_level_catalog(&removal, "removal", REMOVAL_VECTORS);
    assert_entire_test_counts(&removal, "removal", 0, REMOVAL_VECTOR_COUNT);
    assert_apply_fn_and_payload_free(
        &removal,
        "removal",
        REMOVAL_VECTORS,
        "RECIPE_DUPLICATE_PROJECTION_REMOVAL",
        "apply_duplicate_projection_removal",
    );
    assert_absent(&removal, "removal", PIN_IDENTIFIERS);
    assert!(!removal.contains("SL007"), "removal");
    assert!(removal.contains(
        "tests/repair/test_scoped_abstention.py::test_duplicate_projection_removal_disjoint_from_intermediate_mutating_tool plans and executes"
    ));
    assert!(removal.contains("The pin succeeds"));

    let collapse = read_vectors(
        COLLAPSE_REL,
        CONSERVATIVE_MODULE,
        Some("identical-duplicate-collapse"),
    );
    assert_top_level_catalog(&collapse, "collapse", COLLAPSE_VECTORS);
    assert_entire_test_counts(&collapse, "collapse", 0, COLLAPSE_VECTOR_COUNT);
    assert_apply_fn_and_payload_free(
        &collapse,
        "collapse",
        COLLAPSE_VECTORS,
        "RECIPE_IDENTICAL_DUPLICATE_COLLAPSE",
        "apply_identical_duplicate_collapse",
    );
    assert_absent(&collapse, "collapse", PIN_IDENTIFIERS);
    assert!(collapse.contains(
        "tests/repair/test_scoped_abstention.py::test_scenario_1_completed_mutating_call_elsewhere_disjoint_repair executes"
    ));
    assert!(collapse.contains(
        "tests/repair/test_scoped_abstention.py::test_scenario_4_ambiguous_call_adjacent_but_outside_region_boundary_pin plans and executes"
    ));
    assert!(collapse.contains(
        "tests/repair/test_scoped_abstention.py::test_multistep_conservative_repair_no_index_drift_in_executor executes"
    ));
    assert!(collapse.contains(
        "tests/repair/test_scoped_abstention.py::test_region_functions_totality_fuzz is a multi-function sweep"
    ));

    let reunion = read_vectors(
        REUNION_REL,
        CONSERVATIVE_MODULE,
        Some("compaction-projection-reunion"),
    );
    assert_top_level_catalog(&reunion, "reunion", REUNION_VECTORS);
    assert_entire_test_counts(&reunion, "reunion", 3, 3);
    assert_apply_fn_and_payload_free(
        &reunion,
        "reunion",
        REUNION_VECTORS,
        "RECIPE_COMPACTION_PROJECTION_REUNION",
        "apply_compaction_projection_reunion",
    );
    assert_named_entire_true(
        &reunion,
        "reunion",
        REUNION_ENTIRE_TRUE,
        "apply_compaction_projection_reunion",
    );
    assert_absent(&reunion, "reunion", PIN_IDENTIFIERS);
    assert!(reunion.contains(
        "tests/repair/test_scoped_abstention.py::test_region_functions_totality_fuzz is a multi-function sweep"
    ));
    assert!(!reunion.contains("\"mode\": \"success\""));

    let seq = read_vectors(SEQ_REL, CONSERVATIVE_MODULE, Some("seq-renumber"));
    assert_typed_fns(&seq, "seq", SEQ_VECTORS);
    assert!(!seq.contains("entire_test"), "seq");
    assert_absent(&seq, "seq", PIN_IDENTIFIERS);
    let seq_region = vector_slice(&seq, "affected_region_seq_renumber");
    assert!(seq_region.contains("\"mode\": \"python_region\""));
    assert!(seq_region.contains("GAP-seq-renumber-affected-region"));
    assert!(!seq_region.contains("affected_region_torn_terminal_record_discard"));
    let seq_apply = vector_slice(&seq, "seq_renumber_step_idempotent");
    assert!(seq_apply.contains("\"v\": \"a\""));
    assert!(seq_apply.contains("\"v\": \"b\""));
    assert!(!seq_apply.contains("payload"));

    let suffix = read_vectors(
        SUFFIX_REL,
        CONSERVATIVE_MODULE,
        Some("terminal-suffix-discard"),
    );
    assert_top_level_catalog(&suffix, "suffix", SUFFIX_VECTORS);
    assert_entire_test_counts(&suffix, "suffix", 2, 7);
    assert_apply_fn_and_payload_free(
        &suffix,
        "suffix",
        SUFFIX_VECTORS,
        "RECIPE_TERMINAL_SUFFIX_DISCARD",
        "apply_terminal_suffix_discard",
    );
    assert_named_entire_true(
        &suffix,
        "suffix",
        SUFFIX_ENTIRE_TRUE,
        "apply_terminal_suffix_discard",
    );
    assert_absent(&suffix, "suffix", PIN_IDENTIFIERS);
    assert!(suffix.contains(
        "tests/repair/test_scoped_abstention.py::test_region_functions_totality_fuzz parametrizes other region functions. This recipe is not one of those calls."
    ));

    let excision = read_vectors(EXCISION_REL, SALVAGE_MODULE, Some("torn-record-excision"));
    assert_typed_fns(&excision, "excision", EXCISION_VECTORS);
    assert_entire_test_counts(&excision, "excision", 1, 4);
    assert_absent(&excision, "excision", PIN_IDENTIFIERS);
    let sl001 = vector_slice(&excision, "sl001_excisable_precondition");
    assert!(sl001.contains("\"entire_test\": true"));
    assert!(sl001.contains("\"assert_count\": 10"));
    assert!(sl001.contains("\"fn\": \"sl001_excisable\""));
    assert!(!sl001.contains("dummy-unproven"));
    assert!(!sl001.contains("side-effect-abstention"));
    let excision_recipe = vector_slice(&excision, "recipe_torn_record_excision");
    assert!(excision_recipe.contains("\"SL001\""));
    assert!(excision_recipe.contains("\"min_policy\": \"salvage\""));
    assert!(!excision_recipe.contains("entire_test"));
    assert!(!excision.contains("\"fn\": \"register_recipe\""));

    let cited = [
        policy.as_str(),
        torn.as_str(),
        restore.as_str(),
        removal.as_str(),
        collapse.as_str(),
        reunion.as_str(),
        seq.as_str(),
        suffix.as_str(),
        excision.as_str(),
    ];
    for json in cited {
        assert!(!json.contains("\"type\": \"plan\""));
        assert!(!json.contains("\"fn\": \"execute\""));
    }

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let mut found = false;
        for json in cited {
            let marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
            if !json.contains(&marker) {
                continue;
            }
            found = true;
            let slice = vector_slice(json, vector_id);
            assert_eq!(
                slice.matches("\"entire_test\": true").count(),
                1,
                "{}",
                row.name
            );
            for needle in needles {
                assert!(
                    slice.contains(needle),
                    "{} vector {vector_id} is missing {needle}",
                    row.name
                );
            }
        }
        assert!(found, "{} cites missing vector {vector_id}", row.name);
    }
}
