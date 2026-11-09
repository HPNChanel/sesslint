//! Dispositions for the 18 `def test_` functions in pinned
//! `tests/test_challenger_stress.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The card names 18 tests;
//! the pin has 18. This integration test crate links `sesslint-rust-workspace`,
//! whose library exports [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.graph/vectors.json`,
//! `repair.recipes_conservative/vectors.json`,
//! `repair.preconditions/vectors.json`, `repair.planner/vectors.json`,
//! `repair.executor/vectors.json`, `repair.fingerprint/vectors.json`,
//! `repair.errors/vectors.json`, `repair.vetting/vectors.json`,
//! `finding/vectors.json`, or `repair/vectors.json` whose construct is the
//! same function and the same success or failure mode as that entire pinned
//! test. One example inside a sweep, a graph reason string, an export name,
//! or a shared `RepairRefused` substring is not coverage. A Rust seam while
//! the pin test succeeds is not coverage.
//! `not_applicable` records an `apply_proven_unique_parent_restore`, `plan`,
//! `execute`, `compute_plan_fingerprint`, `make_finding`,
//! `unique_parent_candidate`, `is_qualifying_parent_candidate`,
//! `find_qualifying_parent_candidates`, `check_missing_parent`,
//! `same_compaction_segment`, `vet_plan`, `PlanTampered`, `RepairRefused`,
//! or `PlanSourceMismatch` check this package cannot reach without a
//! `Cargo.toml` change, or a mode no vector records as the full pin
//! outcome. `plan` after the policy checks stops at `GAP-planner-register-all`.
//! `execute` after the step cap stops at `GAP-repair-executor-import-stops`.
//! Parent-restore apply calls are named in `module_all` and are not vectors.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 18;
const GRAPH_VECTOR_COUNT: usize = 20;
const RECIPES_VECTOR_COUNT: usize = 12;
const PRECONDITIONS_VECTOR_COUNT: usize = 37;
const PLANNER_VECTOR_COUNT: usize = 17;
const EXECUTOR_VECTOR_COUNT: usize = 17;
const FINGERPRINT_VECTOR_COUNT: usize = 7;
const ERRORS_VECTOR_COUNT: usize = 25;
const VETTING_VECTOR_COUNT: usize = 20;
const GRAPH_VECTORS_REL: &str = "parity/vectors/checks.graph/vectors.json";
const RECIPES_VECTORS_REL: &str = "parity/vectors/repair.recipes_conservative/vectors.json";
const PRECONDITIONS_VECTORS_REL: &str = "parity/vectors/repair.preconditions/vectors.json";
const PLANNER_VECTORS_REL: &str = "parity/vectors/repair.planner/vectors.json";
const EXECUTOR_VECTORS_REL: &str = "parity/vectors/repair.executor/vectors.json";
const FINGERPRINT_VECTORS_REL: &str = "parity/vectors/repair.fingerprint/vectors.json";
const ERRORS_VECTORS_REL: &str = "parity/vectors/repair.errors/vectors.json";
const VETTING_VECTORS_REL: &str = "parity/vectors/repair.vetting/vectors.json";
const FINDING_VECTORS_REL: &str = "parity/vectors/finding/vectors.json";
const REPAIR_VECTORS_REL: &str = "parity/vectors/repair/vectors.json";

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

/// Top-level ids. Nested event `"id"` fields are indented further.
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

const RECIPES_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("registration_handles_matrix", "registration_matrix"),
    ("register_all_idempotent", "register_all"),
    ("fixture_terminal_suffix_discard", "fixture_apply"),
    ("suffix_discard_refusal_empty_session", "apply"),
    ("suffix_discard_refusal_out_of_bounds", "apply"),
    ("suffix_discard_refusal_checkpoint_in_suffix", "apply"),
    ("reunion_refusal_zero_boundaries", "apply"),
    ("reunion_refusal_multiple_boundaries", "apply"),
    ("reunion_refusal_boundary_at_endpoint", "apply"),
    ("duplicate_collapse_refusal_checkpoint_or_boundary", "apply"),
    ("duplicate_collapse_refusal_mixed_kinds", "apply"),
];

const PRECONDITIONS_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("precondition_func_names_order", "precondition_func_names"),
    ("no_sl203_empty", "predicate"),
    ("no_sl203_present", "predicate"),
    ("side_effects_empty", "predicate"),
    ("side_effects_tool_unknown", "predicate"),
    ("side_effects_tool_none", "predicate"),
    ("repairability_safe_auto", "predicate"),
    ("repairability_salvage", "predicate"),
    ("source_hash_unpinned", "predicate"),
    ("source_hash_pinned_len64", "predicate"),
    ("adjacent_scan_match", "predicate"),
    ("adjacent_scan_no_match", "predicate"),
    ("adjacent_fingerprint_seam", "predicate"),
    ("unique_parent_no_finding", "predicate"),
    ("unique_parent_orphan", "predicate"),
    ("unique_parent_graph_seam", "predicate"),
    ("single_boundary_one", "predicate"),
    ("single_boundary_none", "predicate"),
    ("duplicate_projection_match", "predicate"),
    ("sl003_identical_duplicate_ok", "predicate"),
    ("sl003_identical_duplicate_no_evidence", "predicate"),
    ("salvage_policy_conservative", "predicate"),
    ("salvage_policy_salvage", "predicate"),
    ("acknowledge_side_effects_false", "predicate"),
    ("acknowledge_side_effects_true", "predicate"),
    ("find_component_simple", "_find_component_indices"),
    (
        "torn_compaction_drop",
        "_find_torn_compaction_dropped_indices",
    ),
    ("no_prior_safe_tool_gap", "predicate"),
    ("no_prior_safe_tool_no_trigger", "predicate"),
    ("torn_terminal_record_target", "predicate"),
    ("branch_has_no_checkpoint_ok", "predicate"),
    ("sl108_present_marker", "predicate"),
    ("register_precondition_empty_name", "register_precondition"),
    ("check_preconditions_all_ok", "check_preconditions"),
    ("check_preconditions_first_fail", "check_preconditions"),
    ("check_preconditions_unknown", "check_preconditions"),
];

const PLANNER_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("module_constants_snapshot", "module_constants"),
    (
        "compute_events_source_hash_empty",
        "compute_events_source_hash",
    ),
    ("plan_step_from_dict_not_object", "plan_step_from_dict"),
    ("plan_step_invalid_loss_class", "plan_step_from_dict"),
    ("plan_policy_aggressive", "plan_call"),
    ("plan_policy_empty_string", "plan_call"),
    ("plan_policy_true_bool", "plan_call"),
    ("plan_policy_none", "plan_call"),
    ("plan_policy_int_one", "plan_call"),
    ("plan_empty_conservative_success_gap", "plan_call"),
    ("get_plan_schema_path_gap", "get_plan_schema_path"),
    ("load_plan_schema_gap", "load_plan_schema"),
    ("repair_plan_from_dict_missing_seq", "repair_plan_from_dict"),
    (
        "repair_plan_from_dict_missing_recipe",
        "repair_plan_from_dict",
    ),
    (
        "repair_plan_from_dict_missing_min_policy",
        "repair_plan_from_dict",
    ),
    (
        "repair_plan_from_dict_missing_recipe_version",
        "repair_plan_from_dict",
    ),
];

const EXECUTOR_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("sqlite_magic_bytes", "sqlite_magic"),
    ("module_private_constants", "module_private_constants"),
    ("is_live_store_suffix_db", "is_live_store_path"),
    ("is_live_store_nonmagic_fixture", "is_live_store_path"),
    ("is_live_store_magic_fixture", "is_live_store_path"),
    ("load_session_missing_path", "load_session_not_found"),
    ("load_session_empty_path", "load_session_not_found"),
    ("load_session_directory_path", "load_session_not_found"),
    (
        "load_session_broken_symlink",
        "load_session_with_findings_not_found",
    ),
    (
        "load_session_symlink_file_seam",
        "load_session_snapshot_seam",
    ),
    (
        "load_source_for_format_import_seam",
        "load_source_for_format_gap",
    ),
    ("execute_cap_257", "execute_cap"),
    ("execute_fingerprint_import_seam", "execute_fingerprint_gap"),
    ("source_positions_duplicate_origin", "source_positions_duplicate"),
    ("relocate_step_removed_target", "relocate_step_removed"),
    (
        "load_plan_salvage_under_conservative",
        "load_plan_salvage_policy_mismatch",
    ),
];

const FINGERPRINT_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("plan_fp_small_policy_omitted", "compute_plan_fingerprint"),
    (
        "plan_fp_small_policy_conservative",
        "compute_plan_fingerprint",
    ),
    (
        "plan_fp_extra_fingerprint_policy_omitted",
        "compute_plan_fingerprint",
    ),
    (
        "plan_fp_extra_fingerprint_policy_conservative",
        "compute_plan_fingerprint",
    ),
    (
        "canonical_json_non_ascii_newline_true",
        "canonical_json_bytes",
    ),
    (
        "canonical_json_non_ascii_newline_false",
        "canonical_json_bytes",
    ),
];

const ERRORS_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("repair_error_default", "RepairError"),
    ("plan_tampered_default", "PlanTampered"),
    ("abstained_default", "Abstained"),
    ("policy_mismatch_default", "PolicyMismatch"),
    ("output_invalid_default", "OutputInvalid"),
    ("repair_refused_default", "RepairRefused"),
    ("vendor_repair_refused_default", "VendorRepairRefused"),
    ("manifest_collision_default", "ManifestCollision"),
    (
        "vendor_projection_refused_default",
        "VendorProjectionRefused",
    ),
    ("plan_source_mismatch_default", "PlanSourceMismatch"),
    ("abstained_sl203_message", "Abstained"),
    ("repair_error_empty_message", "RepairError"),
    ("abstained_empty_message", "Abstained"),
    (
        "vendor_projection_refused_reason_r1",
        "VendorProjectionRefused",
    ),
    (
        "vendor_projection_refused_explicit_empty_reason",
        "VendorProjectionRefused",
    ),
    ("repair_error_custom_code", "RepairError"),
    ("plan_tampered_custom_code", "PlanTampered"),
    ("abstained_custom_code", "Abstained"),
    ("policy_mismatch_custom_code", "PolicyMismatch"),
    ("output_invalid_custom_code", "OutputInvalid"),
    ("repair_refused_custom_code", "RepairRefused"),
    ("vendor_repair_refused_custom_code", "VendorRepairRefused"),
    ("manifest_collision_custom_code", "ManifestCollision"),
    ("plan_source_mismatch_custom_code", "PlanSourceMismatch"),
];

const VETTING_VECTORS: &[(&str, &str)] = &[
    ("plan_step_identity_seq_one", "plan_step_identity"),
    ("plan_step_identity_seq_other", "plan_step_identity"),
    ("plan_step_identity_lossy", "plan_step_identity"),
    (
        "vet_plan_source_hash_mismatch_plan_synthetic_vs_caller",
        "vet_plan",
    ),
    ("vet_plan_source_hash_mismatch_abc_vs_ab", "vet_plan"),
    (
        "vet_plan_source_hash_mismatch_abc_vs_zzabczz",
        "vet_plan",
    ),
    ("vet_plan_source_hash_mismatch_empty_vs_caller", "vet_plan"),
    ("vet_plan_matching_caller_hash", "vet_plan"),
    ("vet_plan_matching_caller_empty_hash", "vet_plan"),
    ("vet_plan_matching_events_hash", "vet_plan"),
    ("vet_plan_matching_events_and_caller_hash", "vet_plan"),
    ("vet_plan_invalid_policy", "vet_plan"),
    ("vet_plan_events_hash_rendered_same", "vet_plan"),
    ("vet_plan_events_hash_rendered_split", "vet_plan"),
    ("vet_plan_events_hash_unrenderable_same", "vet_plan"),
    ("vet_plan_events_hash_unrenderable_split", "vet_plan"),
    ("vet_plan_events_hash_session_same", "vet_plan"),
    ("vet_plan_events_hash_session_split", "vet_plan"),
    ("vet_plan_events_hash_mapping_same", "vet_plan"),
    ("vet_plan_events_hash_mapping_split", "vet_plan"),
];

const REPAIR_VECTORS: &[(&str, &str)] = &[("python_dunder_all", "public_name_list")];

const ROWS: &[Row] = &[
    Row {
        name: "test_forged_step_nonexistent_parent",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore for parent_id forged-nonexistent-id raises PreconditionFailed matching zero candidates matching; module_all_export_order only names that function, registration_handles_matrix lists proven-unique-parent-restore for SL004, no apply vector calls it, find_qualifying_parent_candidates_no_earlier_match returns reason no_full_match for id x-fqc-000, and unique_parent_no_finding is predicate unique_parent_candidate with value false",
        ),
    },
    Row {
        name: "test_forged_step_prefix_collision",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed matching zero candidates matching when the only earlier id is a strict prefix of the requested parent_id; is_qualifying_parent_candidate_prefix_not_full_match returns reason no_full_match for id p-pre-001x with missing_parent_id null, which is a different function and a different reason, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_forged_step_cross_branch_candidate",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed matching cross_branch when the candidate and the child are on different branches; checks.graph records no cross_branch reason, unique_parent_graph_seam stops at GAP-preconditions-parent-candidates, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_forged_step_cross_segment_candidate",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed matching cross_segment when a compaction_boundary sits between the candidate and the child; checks.graph records no cross_segment reason, same_compaction_segment_boundary_between_false returns same false for seq endpoints 0 and 3, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_forged_step_duplicate_candidate",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore raises PreconditionFailed matching ambiguous candidates when two earlier events share the requested parent id; find_qualifying_parent_candidates_two_earlier_exact returns reason ambiguous for missing parent p-fqc-020, which is a finder result rather than that PreconditionFailed, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_forged_step_self_reference",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore at target_index 0 whose parent_id is the child id raises PreconditionFailed matching zero candidates matching; check_missing_parent_self_parent is check_missing_parent with findings_count 0, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_forged_step_post_child_candidate_causal_inversion",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore at target_index 0 whose parent_id occurs later raises PreconditionFailed matching zero candidates matching; check_missing_parent_later_parent is check_missing_parent with findings_count 0, find_qualifying_parent_candidates_no_earlier_match returns reason no_full_match, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_forged_step_invalid_target_index",
        disposition: Disposition::NotApplicable(
            "one test sweeps target_index values -1, 999, the string bad, True, and False, and each apply_proven_unique_parent_restore call raises PreconditionFailed matching missing or invalid target_index; no recipes_conservative vector records that message, and one index would not be the five-call sweep",
        ),
    },
    Row {
        name: "test_forged_step_through_executor_lifecycle",
        disposition: Disposition::NotApplicable(
            "plan on one SL004 finding, a replaced proven-unique-parent-restore step whose parent crosses branches, compute_plan_fingerprint, and execute under policy conservative raise RepairRefused matching not a repair sesslint derives for this source now and leave the output path absent; plan_empty_conservative_success_gap is plan_call gap register_all with step_count 0, execute_fingerprint_import_seam is execute_fingerprint_gap mode fingerprint_unavailable with pin_exception PlanTampered, plan_fp_small_policy_conservative fingerprints id s1, vet_plan_matching_caller_hash is vet_plan mode rust_seam for recipe synthetic-recipe at step 41, make_finding_fingerprint_default_severity is code SL011, and no executor vector has type execute",
        ),
    },
    Row {
        name: "test_events_mutated_in_memory_before_apply",
        disposition: Disposition::NotApplicable(
            "one test sweeps three mutated event lists and expects PreconditionFailed matching no_full_match, then cross_segment, then cross_branch; is_qualifying_parent_candidate_prefix_not_full_match is only reason no_full_match, checks.graph records neither cross_segment nor cross_branch, and one of the three raises would not be the sweep",
        ),
    },
    Row {
        name: "test_disk_file_mutated_between_planning_and_execute",
        disposition: Disposition::NotApplicable(
            "plan on one SL004 finding, an extra event appended to the source file, then execute raises PlanSourceMismatch and leaves the output path absent; vet_plan_source_hash_mismatch_plan_synthetic_vs_caller is vet_plan PlanSourceMismatch for plan-synthetic-hash versus caller-synthetic-hash on an empty event, plan_source_mismatch_default constructs PlanSourceMismatch with message synthetic-plan-source-mismatch, plan_empty_conservative_success_gap has step_count 0, and no executor vector records PlanSourceMismatch",
        ),
    },
    Row {
        name: "test_plan_tampered_detected",
        disposition: Disposition::NotApplicable(
            "plan on one SL004 finding, replace the step parent_id without updating the fingerprint, and execute raises PlanTampered; execute_fingerprint_import_seam stops at mode fingerprint_unavailable while recording pin_exception PlanTampered, plan_tampered_default constructs PlanTampered with message synthetic-plan-tampered, and neither vector is that tampered proven-unique-parent-restore step",
        ),
    },
    Row {
        name: "test_multiple_independent_sl004_findings",
        disposition: Disposition::NotApplicable(
            "plan on two SL004 findings yields two proven-unique-parent-restore steps at target indexes 1 and 3, then execute raises RepairRefused matching not a repair sesslint derives for this source now and leaves the output path absent; plan_empty_conservative_success_gap has step_count 0 under GAP-planner-register-all while the pin plan succeeds, and vet_plan_matching_caller_hash is a rust_seam RepairRefused for synthetic-recipe",
        ),
    },
    Row {
        name: "test_mixed_deterministic_and_manual_sl004_no_crosstalk",
        disposition: Disposition::NotApplicable(
            "plan on one DETERMINISTIC SL004 finding and one MANUAL SL004 finding whose reason is cross_branch yields one step at target index 1 and one blocked entry with reason repairability-manual; planner vectors contain neither SL004 nor repairability-manual, and plan_empty_conservative_success_gap has blocked_count 0",
        ),
    },
    Row {
        name: "test_multiple_children_sharing_same_parent",
        disposition: Disposition::NotApplicable(
            "plan on two SL004 findings yields two steps, and applying each with apply_proven_unique_parent_restore sets both children to the shared parent; plan_empty_conservative_success_gap stops at register_all with step_count 0 while the pin plan succeeds, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_chained_missing_parents_handling",
        disposition: Disposition::NotApplicable(
            "plan on two chained SL004 findings yields two steps, and applying them in order sets the first child parent to root and the second child parent to the first child; plan_empty_conservative_success_gap has step_count 0, and no apply vector calls apply_proven_unique_parent_restore",
        ),
    },
    Row {
        name: "test_corrupted_params_variations",
        disposition: Disposition::NotApplicable(
            "one test calls apply_proven_unique_parent_restore twice, once with an empty parent_id and once with empty params, and both raise PreconditionFailed matching missing parent_id; no recipes_conservative vector records that message, and one call would not be the two-call sweep",
        ),
    },
    Row {
        name: "test_multi_finding_scale_and_order_preservation",
        disposition: Disposition::NotApplicable(
            "plan on twenty SL004 findings yields twenty steps, then execute raises RepairRefused matching not a repair sesslint derives for this source now and leaves the output path absent; execute_cap_257 refuses a 257-step plan with the step-cap message, plan_empty_conservative_success_gap has step_count 0, and a cap refusal is a different failure mode from that twenty-step RepairRefused",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_forged_step_nonexistent_parent",
    "test_forged_step_prefix_collision",
    "test_forged_step_cross_branch_candidate",
    "test_forged_step_cross_segment_candidate",
    "test_forged_step_duplicate_candidate",
    "test_forged_step_self_reference",
    "test_forged_step_post_child_candidate_causal_inversion",
    "test_forged_step_invalid_target_index",
    "test_forged_step_through_executor_lifecycle",
    "test_events_mutated_in_memory_before_apply",
    "test_disk_file_mutated_between_planning_and_execute",
    "test_plan_tampered_detected",
    "test_multiple_independent_sl004_findings",
    "test_mixed_deterministic_and_manual_sl004_no_crosstalk",
    "test_multiple_children_sharing_same_parent",
    "test_chained_missing_parents_handling",
    "test_corrupted_params_variations",
    "test_multi_finding_scale_and_order_preservation",
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

fn assert_absent(json: &str, label: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !json.contains(needle),
            "{label} unexpectedly contains {needle}"
        );
    }
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
fn every_pinned_challenger_stress_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(GRAPH_VECTORS.len(), GRAPH_VECTOR_COUNT);
    assert_eq!(RECIPES_VECTORS.len(), RECIPES_VECTOR_COUNT);
    assert_eq!(PRECONDITIONS_VECTORS.len(), PRECONDITIONS_VECTOR_COUNT);
    assert_eq!(PLANNER_VECTORS.len(), PLANNER_VECTOR_COUNT);
    assert_eq!(EXECUTOR_VECTORS.len(), EXECUTOR_VECTOR_COUNT);
    assert_eq!(FINGERPRINT_VECTORS.len(), FINGERPRINT_VECTOR_COUNT);
    assert_eq!(ERRORS_VECTORS.len(), ERRORS_VECTOR_COUNT);
    assert_eq!(VETTING_VECTORS.len(), VETTING_VECTOR_COUNT);
    assert_eq!(REPAIR_VECTORS.len(), 1);
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
fn cited_challenger_stress_vectors_are_present() {
    let graph = read_vectors(GRAPH_VECTORS_REL, "sesslint.checks.graph");
    assert_top_level_catalog(&graph, "checks.graph", GRAPH_VECTORS);
    assert_absent(
        &graph,
        "checks.graph",
        &[
            "cross_branch",
            "cross_segment",
            "zero candidates",
            "ambiguous candidates",
            "self_candidate",
        ],
    );
    let prefix = vector_slice(
        &graph,
        "is_qualifying_parent_candidate_prefix_not_full_match",
    );
    assert!(prefix.contains("\"type\": \"is_qualifying_parent_candidate\""));
    assert!(prefix.contains("\"v\": \"p-pre-001x\""));
    assert!(prefix.contains("\"missing_parent_id\": null"));
    assert!(prefix.contains("\"reason\": \"no_full_match\""));
    let no_earlier = vector_slice(&graph, "find_qualifying_parent_candidates_no_earlier_match");
    assert!(no_earlier.contains("\"type\": \"find_qualifying_parent_candidates\""));
    assert!(no_earlier.contains("\"v\": \"x-fqc-000\""));
    assert!(no_earlier.contains("\"reason\": \"no_full_match\""));
    let two_earlier = vector_slice(
        &graph,
        "find_qualifying_parent_candidates_two_earlier_exact",
    );
    assert!(two_earlier.contains("\"type\": \"find_qualifying_parent_candidates\""));
    assert!(two_earlier.contains("\"missing_parent_id\": \"p-fqc-020\""));
    assert!(two_earlier.contains("\"reason\": \"ambiguous\""));
    assert!(!two_earlier.contains("ambiguous candidates"));
    let between = vector_slice(&graph, "same_compaction_segment_boundary_between_false");
    assert!(between.contains("\"type\": \"same_compaction_segment\""));
    assert!(between.contains("\"same\": false"));
    assert!(between.contains("\"v\": 0"));
    assert!(between.contains("\"v\": 3"));
    for id in [
        "check_missing_parent_present_parent",
        "check_missing_parent_later_parent",
        "check_missing_parent_self_parent",
    ] {
        let slice = vector_slice(&graph, id);
        assert!(slice.contains("\"type\": \"check_missing_parent\""));
        assert!(
            slice.contains("\"findings_count\": 0"),
            "{id} is a clean check_missing_parent result"
        );
    }

    let recipes = read_vectors(RECIPES_VECTORS_REL, "sesslint.repair.recipes_conservative");
    assert_top_level_catalog(&recipes, "recipes_conservative", RECIPES_VECTORS);
    let exports = vector_slice(&recipes, "module_all_export_order");
    assert!(exports.contains("\"type\": \"module_all\""));
    assert!(exports.contains("apply_proven_unique_parent_restore"));
    let registration = vector_slice(&recipes, "registration_handles_matrix");
    assert!(registration.contains("\"type\": \"registration_matrix\""));
    assert!(registration.contains("proven-unique-parent-restore"));
    assert!(registration.contains("\"SL004\""));
    assert!(registration.contains("unique_parent_candidate"));
    assert!(
        !recipes.contains("\"fn\": \"apply_proven_unique_parent_restore\""),
        "recipes_conservative apply vectors must not be treated as the parent-restore calls"
    );
    assert_absent(
        &recipes,
        "recipes_conservative",
        &[
            "zero candidates matching",
            "ambiguous candidates",
            "cross_segment",
            "cross_branch",
            "no_full_match",
            "missing parent_id",
            "missing or invalid target_index",
            "RepairRefused",
            "PlanTampered",
            "PlanSourceMismatch",
        ],
    );

    let preconditions = read_vectors(PRECONDITIONS_VECTORS_REL, "sesslint.repair.preconditions");
    assert_top_level_catalog(&preconditions, "preconditions", PRECONDITIONS_VECTORS);
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
    assert_absent(
        &preconditions,
        "preconditions",
        &["PreconditionFailed", "apply_proven_unique_parent_restore"],
    );

    let planner = read_vectors(PLANNER_VECTORS_REL, "sesslint.repair.planner");
    assert_top_level_catalog(&planner, "planner", PLANNER_VECTORS);
    assert!(planner.contains("GAP-planner-register-all"));
    let plan_empty = vector_slice(&planner, "plan_empty_conservative_success_gap");
    assert!(plan_empty.contains("\"type\": \"plan_call\""));
    assert!(plan_empty.contains("\"gap\": \"register_all\""));
    assert!(plan_empty.contains("\"step_count\": 0"));
    assert!(plan_empty.contains("\"blocked_count\": 0"));
    assert_absent(
        &planner,
        "planner",
        &[
            "SL004",
            "repairability-manual",
            "proven-unique-parent-restore",
            "RepairRefused",
        ],
    );

    let executor = read_vectors(EXECUTOR_VECTORS_REL, "sesslint.repair.executor");
    assert_top_level_catalog(&executor, "executor", EXECUTOR_VECTORS);
    assert!(executor.contains("GAP-repair-executor-import-stops"));
    let fingerprint_seam = vector_slice(&executor, "execute_fingerprint_import_seam");
    assert!(fingerprint_seam.contains("\"type\": \"execute_fingerprint_gap\""));
    assert!(fingerprint_seam.contains("\"mode\": \"fingerprint_unavailable\""));
    assert!(fingerprint_seam.contains("\"pin_exception\": \"PlanTampered\""));
    let cap = vector_slice(&executor, "execute_cap_257");
    assert!(cap.contains("\"type\": \"execute_cap\""));
    assert!(cap.contains("Plan step count (257) exceeds maximum allowed cap (256)"));
    assert_absent(
        &executor,
        "executor",
        &[
            "RepairRefused",
            "PlanSourceMismatch",
            "proven-unique-parent-restore",
            "\"type\": \"execute\"",
            "not a repair sesslint derives",
        ],
    );

    let fingerprint = read_vectors(FINGERPRINT_VECTORS_REL, "sesslint.repair.fingerprint");
    assert_top_level_catalog(&fingerprint, "fingerprint", FINGERPRINT_VECTORS);
    let small = vector_slice(&fingerprint, "plan_fp_small_policy_conservative");
    assert!(small.contains("\"type\": \"compute_plan_fingerprint\""));
    assert!(small.contains("\"id\": \"s1\""));
    assert!(small.contains("\"policy\": \"conservative\""));
    assert!(vector_slice(&fingerprint, "module_all_export_order").contains("compute_plan_fingerprint"));
    assert_absent(
        &fingerprint,
        "fingerprint",
        &[
            "proven-unique-parent-restore",
            "RepairRefused",
            "PlanTampered",
        ],
    );

    let errors = read_vectors(ERRORS_VECTORS_REL, "sesslint.repair.errors");
    assert_top_level_catalog(&errors, "errors", ERRORS_VECTORS);
    let tampered = vector_slice(&errors, "plan_tampered_default");
    assert!(tampered.contains("\"type\": \"PlanTampered\""));
    assert!(tampered.contains("\"message\": \"synthetic-plan-tampered\""));
    let refused = vector_slice(&errors, "repair_refused_default");
    assert!(refused.contains("\"type\": \"RepairRefused\""));
    assert!(refused.contains("\"message\": \"synthetic-repair-refused\""));
    let mismatch = vector_slice(&errors, "plan_source_mismatch_default");
    assert!(mismatch.contains("\"type\": \"PlanSourceMismatch\""));
    assert!(mismatch.contains("\"message\": \"synthetic-plan-source-mismatch\""));
    assert_absent(
        &errors,
        "errors",
        &[
            "proven-unique-parent-restore",
            "not a repair sesslint derives",
            "\"type\": \"execute\"",
        ],
    );

    let vetting = read_vectors(VETTING_VECTORS_REL, "sesslint.repair.vetting");
    assert_top_level_catalog(&vetting, "vetting", VETTING_VECTORS);
    let vet_refused = vector_slice(&vetting, "vet_plan_matching_caller_hash");
    assert!(vet_refused.contains("\"type\": \"vet_plan\""));
    assert!(vet_refused.contains("\"mode\": \"rust_seam\""));
    assert!(vet_refused.contains("\"error_type\": \"RepairRefused\""));
    assert!(vet_refused.contains("synthetic-recipe"));
    assert!(vet_refused.contains("Plan step 41"));
    assert!(vet_refused.contains("not a repair sesslint derives for this source now"));
    assert!(
        vet_refused.contains("sesslint.repair.recipes_conservative.register_all is not available")
    );
    let vet_mismatch = vector_slice(
        &vetting,
        "vet_plan_source_hash_mismatch_plan_synthetic_vs_caller",
    );
    assert!(vet_mismatch.contains("\"type\": \"vet_plan\""));
    assert!(vet_mismatch.contains("\"error_type\": \"PlanSourceMismatch\""));
    assert!(vet_mismatch.contains("plan-synthetic-hash"));
    assert!(vet_mismatch.contains("caller-synthetic-hash"));
    assert_absent(
        &vetting,
        "vetting",
        &[
            "proven-unique-parent-restore",
            "\"type\": \"execute\"",
            "apply_proven_unique_parent_restore",
        ],
    );

    let finding = read_vectors(FINDING_VECTORS_REL, "sesslint.finding");
    assert_eq!(finding.matches("\"type\": \"make_finding\"").count(), 2);
    let made = vector_slice(&finding, "make_finding_fingerprint_default_severity");
    assert!(made.contains("\"type\": \"make_finding\""));
    assert!(made.contains("\"code\": \"SL011\""));
    let unknown = vector_slice(&finding, "make_finding_unknown_code");
    assert!(unknown.contains("\"type\": \"make_finding\""));
    assert!(unknown.contains("\"code\": \"SL999\""));
    assert!(!finding.contains("\"code\": \"SL004\""));
    assert_absent(
        &finding,
        "finding",
        &[
            "apply_proven_unique_parent_restore",
            "proven-unique-parent-restore",
        ],
    );

    let repair = read_vectors(REPAIR_VECTORS_REL, "sesslint.repair");
    assert_top_level_catalog(&repair, "repair", REPAIR_VECTORS);
    let names = vector_slice(&repair, "python_dunder_all");
    assert!(names.contains("\"type\": \"public_name_list\""));
    assert!(names.contains("apply_proven_unique_parent_restore"));
    assert_absent(
        &repair,
        "repair",
        &[
            "\"type\": \"apply\"",
            "\"type\": \"plan_call\"",
            "\"type\": \"execute\"",
        ],
    );

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
        let slice = if graph.contains(&marker) {
            vector_slice(&graph, vector_id)
        } else if recipes.contains(&marker) {
            vector_slice(&recipes, vector_id)
        } else if preconditions.contains(&marker) {
            vector_slice(&preconditions, vector_id)
        } else if planner.contains(&marker) {
            vector_slice(&planner, vector_id)
        } else if executor.contains(&marker) {
            vector_slice(&executor, vector_id)
        } else if fingerprint.contains(&marker) {
            vector_slice(&fingerprint, vector_id)
        } else if errors.contains(&marker) {
            vector_slice(&errors, vector_id)
        } else if vetting.contains(&marker) {
            vector_slice(&vetting, vector_id)
        } else if finding.contains(&marker) {
            vector_slice(&finding, vector_id)
        } else {
            vector_slice(&repair, vector_id)
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
