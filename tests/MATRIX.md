# AC-025 Coverage Matrix (human mirror)

Enforced by `tests/test_coverage_matrix.py`. Each cell is a collected pytest node-id substring (positive / negative / boundary / malformed). Update both files together.

## Reason codes

| Code | Positive | Negative | Boundary | Malformed |
| ---- | -------- | -------- | -------- | --------- |
| SL001 | test_healthy_clean | test_malformed_delegates_SL001 | test_regression_encoding_sl001_mid_and_sl002_tail | test_parse_session_lines_malformed_json |
| SL002 | test_healthy_clean | test_torn_tail_SL002 | test_canonical_torn_final_repairable | test_jsonl_torn_tail_delegates_SL002 |
| SL003 | test_healthy_clean | test_conflicting_dup_policy | test_adversarial_1k_identical_duplicates_cap | test_provenance_coordinates_do_not_cause_conflicting_duplicate |
| SL004 | test_graph healthy_clean | test_sl004_missing_parent | test_caps_missing_parent_and_components | test_adversarial_empty_string_parent |
| SL005 | test_graph healthy_clean | test_sl005_cycle_path | test_multiple_cycles_disjoint | test_adversarial_self_loop |
| SL006 | test_graph healthy_clean | test_sl006_disconnected | test_adversarial_component_tie_breaking | test_converging_branches_into_cycle |
| SL007 | test_graph healthy_clean | test_sl007_two_heads | test_sl007_all_cycle_suppressed | test_adversarial_two_identical_cycles_dup_ids |
| SL008 | test_ts_ordering equal_timestamps_allowed | test_sl008_fixture_single_regression | test_epoch_sentinel_edges_skipped | test_unparseable_and_naive_ts_skipped |
| SL101 | pairing_1 healthy_clean | test_sl101_orphan_fixture | test_multi_orphan_same_corr | test_null_correlation |
| SL102 | pairing_1 healthy_clean | test_sl102_dangling_fixture | test_sl102_torn_tail_not_downgraded | test_empty_string_correlation |
| SL103 | pairing_1 healthy_clean | test_sl103_reused_fixture | test_sl103_plus_sl104_interaction | test_corr_event_id_collision |
| SL104 | pairing_1 healthy_clean | test_sl104_multi_result_fixture | test_adversarial_10k_multi_result | test_unicode_corr_ids |
| SL105 | test_parallel_valid_clean | test_sl105_reversed_fixture | test_reversed_plus_boundary | test_cardinality_precedence |
| SL106 | test_parallel_valid_clean | test_sl106_cross_branch_fixture | test_sl106_scope_mismatch_interleaved_agent | test_sl106_empty_id_deterministic |
| SL107 | test_parallel_valid_clean | test_sl107_gap_fixture | test_profile_severity_modulation_sl107_sl108 | test_nested_fanout_exemption_scaling |
| SL108 | test_parallel_valid_clean | test_sl108_compaction_fixture | test_boundary_at_endpoint_no_sl108 | test_nested_fanout_exemption_scaling |
| SL201 | test_checkpoint_clean | test_sl201_gap_fixture | test_missing_state_hash_triggers_sl201 | test_sl201_run_state_evidence_preservation |
| SL202 | test_checkpoint_clean | test_sl202_divergence_fixture | test_idempotent_duplicate_checkpoint_no_sl202 | test_sl202_run_state_evidence_preservation |
| SL203 | test_checkpoint_clean | test_sl203_continuation_fixture | test_sl203_single_finding_cap | test_compaction_boundary_without_checkpoint_triggers_sl203 |
| SL301 | detect each_vendor_clear_winner | test_version_old_emits_SL301 | test_confidence_boundary_exact_055 | test_lying_extension |
| SL302 | detect each_vendor_clear_winner | test_unknown_type_emits_SL302 | test_regression_sl302_long_type_truncated | test_critical_field_sl302 |
| SL303 | test_dup_keys decode_clean_no_dups | test_fixture_critical_dup | test_dup_cap_truncated | test_strictness_preserved |
| SL204 | test_accounting fixture_consistent_clean | test_fixture_divergent_fires | test_zero_baseline_first_marker_checked | test_non_int_counters_ignored |
| SL205 | test_compaction_coverage fixture_valid_clean | test_fixture_missing_leaf | test_pointerless_boundary_silent | test_broken_ancestor_chain_fires |
| SL206 | test_durable_prefix conformance_healthy_stays_clean | test_trailing_nondurable_fires_once_with_ordinals | test_gap_beyond_durable_range_not_a_hole | test_malformed_codex_markers_ignored |
| SL207 | test_context_pressure fixture_healthy_silent | test_fixture_near_limit_fires | test_boundary_exactly_15pct_silent | test_malformed_markers_ignored |
| SL208 | test_compaction_snapshot e2e_healthy_fixture_silent | test_type_mismatch_fires_once | test_snapshot_only_ids_silent | test_malformed_markers_ignored |
| SL304 | test_schema_drift fixture_compatible_bump_clean | test_fixture_version_drift | test_fixture_multi_transition_cap | test_fixture_foreign_splice |
| SL401 | test_cross_file_links intact_chain_emits_nothing | test_missing_middle_warns_on_child | test_ambiguous_target_warns | test_outside_scan_root_is_info_unresolved |
| SL011 | test_size_anomaly uniform_file_stays_clean | test_outlier_fires_once_with_numbers_only_evidence | test_threshold_boundary_exact | test_missing_size_metadata_yields_nothing |

## Recipes

| Recipe | Positive | Negative | Boundary | Malformed |
| ------ | -------- | -------- | -------- | --------- |
| terminal-suffix-discard | …_fixture | …_refusal_empty_session | …_refusal_out_of_bounds | …_refusal_checkpoint_in_suffix |
| identical-duplicate-collapse | …_fixture | …_mixed_kinds | 1k_duplicates_cap | …_checkpoint_or_boundary |
| proven-unique-parent-restore | …_fixture | …_zero_candidates | …_cross_branch | …_cross_segment |
| compaction-projection-reunion | …_fixture | …_zero_boundaries | …_boundary_at_endpoint | …_multiple_boundaries |
| duplicate-projection-removal | …_fixture | …_differing_fingerprints | test_purity_and_immutability | test_no_synthetic_success_multiset_proof |
| torn-terminal-record-discard | canonical_torn_final_repairable | hostile_repair_refusal_on_non_repairable | sl002_repair_round_trip | regression_encoding_sl001_mid_and_sl002_tail |
| unresolvable-branch-amputate | salvage_recipe_applications | conservative_default_blocks_salvage | amputate_resolves_index_from_root_id | amputate_direct_apply_validation |
| torn-compaction-project | salvage_recipe_applications | conservative_default_blocks_salvage | empty_events_salvage_policy | torn_compaction_direct_apply_validation |
| side-effect-unknown-truncate | salvage_recipe_applications | sl203_refusal_beats_salvage | empty_events_salvage_policy | truncate_direct_apply_validation |
| orphan-result-drop | test_orphan_result_drop_plans_and_applies | test_orphan_result_drop_conservative_blocks | test_orphan_result_drop_resolves_by_params | test_orphan_result_drop_direct_apply_refusals |
