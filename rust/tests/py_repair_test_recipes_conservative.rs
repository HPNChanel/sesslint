//! Dispositions for the 35 `def test_` functions in pinned
//! `tests/repair/test_recipes_conservative.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The card names 35 tests;
//! `lstrip` finds 35 `def test_` functions and none are indented. This
//! integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call repair without a
//! `Cargo.toml` change.
//!
//! `covered` names one id in
//! `parity/recipes/compaction-projection-reunion/vectors.json` or
//! `parity/recipes/terminal-suffix-discard/vectors.json` whose construct is
//! the same function and the same refusal as that entire pinned test.
//! `entire_test` is true and `assert_count` is 1, and the stored events and
//! message are that test. One refusal inside a sweep is not the whole test.
//! A payload-free rewrite of a test whose events carry payload is not that
//! test. A Rust seam while the pin succeeds is not coverage. Sharing a field
//! is not coverage. `duplicate-projection-removal`,
//! `identical-duplicate-collapse`, and `proven-unique-parent-restore` stay
//! `not_applicable` for every test they did not cover. Checkpoint, payload,
//! fixture, plan, and canonical success rows stay gaps. SL001 and SL002 are
//! absent from these sets.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 35;
const COVERED_COUNT: usize = 5;
const MODULE: &str = "sesslint.repair.recipes_conservative";
const REUNION_VECTOR_COUNT: usize = 6;
const SUFFIX_VECTOR_COUNT: usize = 9;
const REMOVAL_VECTOR_COUNT: usize = 5;
const COLLAPSE_VECTOR_COUNT: usize = 14;
const RESTORE_VECTOR_COUNT: usize = 20;
const REUNION_REL: &str = "parity/recipes/compaction-projection-reunion/vectors.json";
const SUFFIX_REL: &str = "parity/recipes/terminal-suffix-discard/vectors.json";
const REMOVAL_REL: &str = "parity/recipes/duplicate-projection-removal/vectors.json";
const COLLAPSE_REL: &str = "parity/recipes/identical-duplicate-collapse/vectors.json";
const RESTORE_REL: &str = "parity/recipes/proven-unique-parent-restore/vectors.json";

/// `covered` names one vector id whose construct is that entire pinned test.
/// `not_applicable` records an apply, plan, fixture, or source check this
/// package cannot reach without a `Cargo.toml` change, or a mode no cited
/// vector records as the full pin outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

const REUNION_VECTORS: &[(&str, &str)] = &[
    ("recipe_compaction_projection_reunion", "recipe_constant"),
    ("reunion_refusal_missing_correlation_id", "apply_refusal"),
    ("reunion_refusal_unclean_pair", "apply_refusal"),
    ("reunion_refusal_zero_boundaries", "apply_refusal"),
    ("reunion_refusal_multiple_boundaries", "apply_refusal"),
    ("reunion_refusal_boundary_at_endpoint", "apply_refusal"),
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

const EMPTY_SESSION_NEEDLES: &[&str] = &[
    "\"type\": \"apply_refusal\"",
    "\"fn\": \"apply_terminal_suffix_discard\"",
    "\"entire_test\": true",
    "\"assert_count\": 1",
    "\"mode\": \"refusal\"",
    "\"error_type\": \"PreconditionFailed\"",
    "\"v\": \"e0\"",
    "\"v\": \"e1\"",
    "\"v\": \"user\"",
    "\"v\": \"assistant\"",
    "\"message\": \"terminal-suffix-discard: cut at index 0 would empty session (refused)\"",
];

const OUT_OF_BOUNDS_NEEDLES: &[&str] = &[
    "\"type\": \"apply_refusal\"",
    "\"fn\": \"apply_terminal_suffix_discard\"",
    "\"entire_test\": true",
    "\"assert_count\": 1",
    "\"mode\": \"refusal\"",
    "\"error_type\": \"PreconditionFailed\"",
    "\"v\": \"e0\"",
    "\"v\": \"user\"",
    "\"v\": 5",
    "\"message\": \"terminal-suffix-discard: cut at index 5 >= session length 1\"",
];

const ZERO_BOUNDARIES_NEEDLES: &[&str] = &[
    "\"type\": \"apply_refusal\"",
    "\"fn\": \"apply_compaction_projection_reunion\"",
    "\"entire_test\": true",
    "\"assert_count\": 1",
    "\"mode\": \"refusal\"",
    "\"error_type\": \"PreconditionFailed\"",
    "\"v\": \"c1\"",
    "\"v\": \"tool_call\"",
    "\"v\": \"r1\"",
    "\"v\": \"tool_result\"",
    "\"message\": \"compaction-projection-reunion: expected exactly 1 boundary strictly between pair, found 0\"",
];

const MULTIPLE_BOUNDARIES_NEEDLES: &[&str] = &[
    "\"type\": \"apply_refusal\"",
    "\"fn\": \"apply_compaction_projection_reunion\"",
    "\"entire_test\": true",
    "\"assert_count\": 1",
    "\"mode\": \"refusal\"",
    "\"error_type\": \"PreconditionFailed\"",
    "\"v\": \"b1\"",
    "\"v\": \"b2\"",
    "\"v\": \"compaction_boundary\"",
    "\"message\": \"compaction-projection-reunion: expected exactly 1 boundary strictly between pair, found 2\"",
];

const ENDPOINT_NEEDLES: &[&str] = &[
    "\"type\": \"apply_refusal\"",
    "\"fn\": \"apply_compaction_projection_reunion\"",
    "\"entire_test\": true",
    "\"assert_count\": 1",
    "\"mode\": \"refusal\"",
    "\"error_type\": \"PreconditionFailed\"",
    "\"boundary_index\"",
    "\"v\": \"b1\"",
    "\"v\": \"r1\"",
    "\"message\": \"compaction-projection-reunion: boundary sits at pair endpoint (not strictly between)\"",
];

const COVERED_PAIRS: &[(&str, &str)] = &[
    (
        "test_suffix_discard_refusal_empty_session",
        "suffix_discard_refusal_empty_session",
    ),
    (
        "test_suffix_discard_refusal_out_of_bounds",
        "suffix_discard_refusal_out_of_bounds",
    ),
    (
        "test_reunion_refusal_zero_boundaries",
        "reunion_refusal_zero_boundaries",
    ),
    (
        "test_reunion_refusal_multiple_boundaries",
        "reunion_refusal_multiple_boundaries",
    ),
    (
        "test_reunion_refusal_boundary_at_endpoint",
        "reunion_refusal_boundary_at_endpoint",
    ),
];

const ABSENT_CODES: &[&str] = &["SL001", "SL002", "cap-overflow", "SL203-refusal"];

const ROWS: &[Row] = &[
    Row {
        name: "test_conservative_recipes_registration_and_handles",
        disposition: Disposition::NotApplicable(
            "list_recipes returns 7 recipes, get_recipe checks handles, preconditions, lossy, and salvage_only for terminal-suffix-discard, identical-duplicate-collapse, proven-unique-parent-restore, compaction-projection-reunion, duplicate-projection-removal, identical-duplicate-drop, and seq-renumber, and recipes_for maps SL003, SL004, SL005, SL104, SL108, SL203, and SL101; each recipe_constant in these five sets is entire_test false and records one recipe, identical-duplicate-drop and seq-renumber sit outside these sets, and one constant is one field of that registration sweep",
        ),
    },
    Row {
        name: "test_register_all_idempotent",
        disposition: Disposition::NotApplicable(
            "register_all_conservative runs twice and list_recipes stays at length 7; each recipe_constant is entire_test false and records one recipe, and these sets do not record that second registration",
        ),
    },
    Row {
        name: "test_terminal_suffix_discard_fixture",
        disposition: Disposition::NotApplicable(
            "apply_terminal_suffix_discard on recipe_suffix_discard.json equals expected_events, canonical_json_bytes matches, and the dropped length equals expected_loss_count; the pin apply succeeds, and recipe_terminal_suffix_discard is recipe_constant with entire_test false, so this fixture success stays a gap",
        ),
    },
    Row {
        name: "test_identical_duplicate_collapse_fixture",
        disposition: Disposition::NotApplicable(
            "apply_identical_duplicate_collapse on recipe_duplicate_collapse.json equals expected_events and canonical_json_bytes matches; the pin apply succeeds, and recipe_identical_duplicate_collapse is recipe_constant with entire_test false, so this canonical success stays a gap",
        ),
    },
    Row {
        name: "test_proven_unique_parent_restore_fixture",
        disposition: Disposition::NotApplicable(
            "recipe_parent_restore.json applies the happy path and compares canonical_json_bytes, then the ambiguous case raises PreconditionFailed matching ambiguous candidates; the happy path succeeds and both cases carry payload, recipe_proven_unique_parent_restore is recipe_constant with entire_test false, and these vectors do not store ambiguous candidates, so one refusal inside that test stays a gap and a payload-free result stays a gap",
        ),
    },
    Row {
        name: "test_compaction_projection_reunion_fixture",
        disposition: Disposition::NotApplicable(
            "apply_compaction_projection_reunion on recipe_reunion.json equals expected_events and canonical_json_bytes matches; the pin apply succeeds, and recipe_compaction_projection_reunion is recipe_constant with entire_test false, so this fixture success stays a gap",
        ),
    },
    Row {
        name: "test_duplicate_projection_removal_fixture",
        disposition: Disposition::NotApplicable(
            "apply_duplicate_projection_removal on recipe_projection_removal.json equals expected_events and canonical_json_bytes matches; the pin apply succeeds, and recipe_duplicate_projection_removal is recipe_constant with entire_test false, so this canonical success stays a gap",
        ),
    },
    // Events e0/user and e1/assistant, cut index 0, one PreconditionFailed.
    Row {
        name: "test_suffix_discard_refusal_empty_session",
        disposition: Disposition::Covered {
            vector_id: "suffix_discard_refusal_empty_session",
            needles: EMPTY_SESSION_NEEDLES,
        },
    },
    // One event e0/user, cut index 5, one PreconditionFailed.
    Row {
        name: "test_suffix_discard_refusal_out_of_bounds",
        disposition: Disposition::Covered {
            vector_id: "suffix_discard_refusal_out_of_bounds",
            needles: OUT_OF_BOUNDS_NEEDLES,
        },
    },
    Row {
        name: "test_suffix_discard_refusal_checkpoint_in_suffix",
        disposition: Disposition::NotApplicable(
            "apply_terminal_suffix_discard on e0, e1, and chk with payload {} at target_index 1 raises PreconditionFailed matching checkpoint at index 2 cannot be discarded; suffix_refusal_checkpoint has that message and assert_count 1 with entire_test false, and its events are evt-keep, evt-next, and evt-mark with no payload, so the stored events differ and this checkpoint row stays a gap",
        ),
    },
    Row {
        name: "test_parent_restore_refusal_zero_candidates",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore on e1 with parent_id unknown-ghost and parent_fingerprint_prefix no-such-id raises PreconditionFailed matching zero candidates; every proven-unique-parent-restore vector is entire_test false, the stored messages are missing or invalid target_index or missing parent_id, and the set does not store zero candidates",
        ),
    },
    Row {
        name: "test_parent_restore_refusal_self_candidate",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore on self-loop-1 with parent_fingerprint_prefix self-loop- raises PreconditionFailed matching zero candidates; restore vectors are entire_test false and their messages are missing or invalid target_index or missing parent_id",
        ),
    },
    Row {
        name: "test_parent_restore_refusal_cross_branch",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore on node-child with branch_id branch-b and params parent_id node-target raises PreconditionFailed matching cross_branch; restore vectors are entire_test false and their messages are missing or invalid target_index or missing parent_id, a different failure mode",
        ),
    },
    Row {
        name: "test_parent_restore_refusal_cross_segment",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore with compaction_boundary b-1 between node-target and node-child raises PreconditionFailed matching cross_segment; restore vectors are entire_test false and do not store that message",
        ),
    },
    // Call c1 and result r1, zero boundaries, one PreconditionFailed.
    Row {
        name: "test_reunion_refusal_zero_boundaries",
        disposition: Disposition::Covered {
            vector_id: "reunion_refusal_zero_boundaries",
            needles: ZERO_BOUNDARIES_NEEDLES,
        },
    },
    // Boundaries b1 and b2 between c1 and r1, one PreconditionFailed.
    Row {
        name: "test_reunion_refusal_multiple_boundaries",
        disposition: Disposition::Covered {
            vector_id: "reunion_refusal_multiple_boundaries",
            needles: MULTIPLE_BOUNDARIES_NEEDLES,
        },
    },
    // Boundary b1 at the pair endpoint, boundary_index 0, one PreconditionFailed.
    Row {
        name: "test_reunion_refusal_boundary_at_endpoint",
        disposition: Disposition::Covered {
            vector_id: "reunion_refusal_boundary_at_endpoint",
            needles: ENDPOINT_NEEDLES,
        },
    },
    Row {
        name: "test_duplicate_projection_removal_differing_fingerprints",
        disposition: Disposition::NotApplicable(
            "apply_duplicate_projection_removal on c1, r1 with payload val 1, and r2 with payload val 2 raises PreconditionFailed matching fingerprints differ; removal_refusal_fingerprints_differ is entire_test false, its events start at evt-kept with correlation corr-synthetic, and it stores no payload, so the stored events differ",
        ),
    },
    Row {
        name: "test_duplicate_collapse_refusal_checkpoint_or_boundary",
        disposition: Disposition::NotApplicable(
            "apply_identical_duplicate_collapse on chk1 and chk2 with payload hash h1 raises PreconditionFailed matching cannot collapse boundary kind; collapse_refusal_boundary_checkpoint stores chk1 and chk2 without payload and entire_test is false, so this payload-free checkpoint refusal stays a gap",
        ),
    },
    Row {
        name: "test_duplicate_collapse_refusal_mixed_kinds",
        disposition: Disposition::NotApplicable(
            "apply_identical_duplicate_collapse on e0 tool_call and e1 tool_result, both with payload data shared, raises PreconditionFailed matching kind mismatch; collapse_refusal_kind_mismatch stores those ids and kinds without payload and entire_test is false, so this payload-free refusal stays a gap",
        ),
    },
    Row {
        name: "test_sl203_refusal_blocks_other_conservative_recipes",
        disposition: Disposition::NotApplicable(
            "plan of one SL203 finding and one SL003 finding returns zero steps and two blocked reasons SL203-refusal; the events carry payload, and these sets do not record SL203-refusal or that plan",
        ),
    },
    Row {
        name: "test_sl203_refusal_when_side_effects_unknown",
        disposition: Disposition::NotApplicable(
            "plan of one SL203 finding on a tool_call whose payload side_effects is unknown returns zero steps and one blocked reason SL203-refusal; these sets do not record that plan",
        ),
    },
    Row {
        name: "test_no_synthetic_success_multiset_proof",
        disposition: Disposition::NotApplicable(
            "five fixtures compare tool_result multisets of canonical_json_bytes hex digests; one fixture inside that sweep stays a gap, and a canonical success stays a gap",
        ),
    },
    Row {
        name: "test_no_synthetic_success_static_grep",
        disposition: Disposition::NotApplicable(
            "a read of recipes_conservative.py rejects a tool_result object literal and a SessionEvent constructed with kind tool_result; these sets do not record that source scan",
        ),
    },
    Row {
        name: "test_purity_and_immutability",
        disposition: Disposition::NotApplicable(
            "apply_compaction_projection_reunion on recipe_reunion.json leaves input_events equal to the deep copy and returns a different list; the pin apply succeeds, so this fixture success stays a gap",
        ),
    },
    Row {
        name: "test_idempotence_where_defined",
        disposition: Disposition::NotApplicable(
            "apply_duplicate_projection_removal on recipe_projection_removal.json with correlation_id c-proj-1 shortens the list by one, then a second apply raises PreconditionFailed matching expected at least 2 results; the first apply succeeds, and removal_refusal_one_result is entire_test false and names correlation corr-synthetic, so the stored input differs and one refusal is one part of the test",
        ),
    },
    Row {
        name: "test_adversarial_1k_identical_duplicates_cap",
        disposition: Disposition::NotApplicable(
            "plan of 1000 SL003 findings returns 256 steps and 744 blocked reasons cap-overflow; these sets do not record cap-overflow or that plan",
        ),
    },
    Row {
        name: "test_duplicate_collapse_second_index_resolves_and_collapses",
        disposition: Disposition::NotApplicable(
            "apply_identical_duplicate_collapse at target_index 2 returns ids e0, e1, and e3; the events carry payload text and the pin apply succeeds, and collapse vectors are refusals or one recipe_constant, all with entire_test false",
        ),
    },
    Row {
        name: "test_duplicate_collapse_rewrites_child_parent_pointers",
        disposition: Disposition::NotApplicable(
            "apply_identical_duplicate_collapse drops msg-1b and sets msg-2 parent_id to msg-1a; the events carry payload and the pin apply succeeds, so this successful rewrite stays a gap",
        ),
    },
    Row {
        name: "test_duplicate_projection_removal_rewrites_child_parent_pointers",
        disposition: Disposition::NotApplicable(
            "apply_duplicate_projection_removal drops res-2 and sets msg-after parent_id to res-1; the events carry payload and the pin apply succeeds, so this successful rewrite stays a gap",
        ),
    },
    Row {
        name: "test_parent_restore_excludes_successor_candidates",
        disposition: Disposition::NotApplicable(
            "apply_proven_unique_parent_restore at target_index 1 with parent_fingerprint_prefix prefix-cand raises PreconditionFailed matching zero candidates because the only id match is the later event prefix-cand-later; restore vectors do not store zero candidates and entire_test is false",
        ),
    },
    Row {
        name: "test_plan_and_apply_compaction_reunion_full_flow",
        disposition: Disposition::NotApplicable(
            "plan of one SL108 finding returns one compaction-projection-reunion step with correlation_id c-full-1 and target_index 1, then apply orders ids c1, r1, and b1; the plan and the apply succeed, and the reunion refusal vectors record boundary refusals, so this successful plan stays a gap",
        ),
    },
    Row {
        name: "test_plan_and_apply_duplicate_projection_full_flow",
        disposition: Disposition::NotApplicable(
            "plan of one SL104 finding returns one duplicate-projection-removal step for correlation c-proj-flow, then apply leaves ids c1 and r1; the events carry payload and the plan and the apply succeed, so this successful plan stays a gap",
        ),
    },
    Row {
        name: "test_plan_and_apply_parent_restore_full_flow",
        disposition: Disposition::NotApplicable(
            "plan of one SL004 finding returns one proven-unique-parent-restore step at target_index 1, then apply leaves parent_id msg-root-123; the plan and the apply succeed, and restore vectors are entire_test false and record index or missing-parent refusals",
        ),
    },
    Row {
        name: "test_terminal_suffix_discard_sl005_entry_index",
        disposition: Disposition::NotApplicable(
            "plan of one SL005 finding under salvage returns one terminal-suffix-discard step at target_index 2, then apply leaves ids e0 and e1; the plan and the apply succeed, and suffix_discard_refusal_out_of_bounds refuses cut index 5 on a one-event session, so this successful plan stays a gap",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_conservative_recipes_registration_and_handles",
    "test_register_all_idempotent",
    "test_terminal_suffix_discard_fixture",
    "test_identical_duplicate_collapse_fixture",
    "test_proven_unique_parent_restore_fixture",
    "test_compaction_projection_reunion_fixture",
    "test_duplicate_projection_removal_fixture",
    "test_suffix_discard_refusal_empty_session",
    "test_suffix_discard_refusal_out_of_bounds",
    "test_suffix_discard_refusal_checkpoint_in_suffix",
    "test_parent_restore_refusal_zero_candidates",
    "test_parent_restore_refusal_self_candidate",
    "test_parent_restore_refusal_cross_branch",
    "test_parent_restore_refusal_cross_segment",
    "test_reunion_refusal_zero_boundaries",
    "test_reunion_refusal_multiple_boundaries",
    "test_reunion_refusal_boundary_at_endpoint",
    "test_duplicate_projection_removal_differing_fingerprints",
    "test_duplicate_collapse_refusal_checkpoint_or_boundary",
    "test_duplicate_collapse_refusal_mixed_kinds",
    "test_sl203_refusal_blocks_other_conservative_recipes",
    "test_sl203_refusal_when_side_effects_unknown",
    "test_no_synthetic_success_multiset_proof",
    "test_no_synthetic_success_static_grep",
    "test_purity_and_immutability",
    "test_idempotence_where_defined",
    "test_adversarial_1k_identical_duplicates_cap",
    "test_duplicate_collapse_second_index_resolves_and_collapses",
    "test_duplicate_collapse_rewrites_child_parent_pointers",
    "test_duplicate_projection_removal_rewrites_child_parent_pointers",
    "test_parent_restore_excludes_successor_candidates",
    "test_plan_and_apply_compaction_reunion_full_flow",
    "test_plan_and_apply_duplicate_projection_full_flow",
    "test_plan_and_apply_parent_restore_full_flow",
    "test_terminal_suffix_discard_sl005_entry_index",
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

fn read_vectors(rel: &str, recipe: &str) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(json.contains(&format!("\"module\": \"{MODULE}\"")));
    assert!(json.contains(&format!("\"recipe\": \"{recipe}\"")));
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

fn assert_modes_and_no_payload(json: &str, rows: &[(&str, &str)], label: &str) {
    for &(id, construct) in rows {
        let slice = vector_slice(json, id);
        assert!(!slice.contains("payload"), "{label} {id} stores payload");
        let mode = if construct == "recipe_constant" {
            "\"mode\": \"recipe\""
        } else {
            "\"mode\": \"refusal\""
        };
        assert!(slice.contains(mode), "{label} {id}");
        assert!(
            slice.contains(&format!("\"type\": \"{construct}\"")),
            "{label} {id}"
        );
    }
}

fn assert_partial_set(json: &str, rows: &[(&str, &str)], label: &str) {
    assert_top_level_catalog(json, label, rows);
    assert_entire_test_counts(json, label, 0, rows.len());
    assert_modes_and_no_payload(json, rows, label);
    for &(id, _) in rows {
        let slice = vector_slice(json, id);
        assert!(slice.contains("\"entire_test\": false"), "{label} {id}");
    }
}

fn assert_restore_failure_modes(json: &str) {
    assert!(!json.contains("zero candidates"), "restore set");
    for &(id, construct) in RESTORE_VECTORS {
        let slice = vector_slice(json, id);
        if construct == "recipe_constant" {
            continue;
        }
        let missing_index = slice.contains("missing or invalid target_index");
        let missing_parent = slice.contains("missing parent_id");
        assert!(
            missing_index != missing_parent,
            "{id} should record one early refusal"
        );
        assert!(!slice.contains("zero candidates"), "{id}");
        assert!(!slice.contains("cross_branch"), "{id}");
        assert!(!slice.contains("cross_segment"), "{id}");
        assert!(!slice.contains("ambiguous candidates"), "{id}");
    }
}

fn assert_covered_shape(slice: &str, name: &str, vector_id: &str) {
    assert_eq!(slice.matches("\"entire_test\": true").count(), 1, "{name}");
    assert_eq!(slice.matches("\"assert_count\": 1").count(), 1, "{name}");
    assert!(!slice.contains("\"entire_test\": false"), "{name}");
    assert!(!slice.contains("payload"), "{name}");
    match vector_id {
        "suffix_discard_refusal_empty_session" => {
            assert!(!slice.contains("cut at index -1"), "{name}");
            assert!(!slice.contains(">= session length"), "{name}");
        }
        "suffix_discard_refusal_out_of_bounds" => {
            assert!(!slice.contains("\"v\": \"assistant\""), "{name}");
            assert!(!slice.contains("\"v\": \"e1\""), "{name}");
            assert!(!slice.contains("would empty session"), "{name}");
        }
        "reunion_refusal_zero_boundaries" => {
            assert!(!slice.contains("compaction_boundary"), "{name}");
            assert!(!slice.contains("\"v\": \"b1\""), "{name}");
            assert!(!slice.contains("found 2"), "{name}");
            assert!(!slice.contains("boundary_index"), "{name}");
        }
        "reunion_refusal_multiple_boundaries" => {
            assert!(!slice.contains("boundary_index"), "{name}");
            assert!(!slice.contains("boundary sits at pair endpoint"), "{name}");
            assert!(!slice.contains("found 0"), "{name}");
        }
        "reunion_refusal_boundary_at_endpoint" => {
            assert!(slice.contains("\"v\": 0"), "{name}");
            assert!(!slice.contains("\"v\": \"b2\""), "{name}");
            assert!(!slice.contains("found 2"), "{name}");
            assert!(!slice.contains("found 0"), "{name}");
        }
        _ => panic!("{name} cites unexpected vector {vector_id}"),
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_conservative_recipe_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REUNION_VECTORS.len(), REUNION_VECTOR_COUNT);
    assert_eq!(SUFFIX_VECTORS.len(), SUFFIX_VECTOR_COUNT);
    assert_eq!(REMOVAL_VECTORS.len(), REMOVAL_VECTOR_COUNT);
    assert_eq!(COLLAPSE_VECTORS.len(), COLLAPSE_VECTOR_COUNT);
    assert_eq!(RESTORE_VECTORS.len(), RESTORE_VECTOR_COUNT);
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
fn cited_conservative_recipe_vectors_are_present() {
    let reunion = read_vectors(REUNION_REL, "compaction-projection-reunion");
    assert_top_level_catalog(&reunion, "reunion", REUNION_VECTORS);
    assert_entire_test_counts(&reunion, "reunion", 3, 3);
    assert_modes_and_no_payload(&reunion, REUNION_VECTORS, "reunion");
    assert_absent(&reunion, "reunion", ABSENT_CODES);
    assert!(!reunion.contains("\"mode\": \"success\""));
    assert!(!reunion.contains("canonical_json"));

    let suffix = read_vectors(SUFFIX_REL, "terminal-suffix-discard");
    assert_top_level_catalog(&suffix, "suffix", SUFFIX_VECTORS);
    assert_entire_test_counts(&suffix, "suffix", 2, 7);
    assert_modes_and_no_payload(&suffix, SUFFIX_VECTORS, "suffix");
    assert_absent(&suffix, "suffix", ABSENT_CODES);
    assert!(!suffix.contains("\"mode\": \"success\""));

    let removal = read_vectors(REMOVAL_REL, "duplicate-projection-removal");
    assert_partial_set(&removal, REMOVAL_VECTORS, "removal");
    assert_absent(&removal, "removal", ABSENT_CODES);
    assert!(!removal.contains("\"mode\": \"success\""));
    assert!(!removal.contains("canonical_json"));

    let collapse = read_vectors(COLLAPSE_REL, "identical-duplicate-collapse");
    assert_partial_set(&collapse, COLLAPSE_VECTORS, "collapse");
    assert_absent(&collapse, "collapse", ABSENT_CODES);
    assert!(!collapse.contains("\"mode\": \"success\""));
    assert!(!collapse.contains("canonical_json"));

    let restore = read_vectors(RESTORE_REL, "proven-unique-parent-restore");
    assert_partial_set(&restore, RESTORE_VECTORS, "restore");
    assert_restore_failure_modes(&restore);
    assert_absent(&restore, "restore", ABSENT_CODES);
    assert!(!restore.contains("\"mode\": \"success\""));
    assert!(!restore.contains("canonical_json"));

    let checkpoint = vector_slice(&suffix, "suffix_refusal_checkpoint");
    assert!(checkpoint.contains("\"entire_test\": false"));
    assert!(checkpoint.contains("\"assert_count\": 1"));
    assert!(checkpoint.contains("evt-keep"));
    assert!(checkpoint.contains("evt-next"));
    assert!(checkpoint.contains("evt-mark"));
    assert!(checkpoint.contains("checkpoint at index 2 cannot be discarded"));
    assert!(!checkpoint.contains("\"v\": \"chk\""));
    assert!(!checkpoint.contains("\"v\": \"e0\""));
    let negative = vector_slice(&suffix, "suffix_refusal_negative_cut");
    assert!(negative.contains("\"entire_test\": false"));
    assert!(negative.contains("cut at index -1 would empty session (refused)"));
    let equals_len = vector_slice(&suffix, "suffix_refusal_cut_equals_length");
    assert!(equals_len.contains("\"entire_test\": false"));
    assert!(equals_len.contains("cut at index 2 >= session length 2"));
    let empty_past = vector_slice(&suffix, "suffix_refusal_empty_events_past_end");
    assert!(empty_past.contains("\"entire_test\": false"));
    assert!(empty_past.contains("cut at index 1 >= session length 0"));
    let param_past = vector_slice(&suffix, "suffix_refusal_param_cut_past_end");
    assert!(param_past.contains("\"entire_test\": false"));
    assert!(param_past.contains("cut at index 9 >= session length 2"));
    assert!(
        vector_slice(&suffix, "recipe_terminal_suffix_discard").contains("\"entire_test\": false")
    );

    let fingerprints = vector_slice(&removal, "removal_refusal_fingerprints_differ");
    assert!(fingerprints.contains("\"entire_test\": false"));
    assert!(fingerprints.contains("evt-kept"));
    assert!(fingerprints.contains("corr-synthetic"));
    assert!(fingerprints.contains("projection fingerprints differ"));
    assert!(!fingerprints.contains("\"v\": \"r1\""));
    let one_result = vector_slice(&removal, "removal_refusal_one_result");
    assert!(one_result.contains("\"entire_test\": false"));
    assert!(one_result
        .contains("expected at least 2 results for correlation 'corr-synthetic', found 1"));
    assert!(!one_result.contains("c-proj-1"));

    let boundary_checkpoint = vector_slice(&collapse, "collapse_refusal_boundary_checkpoint");
    assert!(boundary_checkpoint.contains("\"entire_test\": false"));
    assert!(boundary_checkpoint.contains("\"v\": \"chk1\""));
    assert!(boundary_checkpoint.contains("\"v\": \"chk2\""));
    assert!(boundary_checkpoint.contains("cannot collapse boundary kind 'checkpoint'"));
    assert!(!boundary_checkpoint.contains("h1"));
    let kind_mismatch = vector_slice(&collapse, "collapse_refusal_kind_mismatch");
    assert!(kind_mismatch.contains("\"entire_test\": false"));
    assert!(kind_mismatch.contains("\"v\": \"tool_call\""));
    assert!(kind_mismatch.contains("\"v\": \"tool_result\""));
    assert!(kind_mismatch.contains("kind mismatch between 'tool_call' and 'tool_result'"));
    assert!(!kind_mismatch.contains("shared"));
    assert!(
        vector_slice(&collapse, "collapse_refusal_boundary_compaction")
            .contains("cannot collapse boundary kind 'compaction_boundary'")
    );

    assert!(vector_slice(&restore, "restore_refusal_missing_index")
        .contains("missing or invalid target_index"));
    assert!(vector_slice(&restore, "restore_refusal_missing_parent").contains("missing parent_id"));
    assert!(
        vector_slice(&reunion, "reunion_refusal_missing_correlation_id")
            .contains("\"entire_test\": false")
    );
    assert!(
        vector_slice(&reunion, "reunion_refusal_unclean_pair").contains("\"entire_test\": false")
    );
    assert!(
        vector_slice(&reunion, "recipe_compaction_projection_reunion")
            .contains("\"entire_test\": false")
    );

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
        let slice = if reunion.contains(&marker) {
            vector_slice(&reunion, vector_id)
        } else if suffix.contains(&marker) {
            vector_slice(&suffix, vector_id)
        } else {
            panic!(
                "{} cites {vector_id}, which is not in the reunion or suffix sets",
                row.name
            );
        };
        assert!(
            !removal.contains(&marker) && !collapse.contains(&marker) && !restore.contains(&marker),
            "{} vector {vector_id} also appears in a partial set",
            row.name
        );
        assert_covered_shape(slice, row.name, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
