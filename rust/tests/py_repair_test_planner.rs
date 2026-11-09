//! Dispositions for the 22 `def test_` functions in pinned
//! `tests/repair/test_planner.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The card names 22 tests;
//! `lstrip` finds 22 `def test_` functions and none are indented. This
//! integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `repair.registry/vectors.json`,
//! `repair.preconditions/vectors.json`, `repair.planner/vectors.json`,
//! `repair.fingerprint/vectors.json`, or `repair/vectors.json` whose construct
//! is the same function and the same success or failure mode as that entire
//! pinned test. One example inside a sweep, a different input string, or a
//! shared field is not coverage. A Rust seam while the pin test succeeds is
//! not coverage. Canonical JSON and fingerprint seams stay gaps.
//! `not_applicable` records a `register_recipe`, `register_precondition`,
//! `plan`, predicate, or `compute_plan_fingerprint` check this package cannot
//! reach without a `Cargo.toml` change, or a mode no vector records as the
//! full pin outcome. `plan` after the policy checks stops at
//! `GAP-planner-register-all`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 22;
const REGISTRY_VECTOR_COUNT: usize = 16;
const PRECONDITIONS_VECTOR_COUNT: usize = 37;
const PLANNER_VECTOR_COUNT: usize = 17;
const FINGERPRINT_VECTOR_COUNT: usize = 7;
const REGISTRY_VECTORS_REL: &str = "parity/vectors/repair.registry/vectors.json";
const PRECONDITIONS_VECTORS_REL: &str = "parity/vectors/repair.preconditions/vectors.json";
const PLANNER_VECTORS_REL: &str = "parity/vectors/repair.planner/vectors.json";
const FINGERPRINT_VECTORS_REL: &str = "parity/vectors/repair.fingerprint/vectors.json";
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

const REGISTRY_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("recipe_empty_name", "recipe_try_new"),
    ("recipe_plain_handles_sort", "recipe_try_new"),
    ("recipe_lossy_sets_salvage_flags", "recipe_try_new"),
    ("recipe_salvage_only_policy", "recipe_try_new"),
    ("recipe_both_lossy_flags", "recipe_try_new"),
    ("recipe_strict_min_policy_preserved", "recipe_try_new"),
    ("recipe_mixed_case_min_policy", "recipe_try_new"),
    ("recipe_whitespace_name_custom_version", "recipe_try_new"),
    ("recipe_callables_stored_not_invoked", "recipe_try_new"),
    (
        "planner_registry_registration_and_lookup",
        "registration_lookup",
    ),
    ("planner_duplicate_name_rejected", "duplicate_name"),
    ("planner_unknown_precondition_rejected", "unknown_precondition"),
    ("empty_precondition_list_skips_table", "empty_preconditions_register"),
    ("clear_registry_isolation", "clear_registry"),
    ("recipes_for_preserves_insertion_order", "insertion_order"),
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

const REPAIR_VECTORS: &[(&str, &str)] = &[("python_dunder_all", "public_name_list")];

const ROWS: &[Row] = &[
    Row {
        name: "test_registry_registration_and_lookup",
        disposition: Disposition::NotApplicable(
            "register_recipe of stub-clean-1 for SL101, then get_recipe of that name and of non-existent, recipes_for of SL101 and SL201, and list_recipes equality with the registered recipe all succeed; planner_registry_registration_and_lookup is registration_lookup and records the listed recipes only as list_names, which is not that list_recipes equality",
        ),
    },
    Row {
        name: "test_registry_duplicate_name_rejected",
        disposition: Disposition::NotApplicable(
            "the second register_recipe of duplicate-stub raises ValueError matching Duplicate recipe name; planner_duplicate_name_rejected is type duplicate_name on those two recipes and also requires list_names and first_handles, which this pytest does not assert",
        ),
    },
    Row {
        name: "test_registry_unknown_precondition_rejected",
        disposition: Disposition::NotApplicable(
            "register_recipe of bad-precondition-stub whose only precondition is non_existent_precondition raises ValueError matching unknown precondition; planner_unknown_precondition_rejected is type unknown_precondition and its precondition list is no_sl203, non_existent_precondition, and also_missing, a different input",
        ),
    },
    Row {
        name: "test_custom_precondition_registration",
        disposition: Disposition::NotApplicable(
            "register_precondition custom_test_flag, then plan under profile neutral blocks with precondition-failed:custom_test_flag and plan under profile strict returns one custom-prec-stub step; register_precondition_empty_name is register_precondition of an empty name with a non-empty-string ValueError, check_preconditions_unknown is check_preconditions of missing_precondition, and one of the two plan results would not be the sweep. plan after the policy checks stops at GAP-planner-register-all",
        ),
    },
    Row {
        name: "test_built_in_predicates",
        disposition: Disposition::NotApplicable(
            "one test calls no_sl203, side_effects_known, repairability_is_safe_auto, repairability_is_salvage, and source_hash_pinned on an SL101 context and calls the same predicates except repairability_is_salvage on an SL203 manual context; no_sl203_present is predicate no_sl203 value false on a deterministic SL203 finding, side_effects_tool_unknown is side_effects_known value false for possible rather than unknown, repairability_safe_auto is repairability_is_safe_auto value true on a different code than SL101, repairability_salvage is value true, and source_hash_pinned_len64 is source_hash_pinned value true on a different 64-character hash. One bool inside that sweep is not the whole test",
        ),
    },
    Row {
        name: "test_basic_plan_fixture",
        disposition: Disposition::NotApplicable(
            "register_recipe stub-strip-call and plan of the basic fixture match its fingerprint, source hash, and to_dict, and a second plan keeps that fingerprint; plan_empty_conservative_success_gap is plan_call gap register_all with step_count 0 while the pin plan succeeds, and no planner vector records that fixture. Canonical JSON and fingerprint seams stay gaps",
        ),
    },
    Row {
        name: "test_blocked_plan_fixture",
        disposition: Disposition::NotApplicable(
            "plan of the blocked fixture has zero steps, one blocked reason SL203-refusal, and matches that fixture fingerprint and to_dict; no_sl203_present is predicate no_sl203 value false, plan_empty_conservative_success_gap has blocked_count 0, and no planner vector records SL203-refusal. A fingerprint seam stays a gap",
        ),
    },
    Row {
        name: "test_empty_plan_fixture",
        disposition: Disposition::NotApplicable(
            "plan of no findings and no events matches the empty fixture fingerprint and to_dict, with the empty-events hash and zero steps and zero blocked; plan_empty_conservative_success_gap is plan_call gap register_all with step_count 0, blocked_count 0, and policy null while the pin plan succeeds, and compute_events_source_hash_empty is compute_events_source_hash rather than that plan. Sharing the empty digest is not the fixture equality. Canonical JSON and fingerprint seams stay gaps",
        ),
    },
    Row {
        name: "test_fingerprint_stability",
        disposition: Disposition::NotApplicable(
            "compute_plan_fingerprint is equal for one plan dict, the same dict with reversed keys, and that dict plus a fingerprint key; plan_fp_extra_fingerprint_policy_omitted is compute_plan_fingerprint of id s1 with an extra fingerprint field and matches plan_fp_small_policy_omitted, which is a different input, and one equality is not the three-call sweep. Canonical JSON and fingerprint seams stay gaps",
        ),
    },
    Row {
        name: "test_first_match_wins",
        disposition: Disposition::NotApplicable(
            "plan of one SL101 finding chooses recipe stub-first when stub-second was registered later; recipes_for_preserves_insertion_order is insertion_order for synthetic-clean then aaa-later on SL101 and does not call plan, and plan_empty_conservative_success_gap has step_count 0 while the pin plan succeeds",
        ),
    },
    Row {
        name: "test_cap_overflow",
        disposition: Disposition::NotApplicable(
            "plan of 300 SL101 findings yields 256 steps and 44 blocked entries whose only reason is cap-overflow; module_constants_snapshot is module_constants with max_steps 256 and is not that plan, and plan_empty_conservative_success_gap has step_count 0 and blocked_count 0. No planner vector records cap-overflow",
        ),
    },
    Row {
        name: "test_duplicate_finding_fingerprint_deduped",
        disposition: Disposition::NotApplicable(
            "plan of two SL101 findings with one shared fingerprint yields one step and zero blocked entries; plan_empty_conservative_success_gap is plan_call gap register_all with step_count 0 while the pin plan succeeds, and no planner vector records that dedup",
        ),
    },
    Row {
        name: "test_target_missing_event_index",
        disposition: Disposition::NotApplicable(
            "plan of one SL101 finding whose target index is outside the event list blocks with reason target-missing; plan_empty_conservative_success_gap has blocked_count 0, and no planner vector records target-missing",
        ),
    },
    Row {
        name: "test_manual_and_unknown_repairability_blocked",
        disposition: Disposition::NotApplicable(
            "plan of three findings blocks all three, with reasons repairability-manual, repairability-unsupported, and repairability-unknown; repairability_safe_auto is predicate repairability_is_safe_auto value true on a different code than SL101, plan_empty_conservative_success_gap has blocked_count 0, and one reason would not be the three-reason sweep",
        ),
    },
    Row {
        name: "test_no_recipe_available_blocked",
        disposition: Disposition::NotApplicable(
            "plan of one SL302 finding with an empty registry blocks with reason no-recipe; registry module_all_export_order only lists recipes_for, plan_empty_conservative_success_gap has blocked_count 0, and no planner vector records no-recipe",
        ),
    },
    Row {
        name: "test_no_writes_static_audit",
        disposition: Disposition::NotApplicable(
            "a static scan of repair sources other than executor rejects write primitives; python_dunder_all is public_name_list and names plan, and no cited vector records that source scan",
        ),
    },
    Row {
        name: "test_no_writes_runtime_read_only_proof",
        disposition: Disposition::NotApplicable(
            "plan of one SL101 finding returns one step while open rejects write modes; plan_empty_conservative_success_gap stops at register_all with step_count 0 while the pin plan succeeds, and no cited vector records that open guard",
        ),
    },
    Row {
        name: "test_vendor_free",
        disposition: Disposition::NotApplicable(
            "a source scan of every repair module rejects vendor keywords; python_dunder_all is public_name_list, and no cited vector records that scan",
        ),
    },
    Row {
        name: "test_perf_10k_findings",
        disposition: Disposition::NotApplicable(
            "plan of 10000 SL101 findings yields 256 steps and the rest blocked, and a fresh process must finish that plan in under 2 seconds; module_constants_snapshot records max_steps 256 and is not that plan or the time bound, and plan_empty_conservative_success_gap has step_count 0 while the pin plan succeeds",
        ),
    },
    Row {
        name: "test_planner_conservative_blocks_salvage_recipe",
        disposition: Disposition::NotApplicable(
            "plan under conservative blocks with needs-salvage-policy, and plan under salvage returns one stub-salvage-recipe step; salvage_policy_conservative is predicate salvage_policy value false and salvage_policy_salvage is value true, neither call is plan, one of the two results would not be the sweep, and the salvage plan succeeds while plan_empty_conservative_success_gap stops at register_all with step_count 0",
        ),
    },
    Row {
        name: "test_planner_conservative_invariant_raises_on_lossy_step",
        disposition: Disposition::NotApplicable(
            "plan under conservative raises ValueError matching Conservative plan cannot include salvage-class or lossy step; plan_policy_aggressive is plan_call for policy Aggressive with an invalid-policy message, recipe_lossy_sets_salvage_flags is recipe_try_new and expects salvage_only true for lossy-conservative, and neither is that plan error",
        ),
    },
    Row {
        name: "test_planner_policy_fingerprint_distinctness",
        disposition: Disposition::NotApplicable(
            "plan of one event under conservative and plan under salvage return different fingerprints; plan_empty_conservative_success_gap is plan_call gap register_all with policy null while both pin plans succeed, and plan_fp_small_policy_conservative is compute_plan_fingerprint of id s1. Canonical JSON and fingerprint seams stay gaps",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_registry_registration_and_lookup",
    "test_registry_duplicate_name_rejected",
    "test_registry_unknown_precondition_rejected",
    "test_custom_precondition_registration",
    "test_built_in_predicates",
    "test_basic_plan_fixture",
    "test_blocked_plan_fixture",
    "test_empty_plan_fixture",
    "test_fingerprint_stability",
    "test_first_match_wins",
    "test_cap_overflow",
    "test_duplicate_finding_fingerprint_deduped",
    "test_target_missing_event_index",
    "test_manual_and_unknown_repairability_blocked",
    "test_no_recipe_available_blocked",
    "test_no_writes_static_audit",
    "test_no_writes_runtime_read_only_proof",
    "test_vendor_free",
    "test_perf_10k_findings",
    "test_planner_conservative_blocks_salvage_recipe",
    "test_planner_conservative_invariant_raises_on_lossy_step",
    "test_planner_policy_fingerprint_distinctness",
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
fn every_pinned_planner_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REGISTRY_VECTORS.len(), REGISTRY_VECTOR_COUNT);
    assert_eq!(PRECONDITIONS_VECTORS.len(), PRECONDITIONS_VECTOR_COUNT);
    assert_eq!(PLANNER_VECTORS.len(), PLANNER_VECTOR_COUNT);
    assert_eq!(FINGERPRINT_VECTORS.len(), FINGERPRINT_VECTOR_COUNT);
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
fn cited_planner_vectors_are_present() {
    let registry = read_vectors(REGISTRY_VECTORS_REL, "sesslint.repair.registry");
    assert_top_level_catalog(&registry, "registry", REGISTRY_VECTORS);
    let exports = vector_slice(&registry, "module_all_export_order");
    assert!(exports.contains("\"type\": \"module_all\""));
    assert!(exports.contains("register_recipe"));
    assert!(exports.contains("get_recipe"));
    assert!(exports.contains("recipes_for"));
    assert!(exports.contains("list_recipes"));
    let lookup = vector_slice(&registry, "planner_registry_registration_and_lookup");
    assert!(lookup.contains("\"type\": \"registration_lookup\""));
    assert!(lookup.contains("stub-clean-1"));
    assert!(lookup.contains("\"code\": \"SL101\""));
    assert!(lookup.contains("\"other_code\": \"SL201\""));
    assert!(lookup.contains("\"missing_name\": \"non-existent\""));
    assert!(lookup.contains("no_sl203"));
    assert!(lookup.contains("\"list_names\""));
    assert!(
        !lookup.contains("list_recipes"),
        "registration_lookup must not be treated as list_recipes equality"
    );
    let duplicate = vector_slice(&registry, "planner_duplicate_name_rejected");
    assert!(duplicate.contains("\"type\": \"duplicate_name\""));
    assert!(duplicate.contains("duplicate-stub"));
    assert!(
        duplicate.contains("Duplicate recipe name: 'duplicate-stub' is already registered")
    );
    assert!(duplicate.contains("\"list_names\""));
    assert!(duplicate.contains("\"first_handles\""));
    assert!(duplicate.contains("\"SL101\""));
    let unknown = vector_slice(&registry, "planner_unknown_precondition_rejected");
    assert!(unknown.contains("\"type\": \"unknown_precondition\""));
    assert!(unknown.contains("bad-precondition-stub"));
    assert!(unknown.contains("non_existent_precondition"));
    assert!(unknown.contains("also_missing"));
    assert!(unknown.contains("no_sl203"));
    assert!(unknown.contains("unknown precondition"));
    let lossy = vector_slice(&registry, "recipe_lossy_sets_salvage_flags");
    assert!(lossy.contains("\"type\": \"recipe_try_new\""));
    assert!(lossy.contains("lossy-conservative"));
    assert!(lossy.contains("\"salvage_only\": true"));
    assert!(!lossy.contains("bypassed-recipe"));
    let order = vector_slice(&registry, "recipes_for_preserves_insertion_order");
    assert!(order.contains("\"type\": \"insertion_order\""));
    assert!(order.contains("synthetic-clean"));
    assert!(order.contains("aaa-later"));
    assert!(order.contains("\"shared_code\": \"SL101\""));
    assert!(!order.contains("stub-first"));
    assert_absent(
        &registry,
        "registry",
        &[
            "cap-overflow",
            "target-missing",
            "no-recipe",
            "needs-salvage-policy",
            "SL203-refusal",
            "precondition-failed",
            "custom_test_flag",
            "stub-first",
            "stub-strip-call",
            "stub-salvage-recipe",
            "Conservative plan cannot include",
            "bypassed-recipe",
            "shutil",
            "toolUse",
            "PermissionError",
        ],
    );

    let preconditions = read_vectors(PRECONDITIONS_VECTORS_REL, "sesslint.repair.preconditions");
    assert_top_level_catalog(&preconditions, "preconditions", PRECONDITIONS_VECTORS);
    let no_sl203 = vector_slice(&preconditions, "no_sl203_present");
    assert!(no_sl203.contains("\"type\": \"predicate\""));
    assert!(no_sl203.contains("\"predicate\": \"no_sl203\""));
    assert!(no_sl203.contains("\"code\": \"SL203\""));
    assert!(no_sl203.contains("\"repairability\": \"DETERMINISTIC\""));
    assert!(no_sl203.contains("\"value\": false"));
    assert!(!no_sl203.contains("\"repairability\": \"MANUAL\""));
    let side_unknown = vector_slice(&preconditions, "side_effects_tool_unknown");
    assert!(side_unknown.contains("\"predicate\": \"side_effects_known\""));
    assert!(side_unknown.contains("\"v\": \"possible\""));
    assert!(side_unknown.contains("\"value\": false"));
    assert!(!side_unknown.contains("\"v\": \"unknown\""));
    let safe_auto = vector_slice(&preconditions, "repairability_safe_auto");
    assert!(safe_auto.contains("\"predicate\": \"repairability_is_safe_auto\""));
    assert!(safe_auto.contains("\"value\": true"));
    assert!(safe_auto.contains("\"code\": \"SL005\""));
    assert!(!safe_auto.contains("\"code\": \"SL101\""));
    let salvage_pred = vector_slice(&preconditions, "repairability_salvage");
    assert!(salvage_pred.contains("\"predicate\": \"repairability_is_salvage\""));
    assert!(salvage_pred.contains("\"value\": true"));
    let hash_pinned = vector_slice(&preconditions, "source_hash_pinned_len64");
    assert!(hash_pinned.contains("\"predicate\": \"source_hash_pinned\""));
    assert!(hash_pinned.contains("\"value\": true"));
    assert!(hash_pinned.contains("\"source_hash\": \"g"));
    assert!(!hash_pinned.contains(&"a".repeat(64)));
    let hash_open = vector_slice(&preconditions, "source_hash_unpinned");
    assert!(hash_open.contains("\"predicate\": \"source_hash_pinned\""));
    assert!(hash_open.contains("\"source_hash\": \"\""));
    assert!(hash_open.contains("\"value\": false"));
    let empty_name = vector_slice(&preconditions, "register_precondition_empty_name");
    assert!(empty_name.contains("\"type\": \"register_precondition\""));
    assert!(empty_name.contains("\"name\": \"\""));
    assert!(empty_name.contains("Precondition name must be a non-empty string"));
    let missing_prec = vector_slice(&preconditions, "check_preconditions_unknown");
    assert!(missing_prec.contains("\"type\": \"check_preconditions\""));
    assert!(missing_prec.contains("Unknown precondition: missing_precondition"));
    let salvage_cons = vector_slice(&preconditions, "salvage_policy_conservative");
    assert!(salvage_cons.contains("\"predicate\": \"salvage_policy\""));
    assert!(salvage_cons.contains("\"policy\": \"conservative\""));
    assert!(salvage_cons.contains("\"value\": false"));
    let salvage_ok = vector_slice(&preconditions, "salvage_policy_salvage");
    assert!(salvage_ok.contains("\"predicate\": \"salvage_policy\""));
    assert!(salvage_ok.contains("\"policy\": \"salvage\""));
    assert!(salvage_ok.contains("\"value\": true"));
    assert_absent(
        &preconditions,
        "preconditions",
        &[
            "cap-overflow",
            "target-missing",
            "no-recipe",
            "needs-salvage-policy",
            "SL203-refusal",
            "precondition-failed",
            "custom_test_flag",
            "custom-prec-stub",
            "repairability-manual",
            "repairability-unsupported",
            "repairability-unknown",
            "Conservative plan cannot include",
            "stub-salvage-recipe",
            "shutil",
            "toolUse",
            "PermissionError",
        ],
    );

    let planner = read_vectors(PLANNER_VECTORS_REL, "sesslint.repair.planner");
    assert_top_level_catalog(&planner, "planner", PLANNER_VECTORS);
    assert!(planner.contains("GAP-planner-register-all"));
    assert!(planner.contains("does not return a RepairPlan on the pin success path"));
    let constants = vector_slice(&planner, "module_constants_snapshot");
    assert!(constants.contains("\"type\": \"module_constants\""));
    assert!(constants.contains("\"max_steps\": 256"));
    let empty_hash = vector_slice(&planner, "compute_events_source_hash_empty");
    assert!(empty_hash.contains("\"type\": \"compute_events_source_hash\""));
    let aggressive = vector_slice(&planner, "plan_policy_aggressive");
    assert!(aggressive.contains("\"type\": \"plan_call\""));
    assert!(aggressive.contains("\"policy\": \"Aggressive\""));
    assert!(aggressive.contains(
        "Invalid repair policy: 'Aggressive'. Must be 'conservative' or 'salvage'"
    ));
    let plan_empty = vector_slice(&planner, "plan_empty_conservative_success_gap");
    assert!(plan_empty.contains("\"type\": \"plan_call\""));
    assert!(plan_empty.contains("\"gap\": \"register_all\""));
    assert!(plan_empty.contains("\"step_count\": 0"));
    assert!(plan_empty.contains("\"blocked_count\": 0"));
    assert!(plan_empty.contains("\"policy\": null"));
    assert_eq!(planner.matches("\"step_count\":").count(), 1);
    assert!(!planner.contains("\"step_count\": 1"));
    assert!(!planner.contains("\"blocked_count\": 1"));
    assert_absent(
        &planner,
        "planner",
        &[
            "cap-overflow",
            "target-missing",
            "no-recipe",
            "needs-salvage-policy",
            "SL203-refusal",
            "precondition-failed",
            "custom_test_flag",
            "custom-prec-stub",
            "stub-first",
            "stub-strip-call",
            "stub-salvage-recipe",
            "plan_basic",
            "plan_blocked.json",
            "plan_empty.json",
            "repairability-manual",
            "repairability-unsupported",
            "repairability-unknown",
            "Conservative plan cannot include",
            "bypassed-recipe",
            "shutil",
            "toolUse",
            "PermissionError",
        ],
    );

    let fingerprint = read_vectors(FINGERPRINT_VECTORS_REL, "sesslint.repair.fingerprint");
    assert_top_level_catalog(&fingerprint, "fingerprint", FINGERPRINT_VECTORS);
    let small = vector_slice(&fingerprint, "plan_fp_small_policy_omitted");
    assert!(small.contains("\"type\": \"compute_plan_fingerprint\""));
    assert!(small.contains("\"id\": \"s1\""));
    let extra = vector_slice(&fingerprint, "plan_fp_extra_fingerprint_policy_omitted");
    assert!(extra.contains("\"type\": \"compute_plan_fingerprint\""));
    assert!(extra.contains("\"id\": \"s1\""));
    assert!(extra.contains("\"fingerprint\""));
    let conservative = vector_slice(&fingerprint, "plan_fp_small_policy_conservative");
    assert!(conservative.contains("\"type\": \"compute_plan_fingerprint\""));
    assert!(conservative.contains("\"id\": \"s1\""));
    assert!(conservative.contains("\"policy\": \"conservative\""));
    assert!(vector_slice(&fingerprint, "module_all_export_order").contains("compute_plan_fingerprint"));
    assert!(vector_slice(&fingerprint, "canonical_json_non_ascii_newline_true")
        .contains("\"type\": \"canonical_json_bytes\""));
    assert_absent(
        &fingerprint,
        "fingerprint",
        &[
            "stub-1",
            "abc123",
            "loss_accounting",
            "cap-overflow",
            "stub-salvage-recipe",
            "shutil",
            "toolUse",
            "PermissionError",
        ],
    );

    let repair = read_vectors(REPAIR_VECTORS_REL, "sesslint.repair");
    assert_top_level_catalog(&repair, "repair", REPAIR_VECTORS);
    let names = vector_slice(&repair, "python_dunder_all");
    assert!(names.contains("\"type\": \"public_name_list\""));
    assert!(names.contains("\"plan\""));
    assert!(names.contains("register_recipe"));
    assert!(names.contains("register_precondition"));
    assert!(names.contains("compute_plan_fingerprint"));
    assert!(names.contains("no_sl203"));
    assert_absent(
        &repair,
        "repair",
        &[
            "\"type\": \"plan_call\"",
            "\"type\": \"register_recipe\"",
            "cap-overflow",
            "target-missing",
            "no-recipe",
            "SL203-refusal",
            "needs-salvage-policy",
            "custom_test_flag",
            "shutil",
            "toolUse",
            "PermissionError",
        ],
    );

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
        let slice = if registry.contains(&marker) {
            vector_slice(&registry, vector_id)
        } else if preconditions.contains(&marker) {
            vector_slice(&preconditions, vector_id)
        } else if planner.contains(&marker) {
            vector_slice(&planner, vector_id)
        } else if fingerprint.contains(&marker) {
            vector_slice(&fingerprint, vector_id)
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
