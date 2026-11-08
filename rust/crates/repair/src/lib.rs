//! Empty scaffold for the `repair` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::RepairError;

pub mod assurance;
pub mod fingerprint;
pub mod preconditions;
pub mod refusals;
pub mod registry;
pub mod recipes_sl002;
pub mod planner;
pub mod errors;
pub mod recipes_conservative;
pub mod recipes_salvage;
pub mod vetting;
pub mod writeback;
pub mod executor;

// `sesslint.repair` package surface from `repair/__init__.py` `__all__`
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
// `RepairError` stays the existing `error::RepairError` re-export.
// `errors::RepairError` is a different public type and is not imported again.
// `PRECONDITION_FUNCS`, `REGISTRY`, and `run_all_checks` have no public item.
// `run_all_checks` is absent from `executor` and is not declared here.
// The three `register_all` aliases are not called: each returns `Result` and
// mutates the recipe registry.

#[rustfmt::skip]
pub use assurance::{
    ASSURANCE_CEILING_TABLE,
    ASSURANCE_LATTICE,
    cap_assurance,
    compute_assurance_ceiling,
};
#[rustfmt::skip]
pub use errors::{
    Abstained,
    ManifestCollision,
    OutputInvalid,
    PlanSourceMismatch,
    PlanTampered,
    PolicyMismatch,
    RepairRefused,
    VendorRepairRefused,
};
#[rustfmt::skip]
pub use executor::{
    SQLITE_MAGIC,
    execute,
    is_live_store_path,
    load_plan,
    load_session_source,
    load_session_source_with_findings,
};
#[rustfmt::skip]
pub use fingerprint::{canonical_json_bytes, compute_plan_fingerprint};
#[rustfmt::skip]
pub use planner::{
    ALLOWED_LOSS_CLASSES,
    EMPTY_EVENTS_HASH,
    MAX_STEPS,
    PLAN_VERSION,
    Blocked,
    Loss,
    PlanStep,
    RepairPlan,
    compute_events_source_hash,
    plan,
};
#[rustfmt::skip]
pub use preconditions::{
    PreconditionContext,
    acknowledge_side_effects,
    adjacent_identical_duplicate,
    branch_has_no_checkpoint,
    check_preconditions,
    duplicate_projection_identical,
    no_prior_safe_tool_after_cut,
    no_sl203,
    register_precondition,
    repairability_is_safe_auto,
    repairability_is_salvage,
    salvage_policy,
    side_effects_known,
    single_boundary_split,
    sl108_present,
    source_hash_pinned,
    unique_parent_candidate,
};
#[rustfmt::skip]
pub use recipes_conservative::{
    CONSERVATIVE_RECIPES,
    PreconditionFailed,
    RECIPE_COMPACTION_PROJECTION_REUNION,
    RECIPE_DUPLICATE_PROJECTION_REMOVAL,
    RECIPE_IDENTICAL_DUPLICATE_COLLAPSE,
    RECIPE_PROVEN_UNIQUE_PARENT_RESTORE,
    RECIPE_TERMINAL_SUFFIX_DISCARD,
    apply_compaction_projection_reunion,
    apply_duplicate_projection_removal,
    apply_identical_duplicate_collapse,
    apply_proven_unique_parent_restore,
    apply_terminal_suffix_discard,
    compaction_projection_reunion,
    duplicate_projection_removal,
    identical_duplicate_collapse,
    proven_unique_parent_restore,
    terminal_suffix_discard,
    register_all as register_all_conservative_recipes,
};
#[rustfmt::skip]
pub use recipes_salvage::{
    MAX_COMPONENT_SIZE,
    RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE,
    RECIPE_TORN_COMPACTION_PROJECT,
    RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE,
    SALVAGE_RECIPES,
    apply_side_effect_unknown_truncate,
    apply_side_effect_unknown_truncate_with_loss,
    apply_torn_compaction_project,
    apply_torn_compaction_project_with_loss,
    apply_unresolvable_branch_amputate,
    apply_unresolvable_branch_amputate_with_loss,
    register_all as register_all_salvage_recipes,
};
#[rustfmt::skip]
pub use recipes_sl002::{
    RECIPE_TORN_TERMINAL_RECORD_DISCARD,
    apply_torn_terminal_record_discard,
    register_all as register_all_sl002_recipes,
};
#[rustfmt::skip]
pub use registry::{
    Recipe,
    clear_registry,
    get_recipe,
    list_recipes,
    recipes_for,
    register_recipe,
};

/// Pin `repair/__init__.py` `__all__`, in that order.
pub const ALL: &[&str] = &[
    "ALLOWED_LOSS_CLASSES",
    "ASSURANCE_CEILING_TABLE",
    "ASSURANCE_LATTICE",
    "Abstained",
    "CONSERVATIVE_RECIPES",
    "EMPTY_EVENTS_HASH",
    "MAX_COMPONENT_SIZE",
    "MAX_STEPS",
    "ManifestCollision",
    "OutputInvalid",
    "PLAN_VERSION",
    "PRECONDITION_FUNCS",
    "PlanSourceMismatch",
    "PlanTampered",
    "PolicyMismatch",
    "PreconditionFailed",
    "RECIPE_COMPACTION_PROJECTION_REUNION",
    "RECIPE_DUPLICATE_PROJECTION_REMOVAL",
    "RECIPE_IDENTICAL_DUPLICATE_COLLAPSE",
    "RECIPE_PROVEN_UNIQUE_PARENT_RESTORE",
    "RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE",
    "RECIPE_TERMINAL_SUFFIX_DISCARD",
    "RECIPE_TORN_COMPACTION_PROJECT",
    "RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE",
    "REGISTRY",
    "RepairError",
    "RepairRefused",
    "SALVAGE_RECIPES",
    "VendorRepairRefused",
    "SQLITE_MAGIC",
    "Blocked",
    "Loss",
    "PlanStep",
    "PreconditionContext",
    "Recipe",
    "RepairPlan",
    "acknowledge_side_effects",
    "adjacent_identical_duplicate",
    "apply_compaction_projection_reunion",
    "apply_duplicate_projection_removal",
    "apply_identical_duplicate_collapse",
    "apply_proven_unique_parent_restore",
    "apply_side_effect_unknown_truncate",
    "apply_side_effect_unknown_truncate_with_loss",
    "apply_terminal_suffix_discard",
    "apply_torn_compaction_project",
    "apply_torn_compaction_project_with_loss",
    "apply_unresolvable_branch_amputate",
    "apply_unresolvable_branch_amputate_with_loss",
    "branch_has_no_checkpoint",
    "canonical_json_bytes",
    "cap_assurance",
    "check_preconditions",
    "clear_registry",
    "compaction_projection_reunion",
    "compute_assurance_ceiling",
    "compute_events_source_hash",
    "compute_plan_fingerprint",
    "duplicate_projection_identical",
    "duplicate_projection_removal",
    "execute",
    "get_recipe",
    "identical_duplicate_collapse",
    "is_live_store_path",
    "list_recipes",
    "load_plan",
    "load_session_source",
    "load_session_source_with_findings",
    "no_prior_safe_tool_after_cut",
    "no_sl203",
    "plan",
    "proven_unique_parent_restore",
    "recipes_for",
    "register_all_conservative_recipes",
    "register_all_salvage_recipes",
    "register_all_sl002_recipes",
    "register_precondition",
    "register_recipe",
    "repairability_is_safe_auto",
    "repairability_is_salvage",
    "run_all_checks",
    "salvage_policy",
    "side_effects_known",
    "single_boundary_split",
    "sl108_present",
    "source_hash_pinned",
    "terminal_suffix_discard",
    "unique_parent_candidate",
    "RECIPE_TORN_TERMINAL_RECORD_DISCARD",
    "apply_torn_terminal_record_discard",
];

#[cfg(test)]
mod tests {
    #[test]
    fn register_aliases_name_existing_items_without_invoking_them() {
        same_item(
            super::register_all_conservative_recipes,
            super::recipes_conservative::register_all,
        );
        same_item(
            super::register_all_salvage_recipes,
            super::recipes_salvage::register_all,
        );
        same_item(
            super::register_all_sl002_recipes,
            super::recipes_sl002::register_all,
        );
        assert_eq!(super::ALL.len(), 90);
        assert_eq!(super::ALL.first().copied(), Some("ALLOWED_LOSS_CLASSES"));
        assert_eq!(super::ALL.get(11).copied(), Some("PRECONDITION_FUNCS"));
        assert_eq!(super::ALL.get(24).copied(), Some("REGISTRY"));
        assert_eq!(super::ALL.get(80).copied(), Some("run_all_checks"));
        assert_eq!(
            super::ALL.last().copied(),
            Some("apply_torn_terminal_record_discard")
        );
    }

    /// Names two function items. The items are not called.
    fn same_item<T>(left: T, right: T) {
        let _ = (left, right);
    }
}
