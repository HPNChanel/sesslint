"""Repair planning and recipe framework (Milestone M4 / TASK-018).

This package implements the dry-run repair planning core for SessLint:
- Recipe metadata definitions and in-memory registry.
- Precondition context and machine-checked predicates.
- Pure in-memory deterministic plan planner.
- Stable 64-character cryptographic plan fingerprinting.
"""

from __future__ import annotations

from sesslint.repair.assurance import (
    ASSURANCE_LATTICE,
    cap_assurance,
)
from sesslint.repair.errors import (
    Abstained,
    OutputInvalid,
    PlanSourceMismatch,
    PlanTampered,
    PolicyMismatch,
    RepairError,
    RepairRefused,
)
from sesslint.repair.executor import (
    SQLITE_MAGIC,
    execute,
    is_live_store_path,
    load_plan,
    load_session_source,
    load_session_source_with_findings,
    run_all_checks,
)
from sesslint.repair.fingerprint import (
    canonical_json_bytes,
    compute_plan_fingerprint,
)
from sesslint.repair.planner import (
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
)
from sesslint.repair.preconditions import (
    PRECONDITION_FUNCS,
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
)
from sesslint.repair.recipes_conservative import (
    RECIPE_COMPACTION_PROJECTION_REUNION,
    RECIPE_DUPLICATE_PROJECTION_REMOVAL,
    RECIPE_IDENTICAL_DUPLICATE_COLLAPSE,
    RECIPE_PROVEN_UNIQUE_PARENT_RESTORE,
    RECIPE_TERMINAL_SUFFIX_DISCARD,
    PreconditionFailed,
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
)
from sesslint.repair.recipes_conservative import (
    RECIPES as CONSERVATIVE_RECIPES,
)
from sesslint.repair.recipes_conservative import (
    register_all as register_all_conservative_recipes,
)
from sesslint.repair.recipes_salvage import (
    MAX_COMPONENT_SIZE,
    RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE,
    RECIPE_TORN_COMPACTION_PROJECT,
    RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE,
    apply_side_effect_unknown_truncate,
    apply_side_effect_unknown_truncate_with_loss,
    apply_torn_compaction_project,
    apply_torn_compaction_project_with_loss,
    apply_unresolvable_branch_amputate,
    apply_unresolvable_branch_amputate_with_loss,
)
from sesslint.repair.recipes_salvage import (
    RECIPES as SALVAGE_RECIPES,
)
from sesslint.repair.recipes_salvage import (
    register_all as register_all_salvage_recipes,
)
from sesslint.repair.recipes_sl002 import (
    RECIPE_TORN_TERMINAL_RECORD_DISCARD,
    apply_torn_terminal_record_discard,
)
from sesslint.repair.recipes_sl002 import (
    register_all as register_all_sl002_recipes,
)
from sesslint.repair.registry import (
    REGISTRY,
    Recipe,
    clear_registry,
    get_recipe,
    list_recipes,
    recipes_for,
    register_recipe,
)

__all__ = [
    "ALLOWED_LOSS_CLASSES",
    "ASSURANCE_LATTICE",
    "Abstained",
    "CONSERVATIVE_RECIPES",
    "EMPTY_EVENTS_HASH",
    "MAX_COMPONENT_SIZE",
    "MAX_STEPS",
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
]

register_all_conservative_recipes()
register_all_salvage_recipes()
register_all_sl002_recipes()
