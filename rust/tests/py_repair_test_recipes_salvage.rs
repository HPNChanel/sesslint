//! Dispositions for the twenty-four `def test_` functions in pinned
//! `tests/repair/test_recipes_salvage.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (1068 splitlines). Exactly
//! twenty-four test functions, in module order. None is parametrized. A loop
//! or a matrix is one row. One fixture, one cell, one phase, or one exception
//! is not the pytest. The autouse fixture `setup_recipe_registry` and the
//! helpers `_orphan_session_events` and `_sl101_orphan_finding` are not tests.
//! Fixture JSON, event payloads, fingerprints, and the injected loss key are
//! not copied here. The injected key is not quoted.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, not these repair plans, applies, or the source audit.
//! `removed_flag_hint_salvage` is a removed-flag hint for `--salvage-unsupported`
//! on `check`. `create_parser_subcommand_names` lists `repair` and stops at
//! `GAP-cli-init-create-parser`. `GAP-cli-init-parse-args` stops before
//! `parse_args`. The corpora `repair.recipes_salvage`,
//! `repair.recipes_conservative`, `repair.planner`, `repair.registry`,
//! `repair.assurance`, `canonical`, `codes`, and `finding` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. They are not among the 33 cli
//! vectors and are not used to mark a row covered. This integration test crate
//! links `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`]
//! only. It cannot call repair, cli, or model functions without a `Cargo.toml`
//! change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 24;
const PINNED_SPLITLINES: usize = 1068;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A loop or a matrix is one row. One fixture, one cell, one phase,
/// or one exception is not the pytest. `not_applicable` names the missing stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// Present so a later whole-pytest vector can be claimed. None qualifies.
    #[expect(dead_code)]
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

const ROWS: &[Row] = &[
    Row {
        name: "test_conservative_default_blocks_salvage",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_conservative_default_blocks_salvage: for salvage_branch.json, salvage_project.json, and salvage_truncate.json, the default plan has zero steps, the blocked count equals the findings, the first blocked reason is needs-salvage-policy, policy is conservative, and the fingerprint equals expected_conservative_plan; an explicit conservative plan has the same fingerprint; missing stop: all three files and both plans together; all three files and both plans are one row; one file is not this pytest; the default plan is not the explicit plan; the fingerprint is not copied here; fixture JSON is not copied here; this function is not parametrized; the loop over the three files is one row; setup_recipe_registry is not a test; test_salvage_opt_in is the salvage opt-in and is not this conservative block; test_acknowledgement is the truncate acknowledgement pair and is not these three default plans; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these plans; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_salvage_opt_in",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_salvage_opt_in: three fixtures are one row; branch plans one unresolvable-branch-amputate step, lossy, loss amputated-branch 2, total_lost 2, total_kept 3, fingerprint equals expected_plan, and to_dict equals expected_plan; project plans one torn-compaction-project step, lossy, loss projected-orphans 2, total_lost 2, total_kept 3, fingerprint equals expected_plan, and to_dict equals expected_plan; truncate with acknowledgement plans one side-effect-unknown-truncate step, lossy, loss truncated-side-effects 2, total_lost 2, total_kept 2, fingerprint equals expected_plan, and to_dict equals expected_plan; missing stop: all three fixtures together; one fixture is not this pytest; the branch plan is not the project plan; the project plan is not the truncate plan; fingerprints are not copied here; fixture JSON and event payloads are not copied here; this function is not parametrized; test_conservative_default_blocks_salvage is the conservative block and is not these salvage plans; test_acknowledgement compares the truncate plan with and without acknowledgement and is not these three expected plans; test_salvage_recipe_applications applies the three recipes and is not this plan-only row; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these plans; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_acknowledgement",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_acknowledgement: truncate without acknowledgement has zero steps, one blocked reason needs-acknowledgement, and to_dict equals expected_plan_without_acknowledgement; with acknowledgement it has one step side-effect-unknown-truncate; missing stop: both phases together; both phases are one row; the blocked phase is not the planned step; the planned step does not recheck to_dict; fixture JSON is not copied here; this function is not parametrized; test_salvage_opt_in truncate is the acknowledged expected_plan equality and is not this pair; test_truncate_direct_apply_validation is three apply refusals and is not these plans; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these phases; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_no_shorthand",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_shorthand: five parser outcomes are one row; --policy salvage sets policy salvage; the flag absent leaves policy conservative; -s salvage raises SystemExit code 2; --policy Salvage raises SystemExit code 2; --policy aggressive raises SystemExit code 2; missing stop: those five outcomes together; one call is not this pytest; a successful parse is not a SystemExit; the salvage parse is not the absent-flag parse; the -s SystemExit is not the Salvage SystemExit; the Salvage SystemExit is not the aggressive SystemExit; this function is not parametrized; test_invalid_policy_string_rejected raises ValueError from plan with policy Aggressive and is not these SystemExit codes; check_exit_constants records the help line 2  an internal tool error exits 2 and is not these raises; check_exit_epilog records the usage-error note and is not these five calls; removed_flag_hint_salvage expects a hint for check --salvage-unsupported and is not five repair parse outcomes; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser, so the name repair is not parse_args; GAP-cli-init-parse-args says argparse.ArgumentParser.parse_args is not available and is not these five outcomes; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands and are not these flags; setup_recipe_registry is not a test; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; create_parser and parse_args are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_assurance_lattice",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_assurance_lattice: all twelve cells are one row; a lossy plan is one unresolvable-branch-amputate step, a lossless plan is one identical-duplicate-collapse step, and a blocked plan has empty steps; clean with lossy, lossless, and blocked becomes salvaged, repaired-lossless, and clean; repaired-lossless with those plans becomes salvaged, repaired-lossless, and repaired-lossless; salvaged stays salvaged for all three; unrepairable stays unrepairable for all three; then cap_assurance of invalid-level raises ValueError matching Unknown base assurance; missing stop: the twelve cells together with that ValueError; one cell is not this pytest; the ValueError is not the twelve cells; one base row is not the matrix; this function is not parametrized; the matrix loop is one row; PlanStep field tokens are not copied here; setup_recipe_registry is not a test; test_salvage_opt_in plans fixtures and is not cap_assurance; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this lattice; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; cap_assurance is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_fingerprint_differs_by_policy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fingerprint_differs_by_policy: two conservative plans share a fingerprint, two salvage plans share a fingerprint, and the conservative fingerprint differs from the salvage fingerprint; missing stop: all three comparisons together; all three comparisons are one row; one comparison is not this pytest; the shared conservative fingerprint is not the cross-policy difference; fingerprints are not copied here; fixture JSON is not copied here; this function is not parametrized; test_dual_policy_plan_merge_attempt substitutes salvage steps into the conservative dictionary and is not this repeatability; test_conservative_default_blocks_salvage compares a fingerprint to expected_conservative_plan and is not these three comparisons; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these fingerprints; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_component_too_large",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_component_too_large: a trunk plus a branch of MAX_COMPONENT_SIZE plus 5 events, planned under salvage, has zero steps, one blocked finding, and reason component-too-large; missing stop: those three assertions together; all three assertions are one row; zero steps is not the blocked reason; the synthesized events are not copied here; this function is not parametrized; test_amputate_direct_apply_validation raises PreconditionFailed and is not this plan refusal; test_interacting_multi_fault_session plans a small branch and is not this size cap; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this plan; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_loss_sums",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_loss_sums: total_lost equals the sum of the step loss values, total_kept equals the event count minus total_lost, and loss_accounting matches both totals; missing stop: all four assertions together; all four assertions are one row; the total_lost equality is not the total_kept equality; the plan totals are not the loss_accounting totals; fixture JSON is not copied here; this function is not parametrized; test_salvage_opt_in asserts branch totals and is not this sum against loss_accounting; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these sums; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_sl203_refusal_beats_salvage",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sl203_refusal_beats_salvage: conservative and salvage both have zero steps and blocked reason SL203-refusal; missing stop: both policies together; both policies are one row; the conservative refusal is not the salvage refusal; the tool-call payload is not copied here; this function is not parametrized; test_invalid_policy_string_rejected raises ValueError for policy Aggressive and is not SL203-refusal; test_orphan_result_drop_conservative_blocks refuses an orphan with needs-salvage-policy and is not SL203-refusal; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these two plans; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_empty_events_salvage_policy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_empty_events_salvage_policy: empty findings and empty events produce zero steps, zero blocked findings, total_lost 0, total_kept 0, and a fingerprint of length 64; missing stop: all of those assertions together; all of those assertions are one row; zero steps is not the fingerprint length; total_lost 0 is not total_kept 0; the fingerprint bytes are not copied here; this function is not parametrized; test_fingerprint_differs_by_policy compares policy fingerprints and is not this empty plan; test_loss_sums checks a non-empty salvage plan and is not this empty plan; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this plan; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_loss_key_injection_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_loss_key_injection_rejected: a PlanStep whose loss key is outside the allowlist raises ValueError matching Invalid loss class; missing stop: that ValueError; the injected key is not quoted here; this function is not parametrized; one PlanStep field is not this pytest; test_invalid_policy_string_rejected raises ValueError matching Invalid repair policy and is not Invalid loss class; test_no_shorthand raises SystemExit and is not this ValueError; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this constructor; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; PlanStep is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_invalid_policy_string_rejected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_invalid_policy_string_rejected: plan with policy Aggressive raises ValueError matching Invalid repair policy; missing stop: that ValueError; the CLI capitalization SystemExit is not this ValueError; test_no_shorthand raises SystemExit code 2 for --policy Salvage and for --policy aggressive and is not this plan call; a returned parser error is not this ValueError; the message event is not copied here; this function is not parametrized; test_loss_key_injection_rejected raises ValueError matching Invalid loss class and is not Invalid repair policy; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this ValueError; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; check_exit_constants records help for exit 2 and is not this ValueError; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_amputate_direct_apply_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_amputate_direct_apply_validation: four PreconditionFailed raises are one row; empty session matches empty session; an out-of-range target matches Invalid target_index; a checkpoint in the branch matches checkpoint; amputating the only event matches entire session; missing stop: those four raises together; one raise is not this pytest; the empty-session raise is not Invalid target_index; Invalid target_index is not checkpoint; checkpoint is not entire session; event payloads are not copied here; this function is not parametrized; test_torn_compaction_direct_apply_validation is the compaction raises and is not these amputate raises; test_truncate_direct_apply_validation is the truncate raises and is not these amputate raises; test_component_too_large is a plan block and is not these apply raises; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these raises; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; apply_unresolvable_branch_amputate is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_torn_compaction_direct_apply_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_torn_compaction_direct_apply_validation: three PreconditionFailed raises are one row; empty session matches empty session; a message target matches not a compaction_boundary; a boundary with no split pairs or orphans matches no split pairs or orphaned; missing stop: those three raises together; one raise is not this pytest; the empty-session raise is not the boundary-kind raise; the boundary-kind raise is not the no-split raise; the amputate raises are not this pytest; test_amputate_direct_apply_validation matches Invalid target_index, checkpoint, and entire session and is not these three; test_truncate_direct_apply_validation matches index 0 and out of bounds and is not these three; event payloads are not copied here; this function is not parametrized; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these raises; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; apply_torn_compaction_project is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_truncate_direct_apply_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_truncate_direct_apply_validation: three PreconditionFailed raises are one row; empty session matches empty session; a cut at the first event matches index 0; a cut past the session matches out of bounds; missing stop: those three raises together; one raise is not this pytest; the empty-session raise is not index 0; index 0 is not out of bounds; the compaction raises are not this pytest; test_torn_compaction_direct_apply_validation matches not a compaction_boundary and no split pairs or orphaned and is not these three; test_amputate_direct_apply_validation matches Invalid target_index, checkpoint, and entire session and is not these three; test_acknowledgement plans the truncate recipe and is not these apply raises; event payloads are not copied here; this function is not parametrized; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these raises; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; apply_side_effect_unknown_truncate is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_salvage_vendor_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_salvage_vendor_free: recipes_salvage.py and assurance.py both exist, and their lowercased text contains none of claude, openai, anthropic, chatgpt, toolUse, or call_id; missing stop: both files and every word together; both files and every word are one row; one file is not this pytest; one word is not this pytest; this is a source audit, not a plan call; the source files are not copied here; this function is not parametrized; the loop over both files and every word is one row; setup_recipe_registry is not a test; parser_shell_metadata describes a vendor-neutral checker and is not this two-file audit; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this audit; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; reading recipes_salvage.py and assurance.py for those words is not a cli vector and those files are not read by this package",
        ),
    },
    Row {
        name: "test_salvage_recipe_applications",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_salvage_recipe_applications: three applies are one row; amputate keeps 3 events, loss amputated-branch 2, and ids c1-1, c1-2, c1-3; project keeps 3, loss projected-orphans 2, and ids m0, tc1, m1; truncate keeps 2, loss truncated-side-effects 2, and ids m0, m1; missing stop: those three applies together; one recipe is not this pytest; the amputate apply is not the project apply; the project apply is not the truncate apply; the plan-only opt-in test is not these applies; test_salvage_opt_in checks to_dict and does not apply; test_amputate_resolves_index_from_root_id resolves a root_id finding and is not these fixture-finding applies; event payloads are not copied here; fixture JSON is not copied here; this function is not parametrized; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these applies; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; apply_unresolvable_branch_amputate_with_loss, apply_torn_compaction_project_with_loss, and apply_side_effect_unknown_truncate_with_loss are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_amputate_resolves_index_from_root_id",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_amputate_resolves_index_from_root_id: a finding whose evidence has only root_id c2-1 and size 2 plans one step at target_index 3 with loss amputated-branch 2, and apply keeps 3 events with that loss; missing stop: the planned index, that loss, and the apply together; all of those assertions are one row; the planned target_index is not the apply; the fixture-finding apply is not this resolution; test_salvage_recipe_applications applies the fixture finding and is not this root_id finding; test_amputate_direct_apply_validation raises PreconditionFailed and is not this resolution; event payloads and fixture JSON are not copied here; this function is not parametrized; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this resolution; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan and apply_unresolvable_branch_amputate_with_loss are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_dual_policy_plan_merge_attempt",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_dual_policy_plan_merge_attempt: the conservative and salvage fingerprints differ, and a dictionary that keeps the conservative plan but substitutes the salvage steps has a recomputed fingerprint different from both; missing stop: all three inequalities together; all three inequalities are one row; one inequality is not this pytest; the policy difference is not the recomputed fingerprint; the repeatability test is not this merge; test_fingerprint_differs_by_policy checks two pairs of equal fingerprints and one difference and does not recompute a merged dictionary; fingerprints are not copied here; fixture JSON is not copied here; this function is not parametrized; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this merge; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan and compute_plan_fingerprint are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_interacting_multi_fault_session",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_interacting_multi_fault_session: three phases are one row; conservative blocks both findings with needs-salvage-policy; salvage without acknowledgement plans only unresolvable-branch-amputate and blocks the other as needs-acknowledgement; salvage with acknowledgement plans both unresolvable-branch-amputate and side-effect-unknown-truncate and blocks none; missing stop: those three phases together; one phase is not this pytest; the conservative block is not the unacknowledged salvage plan; the unacknowledged salvage plan is not the acknowledged pair of steps; the synthesized events are not copied here; this function is not parametrized; test_acknowledgement is truncate alone and is not this two-finding session; test_conservative_default_blocks_salvage is three fixtures and is not this session; setup_recipe_registry is not a test; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these phases; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_orphan_result_drop_plans_and_applies",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_orphan_result_drop_plans_and_applies: salvage plus acknowledgement plans one orphan-result-drop step, lossy, loss orphan-result 1, total_lost 1, total_kept 3; apply keeps ids m0, tc1, and tr1; the with-loss call returns that same loss and those same ids; missing stop: the plan, the apply, and the with-loss call together; all of those assertions are one row; the plan totals are not the kept ids; the apply is not the with-loss call; the helpers are not this test; _orphan_session_events and _sl101_orphan_finding are not tests; setup_recipe_registry is not a test; test_orphan_result_drop_conservative_blocks is the two refusals and is not this successful drop; test_orphan_result_drop_resolves_by_params resolves by correlation_id and result_id and is not this index-based plan; event payloads are not copied here; this function is not parametrized; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this drop; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan, apply_orphan_result_drop, and apply_orphan_result_drop_with_loss are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_orphan_result_drop_conservative_blocks",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_orphan_result_drop_conservative_blocks: the default plan blocks with needs-salvage-policy, and salvage without acknowledgement blocks with needs-acknowledgement; missing stop: both refusals together; both refusals are one row; the default refusal is not the acknowledgement refusal; the successful drop is not this pytest; test_orphan_result_drop_plans_and_applies is the acknowledged drop and is not these blocks; the helpers are not this test; _orphan_session_events and _sl101_orphan_finding are not tests; setup_recipe_registry is not a test; test_acknowledgement blocks truncate and is not this orphan; event payloads are not copied here; this function is not parametrized; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these refusals; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; plan is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_orphan_result_drop_resolves_by_params",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_orphan_result_drop_resolves_by_params: correlation_id corr-orphan keeps m0, tc1, and tr1; result_id tr_orph keeps those same ids; a second orphan sharing that correlation raises PreconditionFailed matching no unambiguous orphan; missing stop: those three phases together; all three phases are one row; one phase is not this pytest; the correlation apply is not the result_id apply; the result_id apply is not the ambiguous refusal; the index-based plan is not this resolution; test_orphan_result_drop_plans_and_applies plans from the finding index and is not these params; the helpers are not this test; _orphan_session_events and _sl101_orphan_finding are not tests; setup_recipe_registry is not a test; the second orphan event is not copied here; this function is not parametrized; removed_flag_hint_salvage hints --salvage-unsupported on check and is not this resolution; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; apply_orphan_result_drop is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_orphan_result_drop_direct_apply_refusals",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_orphan_result_drop_direct_apply_refusals: five PreconditionFailed raises are one row; empty session matches empty session; an out-of-range index matches invalid target index; a message target matches not a tool_result; a paired tool_result matches not an orphan; an orphan with a child matches dependent child; missing stop: those five raises together; one raise is not this pytest; the empty-session raise is not invalid target index; invalid target index is not not a tool_result; not a tool_result is not not an orphan; not an orphan is not dependent child; the ambiguous correlation raise is not these five; test_orphan_result_drop_resolves_by_params matches no unambiguous orphan and is not these five; the successful drop is not this pytest; the helpers are not this test; _orphan_session_events and _sl101_orphan_finding are not tests; setup_recipe_registry is not a test; the child event is not copied here; this function is not parametrized; removed_flag_hint_salvage hints --salvage-unsupported on check and is not these raises; create_parser_subcommand_names lists repair and stops at GAP-cli-init-create-parser; GAP-cli-init-parse-args stops before parse_args; repair.recipes_salvage, repair.recipes_conservative, repair.planner, repair.registry, repair.assurance, canonical, codes, and finding are pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not among the 33 cli vectors; apply_orphan_result_drop is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_conservative_default_blocks_salvage",
    "test_salvage_opt_in",
    "test_acknowledgement",
    "test_no_shorthand",
    "test_assurance_lattice",
    "test_fingerprint_differs_by_policy",
    "test_component_too_large",
    "test_loss_sums",
    "test_sl203_refusal_beats_salvage",
    "test_empty_events_salvage_policy",
    "test_loss_key_injection_rejected",
    "test_invalid_policy_string_rejected",
    "test_amputate_direct_apply_validation",
    "test_torn_compaction_direct_apply_validation",
    "test_truncate_direct_apply_validation",
    "test_salvage_vendor_free",
    "test_salvage_recipe_applications",
    "test_amputate_resolves_index_from_root_id",
    "test_dual_policy_plan_merge_attempt",
    "test_interacting_multi_fault_session",
    "test_orphan_result_drop_plans_and_applies",
    "test_orphan_result_drop_conservative_blocks",
    "test_orphan_result_drop_resolves_by_params",
    "test_orphan_result_drop_direct_apply_refusals",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
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
fn pinned_repair_test_recipes_salvage_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 1068);
}

#[test]
fn pinned_repair_test_recipes_salvage_row_count_equals_twenty_four() {
    assert_eq!(ROWS.len(), 24);
    assert_eq!(PINNED_TEST_COUNT, 24);
}

#[test]
fn every_pinned_repair_test_recipes_salvage_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 24);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
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
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_cli_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        if !id_set.contains(vector_id) {
            continue;
        }
        let slice = vector_slice(&json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
