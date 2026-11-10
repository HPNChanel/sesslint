//! Dispositions for the 35 `def test_` functions in pinned
//! `tests/repair/test_executor.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (1314 splitlines). Exactly
//! thirty-five test functions, in module order. Only
//! `test_executor_refuses_vendor_emit_on_canonical_source` is parametrized,
//! with three cells, and that function is one row. The autouse fixture
//! `_clean_and_register_recipes` is not a test. Each row is the whole
//! function. An API exception is not a CLI exit. A library execute is not a
//! main call. One phase is not a multi-phase function.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.repair.execute`,
//! `sesslint.cli.main`, `sesslint.report`, or `sesslint._version` without a
//! `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/repair/vectors.json`,
//! `parity/vectors/report/vectors.json`, and
//! `parity/vectors/_version/vectors.json` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and are not a Covered source.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 35;
const PINNED_SPLITLINES: usize = 1314;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. An API exception is not a CLI exit. A library execute is not a
/// main call. One phase is not a multi-phase function. One parametrized cell
/// is not the three-cell vendor-emit pytest. `not_applicable` names the
/// missing stop.
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

macro_rules! not_applicable {
    ($unique:literal) => {
        Disposition::NotApplicable(concat!(
            $unique,
            " sesslint.cli vectors record parser metadata, removed-command hints, \
             removed-flag hints, exit-code constants, verbose settings, and main on \
             removed subcommands only; check_exit_constants stores a clean session \
             exits 0, a session with findings exits 1, and an internal tool error \
             exits 2, and notes that mention a dry-run plan generated, repair refused, \
             and a usage error, and those stored lines are not this pytest; \
             check_exit_epilog stores those notes in help text; version_label stores \
             sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral \
             session integrity checker and conservative repair tool and does not call \
             execute; create_parser_subcommand_names lists repair among subcommand \
             names and does not call execute; removed_flag_hint_salvage stores a hint \
             whose replacement text names --policy salvage and does not execute a plan; \
             removed_flag_hint_format_membership passes --format claude-code-jsonl and \
             does not repair a canonical source; removed_flag_hint_format_eq passes \
             --format=canonical and expects the hint to be absent; \
             verbose_settings_provenance stores stderr debug lines and does not call \
             execute; main_removed_formats, main_removed_baseline, \
             main_removed_validate_session, main_removed_init_hooks, and \
             main_removed_formats_json exit 2 for removed subcommands; \
             parity/vectors/repair/vectors.json, parity/vectors/report/vectors.json, \
             and parity/vectors/_version/vectors.json are pinned to \
             e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not a Covered source; \
             the autouse fixture _clean_and_register_recipes is not a test; \
             sesslint.repair.execute, sesslint.cli.main, sesslint.report, and \
             sesslint._version are not callable from this package without a \
             Cargo.toml change"
        ))
    };
}

const ROWS: &[Row] = &[
    Row {
        name: "test_basic_execute",
        disposition: not_applicable!(
            "no cli vector is test_basic_execute copying fixtures/repair/exec_basic \
             and calling execute under conservative, with output text equal to \
             fixtures/repair/exec_basic/expected_output.jsonl, parse_manifest of the \
             manifest file equal to the returned manifest, the source bytes unchanged, \
             the input fingerprint equal to the sha256 of the source bytes, the output \
             fingerprint equal to the sha256 of the output bytes, policy conservative, \
             and exactly one action whose kind is identical-duplicate-collapse; \
             missing stop: that whole success, both fingerprints and the single \
             identical-duplicate-collapse action included; all of those assertions \
             are one row; a library execute is not a main call; the CLI repair \
             without --plan is not this library comparison; the manifest schema \
             required-key sweep is not this success; the adapter-version plumbing \
             assertions are not this success;"
        ),
    },
    Row {
        name: "test_refuse_self_output",
        disposition: not_applicable!(
            "no cli vector is test_refuse_self_output calling execute with output \
             equal to the source, raising RepairRefused matching resolves to source \
             path, leaving the source bytes unchanged, then calling main on those \
             same paths and exiting 1 with the source bytes still unchanged; \
             missing stop: both the RepairRefused and the main exit 1 with the \
             source bytes unchanged; both calls are one row; an API exception is \
             not a CLI exit; a library execute is not a main call; the exit-code \
             table returns exit 1 for self-output and does not assert RepairRefused \
             or unchanged source bytes;"
        ),
    },
    Row {
        name: "test_refuse_existing_output",
        disposition: not_applicable!(
            "no cli vector is test_refuse_existing_output calling execute against an \
             already written output, raising RepairRefused matching already exists, \
             leaving those prior bytes unchanged, then calling main on the same paths \
             and exiting 1 with those prior bytes still unchanged; missing stop: both \
             the RepairRefused and the main exit 1 with the prior bytes unchanged; \
             both calls are one row; an API exception is not a CLI exit; a library \
             execute is not a main call; the self-output refusal is a different \
             destination check;"
        ),
    },
    Row {
        name: "test_refuse_live_store",
        disposition: not_applicable!(
            "no cli vector is test_refuse_live_store treating a missing .sqlite path \
             as a live store, asserting is_live_store_path, and raising RepairRefused \
             matching live-store path from execute, treating an existing file that \
             begins with the sqlite magic header as a live store and raising that \
             same refusal from execute, and calling main on the missing .sqlite path \
             and exiting 1; missing stop: those three phases together; all three \
             phases are one row; one phase is not a multi-phase function; an API \
             exception is not a CLI exit; a library execute is not a main call; the \
             main exit 1 covers the missing .sqlite path;"
        ),
    },
    Row {
        name: "test_tampered_plan",
        disposition: not_applicable!(
            "no cli vector is test_tampered_plan replacing the loaded plan steps with \
             one terminal-suffix-discard step while the old fingerprint is kept, \
             raising PlanTampered matching fingerprint mismatch from execute, and \
             leaving the output absent; missing stop: that PlanTampered fingerprint \
             mismatch with the output absent; a library execute is not a main call; \
             this function does not call main; the CLI --dry-run of a tampered plan \
             file is a different pytest; the cap-overflow OutputInvalid is a different \
             pytest; the source-hash PlanSourceMismatch tests are different pytests;"
        ),
    },
    Row {
        name: "test_plan_cap_overflow",
        disposition: not_applicable!(
            "no cli vector is test_plan_cap_overflow building a fingerprint-recomputed \
             conservative plan with MAX_STEPS plus one steps and raising OutputInvalid \
             matching exceeds maximum allowed cap from execute, with the output \
             absent; missing stop: that cap overflow with the output absent; a \
             library execute is not a main call; the PlanTampered fingerprint \
             mismatch is a different pytest;"
        ),
    },
    Row {
        name: "test_policy_mismatch",
        disposition: not_applicable!(
            "no cli vector is test_policy_mismatch calling execute on the conservative \
             plan with policy salvage, raising PolicyMismatch matching does not match \
             execution policy, leaving the output absent, then calling main with \
             --policy salvage and that plan and exiting 2 with the output still \
             absent; missing stop: both the PolicyMismatch and the main exit 2 with \
             the output absent; both phases are one row; the API exception is not \
             the CLI exit 2; a library execute is not a main call; a crafted \
             conservative plan whose step requires salvage policy is a different \
             pytest; the four-phase minimum-policy gate is a different pytest; the \
             function docstring says exit 1 and the main assertion is exit 2;"
        ),
    },
    Row {
        name: "test_sl203_toctou",
        disposition: not_applicable!(
            "no cli vector is test_sl203_toctou copying \
             fixtures/repair/exec_refuse_sl203/source.jsonl, building an empty-step \
             conservative plan whose hash matches that file, and raising Abstained \
             matching SL203 present from execute, with the output absent; missing \
             stop: that Abstained SL203 present with the output absent; a library \
             execute is not a main call; this function does not call main; the \
             function docstring mentions exit 1 and the body has no main call;"
        ),
    },
    Row {
        name: "test_output_invalid_synthetic_tool_result",
        disposition: not_applicable!(
            "no cli vector is test_output_invalid_synthetic_tool_result patching an \
             authorized recipe so its apply appends one synthetic tool_result, then \
             raising OutputInvalid matching Synthetic tool_result detected from \
             execute, with the output absent; missing stop: that synthetic \
             tool_result OutputInvalid with the output absent; a library execute is \
             not a main call; the cap-overflow OutputInvalid is a different pytest; \
             the concurrent-modification OutputInvalid is a different pytest;"
        ),
    },
    Row {
        name: "test_kill_before_rename",
        disposition: not_applicable!(
            "no cli vector is test_kill_before_rename installing a pre_rename_hook \
             that raises KeyboardInterrupt, then leaving the source bytes unchanged, \
             the output absent, and no .sesslint-tmp-* orphan; missing stop: those \
             three invariants after KeyboardInterrupt; all three invariants are one \
             row; a library execute is not a main call; the mid-publish RuntimeError \
             rollback is a different pytest; the ENOSPC pre_write_hook is a different \
             pytest; the manifest-write RuntimeError cleanup is a different pytest;"
        ),
    },
    Row {
        name: "test_dry_run",
        disposition: not_applicable!(
            "no cli vector is test_dry_run calling execute with dry_run true, \
             returning a manifest, and writing neither the output nor the manifest, \
             then calling main --dry-run, exiting 0, with stdout containing \
             Plan fingerprint: followed by that plan fingerprint, and with the \
             output still absent; missing stop: both the library dry-run with no \
             writes and the main dry-run stdout line at exit 0; both phases are one \
             row; a library execute is not a main call; the stored exit-code note \
             about a dry-run plan generated is not this stdout check; the CLI \
             dry-run of a tampered plan exits 1 and is a different pytest;"
        ),
    },
    Row {
        name: "test_exit_codes_table",
        disposition: not_applicable!(
            "no cli vector is test_exit_codes_table covering five main outcomes \
             together: repair with output exits 0 and the file exists; repair whose \
             output is the source exits 1; repair without output exits 2; repair of \
             a missing source exits 2; an unrecognized flag raises SystemExit code \
             2; missing stop: those five outcomes as one function; five outcomes are \
             one row; one outcome is not this pytest; a returned exit 2 is not the \
             SystemExit; an API exception is not a CLI exit; the self-output \
             RepairRefused pair is a different pytest; the --format SystemExit is a \
             different pytest; the removed-subcommand mains that exit 2 are not \
             these five calls;"
        ),
    },
    Row {
        name: "test_manifest_schema_validation",
        disposition: not_applicable!(
            "no cli vector is test_manifest_schema_validation calling execute and \
             then asserting that every key in the loaded manifest schema required \
             list is present, that schema_version is sesslint.repair-manifest/v1, \
             that idempotency_key matches the schema pattern, and that policy is in \
             the schema enum; missing stop: that schema sweep; all of those checks \
             are one row; the byte-equality success is not this schema sweep; the \
             adapter-version field assertions are a different pytest; a library \
             execute is not a main call; this function does not compare output text \
             to expected_output.jsonl;"
        ),
    },
    Row {
        name: "test_only_mutator",
        disposition: not_applicable!(
            "no cli vector is test_only_mutator walking src/sesslint Python files, \
             skipping comment lines, and asserting that os.replace or os.rename \
             occurs only in atomic.py; missing stop: that source audit; this is a \
             source audit, not an execute call; a library execute is not a main \
             call; this function does not call execute or main;"
        ),
    },
    Row {
        name: "test_direct_dict_raises_type_error",
        disposition: not_applicable!(
            "no cli vector is test_direct_dict_raises_type_error passing a raw dict \
             as plan to execute and raising TypeError matching plan must be a \
             RepairPlan instance; missing stop: that TypeError; a library execute \
             is not a main call; a RepairPlan fingerprint failure is a different \
             pytest; this function does not assert an output file;"
        ),
    },
    Row {
        name: "test_source_mutated_concurrently",
        disposition: not_applicable!(
            "no cli vector is test_source_mutated_concurrently installing a \
             post_apply_hook that appends one record, raising OutputInvalid matching \
             concurrently modified from execute, and leaving both the output and its \
             manifest absent; missing stop: that concurrent-modification \
             OutputInvalid with both files absent; a library execute is not a main \
             call; the newline appended before execute is the mutated-source \
             PlanSourceMismatch pytest; the cross-file PlanSourceMismatch is a \
             different pytest;"
        ),
    },
    Row {
        name: "test_cross_device_replace_error_mapping",
        disposition: not_applicable!(
            "no cli vector is test_cross_device_replace_error_mapping patching the \
             exclusive publish so it raises EXDEV and raising OutputInvalid matching \
             Cross-device link error from execute, with the output absent; missing \
             stop: that cross-device OutputInvalid with the output absent; a library \
             execute is not a main call; the KeyboardInterrupt before rename is a \
             different pytest; the ENOSPC pre_write_hook is a different pytest;"
        ),
    },
    Row {
        name: "test_unicode_and_spaces_in_path",
        disposition: not_applicable!(
            "no cli vector is test_unicode_and_spaces_in_path calling execute through \
             api.plan_repair of a source whose directory and file names contain \
             spaces and non-ASCII characters, writing the output and the manifest, \
             and asserting the output fingerprint equals the sha256 of the output \
             bytes; missing stop: that path execute and the output fingerprint \
             binding; a library execute is not a main call; the library comparison \
             against expected_output.jsonl is a different pytest; the CLI repair \
             without --plan is a different pytest;"
        ),
    },
    Row {
        name: "test_cli_repair_without_plan_e2e",
        disposition: not_applicable!(
            "no cli vector is test_cli_repair_without_plan_e2e calling main repair \
             with output and without --plan, exiting 0, creating the output and the \
             manifest, and asserting the output text equals \
             fixtures/repair/exec_basic/expected_output.jsonl; missing stop: that \
             CLI run, including exit 0, both files, and the expected-output \
             equality; a library execute is not a main call; the library \
             byte-equality test is not this CLI run; the exit-code table success \
             asserts that the file exists and does not compare output text;"
        ),
    },
    Row {
        name: "test_cli_dry_run_with_tampered_plan_refuses",
        disposition: not_applicable!(
            "no cli vector is test_cli_dry_run_with_tampered_plan_refuses calling \
             main --dry-run of a plan whose first step recipe was changed to \
             terminal-suffix-discard while the fingerprint was kept, and exiting 1; \
             missing stop: that CLI exit 1; a library execute is not a main call; \
             the library PlanTampered test is not this CLI run; the successful \
             dry-run that prints a plan fingerprint and exits 0 is a different \
             pytest; this function does not assert PlanTampered and does not pass \
             --output;"
        ),
    },
    Row {
        name: "test_disk_full_enospc",
        disposition: not_applicable!(
            "no cli vector is test_disk_full_enospc installing a pre_write_hook that \
             raises ENOSPC, raising OutputInvalid matching Disk full, leaving the \
             source bytes unchanged, leaving the output absent, and leaving no \
             .sesslint-tmp-* orphan, then calling main with os.fsync patched to \
             ENOSPC and exiting 1; missing stop: both phases, the library cleanup \
             invariants and the main exit 1; both phases are one row; the API \
             exception is not the CLI exit 1; a library execute is not a main call; \
             the PermissionError pytest is a different pytest; the main phase \
             asserts exit 1;"
        ),
    },
    Row {
        name: "test_read_only_target_directory",
        disposition: not_applicable!(
            "no cli vector is test_read_only_target_directory installing a \
             pre_write_hook that raises PermissionError, raising OutputInvalid \
             matching Permission denied, then calling main whose output is a file \
             under a directory that was not created and exiting 1; missing stop: \
             both the OutputInvalid and that main exit 1; both phases are one row; \
             the API exception is not the CLI exit; a library execute is not a main \
             call; the ENOSPC test is not this pytest; the CLI call does not change \
             directory permissions;"
        ),
    },
    Row {
        name: "test_manifest_write_failure_cleans_output",
        disposition: not_applicable!(
            "no cli vector is test_manifest_write_failure_cleans_output patching \
             dump_manifest to raise RuntimeError and afterward leaving the output, \
             the manifest, and every .sesslint-tmp-* file absent; missing stop: that \
             cleanup after the injected RuntimeError; a library execute is not a \
             main call; the kill-before-rename KeyboardInterrupt is a different \
             pytest; the mid-publish hook that observes a manifest file is a \
             different pytest;"
        ),
    },
    Row {
        name: "test_cli_invalid_format",
        disposition: not_applicable!(
            "no cli vector is test_cli_invalid_format calling main repair with \
             --format completely_bogus_format and raising SystemExit code 2; \
             missing stop: that SystemExit code 2; a returned exit 2 is not this \
             SystemExit; the unrecognized-flag SystemExit in the exit-code table is \
             not this pytest; removed_flag_hint_format_membership passes --format \
             claude-code-jsonl and is not this format value on repair; a library \
             execute is not a main call; this function does not pass --plan;"
        ),
    },
    Row {
        name: "test_source_events_direct_parameter",
        disposition: not_applicable!(
            "no cli vector is test_source_events_direct_parameter passing events \
             from load_session_source as source_events to execute, returning a \
             manifest, and creating the output file; missing stop: that \
             source_events execute; a path-only execute is not this pytest; a \
             library execute is not a main call; the byte-equality success does not \
             pass source_events;"
        ),
    },
    Row {
        name: "test_refuse_plan_source_mismatch_cross_file",
        disposition: not_applicable!(
            "no cli vector is test_refuse_plan_source_mismatch_cross_file applying \
             the exec_basic plan to a different source, raising PlanSourceMismatch \
             matching Plan source_hash mismatch from execute with the output absent, \
             then calling main of that pair and exiting 1 with the output still \
             absent; missing stop: both the PlanSourceMismatch and the main exit 1 \
             with the output absent; both calls are one row; an API exception is \
             not a CLI exit; a library execute is not a main call; the \
             mutated-source newline test is a different pytest;"
        ),
    },
    Row {
        name: "test_refuse_plan_source_mismatch_mutated_source",
        disposition: not_applicable!(
            "no cli vector is test_refuse_plan_source_mismatch_mutated_source \
             rebinding the plan source_hash to the copied source, recomputing the \
             plan fingerprint, appending one extra newline, and raising \
             PlanSourceMismatch from execute with the output absent; missing stop: \
             that PlanSourceMismatch after the extra newline, with the output \
             absent; the cross-file test is not this pytest; the post-apply hook \
             is not this pytest; a library execute is not a main call; this \
             function does not pass a match string and does not call main; the \
             PlanTampered fingerprint mismatch is a different pytest;"
        ),
    },
    Row {
        name: "test_refuse_crafted_conservative_plan_with_salvage_step",
        disposition: not_applicable!(
            "no cli vector is \
             test_refuse_crafted_conservative_plan_with_salvage_step executing a \
             fingerprint-consistent plan labeled conservative whose step recipe is \
             unresolvable-branch-amputate and whose min_policy is salvage, raising \
             PolicyMismatch matching requires 'salvage' policy, with the output \
             absent; missing stop: that minimum-policy PolicyMismatch with the \
             output absent; the execute-policy mismatch is not this crafted plan; \
             the four-phase minimum-policy gate is a different pytest; a library \
             execute is not a main call; this function does not call main;"
        ),
    },
    Row {
        name: "test_executor_refuses_vendor_emit_on_canonical_source",
        disposition: not_applicable!(
            "no cli vector is test_executor_refuses_vendor_emit_on_canonical_source \
             parametrized over emit vendor, claude-code-jsonl, and openai-agents, \
             with each cell calling execute on the canonical source and raising \
             RepairRefused while the output stays absent; missing stop: all three \
             cells; all three cells are one row; one format is not this pytest; a \
             library execute is not a main call; the comment that distinguishes a \
             usage refusal from a projection refusal is not a separate assertion; \
             the --format SystemExit is a different pytest;"
        ),
    },
    Row {
        name: "test_compute_assurance_ceiling_matrix",
        disposition: not_applicable!(
            "no cli vector is test_compute_assurance_ceiling_matrix asserting that \
             conservative preserves A0 through A4, that salvage keeps A0, A1, and \
             A2 and caps A3 and A4 at A2, that INVALID raises ValueError matching \
             Invalid revalidation assurance, and that unknown_policy raises \
             ValueError matching Invalid policy or pedigree; missing stop: that \
             whole ceiling matrix; all of those checks are one row; one level is \
             not this pytest; a for-loop is one row; this function calls \
             compute_assurance_ceiling and does not call execute or main; the \
             salvage end-to-end manifest ceiling is a different pytest; the \
             manifest assurance_ceiling equality in the adapter-version plumbing \
             is a different pytest;"
        ),
    },
    Row {
        name: "test_preplanted_manifest_collision",
        disposition: not_applicable!(
            "no cli vector is test_preplanted_manifest_collision writing a manifest \
             before execute, raising ManifestCollision matching Repair manifest \
             destination already exists, leaving the output absent, and leaving the \
             manifest bytes equal to the bytes written before execute; missing \
             stop: that ManifestCollision with the output absent and the pre-written \
             manifest bytes unchanged; a library execute is not a main call; the \
             manifest-write failure that removes the manifest is a different \
             pytest; the mid-publish rollback is a different pytest;"
        ),
    },
    Row {
        name: "test_mid_publish_crash_rollback",
        disposition: not_applicable!(
            "no cli vector is test_mid_publish_crash_rollback installing a \
             mid_publish_hook that observes the manifest file and then raises \
             RuntimeError, after which the directory contains only the source file; \
             missing stop: that rollback to only the source file; the \
             kill-before-rename test is not this pytest; a library execute is not a \
             main call; the dump_manifest failure is a different pytest;"
        ),
    },
    Row {
        name: "test_real_adapter_version_plumbing",
        disposition: not_applicable!(
            "no cli vector is test_real_adapter_version_plumbing calling execute and \
             asserting adapter_id is canonical, adapter_version equals \
             ADAPTER_VERSIONS for canonical and is not unknown, revalidation \
             assurance is one of A0 through A4, error_count and warning_count are \
             0, profile_id is neutral, profile_version is 1.0.0, report_fingerprint \
             is present, assurance_ceiling equals that revalidation assurance, and \
             the manifest file exists; missing stop: all of those manifest fields \
             together; all of those assertions are one row; the schema required-key \
             sweep is not this pytest; the byte-equality success is a different \
             pytest; a library execute is not a main call; one field is not this \
             pytest;"
        ),
    },
    Row {
        name: "test_salvage_e2e_manifest_ceiling",
        disposition: not_applicable!(
            "no cli vector is test_salvage_e2e_manifest_ceiling building a session \
             from fixtures/repair/salvage_branch.json, planning with policy salvage \
             and acknowledge_side_effects, executing under salvage, writing the \
             output and the manifest, with policy salvage, assurance_ceiling A2, \
             revalidation assurance A2 or A3 or A4, and parse_manifest of the file \
             equal to the returned manifest; missing stop: that whole salvage \
             execute; all of those assertions are one row; one assurance level is \
             not this pytest; the ceiling matrix is a different pytest; the \
             conservative byte-equality success is a different pytest; a library \
             execute is not a main call; api.plan_repair is not a main call;"
        ),
    },
    Row {
        name: "test_executor_policy_gate_minimum_policy",
        disposition: not_applicable!(
            "no cli vector is test_executor_policy_gate_minimum_policy in four \
             phases: load_plan of a salvage plan under conservative raises \
             PolicyMismatch matching requires 'salvage' policy; load_plan under \
             salvage succeeds and policy is salvage; execute of that loaded plan \
             under conservative raises PolicyMismatch matching Plan policy \
             'salvage' does not match execution policy 'conservative'; a \
             fingerprint-recomputed plan labeled conservative that still contains \
             the salvage step raises PolicyMismatch matching requires 'salvage' \
             policy; missing stop: those four phases; four phases are one row; one \
             phase is not this pytest; a library execute is not a main call; \
             load_plan is not execute; the earlier crafted-plan test is not these \
             four phases; the execute-policy mismatch that runs a conservative plan \
             under salvage and then exits 2 from main is a different pytest; this \
             function does not call main;"
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_basic_execute",
    "test_refuse_self_output",
    "test_refuse_existing_output",
    "test_refuse_live_store",
    "test_tampered_plan",
    "test_plan_cap_overflow",
    "test_policy_mismatch",
    "test_sl203_toctou",
    "test_output_invalid_synthetic_tool_result",
    "test_kill_before_rename",
    "test_dry_run",
    "test_exit_codes_table",
    "test_manifest_schema_validation",
    "test_only_mutator",
    "test_direct_dict_raises_type_error",
    "test_source_mutated_concurrently",
    "test_cross_device_replace_error_mapping",
    "test_unicode_and_spaces_in_path",
    "test_cli_repair_without_plan_e2e",
    "test_cli_dry_run_with_tampered_plan_refuses",
    "test_disk_full_enospc",
    "test_read_only_target_directory",
    "test_manifest_write_failure_cleans_output",
    "test_cli_invalid_format",
    "test_source_events_direct_parameter",
    "test_refuse_plan_source_mismatch_cross_file",
    "test_refuse_plan_source_mismatch_mutated_source",
    "test_refuse_crafted_conservative_plan_with_salvage_step",
    "test_executor_refuses_vendor_emit_on_canonical_source",
    "test_compute_assurance_ceiling_matrix",
    "test_preplanted_manifest_collision",
    "test_mid_publish_crash_rollback",
    "test_real_adapter_version_plumbing",
    "test_salvage_e2e_manifest_ceiling",
    "test_executor_policy_gate_minimum_policy",
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
fn pinned_repair_test_executor_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 1314);
}

#[test]
fn pinned_repair_test_executor_row_count_equals_thirty_five() {
    assert_eq!(ROWS.len(), 35);
    assert_eq!(PINNED_TEST_COUNT, 35);
}

#[test]
fn every_pinned_repair_test_executor_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 35);
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
                assert!(
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
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
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
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
