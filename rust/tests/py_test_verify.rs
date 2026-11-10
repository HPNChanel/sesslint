//! Dispositions for the fifty-two `def test_` functions in pinned
//! `tests/test_verify.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (1283 splitlines). Exactly
//! fifty-two test functions, in module order. None is parametrized. The helpers
//! `_write_ok_bundle`, `_repair_canonical_dup_bundle`, and
//! `_spy_detector_profiles` are not tests. Each row is the whole function. One
//! check is not seven checks. A library verify is not a CLI exit. A docstring
//! is not an assertion. Fixture bytes, session lines, ledger lines, and the
//! long hostile strings are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.verify`,
//! `sesslint.cli`, or repair functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. `parity/vectors/cli/vectors.json` has 33 vectors at this pin and
//! they are parser metadata. `parity/vectors/verify/vectors.json` is at this
//! pin, but its twelve ids are `module_all`, `dataclass_serialization`,
//! `render_verify_human_formatting`, and nine parse probes:
//! `parse_rejects_nan`, `parse_rejects_infinity`,
//! `parse_rejects_out_of_range_float`, `parse_rejects_deep_nesting`,
//! `parse_rejects_oversized_line`, `parse_rejects_nul_byte`,
//! `parse_rejects_oversized_file`, `parse_tolerates_headerless`, and
//! `parse_accepts_valid_jsonl`. Fixture bundles, CLI exits, filesystem raises,
//! repair bootstrap, and the dataclass `to_dict` calls are not those vectors.
//! None of those twelve ids is marked covered for these fifty-two tests.
//! `parity/vectors/repair.fingerprint/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and is not a Covered source.
//! `not_applicable` names the missing stop and the nearest different test.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 52;
const PINNED_SPLITLINES: usize = 1283;
const CLI_VECTOR_COUNT: usize = 33;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const VERIFY_VECTORS_REL: &str = "parity/vectors/verify/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One check is not seven checks. A library verify is not a CLI exit.
/// A docstring is not an assertion. `not_applicable` names the missing stop
/// and the nearest different test.
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
        name: "test_fixture_ok",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_fixture_ok: fixtures/verify/ok is ok, assurance is repaired-lossless, there are seven checks, every check is ok, and the names are source_hash, plan_fingerprint, output_hash, transformation_audit, loss_audit, assurance_audit, idempotence in that order; missing stop: that whole ok fixture; all of those are one row; test_cli_exit_code_0 is a JSON CLI exit with the same assurance and seven checks and is not this pytest; a library verify is not a CLI exit",
        ),
    },
    Row {
        name: "test_fixture_tampered_output",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_fixture_tampered_output: ok is false, source_hash and plan_fingerprint and loss_audit and assurance_audit and idempotence are true, output_hash is false with mismatch, and transformation_audit is false; missing stop: that whole tampered-output fixture; all of those are one row; test_fixture_ok is the ok fixture and is not this pytest",
        ),
    },
    Row {
        name: "test_fixture_tampered_plan",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_fixture_tampered_plan: ok is false, source_hash is true, plan_fingerprint is false with plan-tampered, and output_hash is true; missing stop: those four assertions; all of those are one row; it does not assert the other four checks; test_tampered_plan_fingerprint asserts only plan_fingerprint and is not this pytest",
        ),
    },
    Row {
        name: "test_fixture_non_idempotent",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_fixture_non_idempotent: ok is false, the first six named checks source_hash, plan_fingerprint, output_hash, transformation_audit, loss_audit, and assurance_audit are true, and idempotence is false with non-idempotent; missing stop: that whole non-idempotent fixture; all of those are one row; test_fixture_tampered_output is the tampered-output fixture and is not this pytest",
        ),
    },
    Row {
        name: "test_tampered_source",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tampered_source: a modified source makes ok false, source_hash false, and its detail contains mismatch; missing stop: those three assertions; all three are one row; test_in_place_manifest_rejected has source_hash detail equal to manifest-schema and is not this pytest",
        ),
    },
    Row {
        name: "test_in_place_manifest_rejected",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_in_place_manifest_rejected: ok is false, source_hash is false, and its detail equals manifest-schema; missing stop: those three assertions; all three are one row; test_tampered_source contains mismatch and is not this pytest",
        ),
    },
    Row {
        name: "test_verdict_artifact_hash_uses_verified_output_snapshot",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verdict_artifact_hash_uses_verified_output_snapshot: artifact_sha256 equals the verified output snapshot, it differs from the manifest output fingerprint, the output is read once, and artifact_sha256 is absent from to_dict; missing stop: those four assertions; all four are one row; test_tampered_output_hash asserts output_hash contains mismatch and is not this pytest",
        ),
    },
    Row {
        name: "test_tampered_plan_fingerprint",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tampered_plan_fingerprint: plan_fingerprint is false and its detail contains plan-tampered; missing stop: both assertions; both are one row; test_fixture_tampered_plan also asserts source_hash and output_hash and is not this pytest",
        ),
    },
    Row {
        name: "test_manifest_plan_fingerprint_mismatch",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_manifest_plan_fingerprint_mismatch: plan_fingerprint is false and its detail contains manifest-mismatch; missing stop: both assertions; both are one row; test_tampered_plan_fingerprint contains plan-tampered and is not this pytest",
        ),
    },
    Row {
        name: "test_tampered_output_hash",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tampered_output_hash: output_hash is false and its detail contains mismatch; missing stop: both assertions; both are one row; test_fixture_tampered_output also fails transformation_audit and is not this pytest",
        ),
    },
    Row {
        name: "test_key_reorder_passes",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_key_reorder_passes: output_hash is true, transformation_audit is true, and verdict ok is true; missing stop: those three assertions; all three are one row; test_event_reorder_fails swaps events and is not this pytest",
        ),
    },
    Row {
        name: "test_event_reorder_fails",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_event_reorder_fails: output_hash is true, transformation_audit is false, and its detail contains events-mismatch; missing stop: those three assertions; all three are one row; test_key_reorder_passes keeps transformation_audit true and is not this pytest",
        ),
    },
    Row {
        name: "test_tampered_loss_audit",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tampered_loss_audit: loss_audit is false and its detail contains mismatch; missing stop: both assertions; both are one row; test_loss_totals_fallback has loss_audit detail equal to manifest-schema and is not this pytest",
        ),
    },
    Row {
        name: "test_loss_totals_fallback",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_loss_totals_fallback: ok is false, loss_audit is false, and its detail equals manifest-schema; missing stop: those three assertions; all three are one row; test_tampered_loss_audit contains mismatch and is not this pytest",
        ),
    },
    Row {
        name: "test_tampered_assurance_audit",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tampered_assurance_audit: assurance_audit is false and its detail contains mismatch; missing stop: both assertions; both are one row; test_verify_missing_assurance_fails_check_6 has assurance_audit detail equal to manifest-missing-assurance and is not this pytest",
        ),
    },
    Row {
        name: "test_non_short_circuiting",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_non_short_circuiting: source, plan, and output are all tampered, ok is false, the check count is 7, and source_hash, plan_fingerprint, and output_hash are false; missing stop: those assertions; all of those are one row; it does not assert the other four checks; test_tampered_source tampers only the source and is not this pytest",
        ),
    },
    Row {
        name: "test_truncated_manifest",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_truncated_manifest: the docstring names manifest-schema, but the assertion is output_hash false and its detail is field-missing or manifest-schema, and ok is false; missing stop: those three assertions; all three are one row; a docstring is not an assertion; test_loss_totals_fallback equals manifest-schema on loss_audit and is not this pytest",
        ),
    },
    Row {
        name: "test_empty_output_file",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_empty_output_file: ok is false, output_hash is false, and transformation_audit is false; missing stop: those three assertions; all three are one row; test_tampered_output_hash asserts an output_hash mismatch detail and is not this pytest",
        ),
    },
    Row {
        name: "test_malformed_json_files",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_malformed_json_files: plan and manifest are malformed, ok is false, source_hash is false with detail manifest-invalid-json, and plan_fingerprint is false with detail invalid-plan-json; missing stop: those assertions; all of those are one row; it does not assert output_hash; test_truncated_manifest asserts output_hash and is not this pytest",
        ),
    },
    Row {
        name: "test_missing_files_raise_filenotfound",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_missing_files_raise_filenotfound: two FileNotFoundError raises, one for a missing source and one for a missing plan; missing stop: those two raises; both are one row; it does not pass a missing output or manifest; test_directory_as_file_raises_isadirectoryerror raises IsADirectoryError and is not this pytest",
        ),
    },
    Row {
        name: "test_directory_as_file_raises_isadirectoryerror",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_directory_as_file_raises_isadirectoryerror: only the source path is a directory and verify raises IsADirectoryError; missing stop: that source-directory raise; the plan, output, and manifest stay files; test_symlinked_files verifies through a symlink and is not this pytest",
        ),
    },
    Row {
        name: "test_symlinked_files",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_symlinked_files: a symlink to the source verifies ok true, or the test skips when the symlink cannot be created; missing stop: that success; that success is the row; test_directory_as_file_raises_isadirectoryerror raises IsADirectoryError and is not this pytest",
        ),
    },
    Row {
        name: "test_50_step_plan_replay_perf",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_50_step_plan_replay_perf: the replay duration is under 2 seconds and verdict ok is true; missing stop: both assertions; both are one row; the generated plan is not copied here; test_fixture_ok asserts seven named checks and no duration and is not this pytest",
        ),
    },
    Row {
        name: "test_no_executor_import",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_no_executor_import: verify.py contains no executor word; missing stop: that source scan; test_read_only_runtime blocks writes at runtime and is not this scan",
        ),
    },
    Row {
        name: "test_read_only_static",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_read_only_static: verify.py matches none of the four write patterns, open-for-write, os replace rename remove unlink rmdir mkdir and makedirs, shutil, and write_text or write_bytes; missing stop: that whole scan; the whole scan is one row; test_read_only_runtime blocks writes at runtime and is not this scan",
        ),
    },
    Row {
        name: "test_read_only_runtime",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_read_only_runtime: write_bytes, write_text, os.replace, and os.rename are blocked, and verify still returns ok true; missing stop: those blocks together with that ok result; all of that is one row; test_read_only_static is the four-pattern source scan and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_exit_code_0",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_cli_exit_code_0: the JSON CLI exits 0, ok is true, assurance is repaired-lossless, and there are seven checks; missing stop: those four assertions; all four are one row; test_fixture_ok is the library fixture and is not this pytest; a library verify is not a CLI exit",
        ),
    },
    Row {
        name: "test_cli_exit_code_1_on_audit_failure",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_cli_exit_code_1_on_audit_failure: the JSON CLI exits 1 and ok is false; missing stop: both assertions; both are one row; test_cli_exit_code_0 exits 0 and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_exit_code_2_on_missing_file",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_cli_exit_code_2_on_missing_file: the CLI exits 2 and stderr contains Verify I/O error; missing stop: both assertions; both are one row; test_cli_exit_code_2_on_missing_args raises SystemExit 2 and is not this pytest",
        ),
    },
    Row {
        name: "test_cli_exit_code_2_on_missing_args",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_cli_exit_code_2_on_missing_args: missing arguments raise SystemExit 2; missing stop: that raise; test_cli_exit_code_2_on_missing_file returns exit 2 and is not this raise",
        ),
    },
    Row {
        name: "test_verdict_and_check_dataclasses",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verdict_and_check_dataclasses: Check.to_dict equals the three-key dict, Verdict.to_dict has ok true, assurance clean, and that check, and to_json contains the assurance and ok fragments; missing stop: those calls together; all of those are one row; dataclass_serialization compares Verdict.to_json only, so that vector is not this whole test",
        ),
    },
    Row {
        name: "test_verify_without_plan_bootstrapping",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_without_plan_bootstrapping: repair produces a manifest, verify without a plan is ok, and plan_fingerprint is true with detail matched; missing stop: those assertions together; all of those are one row; test_verify_with_real_manifest_from_executor asserts every check is ok and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_manifest_actions_tampered_fails_check_4",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_manifest_actions_tampered_fails_check_4: ok is false, transformation_audit is false, and its detail contains actions or mismatch; missing stop: those assertions; all of those are one row; test_verify_missing_actions_fails_check_4 has detail manifest-missing-actions or manifest-schema and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_missing_plan_fingerprint_fails_check_2",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_missing_plan_fingerprint_fails_check_2: ok is false, plan_fingerprint is false, and its detail equals manifest-missing-plan-fingerprint; missing stop: those three assertions; all three are one row; test_manifest_plan_fingerprint_mismatch contains manifest-mismatch and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_missing_assurance_fails_check_6",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_missing_assurance_fails_check_6: ok is false, assurance_audit is false, and its detail equals manifest-missing-assurance; missing stop: those three assertions; all three are one row; test_tampered_assurance_audit contains mismatch and is not this pytest",
        ),
    },
    Row {
        name: "test_render_verify_human_formatting",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_render_verify_human_formatting: color false contains Verification: PASSED and [PASS] source_hash: matched, and color true contains FAILED and idempotence: non-idempotent; missing stop: those four substrings; all four substrings are one row; the verify vector of this name records the full pass string, including the assurance line, and the full ANSI fail string; the pytest does not assert those full strings, so that vector is not this entire test",
        ),
    },
    Row {
        name: "test_verify_missing_actions_fails_check_4",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_missing_actions_fails_check_4: ok is false, transformation_audit is false, and its detail is manifest-missing-actions or manifest-schema; missing stop: those three assertions; all three are one row; test_verify_manifest_actions_tampered_fails_check_4 contains actions or mismatch and is not this pytest",
        ),
    },
    Row {
        name: "test_old_shape_manifest_rejected_with_manifest_schema",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_old_shape_manifest_rejected_with_manifest_schema: ok is false, and both source_hash and assurance_audit are false with detail manifest-schema; missing stop: those assertions; all of those are one row; test_missing_revalidation_rejected_no_fallback fails source_hash and plan_fingerprint and is not this pytest",
        ),
    },
    Row {
        name: "test_verify_with_real_manifest_from_executor",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_with_real_manifest_from_executor: repair produces a plan, a manifest, an output, and a manifest file, verify is ok, and every check is ok; missing stop: those assertions together; all of those are one row; the source lines are not copied here; test_verify_cli_with_real_manifest is the CLI and is not this pytest; a library verify is not a CLI exit",
        ),
    },
    Row {
        name: "test_verify_cli_with_real_manifest",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_cli_with_real_manifest: repair exits 0, the manifest file exists, JSON verify exits 0 with ok true, and human verify exits 0 with Verification: PASSED; missing stop: those assertions together; all of those are one row; test_verify_with_real_manifest_from_executor is the library verify and is not this pytest; a library verify is not a CLI exit",
        ),
    },
    Row {
        name: "test_verify_detects_tampered_output_with_real_manifest",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_verify_detects_tampered_output_with_real_manifest: repair produces a plan and a manifest, the output is then extended, and verify ok is false; missing stop: those three assertions; those three assertions are one row; the helper assertions are not this test; the session lines are not copied here; test_verify_with_real_manifest_from_executor stops at every check ok and is not this pytest",
        ),
    },
    Row {
        name: "test_no_plan_binds_neutral_profile",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_no_plan_binds_neutral_profile: ok is true, and every spied profile is neutral; missing stop: both assertions; both are one row; test_no_plan_binds_claude_strict_profile is not this pytest, and test_no_plan_binds_openai_strict_profile is not this pytest",
        ),
    },
    Row {
        name: "test_no_plan_binds_claude_strict_profile",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_no_plan_binds_claude_strict_profile: ok is true, claude-strict is seen, and neutral is not seen; missing stop: those three assertions; all three are one row; test_no_plan_binds_neutral_profile sees only neutral and is not this pytest",
        ),
    },
    Row {
        name: "test_no_plan_binds_openai_strict_profile",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_no_plan_binds_openai_strict_profile: ok is true, openai-strict is seen, and neutral is not seen; missing stop: those three assertions; all three are one row; test_no_plan_binds_claude_strict_profile sees claude-strict and is not this pytest",
        ),
    },
    Row {
        name: "test_tampered_profile_id_fails_deterministically",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_tampered_profile_id_fails_deterministically: ok is false and plan_fingerprint is false; missing stop: both assertions; both are one row; test_unknown_profile_id_fails_closed starts its detail with profile-binding-unknown and is not this pytest",
        ),
    },
    Row {
        name: "test_unknown_profile_id_fails_closed",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_unknown_profile_id_fails_closed: ok is false, the named check is false, and its detail starts with profile-binding-unknown; missing stop: those three assertions; all three are one row; the named-check loop is plan_fingerprint, assurance_audit, and idempotence; test_tampered_profile_id_fails_deterministically does not assert this detail and is not this pytest",
        ),
    },
    Row {
        name: "test_unavailable_profile_version_fails_closed",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_unavailable_profile_version_fails_closed: ok is false, the named check is false, and its detail starts with profile-version-unavailable; missing stop: those three assertions; all three are one row; the named-check loop is plan_fingerprint, assurance_audit, and idempotence; test_root_profile_version_conflict_fails equals profile-version-conflict and is not this pytest",
        ),
    },
    Row {
        name: "test_root_profile_version_conflict_fails",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_root_profile_version_conflict_fails: the root profile_version is 1.0.0, ok is false, the named check is false, and its detail equals profile-version-conflict; missing stop: those assertions; all of those are one row; the named-check loop is plan_fingerprint, assurance_audit, and idempotence; test_unavailable_profile_version_fails_closed starts its detail with profile-version-unavailable and is not this pytest",
        ),
    },
    Row {
        name: "test_plan_profile_conflict_fails",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_plan_profile_conflict_fails: a plan exists, ok is false, and both assurance_audit and idempotence are false with detail plan-profile-conflict; missing stop: those assertions; all of those are one row; test_root_profile_version_conflict_fails has no supplied plan and is not this pytest",
        ),
    },
    Row {
        name: "test_missing_revalidation_rejected_no_fallback",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_missing_revalidation_rejected_no_fallback: ok is false, and both source_hash and plan_fingerprint are false with detail manifest-schema; missing stop: those assertions; all of those are one row; test_old_shape_manifest_rejected_with_manifest_schema fails source_hash and assurance_audit and is not this pytest",
        ),
    },
    Row {
        name: "test_hostile_profile_id_fails_privacy_safe",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_hostile_profile_id_fails_privacy_safe: ok is false, the hostile id and the prefix evil< are absent from every check detail, and plan_fingerprint detail starts with profile-binding-unknown; missing stop: those assertions; all of those are one row; the long id is not copied here; test_unknown_profile_id_fails_closed does not assert that absence and is not this pytest",
        ),
    },
    Row {
        name: "test_hostile_profile_version_fails_privacy_safe",
        disposition: Disposition::NotApplicable(
            "no committed vector is test_hostile_profile_version_fails_privacy_safe: ok is false, the hostile version and the prefix 9.9.9;drop are absent from every check detail, and plan_fingerprint detail starts with profile-version-unavailable; missing stop: those assertions; all of those are one row; the long version is not copied here; test_unavailable_profile_version_fails_closed does not assert that absence and is not this pytest",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_fixture_ok",
    "test_fixture_tampered_output",
    "test_fixture_tampered_plan",
    "test_fixture_non_idempotent",
    "test_tampered_source",
    "test_in_place_manifest_rejected",
    "test_verdict_artifact_hash_uses_verified_output_snapshot",
    "test_tampered_plan_fingerprint",
    "test_manifest_plan_fingerprint_mismatch",
    "test_tampered_output_hash",
    "test_key_reorder_passes",
    "test_event_reorder_fails",
    "test_tampered_loss_audit",
    "test_loss_totals_fallback",
    "test_tampered_assurance_audit",
    "test_non_short_circuiting",
    "test_truncated_manifest",
    "test_empty_output_file",
    "test_malformed_json_files",
    "test_missing_files_raise_filenotfound",
    "test_directory_as_file_raises_isadirectoryerror",
    "test_symlinked_files",
    "test_50_step_plan_replay_perf",
    "test_no_executor_import",
    "test_read_only_static",
    "test_read_only_runtime",
    "test_cli_exit_code_0",
    "test_cli_exit_code_1_on_audit_failure",
    "test_cli_exit_code_2_on_missing_file",
    "test_cli_exit_code_2_on_missing_args",
    "test_verdict_and_check_dataclasses",
    "test_verify_without_plan_bootstrapping",
    "test_verify_manifest_actions_tampered_fails_check_4",
    "test_verify_missing_plan_fingerprint_fails_check_2",
    "test_verify_missing_assurance_fails_check_6",
    "test_render_verify_human_formatting",
    "test_verify_missing_actions_fails_check_4",
    "test_old_shape_manifest_rejected_with_manifest_schema",
    "test_verify_with_real_manifest_from_executor",
    "test_verify_cli_with_real_manifest",
    "test_verify_detects_tampered_output_with_real_manifest",
    "test_no_plan_binds_neutral_profile",
    "test_no_plan_binds_claude_strict_profile",
    "test_no_plan_binds_openai_strict_profile",
    "test_tampered_profile_id_fails_deterministically",
    "test_unknown_profile_id_fails_closed",
    "test_unavailable_profile_version_fails_closed",
    "test_root_profile_version_conflict_fails",
    "test_plan_profile_conflict_fails",
    "test_missing_revalidation_rejected_no_fallback",
    "test_hostile_profile_id_fails_privacy_safe",
    "test_hostile_profile_version_fails_privacy_safe",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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
fn pinned_test_verify_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 1283);
}

#[test]
fn pinned_test_verify_row_count_equals_fifty_two() {
    assert_eq!(ROWS.len(), 52);
    assert_eq!(PINNED_TEST_COUNT, 52);
}

#[test]
fn every_pinned_test_verify_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 52);
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
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
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
    let path = vectors_path(CLI_VECTORS_REL);
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

#[test]
fn verify_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 52);

    let json = read_vectors(VERIFY_VECTORS_REL);
    // `parity/vectors/verify/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "verify vectors python_commit spacing does not match {needle}"
    );
    assert!(json.contains("\"module\": \"sesslint.verify\""));

    let ids = vector_ids(&json);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing verify vector {vector_id}",
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
