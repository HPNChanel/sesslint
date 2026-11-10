//! Dispositions for the 35 `def test_` functions in pinned `tests/adapters/test_detect.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (736 splitlines). Exactly 35
//! test functions, in module order. `_write_sniffable` is a helper, not a test.
//! Only `test_detect_format_rejects_invalid_thresholds` is parametrized: eleven
//! cells, and that row is the whole matrix. One cell is not that pytest.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.adapters`,
//! `sesslint.cli`, or `sesslint.api` without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. A parser probe, an exit-code constant, or one vendor sample is not
//! the whole pytest. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 35;
const PINNED_SPLITLINES: usize = 736;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A parser probe, an exit-code constant, or one vendor sample is not
/// the whole pytest. `not_applicable` names the missing stop.
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
        name: "test_threshold_constants_pinned",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_threshold_constants_pinned asserting CONFIDENCE_MIN is 0.55, MARGIN_MIN is 0.15, SNIFF_BYTES is 65536, EPSILON is 1e-9, FORMAT_CLAUDE_CODE is claude-code-jsonl, FORMAT_OPENAI_AGENTS is openai-agents, FORMAT_CODEX_ROLLOUT is codex-rollout, FORMAT_CANONICAL is canonical, FORMAT_AUTO is auto, SUPPORTED_FORMATS is the frozenset of those four names, and VALID_FORMAT_OPTIONS is that set plus auto; removed_flag_hint_format_membership is a --format claude-code-jsonl hint probe whose rust message says sesslint.adapters.VALID_FORMAT_OPTIONS is not available, and one format token is not this pin; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.adapters.detect constants are not readable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_each_vendor_clear_winner",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_each_vendor_clear_winner calling detect_format on fixtures/detect/claude_sample.jsonl, openai_sample.json, codex_sample.jsonl, and canonical_sample.json and requiring clear-winner for claude-code-jsonl, openai-agents, codex-rollout, and canonical respectively, each with confidence at least 0.55 and margin at least 0.15, where the claude margin subtracts the max of openai-agents and canonical, the openai margin subtracts the max of claude-code-jsonl and canonical, the canonical margin subtracts the max of claude-code-jsonl and openai-agents, and the codex margin subtracts the max of the other three; one vendor sample is not this four-fixture pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_ambiguous_fail_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ambiguous_fail_closed calling detect_format on fixtures/detect/ambiguous.json, requiring format None and REASON_TIE with the top confidence at least CONFIDENCE_MIN and the gap to the second confidence below MARGIN_MIN, then resolve_format(None, that path) while load_canonical, load_claude_code, and load_openai_agents stay uncalled, returning resolved None, detection reason REASON_TIE, and exactly one SL302 finding of severity ERROR and repairability MANUAL whose message contains [detail: ambiguous_format] and whose evidence reason is REASON_TIE, confidence_min is CONFIDENCE_MIN, margin_min is MARGIN_MIN, and confidences is present; the loader spies and the finding together are the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format and resolve_format are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_low_confidence_fail_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_low_confidence_fail_closed writing unstructured text, calling detect_format to require format None, REASON_LOW_CONFIDENCE, and max confidence below CONFIDENCE_MIN, then resolve_format with auto on that file to require resolved None, detection reason REASON_LOW_CONFIDENCE, and exactly one SL302 finding of severity ERROR and repairability MANUAL whose message contains [detail: ambiguous_format] and whose evidence reason is REASON_LOW_CONFIDENCE; both the detect half and the resolve_format auto half are the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format and resolve_format are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_explicit_override_wins",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_explicit_override_wins calling resolve_format with canonical on fixtures/detect/ambiguous.json and requiring resolved canonical, zero findings, detection format canonical, and reason REASON_EXPLICIT_OVERRIDE; the ambiguous fixture tie is not this explicit-override success; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; resolve_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_explicit_invalid_exits",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_explicit_invalid_exits writing a non-empty dummy file and requiring resolve_format of bogus and resolve_format of yaml to each raise ValueError matching Unknown format 'bogus' and Unknown format 'yaml'; one unknown name is not this two-call pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; resolve_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_empty_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_empty_refused on fixtures/detect/empty.jsonl, a zero-byte file, calling detect_format to require format None, REASON_EMPTY, and every confidence 0.0, then resolve_format(None, that path) to require resolved None, detection reason REASON_EMPTY, and exactly one SL001 finding of severity ERROR and repairability MANUAL whose message contains [detail: EMPTY] and whose evidence reason is empty_input; both halves are the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format and resolve_format are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_live_db_short_circuit",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_live_db_short_circuit writing session.sqlite as the openai-agents SQLITE_MAGIC header followed by 84 zero bytes, calling detect_format to require format None, REASON_REFUSED_LIVE_DB, and every confidence 0.0, then resolve_format(None, that path) to require resolved None, detection reason REASON_REFUSED_LIVE_DB, and exactly one SL001 finding of severity FATAL and repairability UNSUPPORTED whose message contains [detail: refused_live_db] and whose evidence reason is refused_live_db; the magic short-circuit regardless of scores is the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format and resolve_format are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_detection_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_detection_deterministic calling detect_format twice on fixtures/detect/canonical_sample.json and requiring the two DetectionResult values, formats, confidence maps, and reasons to be equal, then calling detect_format twice on fixtures/detect/ambiguous.json and requiring those two results to be equal; one sniff is not this two-fixture pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_confidence_boundary_exact_055",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_confidence_boundary_exact_055 patching detect_canonical to 0.55 with detect_claude_code and detect_openai_agents at 0.0 and requiring format canonical, REASON_CLEAR_WINNER, and canonical confidence exactly 0.55, then patching detect_canonical to 0.549 with those two at 0.0 and requiring format None and REASON_LOW_CONFIDENCE; the passing 0.55 half is not this two-branch pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_margin_boundary_exact_015",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_margin_boundary_exact_015 patching detect_canonical to 0.70, detect_claude_code to 0.55, and detect_openai_agents to 0.0 and requiring format canonical and REASON_CLEAR_WINNER, then patching detect_canonical to 0.70, detect_claude_code to 0.551, and detect_openai_agents to 0.0 and requiring format None and REASON_TIE; the clearing margin of 0.15 is not this two-branch pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_epsilon_tie",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_epsilon_tie patching detect_canonical to 0.8000000001, detect_claude_code to 0.80, and detect_openai_agents to 0.0 and requiring format None and REASON_TIE because the scores differ by less than EPSILON 1e-9; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_lying_extension",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_lying_extension copying fixtures/detect/canonical_sample.json onto a path named session.jsonl and requiring detect_format to return canonical and REASON_CLEAR_WINNER, so content sniffing wins over the extension; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_whitespace_only_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_whitespace_only_refused writing a file of only spaces, tabs, newlines, and carriage returns, calling detect_format to require format None and REASON_EMPTY, then resolve_format(None, that path) to require exactly one SL001 finding whose message contains [detail: EMPTY]; both the detect refusal and the SL001 finding are the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format and resolve_format are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_bom_only_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bom_only_refused writing a file whose only bytes are a UTF-8 BOM, calling detect_format to require format None and REASON_EMPTY, then resolve_format(None, that path) to require exactly one SL001 finding whose message contains [detail: EMPTY]; a whitespace-only file is not this BOM-only stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format and resolve_format are not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_bom_and_whitespace_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bom_and_whitespace_refused writing a file that is a UTF-8 BOM followed only by whitespace and calling detect_format to require format None and REASON_EMPTY; this pytest does not call resolve_format and does not assert an SL001 finding; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_giant_first_line_bounded",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_giant_first_line_bounded writing one utf-8 line that starts with a claude-code signal, then 200000 spaces, then a newline, and requiring detect_format to return claude-code-jsonl and REASON_CLEAR_WINNER while the sniff stays capped at SNIFF_BYTES; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_to_source_block_helper",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_to_source_block_helper building a DetectionResult for canonical with claude-code-jsonl confidence 0.123456, openai-agents 0.0, and canonical 1.0 at REASON_CLEAR_WINNER, requiring to_source_block requested auto to equal requested auto, resolved canonical, those confidences with 0.123456 rounded to 0.123, and REASON_CLEAR_WINNER, then requiring DetectionResult.to_source_block requested canonical to keep requested canonical and resolved canonical, then requiring to_source_block of None requested auto to keep requested auto, resolved None, and empty confidences; one block is not this three-call pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; to_source_block is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_detect_format_nonexistent_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_detect_format_nonexistent_raises calling detect_format on nonexistent_session_file_12345.json and requiring FileNotFoundError; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_detect_format_directory_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_detect_format_directory_raises calling detect_format on a directory and requiring IsADirectoryError; a missing file is not this directory failure; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_smoke_invalid_format",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_smoke_invalid_format calling sesslint.cli.main with --format bogus and requiring SystemExit code 2, with no captured stream assertion; check_exit_constants is the exit-code constant table, including the line that an internal tool error exits 2, and is not this SystemExit; removed_flag_hint_format_bare is bare --format with the hint absent, removed_flag_hint_format_eq is --format=canonical with the hint absent, and removed_flag_hint_format_membership is --format claude-code-jsonl hint probe; a parser probe or an exit-code constant is not this pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_smoke_ambiguous_auto",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_smoke_ambiguous_auto calling sesslint.cli.main check on fixtures/detect/ambiguous.json and requiring exit 0, stderr containing unsupported, and stdout not containing healthy, then calling main check on that path with --fail-on-unsupported and requiring exit 1; both invocations are the stop; check_exit_constants lines for exit 0 and exit 1 are the exit-code constant table and are not these two runs; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_smoke_explicit_override_canonical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_smoke_explicit_override_canonical calling sesslint.cli.main check --adapter canonical on fixtures/detect/canonical_sample.json and requiring exit 0 with stdout containing Valid session or Valid canonical session; check_exit_constants is the exit-code constant for a clean session exiting 0 and is not this run; main_removed_validate_session and removed_command_hint_validate_session are the removed validate-session command, exit 2, whose hint text mentions check --adapter canonical PATH, and are not a successful check of the fixture; an exit-code constant or one vendor sample is not this pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_smoke_explicit_override_before_check_honored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_smoke_explicit_override_before_check_honored calling sesslint.cli.main with check, --adapter, openai-agents, then fixtures/detect/ambiguous.json, and requiring exit 0 with stdout containing Valid OpenAI Agents session; the adapter flag before the path is the stop; check_exit_constants is the exit-code constant for a clean session exiting 0 and is not this run; the after-path argv is a different pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_smoke_explicit_override_after_path_honored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_smoke_explicit_override_after_path_honored calling sesslint.cli.main with check, fixtures/detect/ambiguous.json, --adapter, then openai-agents, and requiring exit 0 with stdout containing Valid OpenAI Agents session; the adapter flag after the path is the stop, which is the argv the test runs where the docstring says the flag after the path is honored; check_exit_constants is the exit-code constant for a clean session exiting 0 and is not this run; the before-path argv is a different pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_sniff_boundary_partial_utf8_sliced",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_sniff_boundary_partial_utf8_sliced writing a file larger than 100000 bytes whose first 65536 bytes, equal to SNIFF_BYTES, end on the lead byte of a three-byte UTF-8 sequence whose continuation bytes sit past the sniff window, and requiring detect_format to return claude-code-jsonl and REASON_CLEAR_WINNER; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_defensive_detector_nan_and_out_of_bounds",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_defensive_detector_nan_and_out_of_bounds on a non-empty dummy file, patching detect_canonical to nan with detect_claude_code and detect_openai_agents at 0.0 and requiring format None, REASON_LOW_CONFIDENCE, and canonical confidence 0.0, then patching detect_canonical to -0.5 with those two at 0.0 and requiring canonical confidence 0.0; the nan half is not this two-patch pytest, and the negative half does not assert format or reason; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_effective_confidence_threshold_changes_outcome",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_effective_confidence_threshold_changes_outcome calling _write_sniffable and patching detect_claude_code to 0.60, detect_openai_agents to 0.10, and detect_canonical to 0.10, requiring default detect_format to return claude-code-jsonl and REASON_CLEAR_WINNER, then detect_format with confidence_min 0.70 to return format None and REASON_LOW_CONFIDENCE; the default clear-winner is not this two-outcome pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_effective_thresholds_reported_in_sl302_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_effective_thresholds_reported_in_sl302_evidence calling _write_sniffable and patching detect_claude_code to 0.60, detect_openai_agents to 0.10, and detect_canonical to 0.10, then resolve_format(None, that path, confidence_min 0.70) and requiring a nonempty findings list whose first finding is SL302 with evidence confidence_min 0.70 and margin_min equal to MARGIN_MIN; the overridden confidence and the unchanged margin constant together are the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; resolve_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_effective_margin_threshold_changes_outcome",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_effective_margin_threshold_changes_outcome calling _write_sniffable and patching detect_claude_code to 0.60, detect_openai_agents to 0.50, and detect_canonical to 0.10, requiring default detect_format to return format None and REASON_TIE, then detect_format with margin_min 0.05 to return claude-code-jsonl and REASON_CLEAR_WINNER; the default tie is not this two-outcome pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_resolve_format_margin_override_reaches_arbitration",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_resolve_format_margin_override_reaches_arbitration calling _write_sniffable and patching detect_claude_code to 0.60, detect_openai_agents to 0.45, and detect_canonical to 0.10, requiring resolve_format(None, that path) to return claude-code-jsonl with no findings and reason REASON_CLEAR_WINNER, then resolve_format(None, that path, margin_min 0.20) to return format None, reason REASON_TIE, a first finding of SL302, and evidence margin_min 0.20; the default clear-winner is not this strict arbitration failure, and both calls are the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; resolve_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_detect_format_rejects_invalid_thresholds",
        disposition: Disposition::NotApplicable(
            "no cli vector is the whole test_detect_format_rejects_invalid_thresholds matrix on the _write_sniffable file, eleven detect_format ValueError cells: confidence_min boolean True, the string 0.7, nan, inf, 0.0, 1.0, -0.1, and 1.1, plus margin_min 0.0 and margin_min 1.0, each matching strictly between, plus confidence_min 0.5 with margin_min 0.9 matching cannot exceed confidence_min; one cell is not this pytest, and confidence_min 2.0 on resolve_format is a different pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_resolve_format_rejects_invalid_thresholds_even_with_explicit",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_resolve_format_rejects_invalid_thresholds_even_with_explicit calling resolve_format with explicit canonical, the _write_sniffable file, and confidence_min 2.0 and requiring ValueError matching strictly between before the explicit-format bypass can return a result; this single call is the stop and is not the eleven-cell detect_format matrix; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; resolve_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_explicit_format_bypasses_arbitration_unchanged",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_explicit_format_bypasses_arbitration_unchanged calling resolve_format with explicit claude-code-jsonl, the _write_sniffable file, confidence_min 0.99, and margin_min 0.99 and requiring resolved claude-code-jsonl, reason REASON_EXPLICIT_OVERRIDE, and no findings; those thresholds would not clear arbitration, and the bypass is the stop; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; resolve_format is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_default_thresholds_produce_identical_outcome",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_default_thresholds_produce_identical_outcome calling detect_format on the _write_sniffable file with no threshold arguments and again with confidence_min CONFIDENCE_MIN and margin_min MARGIN_MIN and requiring the two DetectionResult values to be equal; either call alone is not this pytest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; detect_format is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_threshold_constants_pinned",
    "test_each_vendor_clear_winner",
    "test_ambiguous_fail_closed",
    "test_low_confidence_fail_closed",
    "test_explicit_override_wins",
    "test_explicit_invalid_exits",
    "test_empty_refused",
    "test_live_db_short_circuit",
    "test_detection_deterministic",
    "test_confidence_boundary_exact_055",
    "test_margin_boundary_exact_015",
    "test_epsilon_tie",
    "test_lying_extension",
    "test_whitespace_only_refused",
    "test_bom_only_refused",
    "test_bom_and_whitespace_refused",
    "test_giant_first_line_bounded",
    "test_to_source_block_helper",
    "test_detect_format_nonexistent_raises",
    "test_detect_format_directory_raises",
    "test_cli_smoke_invalid_format",
    "test_cli_smoke_ambiguous_auto",
    "test_cli_smoke_explicit_override_canonical",
    "test_cli_smoke_explicit_override_before_check_honored",
    "test_cli_smoke_explicit_override_after_path_honored",
    "test_sniff_boundary_partial_utf8_sliced",
    "test_defensive_detector_nan_and_out_of_bounds",
    "test_effective_confidence_threshold_changes_outcome",
    "test_effective_thresholds_reported_in_sl302_evidence",
    "test_effective_margin_threshold_changes_outcome",
    "test_resolve_format_margin_override_reaches_arbitration",
    "test_detect_format_rejects_invalid_thresholds",
    "test_resolve_format_rejects_invalid_thresholds_even_with_explicit",
    "test_explicit_format_bypasses_arbitration_unchanged",
    "test_default_thresholds_produce_identical_outcome",
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
fn pinned_adapters_test_detect_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 736);
}

#[test]
fn pinned_adapters_test_detect_row_count_equals_35() {
    assert_eq!(ROWS.len(), 35);
    assert_eq!(PINNED_TEST_COUNT, 35);
}

#[test]
fn every_pinned_adapters_test_detect_test_has_one_disposition() {
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
