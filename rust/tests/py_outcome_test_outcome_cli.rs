//! Dispositions for the thirteen `def test_` functions in pinned
//! `tests/outcome/test_outcome_cli.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (148 splitlines). The module
//! covers a violated JSON report, a two-phase verified then inconclusive run,
//! the default human report, a plain target that needs an evaluation instant,
//! two input-error cells, a naive as-of `SystemExit`, an invalid contract,
//! three missing-file calls, explain success then rejection, three overwrite
//! victims, a linked-session report file, hash-keys display, and byte-stable
//! JSON stdout. Exactly thirteen test functions, in module order. Two are
//! parametrized: `test_input_errors_exit_two` has two cells, and
//! `test_output_never_overwrites_inputs` has three cells. A parametrized
//! function is one row covering every cell. A two-phase function is one row.
//! Helpers `_copy`, `BASE`, `CONTRACT`, `SOURCE`, and `TARGET` are not tests.
//! CSV rows, contract JSON, session lines, and the raw key that the hash-keys
//! test checks is absent are not copied here. The raw key is not quoted.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, not these outcome runs. `parity/vectors/outcome/vectors.json`
//! is pinned to the same commit. Its 4818 cases are `verify_outcome` rows. An
//! evaluation case, one human report, or one `EvaluationError` is not an entire
//! CLI pytest. `parity/vectors/outcome/coverage.json` does not name
//! `tests/outcome/test_outcome_cli.py`. The outcome manifest lists the contract,
//! engine, and snapshot tests and does not list this CLI module.
//! `parity/vectors/cli.outcome/vectors.json` is the same pin. Its only vector is
//! `configure_subcommand_declarations`. `GAP-cli-outcome-runtime` claims no exit
//! code or emit_text parity. That id is not one of the 33 cli vectors. This
//! integration test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` or
//! `sesslint.outcome` functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 13;
const PINNED_SPLITLINES: usize = 148;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const OUTCOME_VECTORS_REL: &str = "parity/vectors/outcome/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A parametrized function is one row covering every cell. A two-phase
/// function is one row. An evaluation case, one human report, or one
/// `EvaluationError` is not an entire CLI pytest. A returned exit 2 is not a
/// `SystemExit`. `not_applicable` names the missing stop.
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
        name: "test_json_report_validates_and_exits_one_on_violation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_json_report_validates_and_exits_one_on_violation: BASE plus --source-completeness complete and --json exits 1, the stdout document validates against sesslint.outcome-report.v1.json, and run_status plus outcome are completed and VIOLATED; missing stop: those three assertions together; all three assertions are one row; exit 1 is not the schema validation; the schema validation is not the completed and VIOLATED pair; this function is not parametrized and it is not two-phase; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; the orders fixture bytes are not copied here; test_verified_outcome_exits_zero is the two-phase verified then inconclusive run and is not this violation; test_human_output_is_the_default is the human run and is not this JSON schema test; check_exit_constants records the help line 1  a session with findings exits 1 and is not this outcome report; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser, so the name is not main(); GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, configure_subcommand_declarations lists --source-completeness choice complete and --json, and GAP-cli-outcome-runtime says Rust run() returns Display sesslint.outcome evaluation/report/load exports are not available before args or context use and claims no exit code or emit_text parity, so that declaration is not this run and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin and its cases are verify_outcome rows; outcome case id 480 is one evaluation on contract.json, source.json, and empty.json with hash_keys false, exit 1, run_status completed, outcome VIOLATED, and schema_version sesslint.outcome-report/v1, and it does not call main, does not pass --source-completeness complete, and does not validate against sesslint.outcome-report.v1.json; one evaluation case is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_verified_outcome_exits_zero",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verified_outcome_exits_zero: a one-row source with --source-completeness complete and --format json exits 0 and outcome is VERIFIED, then the same arguments with only --json exit 1 and outcome is INCONCLUSIVE; missing stop: both phases together; both phases are one row; the exit 0 VERIFIED phase is not the exit 1 INCONCLUSIVE phase; the one-row source bytes are not copied here; this function is not parametrized; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; the violated schema test is not this pytest; test_json_report_validates_and_exits_one_on_violation validates a VIOLATED document and is not these two phases; check_exit_constants records help lines for exit 0 and exit 1 and is not this pair of runs; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, configure_subcommand_declarations lists --format choices human and json and --json, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that declaration is not both phases and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; outcome case id 0 is one verify_outcome on source.json and target.json with exit 0 and outcome VERIFIED, and it is not a one-row source, not --format json, and not the following phase; outcome case id 984 is one verify_outcome on unobserved.json with as_of 2026-11-09T00:00:00Z, exit 1, and outcome INCONCLUSIVE, and its target completeness is complete, so it is not the same arguments with only --json; neither case contains both phases; one evaluation case is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_human_output_is_the_default",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_human_output_is_the_default: BASE with no format flag exits 1, stdout starts with SessLint outcome: , and stdout contains both session integrity: and outcome verification:; missing stop: those three assertions together; all three assertions are one row; the exit 1 is not the prefix; the prefix is not the two dimension labels; this function is not parametrized and it passes no --json and no --format; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; the orders fixture bytes are not copied here; the JSON schema test is not this human run; test_json_report_validates_and_exits_one_on_violation validates sesslint.outcome-report.v1.json and is not this human stdout; check_exit_constants records the help line 1  a session with findings exits 1 and is not this human report; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, configure_subcommand_declarations says output format default human, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that help line is not this run and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; outcome case id 480 renders one human report that starts with SessLint outcome: VIOLATED and contains both dimension labels, with exit 1, on empty.json, and that one human report is not main(BASE) with no format flag; outcome case id 0 is exit 0 and outcome VERIFIED, so it is not this exit 1 default; one human report is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_plain_target_needs_an_evaluation_instant",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plain_target_needs_an_evaluation_instant: target.jsonl without an instant exits 2 and stderr contains wall clock is never used, then the same arguments plus --target-observed-at 2026-10-20T12:00:00Z and --json exit 1, target completeness is unknown, and outcome is INCONCLUSIVE or VIOLATED; missing stop: both phases together; both phases are one row; the exit 2 stderr is not the exit 1 document; target completeness unknown is not the outcome membership; this function is not parametrized; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; target.jsonl bytes are not copied here; check_exit_constants records the help line 2  an internal tool error exits 2 and is not this run; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not outcome; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, the --as-of help says no wall clock and is not the stderr phrase wall clock is never used, --target-observed-at is declared with type _instant, and GAP-cli-outcome-parse-instant returns Display sesslint.outcome.snapshot.parse_instant is not available before reading inputs, so that declaration is not both phases and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; the phrase wall clock is never used is absent there; outcome case id 960 is one EvaluationError, an evaluation instant is required: pass as_of or a target observed_at, on unobserved.json, and that error is not exit 2 from main() on target.jsonl; outcome case id 984 is one verify_outcome on unobserved.json with exit 1 and outcome INCONCLUSIVE, and its target completeness is complete, so it is not completeness unknown and it is not the second phase of this argv; one EvaluationError is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_input_errors_exit_two",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_input_errors_exit_two, one row for both cells: --target-completeness partial exits 2 and stderr contains contradicts, and --as-of 2026-10-20T10:00:00Z exits 2 and stderr contains precedes; missing stop: both cells together; one cell is not this pytest; the partial cell is not the as-of cell; a returned exit 2 is the mode of both cells; the naive as-of SystemExit is not this returned exit 2; test_naive_as_of_is_a_usage_error raises SystemExit and is not these returned codes; this function is parametrized and a parametrized function is one row covering every cell; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; check_exit_epilog records the note (also usage error / invalid flags / I/O failure) and is not these two runs; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not these flags; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, configure_subcommand_declarations lists --target-completeness choice partial and --as-of, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that declaration is not both cells and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; the word contradicts is absent there; outcome case id 1920 is one verify_outcome on partial.json with exit 0, outcome VERIFIED, and target completeness partial, so it is not --target-completeness partial and not exit 2; outcome case id 36 is one EvaluationError, the evaluation instant precedes the source observation time, for as_of 2026-11-08T00:00:00Z, and that error is not returned exit 2 for --as-of 2026-10-20T10:00:00Z and is not the partial cell; one EvaluationError is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_naive_as_of_is_a_usage_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_naive_as_of_is_a_usage_error: --as-of 2026-10-20T12:00:00 raises SystemExit code 2 and stderr contains UTC offset; missing stop: that SystemExit together with the stderr phrase; this function is not parametrized; a returned exit 2 is not this SystemExit; test_input_errors_exit_two returns exit 2 for an offset as-of and is not this raise; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; check_exit_constants records the help line 2  an internal tool error exits 2 and is not this SystemExit; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, --as-of and --target-observed-at help text says UTC offset required, which is declaration help and not this raised SystemExit, and GAP-cli-outcome-parse-instant returns Display sesslint.outcome.snapshot.parse_instant is not available before reading inputs, so that gap is not SystemExit code 2 and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; outcome case id 12 is one EvaluationError, the evaluation instant needs a UTC offset, with as_of naive on source.json and target.json, and that EvaluationError is not SystemExit from main() of BASE with this naive as-of; one EvaluationError is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_invalid_contract_lists_problems",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_invalid_contract_lists_problems: a contract whose schema is sesslint.outcome-contract/v1 and whose conditions are empty exits 2, stderr contains invalid outcome contract, and stderr contains at least three indented dash lines; missing stop: both assertions together; both assertions are one row; the invalid-contract phrase is not the indented dash count; this function is not parametrized; the contract document is not copied here; a larger contract is not copied here; the usage SystemExit is not this returned exit 2; test_naive_as_of_is_a_usage_error raises SystemExit and is not this returned exit 2; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; check_exit_epilog is a help note and is not this stderr; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not this contract; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, the contract argument help names sesslint.outcome-contract/v1 JSON file, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that help is not this run and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; the phrase invalid outcome contract is absent there; outcome case id 4800 is one ContractError, contract: not valid strict UTF-8 JSON (JSONDecodeError), for invalid.json, and that error is not this empty-conditions contract, not the stderr phrase, and not three indented dash lines; one ContractError is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_missing_files_and_arguments_exit_two",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_files_and_arguments_exit_two, one row for three calls: a missing contract with --explain exits 2, a contract plus source without a target exits 2, and a missing source file exits 2; the drained stderr contains both could not be read and needs --source and --target; missing stop: that whole three-call sequence together with both stderr phrases; one call is not this pytest; the missing-contract explain exit 2 is not the missing-target exit 2; the missing-target exit 2 is not the missing-source exit 2; the phrases are read once from the drained stderr, not from one call; this function is not parametrized; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; test_explain_reads_only_the_contract is the success-then-rejection and is not this missing-file explain; check_exit_epilog is a help note and is not this drained stderr; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not these three calls; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, configure_subcommand_declarations lists --explain, --source, and --target, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that declaration is not the three calls and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; could not be read and needs --source and --target are absent there; outcome case id 4809 is one OSError with message io for missing.json on the contract, source, and target of a single verify_outcome, and that one error is not three main() calls and not the drained stderr; one OSError is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_explain_reads_only_the_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_explain_reads_only_the_contract: explain exits 0 and stdout contains Conditions:, then explain plus --source exits 2; missing stop: both calls together; both calls are one row; the exit 0 Conditions: stdout is not the following exit 2; the second call does not assert stderr text; this function is not parametrized; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; the contract bytes are not copied here; the missing-file explain exit 2 is not this success-then-rejection; test_missing_files_and_arguments_exit_two starts with a missing contract and --explain at exit 2 and is not this exit 0; check_exit_constants records the help line 0  a clean session exits 0 and is not this explain; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, the --explain help says validate the contract and print what it checks and read no snapshots, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that help is not the success-then-rejection and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; Conditions: is absent there; no verify_outcome row prints Conditions: or rejects explain plus --source; one evaluation case is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_output_never_overwrites_inputs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_output_never_overwrites_inputs, one row for all three victims: copies of contract.json, source.csv, and target_complete.json; for each victim, --json -o of that path exits 2 and the name-to-bytes map is unchanged; missing stop: all three victims together with the unchanged map; one victim is not this pytest; contract.json is not source.csv; source.csv is not target_complete.json; the file bytes are not copied here; this function is parametrized and a parametrized function is one row covering every cell; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; _copy is the helper that makes the copies and is not a test; check_exit_constants records the help line 2  an internal tool error exits 2 and is not this byte map; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not these three destinations; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, the -o/--output help says existing report files are overwritten atomically, which is not exit 2 with an unchanged name-to-bytes map, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that help is not the three victims and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; its cases do not record -o or a name-to-bytes map; the letters -o inside those human reports are the word exactly-once, not this flag; one evaluation case is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_output_file_and_linked_session",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_output_file_and_linked_session: --session of fixtures/sessions/minimal-valid.jsonl with --json and -o of a new report exits 1, the written document has dimensions.session_integrity.link user_asserted, and that document validates against sesslint.outcome-report.v1.json; missing stop: those three assertions together; all three assertions are one row; exit 1 is not the link field; the link field is not the schema validation; the session is not copied here; capsys is drained and stdout is not asserted; this function is not parametrized; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; the stdout schema test is not this file write; test_json_report_validates_and_exits_one_on_violation validates stdout and does not pass --session or -o; check_exit_constants records the help line 1  a session with findings exits 1 and is not this written file; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, the --session help says user-asserted and -o is declared, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that help is not the written link field and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; minimal-valid is absent there; outcome case id 1 is one verify_outcome with session ok, exit 0, outcome VERIFIED, and link user_asserted, and that injected session is not fixtures/sessions/minimal-valid.jsonl, not -o of a new report, not exit 1, and not validation against sesslint.outcome-report.v1.json; one evaluation case is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_hash_keys_flag",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_hash_keys_flag: --hash-keys --json exits 1, the raw key the pytest checks is absent, and key_display is sha256; missing stop: those assertions together; both assertions are one row; the absence is not key_display sha256; the raw key is not quoted here; this function is not parametrized; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; the orders fixture bytes are not copied here; the linked-session test is not this pytest; test_output_file_and_linked_session writes a report and checks link user_asserted and is not this stdout; test_cli_output_is_byte_stable compares two stdout values and is not this absence; check_exit_constants records the help line 1  a session with findings exits 1 and is not this flag; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, the --hash-keys help says truncated SHA-256 pseudonyms, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that help is not key_display sha256 and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; outcome case id 486 is one verify_outcome with hash_keys true on empty.json, exit 1, outcome VIOLATED, and key_display sha256, and it does not assert that the raw key the pytest checks is absent from orders CLI stdout; outcome case id 6 is hash_keys true with exit 0 and outcome VERIFIED, so it is not this exit 1; one evaluation case is not this entire CLI pytest; coverage.json names test_hash_keys_hide_plain_keys from tests/outcome/test_outcome_engine.py with an empty vector id list, and that engine test is not this CLI pytest; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_output_is_byte_stable",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_output_is_byte_stable: two BASE --json runs produce equal stdout; missing stop: that equality; one run is not this pytest; the pytest does not assert either exit code; this function is not parametrized; helpers _copy, BASE, CONTRACT, SOURCE, and TARGET are not tests; the orders fixture bytes are not copied here; the hash-keys run is not this equality; test_hash_keys_flag passes --hash-keys and checks an absence and key_display and is not these two plain JSON runs; test_json_report_validates_and_exits_one_on_violation is one run that validates a schema and is not this equality; create_parser_subcommand_names lists outcome and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.outcome/vectors.json is pinned to 02694d537104659df66cdd084354739f3cccc440, configure_subcommand_declarations lists --json, and GAP-cli-outcome-runtime claims no exit code or emit_text parity, so that declaration is not two equal stdout values and that id is not a cli vector; parity/vectors/outcome/vectors.json is the same pin; each case is one verify_outcome; outcome case id 480 is one VIOLATED report and not two stdout byte strings; no case stores two outputs and compares them; one evaluation case is not this entire CLI pytest; coverage.json does not name tests/outcome/test_outcome_cli.py; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_json_report_validates_and_exits_one_on_violation",
    "test_verified_outcome_exits_zero",
    "test_human_output_is_the_default",
    "test_plain_target_needs_an_evaluation_instant",
    "test_input_errors_exit_two",
    "test_naive_as_of_is_a_usage_error",
    "test_invalid_contract_lists_problems",
    "test_missing_files_and_arguments_exit_two",
    "test_explain_reads_only_the_contract",
    "test_output_never_overwrites_inputs",
    "test_output_file_and_linked_session",
    "test_hash_keys_flag",
    "test_cli_output_is_byte_stable",
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
fn pinned_outcome_test_outcome_cli_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 148);
}

#[test]
fn pinned_outcome_test_outcome_cli_row_count_equals_thirteen() {
    assert_eq!(ROWS.len(), 13);
    assert_eq!(PINNED_TEST_COUNT, 13);
}

#[test]
fn every_pinned_outcome_test_outcome_cli_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 13);
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

#[test]
fn outcome_corpus_was_considered() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(OUTCOME_VECTORS_REL);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "outcome vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\":\"sesslint.outcome\""));
    assert!(json.contains("\"schema\":\"sesslint.parity-module-vectors/v1\""));

    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 13);

    let cli_path = vectors_path();
    let cli = fs::read_to_string(&cli_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", cli_path.display()));
    let cli_ids: BTreeSet<&str> = vector_ids(&cli).into_iter().collect();

    for row in ROWS {
        let Disposition::Covered { vector_id, .. } = row.disposition else {
            continue;
        };
        if cli_ids.contains(vector_id) {
            continue;
        }
        let marker = format!("\"id\":{vector_id},\"input\"");
        assert!(
            json.contains(&marker),
            "{} names missing outcome vector {vector_id}",
            row.name
        );
    }
}
