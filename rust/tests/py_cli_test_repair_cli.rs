//! Dispositions for the 12 `def test_` functions in pinned
//! `tests/cli/test_repair_cli.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (229 splitlines). Exactly twelve
//! test functions, in module order. None is parametrized. The module constant
//! `FIXTURES_DIR` is not a test. Each row is the whole function. A three-phase
//! function is one row. Two API calls are one row. A dry run is not a successful
//! write. A CLI exit is not an API exception. One live-store suffix is not the
//! three-phase test. The basic success test is not the torn-tail repair. The CLI
//! check is not the API pytest.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.cli.main` or
//! `sesslint.api` without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest. A dry run is not a successful write. A CLI exit is not an API
//! exception. One live-store suffix is not the three-phase test. The basic
//! success test is not the torn-tail repair. The CLI check is not the API
//! pytest. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 12;
const PINNED_SPLITLINES: usize = 229;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A dry run is not a successful write. A CLI exit is not an API
/// exception. One live-store suffix is not the three-phase test. The basic
/// success test is not the torn-tail repair. The CLI check is not the API
/// pytest. `not_applicable` names the missing stop.
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
        name: "test_repair_cli_basic_success",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_basic_success calling sesslint.cli.main on repair of fixtures/repair_cli/basic/source.jsonl with --output, requiring exit 0, the output file exists, its manifest sidecar exists, and stdout contains Repair successful and Manifest written to; missing stop: that exit 0 whose output file and manifest sidecar exist and whose stdout contains Repair successful and Manifest written to; a dry run is not a successful write; the dry-run pytest on the same source exits 0 with the output and its manifest absent and stdout containing Plan fingerprint: and is a different pytest; the torn-tail repair calls api.check_file and requires total count 0 and no findings, and the basic success test is not that torn-tail repair; the vendor write-back then check of fixtures/claude_code/basic.jsonl is a different pytest; the overwrite refusal exits 1 and keeps prior text unchanged; check_exit_constants stores the line that a clean session exits 0 and the note that verification passed or a dry-run plan generated, and does not run this repair write; check_exit_epilog stores those notes in help text; create_parser_subcommand_names lists repair among subcommand names and does not run repair --output; parser_shell_metadata describes a conservative repair tool and does not write a manifest; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_dry_run_creates_no_files",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_dry_run_creates_no_files calling sesslint.cli.main on repair of fixtures/repair_cli/basic/source.jsonl with --output and --dry-run, requiring exit 0, the output absent, its manifest absent, and stdout contains Plan fingerprint:; missing stop: that exit 0 whose output and manifest are absent and whose stdout contains Plan fingerprint:; a dry run is not a successful write; the basic success pytest writes the output and the manifest sidecar and requires Repair successful and Manifest written to; the salvage-unsupported pytest also passes --dry-run and --json but exits 2 and requires stderr containing --policy salvage; check_exit_constants stores the note that verification passed or a dry-run plan generated and does not show an absent output; check_exit_epilog stores that note under exit code 0 in help text and does not run repair --dry-run; create_parser_subcommand_names lists repair and does not pass --dry-run; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_refuses_existing_output",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_refuses_existing_output calling sesslint.cli.main on repair of fixtures/repair_cli/basic/source.jsonl with --output set to a prewritten file, requiring exit 1, that prior text unchanged, and stderr lowercased contains refusing to overwrite or repair refused; missing stop: that exit 1 whose prior text is unchanged and whose stderr lowercased contains refusing to overwrite or repair refused; the self-path refusal requires stderr lowercased containing resolves to source path or repair refused; the live-store refusals require refusing to write to live-store path; a dry run is not this refusal; the basic success write exits 0; check_exit_constants stores the line that a session with findings exits 1 and the note that verification failed or repair refused, and does not keep a prewritten output unchanged; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists repair and does not refuse an existing output; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_refuses_self_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_refuses_self_path calling sesslint.cli.main on repair whose --output is the same path as a copy of fixtures/repair_cli/basic/source.jsonl, requiring exit 1 and stderr lowercased contains resolves to source path or repair refused; missing stop: that exit 1 whose stderr lowercased contains resolves to source path or repair refused; the overwrite refusal keeps prior text unchanged and looks for refusing to overwrite or repair refused; the three live-store refusals are a different pytest; check_exit_constants stores the note that verification failed or repair refused and does not resolve an output onto its source; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists repair and does not run this self-path; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_refuses_live_store",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_refuses_live_store calling sesslint.cli.main three times on repair of fixtures/repair_cli/basic/source.jsonl with --output, each requiring exit 1 and stderr lowercased contains refusing to write to live-store path: a .sqlite path that stays absent, a .db path that stays absent, and an existing file that begins with the sqlite magic header; missing stop: those three exit 1 refusals together, the .sqlite path staying absent, the .db path staying absent, and the magic-header file refused; a three-phase function is one row; one live-store suffix is not the three-phase test; the overwrite refusal and the self-path refusal do not require refusing to write to live-store path; check_exit_constants stores the line that a session with findings exits 1 and the note that verification failed or repair refused, and does not refuse a sqlite path, a db path, and a magic header together; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists repair and does not refuse live-store paths; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_invalid_policy_shorthand_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_invalid_policy_shorthand_exits_2 calling sesslint.cli.main on repair of fixtures/repair_cli/basic/source.jsonl with --output and --policy s and raising SystemExit code 2; missing stop: that SystemExit whose code is 2 from --policy s; a CLI exit is not an API exception; this SystemExit is not VendorRepairRefused; the canonical --emit vendor run returns exit 2 with stderr containing no vendor provenance and an absent output; the salvage-unsupported run exits 2 whether returned or raised as SystemExit and requires stderr containing --policy salvage; check_exit_constants stores the line that an internal tool error exits 2 and the note that a usage error, invalid flags, or I/O failure also exits 2, and does not pass --policy s; check_exit_epilog stores that note in help text; verbose_settings_provenance records debug provenance and does not reject this shorthand; removed_flag_hint_salvage is a removed --salvage-unsupported hint on check of synthetic-payload whose text says use --policy salvage, and it is not --policy s; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_rejects_vendor_emit_on_canonical_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_rejects_vendor_emit_on_canonical_exits_2 calling sesslint.cli.main on repair of fixtures/repair_cli/basic/source.jsonl with --output and --emit vendor, requiring exit 2, stderr contains no vendor provenance, and the output is absent; missing stop: that exit 2 whose stderr contains no vendor provenance and whose output is absent; a CLI exit is not an API exception; the API pytest raises VendorRepairRefused matching no vendor provenance, and the CLI exit 2 is not that exception; the --policy s SystemExit does not require no vendor provenance or an absent output; the vendor write-back of fixtures/claude_code/basic.jsonl exits 0; removed_flag_hint_format_membership mentions claude-code-jsonl inside a removed --format hint and does not run repair --emit vendor; check_exit_constants stores the note that a usage error, invalid flags, or I/O failure also exits 2, and does not run this emit refusal; check_exit_epilog stores that note in help text; create_parser_subcommand_names lists repair and does not pass --emit vendor; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_vendor_writeback_detected_format",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_vendor_writeback_detected_format calling sesslint.cli.main on repair of fixtures/claude_code/basic.jsonl with --output, requiring exit 0 and the output exists, draining that repair stdout, then calling sesslint.cli.main on check of that output, requiring exit 0 and stdout contains Claude Code; missing stop: that pair of exit-0 runs, the repair whose output exists and the check whose stdout contains Claude Code; both commands are one row; the API pytest that leaves manifest adapter ids claude-code-jsonl and canonical does not run this check; the CLI check is not that API pytest; the canonical --emit vendor refusal exits 2; the basic success repair of fixtures/repair_cli/basic/source.jsonl requires Repair successful and Manifest written to; a dry run is not a successful write; check_exit_constants stores the line that a clean session exits 0 and does not run this pair; create_parser_subcommand_names lists repair and check among subcommand names and does not run either command on the claude fixture; removed_flag_hint_format_membership mentions claude-code-jsonl as a --format token and does not detect Claude Code; parser_shell_metadata describes a vendor-neutral checker and does not write the claude fixture back; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_api_vendor_writeback_and_canonical_emit",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_api_vendor_writeback_and_canonical_emit calling sesslint.api.repair on fixtures/claude_code/basic.jsonl, leaving the output file and a manifest whose adapter id is claude-code-jsonl, then calling sesslint.api.repair again with emit canonical, leaving that output file and a manifest whose adapter id is canonical; missing stop: those two api.repair calls, the first file and present manifest with adapter id claude-code-jsonl, and the second file and present manifest with adapter id canonical; both calls are one row; two API calls are one row; the CLI check is not this pytest; the CLI repair-then-check whose stdout contains Claude Code is a different pytest; a CLI exit is not an API exception; the canonical emit vendor refusal is a different pytest; removed_flag_hint_format_membership mentions claude-code-jsonl inside a removed --format hint and does not call api.repair or read adapter id canonical; create_parser_subcommand_names lists repair and does not call api.repair; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.api.repair is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_api_vendor_emit_on_canonical_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_api_vendor_emit_on_canonical_refused calling sesslint.api.repair on fixtures/repair_cli/basic/source.jsonl with emit vendor, raising VendorRepairRefused matching no vendor provenance, with the output absent; missing stop: that VendorRepairRefused matching no vendor provenance whose output is absent; a CLI exit is not an API exception; the CLI exit 2 is not this exception; the CLI pytest that returns exit 2 with stderr containing no vendor provenance is a different pytest; the two-call API pytest that leaves adapter ids claude-code-jsonl and canonical is a different pytest; check_exit_constants stores the note that a usage error, invalid flags, or I/O failure also exits 2, and does not raise VendorRepairRefused; removed_flag_hint_format_membership does not raise VendorRepairRefused; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.api.repair is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_salvage_unsupported_flag",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_salvage_unsupported_flag calling sesslint.cli.main on repair of fixtures/repair_cli/basic/source.jsonl with --output, --salvage-unsupported, --dry-run, and --json, requiring exit 2 whether that code is returned or raised as SystemExit, and stderr contains --policy salvage; missing stop: that exit 2, whether returned or raised as SystemExit, whose stderr contains --policy salvage; a dry run is not a successful write; the dry-run pytest exits 0 with stdout containing Plan fingerprint: and files absent; the --policy s pytest raises SystemExit code 2 and does not pass --salvage-unsupported or require --policy salvage in stderr; removed_flag_hint_salvage is a removed-flag hint for check of synthetic-payload with --salvage-unsupported whose hint text says use --policy salvage, and it does not run repair --dry-run --json or accept either a returned code or a SystemExit; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands; check_exit_constants stores the note that a usage error, invalid flags, or I/O failure also exits 2, and does not run this argv; check_exit_epilog stores that note in help text; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_repair_cli_sl002_success",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cli_sl002_success calling sesslint.cli.main on repair of a canonical session whose last line is torn, requiring exit 0, the output exists, and its manifest sidecar exists, then calling sesslint.api.check_file on that output, requiring total count 0 and no findings; missing stop: that exit 0 torn-tail repair whose output and manifest exist and whose api.check_file reports total count 0 and no findings; the basic success test is not this torn-tail repair; the basic success pytest repairs fixtures/repair_cli/basic/source.jsonl and requires stdout containing Repair successful and Manifest written to, and does not call api.check_file; a dry run is not a successful write; a CLI exit is not this check_file result; check_exit_constants stores the line that a clean session exits 0 and does not build a torn tail or call api.check_file; create_parser_subcommand_names lists repair and does not run this torn-tail repair; sesslint.cli vectors record parser metadata, removed-command hints, removed-flag hints, exit-code constants, verbose settings, and main on removed subcommands only; sesslint.cli.main and sesslint.api.check_file are not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_repair_cli_basic_success",
    "test_repair_cli_dry_run_creates_no_files",
    "test_repair_cli_refuses_existing_output",
    "test_repair_cli_refuses_self_path",
    "test_repair_cli_refuses_live_store",
    "test_repair_cli_invalid_policy_shorthand_exits_2",
    "test_repair_cli_rejects_vendor_emit_on_canonical_exits_2",
    "test_repair_cli_vendor_writeback_detected_format",
    "test_repair_api_vendor_writeback_and_canonical_emit",
    "test_repair_api_vendor_emit_on_canonical_refused",
    "test_repair_cli_salvage_unsupported_flag",
    "test_repair_cli_sl002_success",
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
fn pinned_cli_test_repair_cli_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 229);
}

#[test]
fn pinned_cli_test_repair_cli_row_count_equals_twelve() {
    assert_eq!(ROWS.len(), 12);
    assert_eq!(PINNED_TEST_COUNT, 12);
}

#[test]
fn every_pinned_cli_test_repair_cli_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 12);
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
