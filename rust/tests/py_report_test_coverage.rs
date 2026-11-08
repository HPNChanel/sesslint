//! Dispositions for the 17 `def test_` functions in pinned
//! `tests/report/test_coverage.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The card names 17 tests;
//! the pin has 17. This integration test crate links `sesslint-rust-workspace`,
//! whose library exports [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `report/vectors.json`,
//! `checks.runner/vectors.json`, `repair.executor/vectors.json`,
//! `cli.check/vectors.json`, `profiles/vectors.json`, or
//! `profiles.builtin/vectors.json` whose construct is the same function and
//! the same success or failure mode as that entire pinned test. One example
//! inside a sweep, an export name, or a shared substring such as `Coverage:`
//! is not coverage. A Rust seam while the pin test succeeds is not coverage.
//! `not_applicable` records a `CoverageSkip`, `Coverage`, `parse_report`,
//! `dump_report`, `build_report`, `render_human`, `run_all_checks`,
//! `get_profile`, `main`, or `check_file` check this package cannot reach
//! without a `Cargo.toml` change, or a mode no vector records as the full
//! pin outcome. Omitted `build_report` coverage is the
//! `GAP-report-default-coverage` seam. `return_coverage` true is the
//! `GAP-runner-coverage` seam. An existing `check` file stops at
//! `sesslint.api.check_file`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 17;
const REPORT_VECTOR_COUNT: usize = 17;
const RUNNER_VECTOR_COUNT: usize = 8;
const EXECUTOR_REL: &str = "parity/vectors/repair.executor/vectors.json";
const REPORT_VECTORS_REL: &str = "parity/vectors/report/vectors.json";
const RUNNER_VECTORS_REL: &str = "parity/vectors/checks.runner/vectors.json";
const CLI_CHECK_VECTORS_REL: &str = "parity/vectors/cli.check/vectors.json";
const PROFILES_VECTORS_REL: &str = "parity/vectors/profiles/vectors.json";
const BUILTIN_VECTORS_REL: &str = "parity/vectors/profiles.builtin/vectors.json";

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

/// Top-level ids. Nested `"id"` fields are indented further.
const REPORT_VECTORS: &[(&str, &str)] = &[
    ("module_exports", "module_exports"),
    ("module_constants", "module_constants"),
    ("compute_assurance_none_empty", "compute_assurance"),
    ("compute_assurance_nonempty_a3", "compute_assurance"),
    ("dump_report_gap", "dump_report"),
    ("parse_report_json_string_gap", "parse_report"),
    ("parse_report_bool_total", "parse_report"),
    ("build_report_empty_gap", "build_report"),
    ("render_human_healthy_header", "render_human"),
    ("render_human_with_finding_gap", "render_human"),
    ("minimize_path_under_home", "minimize_path"),
    ("minimize_path_home_self", "minimize_path"),
    ("minimize_path_passthrough_tilde", "minimize_path"),
    ("minimize_path_passthrough_dotdot", "minimize_path"),
    ("minimize_path_passthrough_home", "minimize_path"),
    ("minimize_path_outside_gap", "minimize_path"),
    ("compute_assurance_warning_a2", "compute_assurance"),
];

const RUNNER_VECTORS: &[(&str, &str)] = &[
    ("module_all_export", "module_all"),
    ("import_paths_pin_order", "import_paths"),
    ("empty_neutral_no_findings", "run_all_checks"),
    ("return_coverage_empty_stop", "run_all_checks"),
    ("version_gated_skips_detectors", "run_all_checks"),
    ("cap_exceeded_skips_detectors", "run_all_checks"),
    ("graph_healthy_fixture_silent", "run_all_checks"),
    ("profile_name_neutral_builtin", "run_all_checks"),
];

const CLI_CHECK_VECTORS: &[(&str, &str)] = &[("configure_subcommand_declarations", "configure")];

const PROFILES_VECTORS: &[(&str, &str)] = &[
    ("package_all", "noop"),
    ("package_registry_order", "noop"),
    ("package_neutral_name", "noop"),
];

const BUILTIN_VECTORS: &[(&str, &str)] = &[
    ("all_rules_order", "noop"),
    ("neutral_to_dict", "profile_to_dict"),
    ("claude_strict_to_dict", "profile_to_dict"),
    ("openai_strict_to_dict", "profile_to_dict"),
    ("registry_order", "noop"),
    ("all_names", "noop"),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_coverage_skip_dataclass_valid",
        disposition: Disposition::NotApplicable(
            "CoverageSkip for check SL201, reason profile-gated, and detail rule not in profile, then to_dict keys check, detail, and reason; module_exports lists CoverageSkip and VALID_COVERAGE_SKIP_REASONS in python_all only, and no report vector constructs CoverageSkip",
        ),
    },
    Row {
        name: "test_coverage_skip_rejects_unknown_reason",
        disposition: Disposition::NotApplicable(
            "CoverageSkip for check SL201 and reason arbitrary-custom-reason raises SchemaError matching CoverageSkip.reason must be one of; no report vector records that closed-vocabulary rejection",
        ),
    },
    Row {
        name: "test_coverage_skip_rejects_empty_check",
        disposition: Disposition::NotApplicable(
            "CoverageSkip raises SchemaError matching CoverageSkip.check must be a non-empty string for an empty check and again for a whitespace check, both with reason profile-gated; no report vector constructs CoverageSkip, and one empty-string rejection would not be the two-call sweep",
        ),
    },
    Row {
        name: "test_coverage_skip_rejects_content_leak",
        disposition: Disposition::NotApplicable(
            "CoverageSkip for check SL201, reason profile-gated, and a detail that contains a newline raises ContentLeakError matching Intrinsic content leak in CoverageSkip.detail; no report vector records a content-leak rejection",
        ),
    },
    Row {
        name: "test_coverage_skip_sorting_order",
        disposition: Disposition::NotApplicable(
            "sorted on four CoverageSkip values yields SL001 profile-gated, then SL002 adapter-not-applicable, then SL002 profile-gated, then SL002 profile-gated with detail extra; no report vector records CoverageSkip ordering, and one skip would not be that four-item total order",
        ),
    },
    Row {
        name: "test_coverage_dataclass_valid",
        disposition: Disposition::NotApplicable(
            "Coverage performed (SL002, SL001) sorts to SL001 then SL002, skipped sorts an SL101 adapter-not-applicable skip before an SL202 profile-gated skip, and adapter id claude version 1.0.0 and profile id strict version 2.0.0 sort id before version; module_exports lists Coverage in python_all only, and no report vector constructs Coverage",
        ),
    },
    Row {
        name: "test_coverage_rejects_invalid_performed_or_skipped",
        disposition: Disposition::NotApplicable(
            "Coverage raises SchemaError matching Coverage.performed when performed is not a sequence of check strings, and SchemaError matching Coverage.skipped when skipped holds a non-CoverageSkip; no report vector records either rejection, and one of the two raises would not be the sweep",
        ),
    },
    Row {
        name: "test_parse_report_validates_coverage_roundtrip",
        disposition: Disposition::NotApplicable(
            "build_report for session sess_cov_1 with one SL001 finding, assurance A1, performed SL001 and SL002, one profile-gated SL201 skip, adapter claude, and profile strict, then dump_report and parse_report round-trip those coverage fields; dump_report_gap is dump_report of sess_healthy with gap_json_dumps, parse_report_json_string_gap is parse_report of sess_healthy with an empty skipped list and gap_json_loads, and both seams stop while the pin round-trip succeeds",
        ),
    },
    Row {
        name: "test_parse_report_rejects_missing_coverage",
        disposition: Disposition::NotApplicable(
            "build_report for session sess_cov_2 omits coverage, the dict drops coverage, and parse_report raises SchemaError matching Missing required field in report: 'coverage'; build_report_empty_gap stops at gap_all_rules for sess_healthy, parse_report_bool_total fails because counts.total is True, and no report vector deletes coverage",
        ),
    },
    Row {
        name: "test_parse_report_rejects_unknown_skip_reason",
        disposition: Disposition::NotApplicable(
            "build_report for session sess_cov_3, then parse_report of a skipped entry whose reason is unauthorized-magic-reason raises SchemaError matching Invalid coverage skip reason; no report vector records that tampered skip reason",
        ),
    },
    Row {
        name: "test_run_all_checks_profile_gating_never_claims_performed",
        disposition: Disposition::NotApplicable(
            "get_profile neutral then repair.executor run_all_checks on empty events with that profile, adapter canonical, and return_coverage true, asserting performed and skipped are disjoint; return_coverage_empty_stop is checks.runner run_all_checks with return_coverage true and rust mode coverage_unavailable while the pin succeeds, profile_name_neutral_builtin stops at sesslint.profiles.builtin, empty_neutral_no_findings does not return coverage, package_all only names get_profile, and module_all_export_order lists run_all_checks without a run_all_checks construct",
        ),
    },
    Row {
        name: "test_run_all_checks_empty_input_skips_semantic_checks",
        disposition: Disposition::NotApplicable(
            "the same empty neutral canonical run_all_checks call asserts at least one empty-input skip and that SL101 or SL201 is among those codes; return_coverage_empty_stop records findings_count 0 and coverage_unavailable, checks.runner vectors contain neither empty-input nor SL101, and all_rules_order lists those codes under type noop without calling run_all_checks",
        ),
    },
    Row {
        name: "test_human_renderer_includes_coverage_section",
        disposition: Disposition::NotApplicable(
            "build_report for session sess_cov_human with empty findings, assurance A1, limitation Human render coverage test., and omitted coverage, then render_human contains the substrings Coverage: and checks performed; render_human_healthy_header is a different render_human success for session sess_healthy assurance A2 whose full header happens to include those substrings, build_report_empty_gap stops at gap_all_rules, and omitted coverage is the GAP-report-default-coverage seam while the pin render succeeds",
        ),
    },
    Row {
        name: "test_coverage_gated_fixture_roundtrip",
        disposition: Disposition::NotApplicable(
            "parse_report of fixtures/report/coverage_gated.json yields schema sesslint.report/v1, session session-coverage-gated-001, assurance A2, zero findings, four profile-gated skips, adapter canonical, and profile claude-strict, then dump_report is byte-stable across a second parse; parse_report_json_string_gap is sess_healthy with an empty skipped list and gap_json_loads, dump_report_gap is gap_json_dumps, and no report vector names that fixture",
        ),
    },
    Row {
        name: "test_cli_check_json_contains_valid_coverage",
        disposition: Disposition::NotApplicable(
            "cli main check on fixtures/cli/check_basic/healthy.jsonl with --json exits 0, the stdout object has coverage performed, skipped, adapter, and profile, performed is a non-empty list, and parse_report keeps that performed list; cli.check has only configure_subcommand_declarations, which declares --json, and GAP-cli-check-run-stops omits run vectors because an existing file stops at sesslint.api.check_file is not available while the pin check succeeds",
        ),
    },
    Row {
        name: "test_cli_check_detection_failure_records_coverage",
        disposition: Disposition::NotApplicable(
            "cli main check --json on an unparseable session file exits 0 with assurance A0, a limitation starting Unsupported: format-undetected, empty findings, empty performed, and every skip reason adapter-not-applicable; no cited vector records that detection-failure coverage, and the same check_file stop means the pin success is not a covered run",
        ),
    },
    Row {
        name: "test_detection_failure_coverage_tracks_registry",
        disposition: Disposition::NotApplicable(
            "check_file on that same unparseable file yields skipped checks equal to ALL_RULES; all_rules_order is type noop listing the registry codes, package_all names ALL_RULES, and no cited vector calls check_file or compares a detection-failure skip set to that registry",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_coverage_skip_dataclass_valid",
    "test_coverage_skip_rejects_unknown_reason",
    "test_coverage_skip_rejects_empty_check",
    "test_coverage_skip_rejects_content_leak",
    "test_coverage_skip_sorting_order",
    "test_coverage_dataclass_valid",
    "test_coverage_rejects_invalid_performed_or_skipped",
    "test_parse_report_validates_coverage_roundtrip",
    "test_parse_report_rejects_missing_coverage",
    "test_parse_report_rejects_unknown_skip_reason",
    "test_run_all_checks_profile_gating_never_claims_performed",
    "test_run_all_checks_empty_input_skips_semantic_checks",
    "test_human_renderer_includes_coverage_section",
    "test_coverage_gated_fixture_roundtrip",
    "test_cli_check_json_contains_valid_coverage",
    "test_cli_check_detection_failure_records_coverage",
    "test_detection_failure_coverage_tracks_registry",
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
fn every_pinned_report_coverage_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REPORT_VECTORS.len(), REPORT_VECTOR_COUNT);
    assert_eq!(RUNNER_VECTORS.len(), RUNNER_VECTOR_COUNT);
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
fn cited_report_coverage_vectors_are_present() {
    let report = read_vectors(REPORT_VECTORS_REL, "sesslint.report");
    assert_top_level_catalog(&report, "report", REPORT_VECTORS);
    for absent in [
        "profile-gated",
        "empty-input",
        "adapter-not-applicable",
        "sess_cov_",
        "session-coverage-gated",
        "unauthorized-magic-reason",
        "arbitrary-custom-reason",
        "ContentLeakError",
        "Missing required field",
        "Invalid coverage skip",
        "\"type\": \"Coverage",
    ] {
        assert!(
            !report.contains(absent),
            "report vectors unexpectedly contain {absent}"
        );
    }
    assert!(report.contains("GAP-report-json-dumps"));
    assert!(report.contains("GAP-report-json-loads"));
    assert!(report.contains("GAP-report-default-coverage"));
    let exports = vector_slice(&report, "module_exports");
    for name in [
        "VALID_COVERAGE_SKIP_REASONS",
        "Coverage",
        "CoverageSkip",
        "build_report",
        "dump_report",
        "parse_report",
        "render_human",
    ] {
        assert!(exports.contains(&format!("\"{name}\"")));
    }
    let dumped = vector_slice(&report, "dump_report_gap");
    assert!(dumped.contains("\"type\": \"dump_report\""));
    assert!(dumped.contains("\"session_id\": \"sess_healthy\""));
    assert!(dumped.contains("\"mode\": \"gap_json_dumps\""));
    let parsed = vector_slice(&report, "parse_report_json_string_gap");
    assert!(parsed.contains("\"type\": \"parse_report\""));
    assert!(parsed.contains("\"input_kind\": \"json_string\""));
    assert!(parsed.contains("\"session_id\": \"sess_healthy\""));
    assert!(parsed.contains(r#"\"skipped\":[]"#));
    assert!(parsed.contains("\"mode\": \"gap_json_loads\""));
    let bool_total = vector_slice(&report, "parse_report_bool_total");
    assert!(bool_total
        .contains("\"display\": \"counts.total must be a non-negative integer, got True\""));
    let built = vector_slice(&report, "build_report_empty_gap");
    assert!(built.contains("\"type\": \"build_report\""));
    assert!(built.contains("\"findings_count\": 0"));
    assert!(built.contains("\"session_id\": \"sess_healthy\""));
    assert!(built.contains("\"mode\": \"gap_all_rules\""));
    let header = vector_slice(&report, "render_human_healthy_header");
    assert!(header.contains("\"type\": \"render_human\""));
    assert!(header.contains("\"session_id\": \"sess_healthy\""));
    assert!(header.contains("\"assurance\": \"A2\""));
    assert!(header.contains("\"limitation\": \"Graph invariants validated.\""));
    assert!(header.contains("Coverage:"));
    assert!(header.contains("checks performed"));
    assert!(!header.contains("sess_cov_human"));
    let finding_gap = vector_slice(&report, "render_human_with_finding_gap");
    assert!(finding_gap.contains("\"mode\": \"gap_refusal_rationale\""));

    let runner = read_vectors(RUNNER_VECTORS_REL, "sesslint.checks.runner");
    assert_top_level_catalog(&runner, "checks.runner", RUNNER_VECTORS);
    for absent in [
        "profile-gated",
        "empty-input",
        "adapter-not-applicable",
        "SL101",
        "SL201",
    ] {
        assert!(
            !runner.contains(absent),
            "checks.runner vectors unexpectedly contain {absent}"
        );
    }
    assert!(runner.contains("GAP-runner-coverage"));
    assert!(runner.contains("GAP-runner-executor-alias"));
    let coverage_stop = vector_slice(&runner, "return_coverage_empty_stop");
    assert!(coverage_stop.contains("\"type\": \"run_all_checks\""));
    assert!(coverage_stop.contains("\"return_coverage\": true"));
    assert!(coverage_stop.contains("\"findings_count\": 0"));
    assert!(coverage_stop.contains("\"mode\": \"coverage_unavailable\""));
    assert!(coverage_stop.contains("\"message\": \"sesslint.report.Coverage is not available\""));
    let empty = vector_slice(&runner, "empty_neutral_no_findings");
    assert!(empty.contains("\"findings_count\": 0"));
    assert!(!empty.contains("return_coverage"));
    let profile_name = vector_slice(&runner, "profile_name_neutral_builtin");
    assert!(profile_name.contains("\"profile\": \"neutral\""));
    assert!(profile_name.contains("\"mode\": \"builtin_unavailable\""));
    assert!(profile_name.contains("\"message\": \"sesslint.profiles.builtin is not available\""));
    assert!(!profile_name.contains("return_coverage"));

    let executor = read_vectors(EXECUTOR_REL, "sesslint.repair.executor");
    let executor_names = vector_slice(&executor, "module_all_export_order");
    assert!(executor_names.contains("\"type\": \"module_all\""));
    assert!(executor_names.contains("\"run_all_checks\""));
    assert!(
        !executor.contains("\"type\": \"run_all_checks\""),
        "repair.executor must not be treated as a run_all_checks call"
    );

    let cli_check = read_vectors(CLI_CHECK_VECTORS_REL, "sesslint.cli.check");
    assert_top_level_catalog(&cli_check, "cli.check", CLI_CHECK_VECTORS);
    assert!(cli_check.contains("sesslint.api.check_file is not available"));
    assert!(cli_check.contains("Run vectors omitted"));
    assert!(!cli_check.contains("coverage"));
    let configure = vector_slice(&cli_check, "configure_subcommand_declarations");
    assert!(configure.contains("\"type\": \"configure\""));
    assert!(configure.contains("\"--json\""));

    let profiles = read_vectors(PROFILES_VECTORS_REL, "sesslint.profiles");
    assert_top_level_catalog(&profiles, "profiles", PROFILES_VECTORS);
    assert!(profiles.contains("sesslint.profiles.builtin is not available"));
    assert!(profiles.contains("get_profile and list_profiles are re-exported"));
    let package_all = vector_slice(&profiles, "package_all");
    assert!(package_all.contains("\"type\": \"noop\""));
    assert!(package_all.contains("\"get_profile\""));
    assert!(package_all.contains("\"ALL_RULES\""));
    let neutral_name = vector_slice(&profiles, "package_neutral_name");
    assert!(neutral_name.contains("\"neutral\": \"neutral\""));
    assert!(!neutral_name.contains("get_profile"));

    let builtin = read_vectors(BUILTIN_VECTORS_REL, "sesslint.profiles.builtin");
    assert_top_level_catalog(&builtin, "profiles.builtin", BUILTIN_VECTORS);
    assert!(!builtin.contains("check_file"));
    let all_rules = vector_slice(&builtin, "all_rules_order");
    assert!(all_rules.contains("\"type\": \"noop\""));
    assert!(all_rules.contains("\"SL101\""));
    assert!(all_rules.contains("\"SL201\""));
    assert!(vector_slice(&builtin, "all_names").contains("\"ALL_RULES\""));

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let slice = if report.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&report, vector_id)
        } else if runner.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&runner, vector_id)
        } else if executor.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&executor, vector_id)
        } else if cli_check.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&cli_check, vector_id)
        } else if profiles.contains(&format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"")) {
            vector_slice(&profiles, vector_id)
        } else {
            vector_slice(&builtin, vector_id)
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
