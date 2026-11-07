//! Dispositions for the 36 `def test_` functions in pinned
//! `tests/test_report.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (1066 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.report`.
//!
//! `covered` names one id in `report/vectors.json` whose construct is the same
//! function and the same result as that entire pinned test. `build_report_empty_gap`
//! is the ALL_RULES seam, and `render_human_healthy_header` is a header vector,
//! so the report parity file does not make these tests covered. One example
//! inside a sweep is not coverage. No `def test_` in this file calls
//! `minimize_path`. `test_minimize_path_already_minimized` lives in
//! `tests/report/test_paths.py`. `not_applicable` records a `sesslint.report`
//! call this package cannot reach without a `Cargo.toml` change, or a mode no
//! vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 36;
const REPORT_VECTOR_COUNT: usize = 17;
const VECTORS_REL: &str = "parity/vectors/report/vectors.json";

/// `covered` names a vector id in `report/vectors.json`.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from that
/// vector file.
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

/// Vector id, construct type, and whether the expected result is an error.
/// A thrown failure would be the key `"message"`. Header text, display
/// strings, pin summaries, and gap assertions are not that key.
const REPORT_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("compute_assurance_none_empty", "compute_assurance", false),
    ("compute_assurance_nonempty_a3", "compute_assurance", false),
    ("dump_report_gap", "dump_report", false),
    ("parse_report_json_string_gap", "parse_report", false),
    ("parse_report_bool_total", "parse_report", false),
    ("build_report_empty_gap", "build_report", false),
    ("render_human_healthy_header", "render_human", false),
    ("render_human_with_finding_gap", "render_human", false),
    ("minimize_path_under_home", "minimize_path", false),
    ("minimize_path_home_self", "minimize_path", false),
    ("minimize_path_passthrough_tilde", "minimize_path", false),
    ("minimize_path_passthrough_dotdot", "minimize_path", false),
    ("minimize_path_passthrough_home", "minimize_path", false),
    ("minimize_path_outside_gap", "minimize_path", false),
    ("compute_assurance_warning_a2", "compute_assurance", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_build_report_derives_counts_correctly",
        disposition: Disposition::NotApplicable(
            "build_report of six findings for session sess-test-counts returns total 6, by_severity fatal 1 error 3 warning 1 info 1, and by_code SL001 2 SL002 2 SL003 1 SL101 1; build_report_empty_gap is the ALL_RULES seam for findings_count 0",
        ),
    },
    Row {
        name: "test_build_report_signature_has_no_counts_parameter",
        disposition: Disposition::NotApplicable(
            "inspect.signature of build_report has no counts parameter, and passing counts raises TypeError; no report vector records the signature or that TypeError",
        ),
    },
    Row {
        name: "test_empty_findings_clean_bill_report",
        disposition: Disposition::NotApplicable(
            "build_report of session sess-clean with zero findings and assurance A2 returns zero counts, then dump_report and parse_report round-trip those counts; build_report_empty_gap is the ALL_RULES seam for findings_count 0, and render_human_healthy_header is a header string",
        ),
    },
    Row {
        name: "test_limitation_required_for_all_assurance_levels",
        disposition: Disposition::NotApplicable(
            "build_report and Report reject an empty limitation and a whitespace limitation at A0, A1, A2, A3, and A4; no report vector records those AssuranceError cases, and one level would not be the sweep",
        ),
    },
    Row {
        name: "test_invalid_assurance_level_raises",
        disposition: Disposition::NotApplicable(
            "build_report rejects assurance A5, clean, healthy, A, and the empty string; no report vector records that AssuranceError sweep",
        ),
    },
    Row {
        name: "test_build_report_sorts_shuffled_findings_deterministically",
        disposition: Disposition::NotApplicable(
            "ten shuffled build_report calls on the same five findings keep one findings tuple and one dump_report byte string; build_report_empty_gap is the ALL_RULES seam for findings_count 0, and dump_report_gap is the json.dumps seam for one empty report",
        ),
    },
    Row {
        name: "test_minimal_report_fixture_roundtrip",
        disposition: Disposition::NotApplicable(
            "parse_report of fixtures/reports/minimal.json yields schema sesslint.report/v1, session session-minimal-001, assurance A1, two findings, and counts total 2, then dump and parse are byte-stable; parse_report_json_string_gap is the json.loads seam for session sess_healthy and counts total 0",
        ),
    },
    Row {
        name: "test_report_schema_anti_drift",
        disposition: Disposition::NotApplicable(
            "load_report_schema matches the schema id, draft 2020-12, additionalProperties false, the required and known report fields, the assurance enum, and the counts keys; module_constants records the schema version string and the assurance names, and no report vector loads the schema",
        ),
    },
    Row {
        name: "test_parse_report_unknown_field_raises_sl302",
        disposition: Disposition::NotApplicable(
            "build_report then parse_report of a mapping with rogue_field raises UnknownFieldError SL302 naming rogue_field; no report vector records that field",
        ),
    },
    Row {
        name: "test_parse_report_unsupported_version_raises_sl301",
        disposition: Disposition::NotApplicable(
            "build_report then parse_report of schema_version sesslint.report/v99 raises VersionError SL301; no report vector records that version",
        ),
    },
    Row {
        name: "test_enforce_content_free_report_catches_smuggled_payload",
        disposition: Disposition::NotApplicable(
            "enforce_content_free raises ContentLeakError for a payload sentence and its lowercase form, and accepts a disjoint substring; no report vector calls enforce_content_free",
        ),
    },
    Row {
        name: "test_enforce_content_free_report_catches_intrinsic_credentials",
        disposition: Disposition::NotApplicable(
            "enforce_content_free of a limitation that contains an email address raises ContentLeakError for an intrinsic leak; no report vector calls enforce_content_free",
        ),
    },
    Row {
        name: "test_unicode_session_id_support",
        disposition: Disposition::NotApplicable(
            "build_report, dump_report, and parse_report keep session id sess-ünicöde-測試-🚀; dump_report_gap is the json.dumps seam for session sess_healthy, and no report vector records that session id",
        ),
    },
    Row {
        name: "test_large_findings_performance",
        disposition: Disposition::NotApplicable(
            "bench/report_10k.py returns total 10000 equal to by_code SL001, tracing false, and wall_s under 1; no report vector records that bench",
        ),
    },
    Row {
        name: "test_a0_unreadable_invariant_documented_and_asserted",
        disposition: Disposition::NotApplicable(
            "build_report with assurance A0 and limitation No structural conclusion. keeps that pair on one fatal finding; build_report_empty_gap is the ALL_RULES seam, and compute_assurance_none_empty calls compute_assurance on null events",
        ),
    },
    Row {
        name: "test_report_counts_mismatch_in_dataclass_raises",
        disposition: Disposition::NotApplicable(
            "Report with counts.total 99 and one finding raises SchemaError because total does not match the findings count; no report vector constructs Report",
        ),
    },
    Row {
        name: "test_tool_version_variance_affects_dump_not_counts",
        disposition: Disposition::NotApplicable(
            "two build_report calls that differ only by tool_version 0.1.0 and 0.2.0 keep equal counts and unequal dump_report bytes; dump_report_gap is the json.dumps seam for tool_version 0.1.0 on one empty report",
        ),
    },
    Row {
        name: "test_schema_loader_file_not_found",
        disposition: Disposition::NotApplicable(
            "load_report_schema raises FileNotFoundError when get_report_schema_path is patched to a missing schema path; no report vector calls load_report_schema",
        ),
    },
    Row {
        name: "test_counts_model_validation_errors",
        disposition: Disposition::NotApplicable(
            "Counts rejects total -1, total True, a string by_severity, a negative error count, a non-mapping by_code, a non-string code key, and a negative code count; parse_report_bool_total is parse_report of one mapping whose total is True, so it is not this Counts sweep",
        ),
    },
    Row {
        name: "test_report_model_validation_errors",
        disposition: Disposition::NotApplicable(
            "Report rejects schema sesslint.report/v2, a blank session_id, an empty source_fingerprint, an empty tool_version, assurance INVALID, findings as a list, a non-Finding item, and counts as a string; no report vector constructs Report, and one rejection would not be the sweep",
        ),
    },
    Row {
        name: "test_build_report_argument_validation",
        disposition: Disposition::NotApplicable(
            "build_report rejects an empty session_id, an empty source_fingerprint, and an empty tool_version; build_report_empty_gap is the ALL_RULES seam for findings_count 0 and does not record those SchemaErrors",
        ),
    },
    Row {
        name: "test_dump_report_type_error",
        disposition: Disposition::NotApplicable(
            "dump_report of a dict raises TypeError Expected Report instance; dump_report_gap is the json.dumps seam for an empty_clean report",
        ),
    },
    Row {
        name: "test_parse_report_error_cases",
        disposition: Disposition::NotApplicable(
            "parse_report rejects malformed JSON, an integer, a JSON array, a missing session_id, findings as a string, counts as a string, and counts missing total; parse_report_bool_total is a bool total and parse_report_json_string_gap is the json.loads seam, so neither is this sweep",
        ),
    },
    Row {
        name: "test_enforce_content_free_report_all_locations",
        disposition: Disposition::NotApplicable(
            "enforce_content_free raises for a forbidden path, record_id, and related id, and a string artifact raises TypeError; no report vector calls enforce_content_free",
        ),
    },
    Row {
        name: "test_get_report_schema_path_prefix_resolution",
        disposition: Disposition::NotApplicable(
            "get_report_schema_path returns the schema under a patched sys.prefix share directory when the dev path is not a file; no report vector calls get_report_schema_path",
        ),
    },
    Row {
        name: "test_parse_report_invalid_assurance_and_limitation",
        disposition: Disposition::NotApplicable(
            "parse_report rejects assurance INVALID, an empty limitation, and a non-string limitation; no report vector records those three failures",
        ),
    },
    Row {
        name: "test_get_schema_paths_fallback_when_neither_exists",
        disposition: Disposition::NotApplicable(
            "when no schema file exists, get_report_schema_path ends in sesslint.report.v1.json and get_manifest_schema_path ends in sesslint.repair-manifest.v1.json; no report vector calls those path functions",
        ),
    },
    Row {
        name: "test_enforce_content_free_source_fingerprint_and_tool_version_leaks",
        disposition: Disposition::NotApplicable(
            "enforce_content_free raises for a forbidden substring in source_fingerprint and for one in tool_version; no report vector calls enforce_content_free",
        ),
    },
    Row {
        name: "test_enforce_content_free_handles_none_forbidden_substrings",
        disposition: Disposition::NotApplicable(
            "enforce_content_free with forbidden_substrings None returns; no report vector calls enforce_content_free",
        ),
    },
    Row {
        name: "test_parse_report_strict_string_field_validation",
        disposition: Disposition::NotApplicable(
            "parse_report rejects a numeric session_id, a list source_fingerprint, and a numeric tool_version; no report vector records those three type failures",
        ),
    },
    Row {
        name: "test_parse_report_counts_unknown_fields_and_severities",
        disposition: Disposition::NotApplicable(
            "parse_report raises SL302 for an unknown counts field and for severity critical, and SchemaError when fatal is missing from by_severity; no report vector records those three counts-schema failures",
        ),
    },
    Row {
        name: "test_report_and_parse_report_reject_counts_mismatch_with_findings",
        disposition: Disposition::NotApplicable(
            "Report rejects by_severity that counts a fatal for one error finding and by_code that counts SL002 for one SL001 finding; no report vector constructs Report, and the body does not call parse_report",
        ),
    },
    Row {
        name: "test_counts_rejects_unknown_severity",
        disposition: Disposition::NotApplicable(
            "Counts rejects by_severity key bogus; no report vector constructs Counts",
        ),
    },
    Row {
        name: "test_parse_report_counts_subfield_types",
        disposition: Disposition::NotApplicable(
            "parse_report rejects by_severity as a string, by_code as a string, total -1, and total True; parse_report_bool_total is only the total True display, so it is not this sweep",
        ),
    },
    // Six compute_assurance calls. compute_assurance_none_empty is one of them.
    Row {
        name: "test_compute_assurance_empty_matrix",
        disposition: Disposition::NotApplicable(
            "compute_assurance returns A0 and No structural conclusion. for empty or None events with empty findings, a warning, an error, and SL001; compute_assurance_none_empty is only null events and empty findings, so it is not this sweep",
        ),
    },
    // Five transitions. Each committed compute_assurance vector is one transition.
    Row {
        name: "test_compute_assurance_non_empty_transitions",
        disposition: Disposition::NotApplicable(
            "compute_assurance on one event returns A3 with replay, A2 without replay, A2 with an SL003 warning, A1 with an SL101 error, and A0 with SL001; compute_assurance_nonempty_a3 and compute_assurance_warning_a2 are one transition each, so neither is this sweep",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_build_report_derives_counts_correctly",
    "test_build_report_signature_has_no_counts_parameter",
    "test_empty_findings_clean_bill_report",
    "test_limitation_required_for_all_assurance_levels",
    "test_invalid_assurance_level_raises",
    "test_build_report_sorts_shuffled_findings_deterministically",
    "test_minimal_report_fixture_roundtrip",
    "test_report_schema_anti_drift",
    "test_parse_report_unknown_field_raises_sl302",
    "test_parse_report_unsupported_version_raises_sl301",
    "test_enforce_content_free_report_catches_smuggled_payload",
    "test_enforce_content_free_report_catches_intrinsic_credentials",
    "test_unicode_session_id_support",
    "test_large_findings_performance",
    "test_a0_unreadable_invariant_documented_and_asserted",
    "test_report_counts_mismatch_in_dataclass_raises",
    "test_tool_version_variance_affects_dump_not_counts",
    "test_schema_loader_file_not_found",
    "test_counts_model_validation_errors",
    "test_report_model_validation_errors",
    "test_build_report_argument_validation",
    "test_dump_report_type_error",
    "test_parse_report_error_cases",
    "test_enforce_content_free_report_all_locations",
    "test_get_report_schema_path_prefix_resolution",
    "test_parse_report_invalid_assurance_and_limitation",
    "test_get_schema_paths_fallback_when_neither_exists",
    "test_enforce_content_free_source_fingerprint_and_tool_version_leaks",
    "test_enforce_content_free_handles_none_forbidden_substrings",
    "test_parse_report_strict_string_field_validation",
    "test_parse_report_counts_unknown_fields_and_severities",
    "test_report_and_parse_report_reject_counts_mismatch_with_findings",
    "test_counts_rejects_unknown_severity",
    "test_parse_report_counts_subfield_types",
    "test_compute_assurance_empty_matrix",
    "test_compute_assurance_non_empty_transitions",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces.
    const MARKER: &str = "\n      \"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("report vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
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
fn every_pinned_report_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REPORT_VECTORS.len(), REPORT_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_report_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "report vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.report\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = REPORT_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in REPORT_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"message\":"),
            fails,
            "{id} error mode does not match the vector file"
        );
    }

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
