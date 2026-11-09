//! Dispositions for the 48 `def test_` functions in pinned
//! `tests/test_finding.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (1440 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `finding/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! One example inside a multi-assert sweep is not coverage. A different input
//! string is not coverage. If the construct type or error kind differs, the row
//! is `not_applicable`. This file does not re-run the Python tests, does not
//! sort 100000 findings, and does not read a schema file from disk.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 48;
const FINDING_VECTOR_COUNT: usize = 22;
const VECTORS_REL: &str = "parity/vectors/finding/vectors.json";

/// `covered` names a vector id in `finding/vectors.json`. `not_applicable`
/// records a `sesslint.finding` check this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from that
/// vector file. A vector covers a row only when it is that entire pinned test.
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

/// How `finding/vectors.json` records the result of one construct.
enum VectorMode {
    Ok,
    Error,
    ExportList,
    SortOrder,
}

/// Vector id, construct type, and the result flag stored for that vector.
const FINDING_VECTORS: &[(&str, &str, VectorMode)] = &[
    ("all_export_order", "ALL", VectorMode::ExportList),
    (
        "enforce_ascii_accept",
        "enforce_content_free_text",
        VectorMode::Ok,
    ),
    (
        "enforce_eacute_accept",
        "enforce_content_free_text",
        VectorMode::Ok,
    ),
    (
        "enforce_control_before_email",
        "enforce_content_free_text",
        VectorMode::Error,
    ),
    (
        "enforce_email",
        "enforce_content_free_text",
        VectorMode::Error,
    ),
    (
        "enforce_private_key_banner",
        "enforce_content_free_text",
        VectorMode::Error,
    ),
    (
        "enforce_bearer_token",
        "enforce_content_free_text",
        VectorMode::Error,
    ),
    (
        "enforce_api_key_shape",
        "enforce_content_free_text",
        VectorMode::Error,
    ),
    (
        "enforce_credential_assignment",
        "enforce_content_free_text",
        VectorMode::Error,
    ),
    (
        "sourceref_backslash_and_strip",
        "SourceRef_try",
        VectorMode::Ok,
    ),
    ("sourceref_empty_path", "SourceRef_try", VectorMode::Error),
    (
        "sourceref_whitespace_path",
        "SourceRef_try",
        VectorMode::Error,
    ),
    ("sourceref_line_zero", "SourceRef_try", VectorMode::Error),
    ("sourceref_line_bool", "SourceRef_try", VectorMode::Error),
    ("sourceref_line_one", "SourceRef_try", VectorMode::Ok),
    (
        "sort_findings_path_line_severity",
        "sort_findings",
        VectorMode::SortOrder,
    ),
    (
        "make_finding_fingerprint_default_severity",
        "make_finding",
        VectorMode::Ok,
    ),
    (
        "make_finding_unknown_code",
        "make_finding",
        VectorMode::Error,
    ),
    (
        "parse_round_trip_complete",
        "parse_finding_dict",
        VectorMode::Ok,
    ),
    (
        "parse_remediation_without_message",
        "parse_finding_dict",
        VectorMode::Ok,
    ),
    (
        "parse_span_when_source_absent",
        "parse_finding_dict",
        VectorMode::Ok,
    ),
    (
        "parse_reject_schema_version",
        "parse_finding_dict",
        VectorMode::Error,
    ),
];

const ROWS: &[Row] = &[
    // One omitted-severity call is not the 16-pair matrix.
    Row {
        name: "test_severity_repairability_independence_matrix",
        disposition: Disposition::NotApplicable(
            "make_finding succeeds for all 16 severity and repairability pairs and each fingerprint is 16 hex digits; make_finding_fingerprint_default_severity is one SL011 call with severity omitted",
        ),
    },
    // Severity tokens inside sort_findings are not Severity.from_str.
    Row {
        name: "test_severity_from_str",
        disposition: Disposition::NotApplicable(
            "Severity.from_str accepts fatal, error, warning, info, and a Severity value, and rejects critical and the empty string; severity tokens inside sort_findings are not that parser",
        ),
    },
    Row {
        name: "test_repairability_from_str",
        disposition: Disposition::NotApplicable(
            "Repairability.from_str accepts deterministic, lossy-explicit, manual, unsupported, and a Repairability value, and rejects automatic and the empty string; no finding vector calls Repairability.from_str",
        ),
    },
    // Four SourceRef_try failures are single cases, and their paths differ.
    Row {
        name: "test_source_ref_validation",
        disposition: Disposition::NotApplicable(
            "SourceRef accepts session.jsonl at line 10 with a record id and an omitted line, and rejects line 0, a negative line, line True, an empty path, a whitespace path, an empty record id, and a whitespace record id; sourceref_line_zero, sourceref_line_bool, sourceref_empty_path, and sourceref_whitespace_path are single SourceRef_try cases on different paths and omit the negative line and the record id failures",
        ),
    },
    // The vector path is not the sessions ledger path, and it does not fingerprint.
    Row {
        name: "test_source_ref_cross_platform_path_normalization",
        disposition: Disposition::NotApplicable(
            "SourceRef normalizes one Windows backslash path and the same POSIX path, then make_finding fingerprints match; sourceref_backslash_and_strip is SourceRef_try of a different backslash path and does not call make_finding",
        ),
    },
    Row {
        name: "test_finding_immutability",
        disposition: Disposition::NotApplicable(
            "assigning SourceRef.line and Finding.message raises FrozenInstanceError; no finding vector checks a frozen instance",
        ),
    },
    Row {
        name: "test_finding_comparison_operators",
        disposition: Disposition::NotApplicable(
            "Finding ordering covers lt, le, gt, ge, eq, and totality on three findings; sort_findings_path_line_severity is a sort_findings order, not comparison operators",
        ),
    },
    // L{line} on path p is a different template and a different source.
    Row {
        name: "test_make_finding_template_rendering_and_placeholders",
        disposition: Disposition::NotApplicable(
            "make_finding renders line and record_id, then falls back when both are absent; make_finding_fingerprint_default_severity renders template L{line} on a different source and checks default severity",
        ),
    },
    Row {
        name: "test_disallowed_template_placeholder_raises",
        disposition: Disposition::NotApplicable(
            "make_finding rejects a payload placeholder and an email placeholder; no finding vector is a disallowed-placeholder error",
        ),
    },
    Row {
        name: "test_template_format_specifier_disallowed",
        disposition: Disposition::NotApplicable(
            "make_finding rejects a format specifier on line and a conversion flag on record_id; no finding vector is that template error",
        ),
    },
    Row {
        name: "test_malformed_template_syntax_raises",
        disposition: Disposition::NotApplicable(
            "make_finding rejects an unclosed brace; no finding vector is a malformed-template error",
        ),
    },
    Row {
        name: "test_disallowed_template_args_key_raises",
        disposition: Disposition::NotApplicable(
            "make_finding rejects a template_args key other than line and record_id; no finding vector passes template_args",
        ),
    },
    Row {
        name: "test_template_args_line_type_validation",
        disposition: Disposition::NotApplicable(
            "template_args line accepts a positive integer and a digit string and rejects prose, zero, a negative integer, and True; no finding vector validates template_args line",
        ),
    },
    Row {
        name: "test_template_args_record_id_validation",
        disposition: Disposition::NotApplicable(
            "template_args record_id rejects an empty string, whitespace, and a non-string; no finding vector validates template_args record_id",
        ),
    },
    // Each enforce_* vector is one different string, not the sweep.
    Row {
        name: "test_content_free_policy_rejects_control_chars_and_pii",
        disposition: Disposition::NotApplicable(
            "enforce_content_free_text rejects a newline, a tab, a carriage return, and an email, and accepts one clean sentence; enforce_control_before_email, enforce_email, and enforce_ascii_accept are different strings and each is one case",
        ),
    },
    Row {
        name: "test_content_free_policy_rejects_unicode_control_and_formatting",
        disposition: Disposition::NotApplicable(
            "enforce_content_free_text rejects next-line, line separator, paragraph separator, zero-width space, BOM, and bidi override; enforce_control_before_email is a tab on a different string",
        ),
    },
    // Name the credential refusals. The pinned literals stay out of this file.
    Row {
        name: "test_content_free_policy_rejects_credentials_and_tokens",
        disposition: Disposition::NotApplicable(
            "enforce_content_free_text rejects a private-key banner, an OpenSSH private-key banner, a bearer token, two API-key shapes, and a credential assignment; enforce_private_key_banner, enforce_bearer_token, enforce_api_key_shape, and enforce_credential_assignment are different strings and each is one case",
        ),
    },
    Row {
        name: "test_source_ref_rejects_injections_and_pii",
        disposition: Disposition::NotApplicable(
            "SourceRef rejects a newline in the path, an email in the path, an email in record_id, and a newline in record_id; SourceRef_try vectors fail on empty path, whitespace path, line 0, or line bool, which are different error kinds",
        ),
    },
    // Unknown-code failure is a different error kind from an empty template.
    Row {
        name: "test_empty_message_template_rejected",
        disposition: Disposition::NotApplicable(
            "make_finding rejects an empty template and a whitespace template; make_finding_unknown_code fails on unknown code SL999, a different error kind",
        ),
    },
    // Same error kind, different template, path, and supplied fingerprint.
    Row {
        name: "test_unknown_code_rejected",
        disposition: Disposition::NotApplicable(
            "make_finding rejects SL999 for template Defect at {line} on path a.jsonl; make_finding_unknown_code is the same error kind but the template is {line}, the path is p, and a fingerprint is supplied",
        ),
    },
    Row {
        name: "test_message_length_capping_and_truncation",
        disposition: Disposition::NotApplicable(
            "make_finding of a 600-character template succeeds with length 500 and the truncation marker; no finding vector records truncation",
        ),
    },
    Row {
        name: "test_related_ids_deduplication_and_sorting",
        disposition: Disposition::NotApplicable(
            "make_finding deduplicates and sorts four related ids down to three; parse_round_trip_complete sorts two different ids through parse_finding_dict",
        ),
    },
    Row {
        name: "test_related_ids_content_free_validation",
        disposition: Disposition::NotApplicable(
            "make_finding rejects an empty related id, a newline in a related id, and an email related id; no finding vector checks related_ids text",
        ),
    },
    Row {
        name: "test_fingerprint_determinism_and_insensitivity_to_dict_order",
        disposition: Disposition::NotApplicable(
            "two make_finding calls with swapped template_args order and swapped related_ids share a fingerprint, and fingerprint_finding agrees; no finding vector compares two fingerprints",
        ),
    },
    Row {
        name: "test_fingerprint_differs_on_structural_changes",
        disposition: Disposition::NotApplicable(
            "fingerprints differ when code, line, path, or record_id changes; no finding vector compares two fingerprints",
        ),
    },
    Row {
        name: "test_golden_ordering_sample_fixture_shuffled_100_times",
        disposition: Disposition::NotApplicable(
            "sort_findings of the ordering-sample fixture stays golden across 100 shuffles; sort_findings_path_line_severity is one fixed list, not that fixture",
        ),
    },
    Row {
        name: "test_sort_findings_does_not_mutate_input",
        disposition: Disposition::NotApplicable(
            "sort_findings returns a new list and leaves an info-then-fatal pair unchanged; sort_findings_path_line_severity does not check identity and its six findings differ",
        ),
    },
    // One path-line-severity list is not the full key hierarchy.
    Row {
        name: "test_ordering_rules_hierarchy",
        disposition: Disposition::NotApplicable(
            "sort_findings orders by path, line, record ordinal including negative, bool, and str fallbacks, severity, code, record_id, and fingerprint; sort_findings_path_line_severity is one path, line, and severity list and omits the later keys",
        ),
    },
    Row {
        name: "test_schema_file_matches_dataclass",
        disposition: Disposition::NotApplicable(
            "the schema path is a file, the schema id matches, and make_finding round-trips through parse_finding_dict; no finding vector reads a schema, and parse_round_trip_complete is a different dict",
        ),
    },
    Row {
        name: "test_finding_schema_structure_anti_drift",
        disposition: Disposition::NotApplicable(
            "load_finding_schema required fields and properties match the Finding model, including source path, line, and record_id; all_export_order is the ALL name list, not that schema document",
        ),
    },
    Row {
        name: "test_adversarial_10k_related_ids",
        disposition: Disposition::NotApplicable(
            "make_finding deduplicates 10000 related ids to 5000 sorted ids in under one second; no finding vector is that size or timing check",
        ),
    },
    // Do not sort 100000 findings here. The vector file has no timing check.
    Row {
        name: "test_adversarial_100k_findings_sort_performance",
        disposition: Disposition::NotApplicable(
            "a fresh interpreter sorts 100000 findings in under one second; no finding vector is a timing check, and this map does not sort that list",
        ),
    },
    Row {
        name: "test_no_vendor_strings_in_finding_module",
        disposition: Disposition::NotApplicable(
            "finding.py source has no vendor terms; all_export_order lists export names and does not scan module text",
        ),
    },
    Row {
        name: "test_direct_finding_instantiation_validation",
        disposition: Disposition::NotApplicable(
            "Finding, SourceRef, and make_finding reject an empty code, an unregistered code, a bad severity, a bad repairability, a non-string message, an overlong message, a non-SourceRef source, bad fingerprints, a wrong schema version, a non-string message template, a non-sequence related_ids, a non-string record id, a bad make_finding source, a non-mapping template_args, and a non-sequence related_ids; no finding vector constructs Finding",
        ),
    },
    // schema nope is a different string from schema other/v1, and it is one branch.
    Row {
        name: "test_parse_finding_dict_negative_branches",
        disposition: Disposition::NotApplicable(
            "parse_finding_dict rejects a non-mapping and fourteen malformed fields, including schema version other/v1; parse_reject_schema_version is only schema nope with code SL001, a different input string and one branch",
        ),
    },
    Row {
        name: "test_finding_comparison_with_non_finding_raises_type_error",
        disposition: Disposition::NotApplicable(
            "comparing a Finding with an int, a string, None, and a dict raises TypeError; no finding vector is a comparison",
        ),
    },
    Row {
        name: "test_sourceref_record_id_strip_normalization",
        disposition: Disposition::NotApplicable(
            "SourceRef strips surrounding spaces from path a.jsonl and from a record id; sourceref_backslash_and_strip strips a different backslash path, sets line 1, and leaves record_id null",
        ),
    },
    Row {
        name: "test_direct_finding_related_ids_element_validation",
        disposition: Disposition::NotApplicable(
            "Finding rejects an empty related id and a non-string related id; no finding vector constructs Finding, and parse_finding_dict is a different construct",
        ),
    },
    Row {
        name: "test_direct_finding_unsorted_related_ids_normalization",
        disposition: Disposition::NotApplicable(
            "Finding sorts related ids evt-2 then evt-1; parse_round_trip_complete sorts different ids through parse_finding_dict",
        ),
    },
    Row {
        name: "test_get_finding_schema_path_prefix_resolution",
        disposition: Disposition::NotApplicable(
            "get_finding_schema_path follows the prefix share directory when the repo schema is hidden; no finding vector monkeypatches path resolution",
        ),
    },
    Row {
        name: "test_schema_loader_file_not_found",
        disposition: Disposition::NotApplicable(
            "load_finding_schema raises FileNotFoundError when the schema path is missing; no finding vector records that error",
        ),
    },
    Row {
        name: "test_fingerprint_with_adapter_and_profile_versions",
        disposition: Disposition::NotApplicable(
            "compute_fingerprint yields five distinct digests across a missing version, two adapter versions, and two profile versions, and make_finding keeps those fields distinct; no finding vector sets adapter_version or profile_version",
        ),
    },
    // Nested evidence is make_finding. Flat enforce_content_free_text is a different construct.
    Row {
        name: "test_evidence_recursive_content_free_nested_dict_secret",
        disposition: Disposition::NotApplicable(
            "make_finding rejects a credential pattern nested in an evidence dict; enforce_credential_assignment is flat enforce_content_free_text, a different construct",
        ),
    },
    Row {
        name: "test_evidence_recursive_content_free_nested_list_secret",
        disposition: Disposition::NotApplicable(
            "make_finding rejects a credential pattern nested in an evidence list; enforce_api_key_shape is flat enforce_content_free_text, a different construct",
        ),
    },
    Row {
        name: "test_evidence_recursive_content_free_nested_pii_email",
        disposition: Disposition::NotApplicable(
            "make_finding rejects an email nested in evidence; enforce_email is enforce_content_free_text of a different string, a different construct",
        ),
    },
    Row {
        name: "test_evidence_recursive_content_free_nested_control_chars",
        disposition: Disposition::NotApplicable(
            "make_finding rejects a newline and a tab nested in evidence; enforce_control_before_email is enforce_content_free_text of a different string, a different construct",
        ),
    },
    Row {
        name: "test_evidence_recursive_content_free_deeply_nested_valid",
        disposition: Disposition::NotApplicable(
            "make_finding accepts nested evidence of spans and clean values; enforce_ascii_accept is a flat string success, a different construct",
        ),
    },
    Row {
        name: "test_evidence_recursive_content_free_cyclic_rejected",
        disposition: Disposition::NotApplicable(
            "make_finding rejects a cyclic evidence dict and a cyclic evidence list; no finding vector records a cyclic reference",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_severity_repairability_independence_matrix",
    "test_severity_from_str",
    "test_repairability_from_str",
    "test_source_ref_validation",
    "test_source_ref_cross_platform_path_normalization",
    "test_finding_immutability",
    "test_finding_comparison_operators",
    "test_make_finding_template_rendering_and_placeholders",
    "test_disallowed_template_placeholder_raises",
    "test_template_format_specifier_disallowed",
    "test_malformed_template_syntax_raises",
    "test_disallowed_template_args_key_raises",
    "test_template_args_line_type_validation",
    "test_template_args_record_id_validation",
    "test_content_free_policy_rejects_control_chars_and_pii",
    "test_content_free_policy_rejects_unicode_control_and_formatting",
    "test_content_free_policy_rejects_credentials_and_tokens",
    "test_source_ref_rejects_injections_and_pii",
    "test_empty_message_template_rejected",
    "test_unknown_code_rejected",
    "test_message_length_capping_and_truncation",
    "test_related_ids_deduplication_and_sorting",
    "test_related_ids_content_free_validation",
    "test_fingerprint_determinism_and_insensitivity_to_dict_order",
    "test_fingerprint_differs_on_structural_changes",
    "test_golden_ordering_sample_fixture_shuffled_100_times",
    "test_sort_findings_does_not_mutate_input",
    "test_ordering_rules_hierarchy",
    "test_schema_file_matches_dataclass",
    "test_finding_schema_structure_anti_drift",
    "test_adversarial_10k_related_ids",
    "test_adversarial_100k_findings_sort_performance",
    "test_no_vendor_strings_in_finding_module",
    "test_direct_finding_instantiation_validation",
    "test_parse_finding_dict_negative_branches",
    "test_finding_comparison_with_non_finding_raises_type_error",
    "test_sourceref_record_id_strip_normalization",
    "test_direct_finding_related_ids_element_validation",
    "test_direct_finding_unsorted_related_ids_normalization",
    "test_get_finding_schema_path_prefix_resolution",
    "test_schema_loader_file_not_found",
    "test_fingerprint_with_adapter_and_profile_versions",
    "test_evidence_recursive_content_free_nested_dict_secret",
    "test_evidence_recursive_content_free_nested_list_secret",
    "test_evidence_recursive_content_free_nested_pii_email",
    "test_evidence_recursive_content_free_nested_control_chars",
    "test_evidence_recursive_content_free_deeply_nested_valid",
    "test_evidence_recursive_content_free_cyclic_rejected",
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
        .unwrap_or_else(|| panic!("finding vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_vector_mode(id: &str, slice: &str, mode: &VectorMode) {
    match mode {
        VectorMode::Ok => {
            assert!(
                slice.contains("\"ok\": true"),
                "{id} success mode does not match the vector file"
            );
            assert!(
                !slice.contains("\"ok\": false"),
                "{id} also records an error"
            );
        }
        VectorMode::Error => {
            assert!(
                slice.contains("\"ok\": false"),
                "{id} error mode does not match the vector file"
            );
            assert!(!slice.contains("\"ok\": true"), "{id} also records success");
        }
        VectorMode::ExportList => {
            assert!(
                !slice.contains("\"ok\":"),
                "{id} export list has an ok flag"
            );
            assert!(
                slice.contains("\"names\""),
                "{id} is missing the export list"
            );
        }
        VectorMode::SortOrder => {
            assert!(!slice.contains("\"ok\":"), "{id} sort order has an ok flag");
            assert!(
                slice.contains("\"order\""),
                "{id} is missing the sort order"
            );
        }
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_finding_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(FINDING_VECTORS.len(), FINDING_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_finding_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "finding vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.finding\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = FINDING_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, ref mode) in FINDING_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_vector_mode(id, slice, mode);
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
