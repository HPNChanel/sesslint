//! Dispositions for the 8 `def test_` functions in pinned
//! `tests/test_fingerprint_pairing.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (359 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `finding/vectors.json`,
//! `checks.tool_pairing_1/vectors.json`, `checks.tool_pairing_2/vectors.json`,
//! or `context/vectors.json` whose construct is the same function and the same
//! success or failure mode as that entire pinned test. One example inside a
//! matrix or a sweep is not coverage. A different input string is not coverage.
//! `not_applicable` records a `compute_finding_fingerprint`, `make_finding`,
//! `compute_pairing_fingerprint`, `check_tool_pairing_1`, or
//! `check_tool_pairing_2` check this package cannot reach without a
//! `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 8;
const FINDING_VECTOR_COUNT: usize = 22;
const PAIRING_1_VECTOR_COUNT: usize = 7;
const PAIRING_2_VECTOR_COUNT: usize = 9;
const CONTEXT_VECTOR_COUNT: usize = 15;

const FINDING_VECTORS_REL: &str = "parity/vectors/finding/vectors.json";
const FINDING_PROVENANCE_REL: &str = "parity/vectors/finding/PROVENANCE.json";
const PAIRING_1_VECTORS_REL: &str = "parity/vectors/checks.tool_pairing_1/vectors.json";
const PAIRING_2_VECTORS_REL: &str = "parity/vectors/checks.tool_pairing_2/vectors.json";
const CONTEXT_VECTORS_REL: &str = "parity/vectors/context/vectors.json";

/// `Some(true)` is expected `"ok": false`. `Some(false)` is expected `"ok": true`.
/// `None` means the vector records a value and has no ok flag.
type OkFlag = Option<bool>;

/// `covered` names a vector id. `not_applicable` records behavior this package
/// cannot reach without a `Cargo.toml` change outside the owned path, or a mode
/// absent from the pairing fingerprint vector files.
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

/// Vector id, construct type, and ok-flag. Order matches `finding/vectors.json`.
const FINDING_VECTORS: &[(&str, &str, OkFlag)] = &[
    ("all_export_order", "ALL", None),
    (
        "enforce_ascii_accept",
        "enforce_content_free_text",
        Some(false),
    ),
    (
        "enforce_eacute_accept",
        "enforce_content_free_text",
        Some(false),
    ),
    (
        "enforce_control_before_email",
        "enforce_content_free_text",
        Some(true),
    ),
    ("enforce_email", "enforce_content_free_text", Some(true)),
    (
        "enforce_private_key_banner",
        "enforce_content_free_text",
        Some(true),
    ),
    (
        "enforce_bearer_token",
        "enforce_content_free_text",
        Some(true),
    ),
    (
        "enforce_api_key_shape",
        "enforce_content_free_text",
        Some(true),
    ),
    (
        "enforce_credential_assignment",
        "enforce_content_free_text",
        Some(true),
    ),
    (
        "sourceref_backslash_and_strip",
        "SourceRef_try",
        Some(false),
    ),
    ("sourceref_empty_path", "SourceRef_try", Some(true)),
    ("sourceref_whitespace_path", "SourceRef_try", Some(true)),
    ("sourceref_line_zero", "SourceRef_try", Some(true)),
    ("sourceref_line_bool", "SourceRef_try", Some(true)),
    ("sourceref_line_one", "SourceRef_try", Some(false)),
    ("sort_findings_path_line_severity", "sort_findings", None),
    (
        "make_finding_fingerprint_default_severity",
        "make_finding",
        Some(false),
    ),
    ("make_finding_unknown_code", "make_finding", Some(true)),
    (
        "parse_round_trip_complete",
        "parse_finding_dict",
        Some(false),
    ),
    (
        "parse_remediation_without_message",
        "parse_finding_dict",
        Some(false),
    ),
    (
        "parse_span_when_source_absent",
        "parse_finding_dict",
        Some(false),
    ),
    (
        "parse_reject_schema_version",
        "parse_finding_dict",
        Some(true),
    ),
];

/// Vector id and construct type. Order matches `checks.tool_pairing_1/vectors.json`.
const PAIRING_1_VECTORS: &[(&str, &str)] = &[
    ("empty_input_silent", "tool_pairing_events"),
    ("paired_call_and_result_silent", "tool_pairing_events"),
    ("one_result_multi_silent", "tool_pairing_events"),
    ("message_ignored_silent", "tool_pairing_events"),
    (
        "null_result_on_codex_rollout_orphans_silent",
        "tool_pairing_events",
    ),
    ("constants_and_all", "tool_pairing_events"),
    ("fingerprint_sl103_ab", "pairing_fingerprint"),
];

/// Vector id and construct type. Order matches `checks.tool_pairing_2/vectors.json`.
const PAIRING_2_VECTORS: &[(&str, &str)] = &[
    ("empty_input_silent", "tool_pairing_events"),
    ("paired_call_result_parent_adjacent", "tool_pairing_events"),
    (
        "two_tool_calls_mis_correlated_interleaved",
        "tool_pairing_events",
    ),
    (
        "two_calls_one_result_shared_correlation_not_clean",
        "tool_pairing_events",
    ),
    ("message_only_silent", "tool_pairing_events"),
    (
        "compaction_bounds_pair_adjacent_result_parent_call",
        "tool_pairing_events",
    ),
    (
        "same_nonempty_branch_id_adjacent_no_parent",
        "tool_pairing_events",
    ),
    ("constants_and_all", "tool_pairing_events"),
    ("fingerprint_sl105_aba", "pairing_fingerprint"),
];

/// Vector id and construct type. Order matches `context/vectors.json`.
const CONTEXT_VECTORS: &[(&str, &str)] = &[
    ("context_default_unknown_and_skew_2000", "default"),
    ("context_new_blank_whitespace_become_unknown", "new"),
    ("context_new_preserves_inner_whitespace", "new"),
    ("context_create_lookup_when_version_omitted", "create"),
    ("context_create_keeps_explicit_version", "create"),
    (
        "context_create_whitespace_version_triggers_lookup",
        "create",
    ),
    ("context_create_unregistered_id_version_unknown", "create"),
    ("context_create_strips_ids_blank_profile", "create"),
    (
        "context_compaction_checkpoint_capable_matrix",
        "compaction_matrix",
    ),
    ("context_to_dict_four_keys_sorted_json", "to_dict"),
    (
        "context_with_overrides_preserves_skew_unset_metadata",
        "with_overrides",
    ),
    (
        "context_with_overrides_unset_keeps_metadata",
        "with_overrides",
    ),
    (
        "context_with_overrides_explicit_none_clears_metadata",
        "with_overrides",
    ),
    (
        "context_with_overrides_non_mapping_clears_metadata",
        "with_overrides",
    ),
    (
        "context_with_overrides_blank_coords_unknown",
        "with_overrides",
    ),
];

const ROWS: &[Row] = &[
    // Two SL101 orders plus a hex match. One SL103 digest is a different input.
    Row {
        name: "test_legacy_compute_pairing_fingerprint",
        disposition: Disposition::NotApplicable(
            "compute_pairing_fingerprint of SL101 on items call-1 and call-2 equals the reversed items and both are 16 lowercase hex; fingerprint_sl103_ab is pairing_fingerprint of SL103 items b, a, a, and fingerprint_sl105_aba is pairing_fingerprint of SL105 items b, a, a",
        ),
    },
    // Supplied fingerprint and default severity. The pinned call computes a digest.
    Row {
        name: "test_pairing_finding_fingerprint_shape_and_hex",
        disposition: Disposition::NotApplicable(
            "make_finding for SL101 computes a 16-lowercase-hex fingerprint; make_finding_fingerprint_default_severity is make_finding of SL011 with supplied fingerprint 0123456789abcdef and success severity info, and make_finding_unknown_code fails for SL999",
        ),
    },
    // One SL101 fingerprint compared with a neutral context. Event vectors are silent.
    Row {
        name: "test_tool_pairing_1_context_threading",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on one orphan tool_result under adapter gemini 3.4.1 yields one SL101 whose fingerprint equals compute_finding_fingerprint and differs from the default CheckContext; every tool_pairing_1 tool_pairing_events vector records a zero finding count, and null_result_on_codex_rollout_orphans_silent is adapter codex-rollout with check_orphans_len 0",
        ),
    },
    // Six fingerprints. One silent context is not the matrix.
    Row {
        name: "test_tool_pairing_version_sensitivity_matrix",
        disposition: Disposition::NotApplicable(
            "six distinct fingerprints for one base context and five overrides of adapter_id, adapter_version, profile_id, profile_version, and the default context; no vector is that matrix, and null_result_on_codex_rollout_orphans_silent is one silent codex-rollout context",
        ),
    },
    // One SL105 fingerprint. Reversed-order vectors expect a zero count.
    Row {
        name: "test_tool_pairing_2_context_threading",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 on a tool_result before a tool_call yields one SL105 whose fingerprint equals compute_finding_fingerprint for adapter openai 2.1.0; every tool_pairing_2 tool_pairing_events vector records check_reversed_order_len 0, and fingerprint_sl105_aba is pairing_fingerprint of SL105 items b, a, a",
        ),
    },
    // Equality across three evidence objects. No compute_finding_fingerprint vector.
    Row {
        name: "test_pairing_evidence_content_free_filtering",
        disposition: Disposition::NotApplicable(
            "compute_finding_fingerprint is unchanged when non-allowlisted evidence keys are added and changes when correlation_id changes; no vector calls compute_finding_fingerprint, and enforce_content_free_text scans text",
        ),
    },
    // Four coordinate changes. SourceRef_try constructs a source, it does not hash one.
    Row {
        name: "test_pairing_structural_coords_sensitivity",
        disposition: Disposition::NotApplicable(
            "compute_finding_fingerprint changes when path, line, ordinal, or record_id changes; no vector is that four-way sweep, and SourceRef_try constructs a SourceRef",
        ),
    },
    // Three compute_finding_fingerprint calls. Context vectors construct CheckContext.
    Row {
        name: "test_pairing_unknown_version_normalization",
        disposition: Disposition::NotApplicable(
            "compute_finding_fingerprint of omitted, unknown, and empty version coordinates is one digest; context_default_unknown_and_skew_2000, context_new_blank_whitespace_become_unknown, and context_with_overrides_blank_coords_unknown construct CheckContext",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_legacy_compute_pairing_fingerprint",
    "test_pairing_finding_fingerprint_shape_and_hex",
    "test_tool_pairing_1_context_threading",
    "test_tool_pairing_version_sensitivity_matrix",
    "test_tool_pairing_2_context_threading",
    "test_pairing_evidence_content_free_filtering",
    "test_pairing_structural_coords_sensitivity",
    "test_pairing_unknown_version_normalization",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_pinned(rel: &str, module: &str) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(
        json.contains(&format!("\"module\": \"{module}\"")),
        "{rel} module"
    );
    assert!(
        !json.contains("\"type\": \"compute_finding_fingerprint\""),
        "{rel} has no compute_finding_fingerprint vector"
    );
    json
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
        .unwrap_or_else(|| panic!("vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_id_order(json: &str, expected: &[&str], label: &str) {
    let ids = vector_ids(json);
    assert_eq!(ids, expected, "{label}");
    assert_eq!(
        ids.iter().collect::<BTreeSet<_>>().len(),
        ids.len(),
        "{label}"
    );
}

fn assert_construct(slice: &str, id: &str, construct: &str) {
    let type_needle = format!("\"type\": \"{construct}\"");
    assert!(
        slice.contains(&type_needle),
        "{id} is missing construct {construct}"
    );
}

fn assert_finding_catalog(json: &str) {
    let expected: Vec<&str> = FINDING_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_id_order(json, &expected, "finding");
    for &(id, construct, fails) in FINDING_VECTORS {
        let slice = vector_slice(json, id);
        assert_construct(slice, id, construct);
        match fails {
            Some(true) => {
                assert!(slice.contains("\"ok\": false"), "{id}");
                assert!(!slice.contains("\"ok\": true"), "{id}");
            }
            Some(false) => {
                assert!(slice.contains("\"ok\": true"), "{id}");
                assert!(!slice.contains("\"ok\": false"), "{id}");
            }
            None => assert!(!slice.contains("\"ok\":"), "{id} has no ok flag"),
        }
    }
    let supplied = vector_slice(json, "make_finding_fingerprint_default_severity");
    assert!(supplied.contains("\"code\": \"SL011\""));
    assert!(supplied.contains("\"fingerprint\": \"0123456789abcdef\""));
    assert!(supplied.contains("\"severity_omitted\": true"));
    assert!(supplied.contains("\"severity\": \"info\""));
    let unknown = vector_slice(json, "make_finding_unknown_code");
    assert!(unknown.contains("\"code\": \"SL999\""));
}

fn assert_pairing_catalog(json: &str, catalog: &[(&str, &str)], label: &str, reversed_zero: bool) {
    let expected: Vec<&str> = catalog.iter().map(|(id, _)| *id).collect();
    assert_id_order(json, &expected, label);
    assert!(
        json.contains("FINGERPRINT_CODEC_UNAVAILABLE"),
        "{label} records the omitted-fingerprint gap"
    );
    for &(id, construct) in catalog {
        let slice = vector_slice(json, id);
        assert_construct(slice, id, construct);
        if construct == "tool_pairing_events" {
            assert!(
                slice.contains("_len\": 0"),
                "{label} {id} finding count is zero"
            );
        }
        if reversed_zero && construct == "tool_pairing_events" {
            assert!(
                slice.contains("\"check_reversed_order_len\": 0"),
                "{label} {id}"
            );
        }
        if construct == "pairing_fingerprint" {
            assert!(slice.contains("\"fingerprint\": \""), "{label} {id}");
            assert!(slice.contains("\"b\""), "{label} {id} items");
            assert!(slice.contains("\"a\""), "{label} {id} items");
            assert!(!slice.contains("SL101"), "{label} {id} code");
            assert!(!slice.contains("call-1"), "{label} {id} items");
        }
    }
}

fn assert_context_catalog(json: &str) {
    let expected: Vec<&str> = CONTEXT_VECTORS.iter().map(|(id, _)| *id).collect();
    assert_id_order(json, &expected, "context");
    for &(id, construct) in CONTEXT_VECTORS {
        let slice = vector_slice(json, id);
        assert_construct(slice, id, construct);
        assert!(
            !slice.contains("compute_finding_fingerprint"),
            "{id} constructs CheckContext"
        );
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_fingerprint_pairing_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(FINDING_VECTORS.len(), FINDING_VECTOR_COUNT);
    assert_eq!(PAIRING_1_VECTORS.len(), PAIRING_1_VECTOR_COUNT);
    assert_eq!(PAIRING_2_VECTORS.len(), PAIRING_2_VECTOR_COUNT);
    assert_eq!(CONTEXT_VECTORS.len(), CONTEXT_VECTOR_COUNT);
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
                    needles
                        .iter()
                        .all(|needle| !needle.contains("schema_version")),
                    "{} needle is a shared schema_version",
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
fn covered_vector_ids_are_present_in_pairing_vectors() {
    let finding = read_pinned(FINDING_VECTORS_REL, "sesslint.finding");
    let pairing_1 = read_pinned(PAIRING_1_VECTORS_REL, "sesslint.checks.tool_pairing_1");
    let pairing_2 = read_pinned(PAIRING_2_VECTORS_REL, "sesslint.checks.tool_pairing_2");
    let context = read_pinned(CONTEXT_VECTORS_REL, "sesslint.context");
    let provenance_path = vectors_path(FINDING_PROVENANCE_REL);
    let provenance = fs::read_to_string(&provenance_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", provenance_path.display()));
    assert!(provenance.contains(&format!("\"python_commit\": \"{PIN}\"")));
    assert!(provenance.contains("compute_finding_fingerprint_unavailable"));

    assert_finding_catalog(&finding);
    assert_pairing_catalog(&pairing_1, PAIRING_1_VECTORS, "tool_pairing_1", false);
    assert_pairing_catalog(&pairing_2, PAIRING_2_VECTORS, "tool_pairing_2", true);
    assert_context_catalog(&context);

    let finding_ids: BTreeSet<&str> = vector_ids(&finding).into_iter().collect();
    let pairing_1_ids: BTreeSet<&str> = vector_ids(&pairing_1).into_iter().collect();
    let pairing_2_ids: BTreeSet<&str> = vector_ids(&pairing_2).into_iter().collect();
    let context_ids: BTreeSet<&str> = vector_ids(&context).into_iter().collect();

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let json = if finding_ids.contains(vector_id) {
            &finding
        } else if pairing_1_ids.contains(vector_id) {
            &pairing_1
        } else if pairing_2_ids.contains(vector_id) {
            &pairing_2
        } else if context_ids.contains(vector_id) {
            &context
        } else {
            panic!("{} names missing vector {vector_id}", row.name);
        };
        let slice = vector_slice(json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
