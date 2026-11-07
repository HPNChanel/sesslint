//! Dispositions for the 7 `def test_` functions in pinned
//! `tests/test_fingerprint_identity.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (267 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `finding/vectors.json` or
//! `checks.identity/vectors.json` whose construct is the same function and the
//! same success or failure mode as that entire pinned test. One example inside
//! a matrix or a sweep is not coverage. A different input string is not
//! coverage. `not_applicable` records a `make_finding`,
//! `compute_finding_fingerprint`, `canonical_json_bytes`, `CheckContext`, or
//! `check_identities` check this package cannot reach without a `Cargo.toml`
//! change, or a mode no vector records. `repair.fingerprint` vectors call
//! `compute_plan_fingerprint`, which none of these tests call.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 7;
const FINDING_VECTORS_REL: &str = "parity/vectors/finding/vectors.json";
const IDENTITY_VECTORS_REL: &str = "parity/vectors/checks.identity/vectors.json";
const DETERMINISM_VECTORS_REL: &str = "parity/vectors/determinism/vectors.json";
const CONTEXT_VECTORS_REL: &str = "parity/vectors/context/vectors.json";
const PLAN_FINGERPRINT_VECTORS_REL: &str = "parity/vectors/repair.fingerprint/vectors.json";

/// `ok` on a finding vector: success, failure, or no `ok` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FindingOk {
    True,
    False,
    Absent,
}

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

/// Vector id, construct type, and the finding `ok` field.
const FINDING_VECTORS: &[(&str, &str, FindingOk)] = &[
    ("all_export_order", "ALL", FindingOk::Absent),
    (
        "enforce_ascii_accept",
        "enforce_content_free_text",
        FindingOk::True,
    ),
    (
        "enforce_eacute_accept",
        "enforce_content_free_text",
        FindingOk::True,
    ),
    (
        "enforce_control_before_email",
        "enforce_content_free_text",
        FindingOk::False,
    ),
    (
        "enforce_email",
        "enforce_content_free_text",
        FindingOk::False,
    ),
    (
        "enforce_private_key_banner",
        "enforce_content_free_text",
        FindingOk::False,
    ),
    (
        "enforce_bearer_token",
        "enforce_content_free_text",
        FindingOk::False,
    ),
    (
        "enforce_api_key_shape",
        "enforce_content_free_text",
        FindingOk::False,
    ),
    (
        "enforce_credential_assignment",
        "enforce_content_free_text",
        FindingOk::False,
    ),
    (
        "sourceref_backslash_and_strip",
        "SourceRef_try",
        FindingOk::True,
    ),
    ("sourceref_empty_path", "SourceRef_try", FindingOk::False),
    (
        "sourceref_whitespace_path",
        "SourceRef_try",
        FindingOk::False,
    ),
    ("sourceref_line_zero", "SourceRef_try", FindingOk::False),
    ("sourceref_line_bool", "SourceRef_try", FindingOk::False),
    ("sourceref_line_one", "SourceRef_try", FindingOk::True),
    (
        "sort_findings_path_line_severity",
        "sort_findings",
        FindingOk::Absent,
    ),
    (
        "make_finding_fingerprint_default_severity",
        "make_finding",
        FindingOk::True,
    ),
    (
        "make_finding_unknown_code",
        "make_finding",
        FindingOk::False,
    ),
    (
        "parse_round_trip_complete",
        "parse_finding_dict",
        FindingOk::True,
    ),
    (
        "parse_remediation_without_message",
        "parse_finding_dict",
        FindingOk::True,
    ),
    (
        "parse_span_when_source_absent",
        "parse_finding_dict",
        FindingOk::True,
    ),
    (
        "parse_reject_schema_version",
        "parse_finding_dict",
        FindingOk::False,
    ),
];

/// Top-level identity ids. Nested `"id": "evt"` is an argument, not a vector id.
const IDENTITY_VECTORS: &[(&str, &str)] = &[
    ("empty_list_silent", "identity_events"),
    ("two_distinct_string_ids_silent", "identity_events"),
    ("empty_and_whitespace_ids_ignored", "identity_events"),
    ("spaced_and_trimmed_distinct_silent", "identity_events"),
    ("mapping_bool_true_single_silent", "identity_events"),
    ("mapping_int_neg7_single_silent", "identity_events"),
    ("fingerprint_evt_sorted_hashes_ba", "identity_fingerprint"),
    ("fingerprint_evt_no_payload_hashes", "identity_fingerprint"),
    (
        "diff_field_names_zero_session_events",
        "identity_diff_field_names",
    ),
    ("diff_field_names_one_session_event", "identity_events"),
];

const DETERMINISM_VECTORS: &[(&str, &str)] = &[
    (
        "determinism_canonical_json_bytes_newline_true",
        "canonical_json_bytes",
    ),
    (
        "determinism_canonical_json_bytes_newline_false",
        "canonical_json_bytes",
    ),
    (
        "determinism_finding_sort_key_path_order",
        "finding_sort_key",
    ),
    ("determinism_repeat_hash_bytes", "repeat_hash"),
    ("determinism_repeat_hash_text", "repeat_hash"),
    ("determinism_repeat_hash_json_object", "repeat_hash"),
    (
        "determinism_stable_sort_paths_and_stability",
        "stable_sort_findings",
    ),
    ("determinism_module_all_export_order", "module_all"),
];

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

/// Top-level plan-fingerprint ids. Nested `"id": "s1"` is a plan field.
const PLAN_FINGERPRINT_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("plan_fp_small_policy_omitted", "compute_plan_fingerprint"),
    (
        "plan_fp_small_policy_conservative",
        "compute_plan_fingerprint",
    ),
    (
        "plan_fp_extra_fingerprint_policy_omitted",
        "compute_plan_fingerprint",
    ),
    (
        "plan_fp_extra_fingerprint_policy_conservative",
        "compute_plan_fingerprint",
    ),
    (
        "canonical_json_non_ascii_newline_true",
        "canonical_json_bytes",
    ),
    (
        "canonical_json_non_ascii_newline_false",
        "canonical_json_bytes",
    ),
];

const ROWS: &[Row] = &[
    // The supplied-fingerprint vector does not hash this preimage.
    Row {
        name: "test_preimage_ten_element_structure",
        disposition: Disposition::NotApplicable(
            "make_finding of SL003 at session.json line 10 matches sha256 of a ten-element canonical_json_bytes preimage, truncated to 16 hex digits; make_finding_fingerprint_default_severity is make_finding of SL011 at path p line 2 with a supplied fingerprint, and determinism_canonical_json_bytes_newline_false is a different object",
        ),
    },
    // all_export_order lists the name. It does not call the function.
    Row {
        name: "test_direct_compute_finding_fingerprint",
        disposition: Disposition::NotApplicable(
            "compute_finding_fingerprint equals make_finding for one SL003 source and CheckContext; no finding vector calls compute_finding_fingerprint, and make_finding_fingerprint_default_severity supplies the digest",
        ),
    },
    // Blank context fields are not three equal fingerprints.
    Row {
        name: "test_unknown_version_marker",
        disposition: Disposition::NotApplicable(
            "three make_finding calls on path test.json, with missing, blank, and explicit unknown versions, have equal fingerprints; context_new_blank_whitespace_become_unknown is CheckContext::new with different blank strings and checks field text",
        ),
    },
    // Five mutually distinct fingerprints. One make_finding row is not that matrix.
    Row {
        name: "test_version_sensitivity_matrix",
        disposition: Disposition::NotApplicable(
            "five mutually distinct make_finding fingerprints from a base and four single-coordinate changes; no vector is that matrix, and make_finding_fingerprint_default_severity is one different code with a supplied fingerprint",
        ),
    },
    // Path, line, and record_id. sort_findings does not hash those coordinates.
    Row {
        name: "test_structural_coordinates_sensitivity",
        disposition: Disposition::NotApplicable(
            "path, line, and record_id each change the make_finding fingerprint for sessions/a.json; no vector is that three-way inequality, and sort_findings_path_line_severity orders findings",
        ),
    },
    // identity_fingerprint of id evt is not check_identities with and without context.
    Row {
        name: "test_context_object_threading",
        disposition: Disposition::NotApplicable(
            "check_identities with CheckContext.from_profile_and_adapter versus context None yields one finding each and unequal fingerprints; fingerprint_evt_sorted_hashes_ba is identity_fingerprint of id evt, and context_create_lookup_when_version_omitted only builds context fields",
        ),
    },
    // The golden fixture is not an enforce, repeat_hash, or plan canonical_json vector.
    Row {
        name: "test_nonascii_golden_fixture",
        disposition: Disposition::NotApplicable(
            "make_finding recomputed from fixtures/fingerprint/nonascii_plan.json equals that file's golden fingerprint; enforce_eacute_accept is enforce_content_free_text, determinism_repeat_hash_text hashes a different string, and repair.fingerprint canonical_json_non_ascii_newline_false is canonical_json_bytes of a different object",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_preimage_ten_element_structure",
    "test_direct_compute_finding_fingerprint",
    "test_unknown_version_marker",
    "test_version_sensitivity_matrix",
    "test_structural_coordinates_sensitivity",
    "test_context_object_threading",
    "test_nonascii_golden_fixture",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
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

fn assert_naive_catalog(json: &str, label: &str, rows: &[(&str, &str)]) {
    let ids = vector_ids(json);
    let expected: Vec<&str> = rows.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, expected, "{label} vector ids");
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len(), "{label} duplicate id");
    for &(id, construct) in rows {
        let slice = vector_slice(json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{label} {id} is missing construct {construct}"
        );
    }
}

const TOP_LEVEL_ID_PREFIX: &str = "\n      \"id\": \"";

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

fn assert_finding_ok(id: &str, slice: &str, ok: FindingOk) {
    let has_true = slice.contains("\"ok\": true");
    let has_false = slice.contains("\"ok\": false");
    match ok {
        FindingOk::True => {
            assert!(has_true, "{id} success mode is missing ok true");
            assert!(!has_false, "{id} also records ok false");
        }
        FindingOk::False => {
            assert!(has_false, "{id} failure mode is missing ok false");
            assert!(!has_true, "{id} also records ok true");
        }
        FindingOk::Absent => {
            assert!(!has_true && !has_false, "{id} records an ok field");
        }
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_fingerprint_identity_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
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
fn covered_vector_ids_are_present_in_fingerprint_vectors() {
    let finding = read_vectors(FINDING_VECTORS_REL, "sesslint.finding");
    let identity = read_vectors(IDENTITY_VECTORS_REL, "sesslint.checks.identity");
    let determinism = read_vectors(DETERMINISM_VECTORS_REL, "sesslint.determinism");
    let context = read_vectors(CONTEXT_VECTORS_REL, "sesslint.context");
    let plan = read_vectors(PLAN_FINGERPRINT_VECTORS_REL, "sesslint.repair.fingerprint");

    let finding_rows: Vec<(&str, &str)> = FINDING_VECTORS
        .iter()
        .map(|(id, construct, _)| (*id, *construct))
        .collect();
    assert_naive_catalog(&finding, "finding", &finding_rows);
    for &(id, _, ok) in FINDING_VECTORS {
        assert_finding_ok(id, vector_slice(&finding, id), ok);
    }
    assert!(
        vector_slice(&finding, "all_export_order").contains("compute_finding_fingerprint"),
        "finding export list no longer names compute_finding_fingerprint"
    );

    assert_top_level_catalog(&identity, "checks.identity", IDENTITY_VECTORS);
    assert_naive_catalog(&determinism, "determinism", DETERMINISM_VECTORS);
    assert_naive_catalog(&context, "context", CONTEXT_VECTORS);
    assert_top_level_catalog(&plan, "repair.fingerprint", PLAN_FINGERPRINT_VECTORS);

    let finding_ids: BTreeSet<&str> = vector_ids(&finding).into_iter().collect();
    let identity_ids: BTreeSet<&str> = IDENTITY_VECTORS.iter().map(|(id, _)| *id).collect();

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            finding_ids.contains(vector_id) || identity_ids.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = if finding_ids.contains(vector_id) {
            vector_slice(&finding, vector_id)
        } else {
            let marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
            let start = identity
                .find(&marker)
                .unwrap_or_else(|| panic!("checks.identity is missing id {vector_id}"));
            let after = start + marker.len();
            let end = identity[after..]
                .find(TOP_LEVEL_ID_PREFIX)
                .map(|offset| after + offset)
                .unwrap_or(identity.len());
            &identity[start..end]
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
