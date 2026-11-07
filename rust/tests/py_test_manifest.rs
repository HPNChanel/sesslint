//! Dispositions for the 31 `def test_` functions in pinned
//! `tests/test_manifest.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (893 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.report`.
//!
//! `covered` names one id in `report/vectors.json` whose construct is the same
//! function and the same result as that entire pinned test. One example inside
//! a sweep, a different input string, or a name in `module_exports` is not
//! coverage. `not_applicable` records a `sesslint.report` manifest call this
//! package cannot reach without a `Cargo.toml` change, or a mode no vector
//! records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 31;
const REPORT_VECTOR_COUNT: usize = 17;
const VECTORS_REL: &str = "parity/vectors/report/vectors.json";

/// `covered` names a vector id in `report/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file. A vector
/// covers a row only when it is that entire pinned test.
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
/// A thrown `parse_report` failure is the key `"display"`. Levels, paths,
/// rendered text, export lists, pin summaries, and gap assertions are not
/// that key.
const REPORT_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("compute_assurance_none_empty", "compute_assurance", false),
    ("compute_assurance_nonempty_a3", "compute_assurance", false),
    ("dump_report_gap", "dump_report", false),
    ("parse_report_json_string_gap", "parse_report", false),
    ("parse_report_bool_total", "parse_report", true),
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
        name: "test_conservative_empty_fixture_roundtrip",
        disposition: Disposition::NotApplicable(
            "parse_manifest of fixtures/manifests/conservative-empty.json checks schema_version, fingerprints, policy conservative, empty actions and declared_loss, a null revalidate_report, and a 64-character key from compute_manifest_idempotency_key, then dump_manifest, parse_manifest, and dump_manifest are byte-identical; module_exports lists those names and dump_report_gap is dump_report of a different document",
        ),
    },
    Row {
        name: "test_manifest_idempotency_key_stability",
        disposition: Disposition::NotApplicable(
            "build_manifest twice with reorder evt-1 and neutralize evt-2 shares one 64-character key, and policy salvage, input fingerprint in-fp-DIFFERENT, and a one-action list each change that key; no report vector calls build_manifest, and one call would not be the sweep",
        ),
    },
    Row {
        name: "test_action_order_insensitivity_idempotency_key",
        disposition: Disposition::NotApplicable(
            "build_manifest of delete, reparent, and rewrite in two orders shares one idempotency key, one sorted action tuple, and one dump_manifest byte string; no report vector records action order",
        ),
    },
    Row {
        name: "test_never_synthetic_success_contract",
        disposition: Disposition::NotApplicable(
            "RepairManifest has no success, passed, or ok attribute, load_manifest_schema omits success, passed, and ok and sets additionalProperties false, and parse_manifest rejects success, passed, ok, and healthy; module_exports lists RepairManifest and one field would not be the sweep",
        ),
    },
    Row {
        name: "test_manifest_schema_anti_drift",
        disposition: Disposition::NotApplicable(
            "get_manifest_schema_path is a file and load_manifest_schema matches the repair-manifest id, draft 2020-12, additionalProperties false, REQUIRED_MANIFEST_FIELDS, KNOWN_MANIFEST_FIELDS, VALID_POLICIES, and the idempotency_key pattern; module_constants records the report schema version, severities, and assurance levels",
        ),
    },
    Row {
        name: "test_parse_manifest_unknown_field_raises_sl302",
        disposition: Disposition::NotApplicable(
            "parse_manifest of unrecognized_field raises UnknownFieldError SL302 naming that field; parse_report_bool_total is parse_report of a bool total and no report vector calls parse_manifest",
        ),
    },
    Row {
        name: "test_parse_manifest_unsupported_version_raises_sl301",
        disposition: Disposition::NotApplicable(
            "parse_manifest of schema_version sesslint.repair-manifest/v99 raises VersionError SL301; module_constants records sesslint.report/v1 and no report vector calls parse_manifest",
        ),
    },
    Row {
        name: "test_declared_loss_accounting",
        disposition: Disposition::NotApplicable(
            "build_manifest stores dropped_orphan:evt-10 and neutralized_call:call-20 under policy salvage, and an empty loss item raises SchemaError; no report vector records declared_loss, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_revalidate_report_path_handling",
        disposition: Disposition::NotApplicable(
            "build_manifest turns reports\\post_repair.json into reports/post_repair.json and rejects an empty revalidate_report; minimize_path_under_home is minimize_path of a different path, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_enforce_content_free_manifest_catches_smuggled_payload",
        disposition: Disposition::NotApplicable(
            "enforce_content_free of a rewrite action whose detail contains Filament invoice 1234 raises ContentLeakError; no report vector calls enforce_content_free",
        ),
    },
    Row {
        name: "test_repair_action_total_order",
        disposition: Disposition::NotApplicable(
            "RepairAction orders a None record_id before delete evt-1, then delete evt-2, then insert evt-1, and equality holds; no report vector constructs a RepairAction",
        ),
    },
    Row {
        name: "test_invalid_policy_raises",
        disposition: Disposition::NotApplicable(
            "build_manifest rejects policies aggressive, automatic, force, and the empty string; module_exports lists VALID_POLICIES and no report vector records those four raises",
        ),
    },
    Row {
        name: "test_manifest_schema_loader_file_not_found",
        disposition: Disposition::NotApplicable(
            "load_manifest_schema raises FileNotFoundError when get_manifest_schema_path is patched to a missing file; no report vector records that error",
        ),
    },
    Row {
        name: "test_repair_action_validation_errors",
        disposition: Disposition::NotApplicable(
            "RepairAction rejects an empty kind, an empty record_id, and a non-string detail; no report vector records those three SchemaErrors, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_repair_action_comparison_edge_cases",
        disposition: Disposition::NotApplicable(
            "RepairAction comparisons against a str return NotImplemented and the less-than operator raises TypeError; no report vector compares a RepairAction",
        ),
    },
    Row {
        name: "test_repair_manifest_model_validation_errors",
        disposition: Disposition::NotApplicable(
            "RepairManifest rejects schema version v2, empty fingerprints, policy INVALID, a list of actions, a non-RepairAction, a list of declared_loss, an empty loss string, an empty revalidate_report, a short idempotency key, a non-RevalidationSummary, and assurance ceiling INVALID; no report vector constructs a RepairManifest, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_build_manifest_argument_validation",
        disposition: Disposition::NotApplicable(
            "build_manifest rejects an empty input fingerprint and an empty output fingerprint; no report vector records those two SchemaErrors, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_dump_manifest_type_error",
        disposition: Disposition::NotApplicable(
            "dump_manifest of a dict raises TypeError Expected RepairManifest instance; dump_report_gap is dump_report of an empty clean report and a json.dumps gap",
        ),
    },
    Row {
        name: "test_parse_manifest_error_cases",
        disposition: Disposition::NotApplicable(
            "parse_manifest rejects malformed JSON, an int, a JSON list, a missing input_fingerprint, an invalid policy, actions as a string, a non-mapping action, an action missing kind, an unknown action field, and declared_loss as a string; parse_report_json_string_gap and parse_report_bool_total are parse_report, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_enforce_content_free_manifest_all_locations",
        disposition: Disposition::NotApplicable(
            "enforce_content_free raises ContentLeakError for kind neutralize_secret_token, record_id user_payroll_id, declared_loss dropped_ssn_record, and revalidate_report confidential_audit; no report vector calls enforce_content_free, and one location would not be the sweep",
        ),
    },
    Row {
        name: "test_get_manifest_schema_path_prefix_resolution",
        disposition: Disposition::NotApplicable(
            "get_manifest_schema_path with sys.prefix and Path.is_file patched returns share/sesslint/schemas/sesslint.repair-manifest.v1.json; no report vector calls get_manifest_schema_path",
        ),
    },
    Row {
        name: "test_repair_action_whitespace_normalization",
        disposition: Disposition::NotApplicable(
            "RepairAction strips kind, record_id, and detail; no report vector records that constructor",
        ),
    },
    Row {
        name: "test_parse_manifest_with_actions_roundtrip",
        disposition: Disposition::NotApplicable(
            "build_manifest of delete evt-1 and neutralize with record_id None, then parse_manifest of to_dict, equals the original; no report vector calls parse_manifest",
        ),
    },
    Row {
        name: "test_enforce_content_free_manifest_fingerprints_leaks",
        disposition: Disposition::NotApplicable(
            "enforce_content_free raises ContentLeakError for leak_invoice_999 in the input fingerprint and secret_token in the output fingerprint; no report vector calls enforce_content_free, and one fingerprint would not be the sweep",
        ),
    },
    Row {
        name: "test_parse_manifest_strict_field_type_validation",
        disposition: Disposition::NotApplicable(
            "parse_manifest rejects non-string input_fingerprint, output_fingerprint, idempotency_key, revalidate_report, a non-string declared_loss item, and non-string action kind, record_id, and detail; no report vector records those eight SchemaErrors, and one field would not be the sweep",
        ),
    },
    Row {
        name: "test_parse_manifest_sorts_actions_into_canonical_order",
        disposition: Disposition::NotApplicable(
            "parse_manifest sorts rewrite evt-2 ahead of delete evt-1 into delete then rewrite; no report vector records that sort",
        ),
    },
    Row {
        name: "test_compute_manifest_idempotency_key_validations",
        disposition: Disposition::NotApplicable(
            "compute_manifest_idempotency_key rejects an empty input fingerprint and policy INVALID; compute_assurance_none_empty is compute_assurance, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_repair_action_content_leak_raises_content_leak_error",
        disposition: Disposition::NotApplicable(
            "RepairAction rejects a newline in kind, an email in record_id, and a bearer token in detail; no report vector records those three ContentLeakErrors, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_build_manifest_content_leaks_in_declared_loss_and_revalidate_report",
        disposition: Disposition::NotApplicable(
            "build_manifest rejects an email in declared_loss and an email in revalidate_report; no report vector records those two ContentLeakErrors, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_parse_manifest_normalizes_paths_and_loss",
        disposition: Disposition::NotApplicable(
            "parse_manifest of a salvage mapping stores reports/validation_v1.json, declared_loss omitted_orphan:rec-1, revalidation assurance A2, warning_count 1, and assurance_ceiling A2; minimize_path vectors are minimize_path and compute_assurance_warning_a2 returns a different limitation",
        ),
    },
    Row {
        name: "test_revalidation_summary_validations",
        disposition: Disposition::NotApplicable(
            "RevalidationSummary rejects assurance INVALID, a negative error_count, a negative warning_count, an empty profile_id, and an empty profile_version; compute_assurance vectors return levels, and one input would not be the sweep",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_conservative_empty_fixture_roundtrip",
    "test_manifest_idempotency_key_stability",
    "test_action_order_insensitivity_idempotency_key",
    "test_never_synthetic_success_contract",
    "test_manifest_schema_anti_drift",
    "test_parse_manifest_unknown_field_raises_sl302",
    "test_parse_manifest_unsupported_version_raises_sl301",
    "test_declared_loss_accounting",
    "test_revalidate_report_path_handling",
    "test_enforce_content_free_manifest_catches_smuggled_payload",
    "test_repair_action_total_order",
    "test_invalid_policy_raises",
    "test_manifest_schema_loader_file_not_found",
    "test_repair_action_validation_errors",
    "test_repair_action_comparison_edge_cases",
    "test_repair_manifest_model_validation_errors",
    "test_build_manifest_argument_validation",
    "test_dump_manifest_type_error",
    "test_parse_manifest_error_cases",
    "test_enforce_content_free_manifest_all_locations",
    "test_get_manifest_schema_path_prefix_resolution",
    "test_repair_action_whitespace_normalization",
    "test_parse_manifest_with_actions_roundtrip",
    "test_enforce_content_free_manifest_fingerprints_leaks",
    "test_parse_manifest_strict_field_type_validation",
    "test_parse_manifest_sorts_actions_into_canonical_order",
    "test_compute_manifest_idempotency_key_validations",
    "test_repair_action_content_leak_raises_content_leak_error",
    "test_build_manifest_content_leaks_in_declared_loss_and_revalidate_report",
    "test_parse_manifest_normalizes_paths_and_loss",
    "test_revalidation_summary_validations",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are indented further.
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
fn every_pinned_manifest_test_has_one_disposition() {
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
            slice.contains("\"display\":"),
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
