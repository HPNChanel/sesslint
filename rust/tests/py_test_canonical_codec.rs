//! Dispositions for the 17 `def test_` methods in pinned `tests/test_canonical_codec.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (324 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one vector id in `_canonical_codec/vectors.json` whose
//! construct is the same function and the same success or failure mode as that
//! entire pinned test. `not_applicable` records a check no vector has. This
//! package does not depend on the codec crate and cannot run the Hypothesis row.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 17;
const CANONICAL_CODEC_VECTOR_COUNT: usize = 17;
const VECTORS_REL: &str = "parity/vectors/_canonical_codec/vectors.json";

/// `covered` names a vector id in `_canonical_codec/vectors.json`.
/// `not_applicable` records a mode this package cannot reach without a
/// `Cargo.toml` change, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
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
        name: "test_protocol_conformance",
        disposition: Disposition::NotApplicable(
            "get_active_codec protocol check; module_all lists export names and is a different construct",
        ),
    },
    Row {
        name: "test_pure_python_codec_version_binding",
        disposition: Disposition::NotApplicable(
            "PurePythonCanonicalCodec name and version; no vector constructs that class",
        ),
    },
    Row {
        name: "test_fail_closed_on_environment_disable",
        disposition: Disposition::NotApplicable(
            "SESSLINT_DISABLE_ACCEL selects PurePythonCanonicalCodec; no vector sets that variable",
        ),
    },
    Row {
        name: "test_set_and_restore_active_codec",
        disposition: Disposition::NotApplicable(
            "set_active_codec identity and restore; no vector calls set_active_codec",
        ),
    },
    // SessionEvent wire bytes. No vector serializes that value.
    Row {
        name: "test_parent_id_null_retention",
        disposition: Disposition::NotApplicable(
            "canonical_json_bytes keeps a null parent_id on a SessionEvent; no vector serializes that event",
        ),
    },
    Row {
        name: "test_extra_fields_hoisting",
        disposition: Disposition::NotApplicable(
            "canonical_json_bytes hoists only experimental extra fields; no vector records that hoist",
        ),
    },
    // canonical_unicode_utf8 is a different object.
    Row {
        name: "test_non_bmp_astral_unicode_strings",
        disposition: Disposition::NotApplicable(
            "canonical_json_bytes of the emoji and multilingual object; canonical_unicode_utf8 is a different object",
        ),
    },
    // Success for finite floats plus three refusals. One nan or inf vector is not that set.
    Row {
        name: "test_float_edges_and_nan_inf_refusal",
        disposition: Disposition::NotApplicable(
            "finite-float success plus nan, inf, and negative-inf SchemaError; no one vector is that whole set",
        ),
    },
    Row {
        name: "test_empty_vs_none_distinction",
        disposition: Disposition::NotApplicable(
            "canonical_json_bytes of empty dict, list, string, and null; no vector has that object",
        ),
    },
    Row {
        name: "test_key_order_permutations",
        disposition: Disposition::NotApplicable(
            "three key orders of a, b, m, and z; canonical_flat_object is a different object",
        ),
    },
    // Overflow at 993 wraps is a failure of a different shape.
    Row {
        name: "test_deep_legal_nesting",
        disposition: Disposition::NotApplicable(
            "twenty successful nested levels; error_nesting_overflow_dict fails at 993 wraps",
        ),
    },
    Row {
        name: "test_cyclic_reference_refusal",
        disposition: Disposition::Covered {
            vector_id: "error_cyclic_dict",
            needles: &[
                "\"type\": \"canonical_json_bytes\"",
                "\"shape\": \"cycle_dict\"",
                "\"result\": \"error\"",
                "\"raises\": \"SchemaError\"",
                "\"exact_message\": \"Cyclic reference detected during canonical serialization\"",
            ],
        },
    },
    // The pinned calls succeed. Both identity vectors return Unsupported.
    Row {
        name: "test_content_identity_excludes_provenance",
        disposition: Disposition::NotApplicable(
            "content identity succeeds and drops provenance; both identity vectors return Unsupported",
        ),
    },
    // One digest does not cover equality of a second key order.
    Row {
        name: "test_payload_content_hash_deterministic",
        disposition: Disposition::NotApplicable(
            "two payload key orders share one hash; payload_content_hash_synthetic hashes one object",
        ),
    },
    Row {
        name: "test_plan_fingerprint_deterministic_and_binds_policy",
        disposition: Disposition::NotApplicable(
            "plan fingerprint matches across order and changes with policy; plan_fingerprint_synthetic is another plan",
        ),
    },
    Row {
        name: "test_session_event_all_dataclass_fields_covered",
        disposition: Disposition::NotApplicable(
            "SessionEvent field count and _normalize keys; no vector calls _normalize",
        ),
    },
    Row {
        name: "test_seam_matches_reference_json_serialization",
        disposition: Disposition::NotApplicable(
            "Hypothesis differential against json.dumps; this package has no proptest and cannot run it",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_protocol_conformance",
    "test_pure_python_codec_version_binding",
    "test_fail_closed_on_environment_disable",
    "test_set_and_restore_active_codec",
    "test_parent_id_null_retention",
    "test_extra_fields_hoisting",
    "test_non_bmp_astral_unicode_strings",
    "test_float_edges_and_nan_inf_refusal",
    "test_empty_vs_none_distinction",
    "test_key_order_permutations",
    "test_deep_legal_nesting",
    "test_cyclic_reference_refusal",
    "test_content_identity_excludes_provenance",
    "test_payload_content_hash_deterministic",
    "test_plan_fingerprint_deterministic_and_binds_policy",
    "test_session_event_all_dataclass_fields_covered",
    "test_seam_matches_reference_json_serialization",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector objects indent `"id"` by six spaces. A plan action also has an
    // `"id"` field, and that nested key is not a vector id.
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
        .unwrap_or_else(|| panic!("_canonical_codec vectors.json is missing id {id}"));
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
fn every_pinned_canonical_codec_test_has_one_disposition() {
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
    assert_eq!(covered, 1);
    assert_eq!(not_applicable, 16);
}

#[test]
fn covered_vector_ids_are_present_in_canonical_codec_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "_canonical_codec vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint._canonical_codec\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), CANONICAL_CODEC_VECTOR_COUNT);
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
