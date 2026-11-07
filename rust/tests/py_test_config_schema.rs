//! Dispositions for the 11 `def test_` functions in pinned
//! `tests/test_config_schema.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (161 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `config/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! One key inside a per-key sweep is not coverage. A shared `schema_version`
//! is not coverage. `not_applicable` records a `Draft7Validator` or
//! `config._validate_keys` check this package cannot reach without a
//! `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 11;
const CONFIG_VECTOR_COUNT: usize = 13;
const VECTORS_REL: &str = "parity/vectors/config/vectors.json";

/// `covered` names a vector id in `config/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file.
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

/// Vector id, construct type, and whether the expected outcome is an error.
const CONFIG_VECTORS: &[(&str, &str, bool)] = &[
    ("format_renamed", "validate_keys", true),
    ("unknown_key", "validate_keys", true),
    ("select_and_ignore", "validate_keys", true),
    ("empty_profile", "validate_keys", true),
    ("fail_on_stripped", "validate_keys", false),
    ("adapter_claude", "validate_keys", false),
    ("bad_adapter", "validate_keys", true),
    ("bool_is_not_a_number", "validate_keys", true),
    ("timestamp_zero", "validate_keys", false),
    ("timestamp_negative", "validate_keys", true),
    ("list_strip", "validate_keys", false),
    ("key_order", "validate_keys", false),
    ("nothing_found", "load_config", false),
];

const ROWS: &[Row] = &[
    // Draft7Validator.check_schema. The parity file's schema field is shared.
    Row {
        name: "test_schema_is_valid_draft07",
        disposition: Disposition::NotApplicable(
            "Draft7Validator.check_schema on sesslint-config.schema.json; no config vector checks a JSON Schema document, and the shared parity schema field is not that check",
        ),
    },
    Row {
        name: "test_schema_property_set_mirrors_allowed_keys",
        disposition: Disposition::NotApplicable(
            "schema properties set equals _ALLOWED_KEYS, additionalProperties is false, and type is object; no config vector compares that schema document",
        ),
    },
    // adapter_claude and bad_adapter are one adapter value, not every enum.
    Row {
        name: "test_schema_enums_mirror_runtime_tables",
        disposition: Disposition::NotApplicable(
            "schema enum sets for every _ENUM_VALUES key and profile; adapter_claude and bad_adapter are one adapter value, not that enum-table sweep",
        ),
    },
    // nothing_found is load_config. This test calls _validate_keys on {}.
    Row {
        name: "test_empty_config_validates",
        disposition: Disposition::NotApplicable(
            "_validate_keys and Draft7Validator both accept {}; nothing_found is load_config of an empty directory, not validate_keys of an empty table",
        ),
    },
    // One allowed key is not the sweep over every allowed key.
    Row {
        name: "test_each_key_valid_value",
        disposition: Disposition::NotApplicable(
            "one canonical valid value for every allowed key, accepted by _validate_keys and the schema; adapter_claude is validate_keys of one key and does not check the schema",
        ),
    },
    // select_and_ignore fails. This test expects each empty list to succeed.
    Row {
        name: "test_empty_list_is_valid",
        disposition: Disposition::NotApplicable(
            "every list key set to [] is accepted by _validate_keys and the schema; select_and_ignore is both empty lists and its outcome is error",
        ),
    },
    // The pinned test both accepts an omitted side and rejects the pair.
    Row {
        name: "test_full_config_all_keys",
        disposition: Disposition::NotApplicable(
            "all keys are accepted when select or ignore is omitted and rejected when both are set; select_and_ignore is only the empty-list pair error",
        ),
    },
    // bool_is_not_a_number fails. This test expects -1.25 to succeed.
    Row {
        name: "test_negative_float_is_valid_parity",
        disposition: Disposition::NotApplicable(
            "every float key set to -1.25 is accepted by _validate_keys and the schema; bool_is_not_a_number is confidence_min true and its outcome is error",
        ),
    },
    // One invalid value is not the sweep. timestamp_zero is a success skip.
    Row {
        name: "test_each_key_invalid_values",
        disposition: Disposition::NotApplicable(
            "every invalid value of every allowed key fails _validate_keys, and fails the schema except integer-valued floats; bad_adapter is one invalid value, and timestamp_zero is a success the test skips",
        ),
    },
    // unknown_key is one bool. The test rejects three different tables.
    Row {
        name: "test_unknown_keys_rejected",
        disposition: Disposition::NotApplicable(
            "_validate_keys and the schema reject three unknown-key tables; unknown_key is only bogus set to true, and format_renamed fails on the renamed format key",
        ),
    },
    Row {
        name: "test_schema_never_stricter_than_runtime",
        disposition: Disposition::NotApplicable(
            "if _validate_keys accepts a matrix case then the schema must accept it; no config vector calls Draft7Validator",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_schema_is_valid_draft07",
    "test_schema_property_set_mirrors_allowed_keys",
    "test_schema_enums_mirror_runtime_tables",
    "test_empty_config_validates",
    "test_each_key_valid_value",
    "test_empty_list_is_valid",
    "test_full_config_all_keys",
    "test_negative_float_is_valid_parity",
    "test_each_key_invalid_values",
    "test_unknown_keys_rejected",
    "test_schema_never_stricter_than_runtime",
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
        .unwrap_or_else(|| panic!("config vectors.json is missing id {id}"));
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
fn every_pinned_config_schema_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(CONFIG_VECTORS.len(), CONFIG_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_config_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "config vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.config\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = CONFIG_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in CONFIG_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"outcome\": \"error\""),
            fails,
            "{id} error mode does not match the vector file"
        );
        assert_eq!(
            slice.contains("\"outcome\": \"ok\""),
            !fails,
            "{id} success mode does not match the vector file"
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
