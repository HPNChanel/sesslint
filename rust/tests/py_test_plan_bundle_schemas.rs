//! Dispositions for the twelve test functions in pinned
//! `tests/test_plan_bundle_schemas.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (241 splitlines). Exactly
//! twelve test functions, in module order.
//! `test_plan_missing_step_field_fails_validation` is parametrized over seq,
//! recipe, min_policy, and recipe_version and is one row covering every cell.
//! The other eleven are not parametrized. Each row is the whole function. A
//! docstring is not an assertion. A comment is not an assertion.
//! `_validate_plan_dict`, `_validate_bundle_dict`, `PLAN_STEP_REQUIRED`,
//! `PLAN_TOP_REQUIRED`, `BUNDLE_TOP_REQUIRED`, `REPO_ROOT`, and
//! `REPAIR_FIXTURES` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these twelve names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these twelve names.
//! A corpus pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a
//! Covered source.
//! `parity/vectors/repair.planner/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. `load_plan_schema_gap` only
//! loads one schema document. A schema vector that only loads one document is
//! not the whole pytest. `get_plan_schema_path_gap` only records a path.
//! `repair_plan_from_dict_missing_seq`, `repair_plan_from_dict_missing_recipe`,
//! `repair_plan_from_dict_missing_min_policy`, and
//! `repair_plan_from_dict_missing_recipe_version` are four ids at that old
//! pin. Four ids are not the one missing-field row.
//! `plan_empty_conservative_success_gap` is not
//! `test_conservative_plan_dict_validates`.
//! `parity/vectors/bundle/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. `load_bundle_schema_gap` records
//! that the schema load is unavailable. That gap is not
//! `test_bundle_schema_loads_and_self_consistent`. `get_bundle_schema_path_gap`
//! is not that pytest. `build_bundle_import_gap` is not
//! `test_bundle_dict_validates`.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `get_plan_schema_path`,
//! `load_plan_schema`, `get_bundle_schema_path`, `load_bundle_schema`,
//! `load_plan`, `build_bundle`, or `assert_schema` without a `Cargo.toml`
//! change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 12;
const PINNED_SPLITLINES: usize = 241;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `test_plan_missing_step_field_fails_validation` is
/// parametrized over seq, recipe, min_policy, and recipe_version and is one
/// row covering every cell. Each row is the whole function. A docstring is
/// not an assertion. A comment is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A schema vector that only loads one document is not the whole pytest.
/// `not_applicable` names the missing stop and the nearest different test.
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
        name: "test_plan_schema_loads_and_self_consistent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_schema_loads_and_self_consistent: the plan schema path is a file, $schema is https://json-schema.org/draft/2020-12/schema, $id is https://sesslint.dev/schemas/sesslint.plan/v1, required is a subset of the property keys, the step item required set is a subset of the step item property keys, and the step item required keys include min_policy, params, recipe, recipe_version, seq, target_finding_fp, and target_index; missing stop: that file, that $schema, that $id, that required subset, that step-item subset, and those step fields together; A plan schema load is not a bundle schema load; The bundle schema load is not this; test_bundle_schema_loads_and_self_consistent is that bundle schema load",
        ),
    },
    Row {
        name: "test_bundle_schema_loads_and_self_consistent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_schema_loads_and_self_consistent: the bundle schema path is a file, $schema is https://json-schema.org/draft/2020-12/schema, $id is https://sesslint.dev/schemas/sesslint.bundle/v1, required is a subset of the property keys, and bundle_version const is sesslint.bundle/v1; missing stop: that file, that $schema, that $id, that required subset, and that bundle_version const together; A plan schema load is not a bundle schema load; The conservative plan test is not this; test_conservative_plan_dict_validates is that conservative plan test",
        ),
    },
    Row {
        name: "test_conservative_plan_dict_validates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_conservative_plan_dict_validates: the loaded exec_basic plan dict validates; It does not assert the policy value; missing stop: that validation; A conservative plan is not a salvage plan; The refusal-path plan test is not this; test_refusal_path_plan_dict_validates is that refusal-path plan test",
        ),
    },
    Row {
        name: "test_refusal_path_plan_dict_validates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_refusal_path_plan_dict_validates: the loaded exec_refuse_sl203 plan dict validates; The docstring is not an assertion; It does not assert blocked findings or zero steps; missing stop: that validation; The salvage plan test is not this; test_salvage_plan_dict_validates is that salvage plan test",
        ),
    },
    Row {
        name: "test_salvage_plan_dict_validates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_salvage_plan_dict_validates: expected_plan validates and its policy equals salvage; missing stop: that validation and that salvage policy together; A conservative plan is not a salvage plan; The bundle dict test is not this; test_bundle_dict_validates is that bundle dict test",
        ),
    },
    Row {
        name: "test_bundle_dict_validates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_dict_validates: the bundle dict built from fixtures/checks/graph_healthy.json validates; missing stop: that validation; The detection-failed bundle test is not this; test_detection_failed_bundle_dict_validates is that detection-failed bundle test",
        ),
    },
    Row {
        name: "test_detection_failed_bundle_dict_validates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_detection_failed_bundle_dict_validates: the bundle dict built from a temp file validates and detection resolved is None; The written bytes are not an assertion; missing stop: that validation and that None resolved together; The bundle JSON round-trip test is not this; test_bundle_json_round_trip_validates is that bundle JSON round-trip test",
        ),
    },
    Row {
        name: "test_bundle_json_round_trip_validates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_json_round_trip_validates: to_json parses and the parsed dict validates; It does not assert the parsed dict equals to_dict; missing stop: that parse and that validation together; The missing-step-field test is not this; test_plan_missing_step_field_fails_validation is that missing-step-field test",
        ),
    },
    Row {
        name: "test_plan_missing_step_field_fails_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_missing_step_field_fails_validation: deleting seq, deleting recipe, deleting min_policy, and deleting recipe_version from the first step each make validation raise AssertionError; missing stop: those four deletions together; all four fields are one row; one field is not this row; The wrong-version plan test is not this; test_plan_wrong_version_fails_validation is that wrong-version plan test",
        ),
    },
    Row {
        name: "test_plan_wrong_version_fails_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_plan_wrong_version_fails_validation: the exec_basic plan with version set to sesslint.plan/v0 makes validation raise AssertionError; missing stop: that rejected version; The missing-section bundle test is not this; test_bundle_missing_section_fails_validation is that missing-section bundle test",
        ),
    },
    Row {
        name: "test_bundle_missing_section_fails_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_missing_section_fails_validation: deleting fixture_skeleton makes bundle validation raise AssertionError; missing stop: that rejected deletion; The wrong-version bundle test is not this; test_bundle_wrong_version_fails_validation is that wrong-version bundle test",
        ),
    },
    Row {
        name: "test_bundle_wrong_version_fails_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_wrong_version_fails_validation: bundle_version set to sesslint.bundle/v2 makes bundle validation raise AssertionError; missing stop: that rejected version; The missing-section bundle test is not this; test_bundle_missing_section_fails_validation is that missing-section bundle test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_plan_schema_loads_and_self_consistent",
    "test_bundle_schema_loads_and_self_consistent",
    "test_conservative_plan_dict_validates",
    "test_refusal_path_plan_dict_validates",
    "test_salvage_plan_dict_validates",
    "test_bundle_dict_validates",
    "test_detection_failed_bundle_dict_validates",
    "test_bundle_json_round_trip_validates",
    "test_plan_missing_step_field_fails_validation",
    "test_plan_wrong_version_fails_validation",
    "test_bundle_missing_section_fails_validation",
    "test_bundle_wrong_version_fails_validation",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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

fn vector_slice<'a>(json: &'a str, id: &str, corpus: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("{corpus} vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_python_commit_one_space(json: &str, corpus: &str) {
    // The corpus stores one space after the colon.
    let commit = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&commit),
        "{corpus} vectors python_commit spacing does not match {commit}"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "{corpus} python_commit has no space after the colon"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":  \"{PIN}\"")),
        "{corpus} python_commit has more than one space after the colon"
    );
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_test_plan_bundle_schemas_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 241);
}

#[test]
fn pinned_test_plan_bundle_schemas_row_count_equals_twelve() {
    assert_eq!(ROWS.len(), 12);
    assert_eq!(PINNED_TEST_COUNT, 12);
    assert_eq!(PINNED_NAMES.len(), 12);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_plan_bundle_schemas_test_has_one_disposition() {
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
                assert!(
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
                    row.name
                );
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
    let json = read_vectors(CLI_VECTORS_REL);
    assert_python_commit_one_space(&json, "cli");
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
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
        let slice = vector_slice(&json, vector_id, "cli");
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
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 12);

    let json = read_vectors(API_VECTORS_REL);
    assert_python_commit_one_space(&json, "api");
    assert!(json.contains("\"module\": \"sesslint.api\""));

    let ids = vector_ids(&json);
    assert_eq!(API_VECTOR_COUNT, 77);
    assert_eq!(ids.len(), API_VECTOR_COUNT);
    assert_eq!(ids.len(), 77);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    assert_eq!(id_set.len(), 77);
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
    }
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "api");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
