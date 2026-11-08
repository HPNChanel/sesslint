//! Dispositions for the single `def test_` in pinned
//! `tests/repair/test_abstention_matrix.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. This integration test crate
//! links `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`]
//! only.
//!
//! `covered` names one id in `repair.planner/vectors.json` or
//! `repair.executor/vectors.json` whose construct is the same function and the
//! same success or failure mode as that entire pinned test. One matrix cell or
//! seam assertion inside a sweep is not coverage. `not_applicable` records a
//! `plan`, `execute`, or source-derived check this package cannot reach without
//! a `Cargo.toml` change, or a mode no vector records as the full pin outcome.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 1;
const PLANNER_VECTORS_REL: &str = "parity/vectors/repair.planner/vectors.json";
const EXECUTOR_VECTORS_REL: &str = "parity/vectors/repair.executor/vectors.json";

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

const PLANNER_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("module_constants_snapshot", "module_constants"),
    ("compute_events_source_hash_empty", "compute_events_source_hash"),
    ("plan_step_from_dict_not_object", "plan_step_from_dict"),
    ("plan_step_invalid_loss_class", "plan_step_from_dict"),
    ("plan_policy_aggressive", "plan_call"),
    ("plan_policy_empty_string", "plan_call"),
    ("plan_policy_true_bool", "plan_call"),
    ("plan_policy_none", "plan_call"),
    ("plan_policy_int_one", "plan_call"),
    ("plan_empty_conservative_success_gap", "plan_call"),
    ("get_plan_schema_path_gap", "get_plan_schema_path"),
    ("load_plan_schema_gap", "load_plan_schema"),
    ("repair_plan_from_dict_missing_seq", "repair_plan_from_dict"),
    ("repair_plan_from_dict_missing_recipe", "repair_plan_from_dict"),
    ("repair_plan_from_dict_missing_min_policy", "repair_plan_from_dict"),
    ("repair_plan_from_dict_missing_recipe_version", "repair_plan_from_dict"),
];

const EXECUTOR_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("sqlite_magic_bytes", "sqlite_magic"),
    ("module_private_constants", "module_private_constants"),
    ("is_live_store_suffix_db", "is_live_store_path"),
    ("is_live_store_nonmagic_fixture", "is_live_store_path"),
    ("is_live_store_magic_fixture", "is_live_store_path"),
    ("load_session_missing_path", "load_session_not_found"),
    ("load_session_empty_path", "load_session_not_found"),
    ("load_session_directory_path", "load_session_not_found"),
    ("load_session_broken_symlink", "load_session_with_findings_not_found"),
    ("load_session_symlink_file_seam", "load_session_snapshot_seam"),
    ("load_source_for_format_import_seam", "load_source_for_format_gap"),
    ("execute_cap_257", "execute_cap"),
    ("execute_fingerprint_import_seam", "execute_fingerprint_gap"),
    ("source_positions_duplicate_origin", "source_positions_duplicate"),
    ("relocate_step_removed_target", "relocate_step_removed"),
    ("load_plan_salvage_under_conservative", "load_plan_salvage_policy_mismatch"),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_abstention_12_cell_matrix",
        disposition: Disposition::NotApplicable(
            "RVW-011 parametrized matrix over has_sl203, side_effects none unknown or possible, and policy conservative or salvage builds a canonical JSONL source, derives a plan from the same bytes the executor loads, then asserts dry-run and execute agree in all twelve cells; when SL203 is present both policies expect zero executable steps with every blocked reason SL203-refusal and execute raises Abstained with SL203 present without writing output; conservative without SL203 expects recipes identical-duplicate-collapse and seq-renumber then a successful execute manifest whose input_fingerprint equals the plan source hash for every side_effects value; salvage without SL203 and side_effects none matches that success path; salvage without SL203 and side_effects unknown or possible expects execute Abstained matching side-effect-unknown or side-effect-possible without output. plan, execute, load_source_for_format, and run_all_checks are not callable from this package without a Cargo.toml change; repair.planner vectors record plan_call validation and register_all schema gaps, not that full derived-plan matrix; repair.executor vectors record step-cap, fingerprint import, and load_plan salvage policy mismatch fixtures, not Abstained execution or planner agreement; no published vector is the same function and outcome as that entire pin",
        ),
    },
];

const PINNED_NAMES: &[&str] = &["test_abstention_12_cell_matrix"];

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
fn every_pinned_repair_abstention_matrix_test_has_one_disposition() {
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
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn cited_repair_planner_and_executor_vectors_are_present() {
    let planner = read_vectors(PLANNER_VECTORS_REL, "sesslint.repair.planner");
    assert_top_level_catalog(&planner, "repair.planner", PLANNER_VECTORS);

    let executor = read_vectors(EXECUTOR_VECTORS_REL, "sesslint.repair.executor");
    assert_top_level_catalog(&executor, "repair.executor", EXECUTOR_VECTORS);

    let executor_ids: BTreeSet<&str> = vector_ids(&executor).into_iter().collect();

    assert!(
        vector_slice(&planner, "module_all_export_order").contains("plan"),
        "repair.planner export list no longer names plan"
    );
    assert!(
        vector_slice(&executor, "module_all_export_order").contains("execute"),
        "repair.executor export list no longer names execute"
    );
    for &(id, construct) in EXECUTOR_VECTORS {
        assert!(
            executor_ids.contains(id),
            "repair.executor is missing id {id}"
        );
        let slice = vector_slice(&executor, id);
        assert!(
            slice.contains(&format!("\"type\": \"{construct}\"")),
            "repair.executor {id} construct type"
        );
    }

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let plan_marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
        let slice = if planner.contains(&plan_marker) {
            vector_slice(&planner, vector_id)
        } else {
            vector_slice(&executor, vector_id)
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
