//! Dispositions for the 13 `def test_` functions in pinned
//! `tests/test_registry_docs.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The card names 13 tests;
//! `lstrip` finds 13 `def test_` functions and none are indented. This
//! integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call repair without a
//! `Cargo.toml` change.
//!
//! `covered` would name one id in a published `vectors.json` whose construct
//! is the same function and the same success or failure mode as that entire
//! pinned test, with `entire_test` true. A doc-path scan, a recipe name list,
//! or one example inside a sweep is not the whole test. A Rust seam while the
//! pin succeeds is not coverage. The cited registration files have no
//! `entire_test` field. Recipe files that set `entire_test` true record
//! `apply_*` or `sl001_excisable`, which are not these doc tests. Every row
//! is `not_applicable`. SL002 and SL005 are not invented as covered ids.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 13;
const COVERED_COUNT: usize = 0;
const REGISTRY_VECTOR_COUNT: usize = 16;
const REPAIR_VECTOR_COUNT: usize = 1;
const CONSERVATIVE_VECTOR_COUNT: usize = 12;
const SALVAGE_VECTOR_COUNT: usize = 11;
const SL002_VECTOR_COUNT: usize = 24;
const REGISTRY_MODULE: &str = "sesslint.repair.registry";
const REPAIR_MODULE: &str = "sesslint.repair";
const CONSERVATIVE_MODULE: &str = "sesslint.repair.recipes_conservative";
const SALVAGE_MODULE: &str = "sesslint.repair.recipes_salvage";
const SL002_MODULE: &str = "sesslint.repair.recipes_sl002";
const REGISTRY_REL: &str = "parity/vectors/repair.registry/vectors.json";
const REPAIR_REL: &str = "parity/vectors/repair/vectors.json";
const CONSERVATIVE_REL: &str = "parity/vectors/repair.recipes_conservative/vectors.json";
const SALVAGE_REL: &str = "parity/vectors/repair.recipes_salvage/vectors.json";
const SL002_REL: &str = "parity/vectors/repair.recipes_sl002/vectors.json";

/// `covered` would name one vector id whose construct is that entire pinned
/// test. `not_applicable` records a docs-tree, catalog, or `assert_catalog_sync`
/// check this package cannot reach without a `Cargo.toml` change, or a mode
/// no cited vector records as the full pin outcome.
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

struct EntireTrueFile {
    rel: &'static str,
    module: &'static str,
    recipe: &'static str,
    rows: &'static [(&'static str, &'static str, &'static str)],
}

const REGISTRY_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("recipe_empty_name", "recipe_try_new"),
    ("recipe_plain_handles_sort", "recipe_try_new"),
    ("recipe_lossy_sets_salvage_flags", "recipe_try_new"),
    ("recipe_salvage_only_policy", "recipe_try_new"),
    ("recipe_both_lossy_flags", "recipe_try_new"),
    ("recipe_strict_min_policy_preserved", "recipe_try_new"),
    ("recipe_mixed_case_min_policy", "recipe_try_new"),
    ("recipe_whitespace_name_custom_version", "recipe_try_new"),
    ("recipe_callables_stored_not_invoked", "recipe_try_new"),
    (
        "planner_registry_registration_and_lookup",
        "registration_lookup",
    ),
    ("planner_duplicate_name_rejected", "duplicate_name"),
    (
        "planner_unknown_precondition_rejected",
        "unknown_precondition",
    ),
    (
        "empty_precondition_list_skips_table",
        "empty_preconditions_register",
    ),
    ("clear_registry_isolation", "clear_registry"),
    ("recipes_for_preserves_insertion_order", "insertion_order"),
];

const REPAIR_VECTORS: &[(&str, &str)] = &[("python_dunder_all", "public_name_list")];

const CONSERVATIVE_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("registration_handles_matrix", "registration_matrix"),
    ("register_all_idempotent", "register_all"),
    ("fixture_terminal_suffix_discard", "fixture_apply"),
    ("suffix_discard_refusal_empty_session", "apply"),
    ("suffix_discard_refusal_out_of_bounds", "apply"),
    ("suffix_discard_refusal_checkpoint_in_suffix", "apply"),
    ("reunion_refusal_zero_boundaries", "apply"),
    ("reunion_refusal_multiple_boundaries", "apply"),
    ("reunion_refusal_boundary_at_endpoint", "apply"),
    ("duplicate_collapse_refusal_checkpoint_or_boundary", "apply"),
    ("duplicate_collapse_refusal_mixed_kinds", "apply"),
];

const CONSERVATIVE_FNS: &[(&str, &str)] = &[
    (
        "fixture_terminal_suffix_discard",
        "apply_terminal_suffix_discard",
    ),
    (
        "suffix_discard_refusal_empty_session",
        "apply_terminal_suffix_discard",
    ),
    (
        "suffix_discard_refusal_out_of_bounds",
        "apply_terminal_suffix_discard",
    ),
    (
        "suffix_discard_refusal_checkpoint_in_suffix",
        "apply_terminal_suffix_discard",
    ),
    (
        "reunion_refusal_zero_boundaries",
        "apply_compaction_projection_reunion",
    ),
    (
        "reunion_refusal_multiple_boundaries",
        "apply_compaction_projection_reunion",
    ),
    (
        "reunion_refusal_boundary_at_endpoint",
        "apply_compaction_projection_reunion",
    ),
    (
        "duplicate_collapse_refusal_checkpoint_or_boundary",
        "apply_identical_duplicate_collapse",
    ),
    (
        "duplicate_collapse_refusal_mixed_kinds",
        "apply_identical_duplicate_collapse",
    ),
];

const SALVAGE_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("register_all_idempotent", "register_all"),
    ("registration_salvage_matrix", "registration_matrix"),
    (
        "sl001_excisable_precondition",
        "sl001_excisable_precondition",
    ),
    (
        "apply_torn_record_excision_validation",
        "apply_torn_record_excision_validation",
    ),
    (
        "amputate_direct_apply_validation",
        "amputate_direct_apply_validation",
    ),
    (
        "torn_compaction_direct_apply_validation",
        "torn_compaction_direct_apply_validation",
    ),
    (
        "truncate_direct_apply_validation",
        "truncate_direct_apply_validation",
    ),
    (
        "orphan_result_drop_resolves_by_params",
        "orphan_result_drop_resolves_by_params",
    ),
    (
        "orphan_result_drop_direct_apply_refusals",
        "orphan_result_drop_direct_apply_refusals",
    ),
    ("affected_region_orphan_gap", "affected_region_orphan_gap"),
];

const SL002_VECTORS: &[(&str, &str)] = &[
    ("module_all_export_order", "module_all"),
    ("recipe_constant_snapshot", "recipe_constant"),
    ("register_all_idempotent", "register_all"),
    ("apply_discards_named_last_event", "apply"),
    ("apply_reader_minted_keeps_terminal", "apply"),
    ("apply_shared_id_discards_last_only", "apply"),
    ("apply_shared_id_index_zero_keeps_both", "apply"),
    ("apply_bool_cut_index_is_not_int", "apply"),
    ("apply_bool_target_true_discards_index_one", "apply"),
    ("apply_bool_target_false_clears_singleton", "apply"),
    ("apply_bool_true_not_cut_zero_keeps_singleton", "apply"),
    ("apply_non_mapping_params_keeps_events", "apply"),
    ("apply_other_target_keeps_events", "apply"),
    ("apply_ignores_region_fallback_keys", "apply"),
    ("apply_duplicate_cut_index_last_wins", "apply"),
    ("apply_empty_pop_index_error", "apply"),
    ("apply_empty_no_cut_stays_empty", "apply"),
    ("region_gap_empty_events", "affected_region"),
    ("region_gap_proven_cut_suffix", "affected_region"),
    ("region_gap_out_of_range_cut", "affected_region"),
    ("region_gap_bool_step_target", "affected_region"),
    ("region_gap_float_event_id", "affected_region"),
    ("region_gap_ingestion_boundary", "affected_region"),
    ("region_gap_session_boundary_id", "affected_region"),
];

const CONSERVATIVE_MATRIX_NAMES: &[&str] = &[
    "terminal-suffix-discard",
    "identical-duplicate-collapse",
    "proven-unique-parent-restore",
    "compaction-projection-reunion",
    "duplicate-projection-removal",
    "identical-duplicate-drop",
    "seq-renumber",
];

const SALVAGE_MATRIX_NAMES: &[&str] = &[
    "orphan-result-drop",
    "side-effect-unknown-truncate",
    "torn-compaction-project",
    "torn-record-excision",
    "unresolvable-branch-amputate",
];

const REUNION_ENTIRE_TRUE: &[(&str, &str, &str)] = &[
    (
        "reunion_refusal_zero_boundaries",
        "apply_refusal",
        "apply_compaction_projection_reunion",
    ),
    (
        "reunion_refusal_multiple_boundaries",
        "apply_refusal",
        "apply_compaction_projection_reunion",
    ),
    (
        "reunion_refusal_boundary_at_endpoint",
        "apply_refusal",
        "apply_compaction_projection_reunion",
    ),
];

const SUFFIX_ENTIRE_TRUE: &[(&str, &str, &str)] = &[
    (
        "suffix_discard_refusal_empty_session",
        "apply_refusal",
        "apply_terminal_suffix_discard",
    ),
    (
        "suffix_discard_refusal_out_of_bounds",
        "apply_refusal",
        "apply_terminal_suffix_discard",
    ),
];

const TRUNCATE_ENTIRE_TRUE: &[(&str, &str, &str)] = &[(
    "truncate_direct_apply_validation",
    "apply_refusals",
    "apply_side_effect_unknown_truncate",
)];

const TORN_COMPACTION_ENTIRE_TRUE: &[(&str, &str, &str)] = &[(
    "torn_compaction_direct_apply_validation",
    "apply_refusals",
    "apply_torn_compaction_project",
)];

const EXCISION_ENTIRE_TRUE: &[(&str, &str, &str)] = &[(
    "sl001_excisable_precondition",
    "sl001_excisable",
    "sl001_excisable",
)];

const AMPUTATE_ENTIRE_TRUE: &[(&str, &str, &str)] = &[(
    "amputate_direct_apply_validation",
    "apply_refusals",
    "apply_unresolvable_branch_amputate",
)];

const ENTIRE_TRUE_FILES: &[EntireTrueFile] = &[
    EntireTrueFile {
        rel: "parity/recipes/compaction-projection-reunion/vectors.json",
        module: CONSERVATIVE_MODULE,
        recipe: "compaction-projection-reunion",
        rows: REUNION_ENTIRE_TRUE,
    },
    EntireTrueFile {
        rel: "parity/recipes/terminal-suffix-discard/vectors.json",
        module: CONSERVATIVE_MODULE,
        recipe: "terminal-suffix-discard",
        rows: SUFFIX_ENTIRE_TRUE,
    },
    EntireTrueFile {
        rel: "parity/recipes/side-effect-unknown-truncate/vectors.json",
        module: SALVAGE_MODULE,
        recipe: "side-effect-unknown-truncate",
        rows: TRUNCATE_ENTIRE_TRUE,
    },
    EntireTrueFile {
        rel: "parity/recipes/torn-compaction-project/vectors.json",
        module: SALVAGE_MODULE,
        recipe: "torn-compaction-project",
        rows: TORN_COMPACTION_ENTIRE_TRUE,
    },
    EntireTrueFile {
        rel: "parity/recipes/torn-record-excision/vectors.json",
        module: SALVAGE_MODULE,
        recipe: "torn-record-excision",
        rows: EXCISION_ENTIRE_TRUE,
    },
    EntireTrueFile {
        rel: "parity/recipes/unresolvable-branch-amputate/vectors.json",
        module: SALVAGE_MODULE,
        recipe: "unresolvable-branch-amputate",
        rows: AMPUTATE_ENTIRE_TRUE,
    },
];

const COVERED_PAIRS: &[(&str, &str)] = &[];

/// Strings that belong to the pinned tests and are absent from the cited
/// registration files.
const DOC_ABSENT: &[&str] = &[
    "docs/recipes",
    "RELEASING",
    "Recipe Catalog",
    "13 deterministic",
    "All 13 repair recipes",
    "assert_catalog_sync",
    "Missing conservative",
    "Unexpected conservative",
    "misclassified",
    "fake-conservative-recipe",
    "Non-Proof Statement",
    "Tested Fixture",
    "# Recipe:",
    "Handles Codes",
    "test_registry_docs",
    "test_recipes_directory_exists",
    "test_catalog_lock",
    "README.md",
    "Lossy",
    "Salvage Only",
];

const ROWS: &[Row] = &[
    Row {
        name: "test_recipes_directory_exists",
        disposition: Disposition::NotApplicable(
            "docs/recipes is_dir succeeds; python_dunder_all is public_name_list, the cited registration files have no entire_test field, and no cited vector checks that directory",
        ),
    },
    Row {
        name: "test_all_registered_recipes_have_docs",
        disposition: Disposition::NotApplicable(
            "after clear_registry and the three register_all calls, list_recipes asserts length 13, 7 with salvage_only false, and 6 with salvage_only true, then each docs/recipes name file exists; conservative register_all_idempotent is register_all recipe_count 7 for a module set that includes terminal-suffix-discard, salvage register_all_idempotent is recipe_count 5 and omits terminal-suffix-discard, sl002 register_all_idempotent lists only torn-terminal-record-discard, clear_registry_isolation restores synthetic-clear, and a recipe name list is not this doc sweep. The pin succeeds. GAP-repair-package-register-not-called is a Rust seam and is not coverage",
        ),
    },
    Row {
        name: "test_no_extra_or_stale_recipe_docs",
        disposition: Disposition::NotApplicable(
            "registered names equal the docs/recipes *.md stems excluding README.md; a doc-path scan is not registration_handles_matrix or registration_salvage_matrix, and these files have no entire_test field",
        ),
    },
    Row {
        name: "test_recipe_doc_structure_and_sections",
        disposition: Disposition::NotApplicable(
            "parametrized over list_recipes at decoration, each doc starts with the recipe H1 and contains Overview, Preconditions, Risk, Evidence, Non-Proof Statement, Loss Behavior, and Tested Fixture; one name inside registration_handles_matrix is not that sweep",
        ),
    },
    Row {
        name: "test_recipe_doc_fixture_reference_exists",
        disposition: Disposition::NotApplicable(
            "parametrized over list_recipes at decoration, the Tested Fixture Path must name a file on disk; fixture_terminal_suffix_discard is fixture_apply of apply_terminal_suffix_discard on fixtures/repair/recipe_suffix_discard.json, a different function, and one fixture inside the sweep is not the whole test",
        ),
    },
    Row {
        name: "test_recipe_doc_metadata_matches_registry",
        disposition: Disposition::NotApplicable(
            "parametrized over list_recipes at decoration, each doc Lossy, Salvage Only, and Handles Codes match that recipe; registration_handles_matrix, registration_salvage_matrix, and recipe_constant_snapshot are three name lists, and one example inside the sweep is not the whole test",
        ),
    },
    Row {
        name: "test_readme_recipe_catalog_matches_registry",
        disposition: Disposition::NotApplicable(
            "README.md contains 13 deterministic repair recipes, parse_readme_catalog reads the Recipe Catalog, and assert_catalog_sync succeeds; python_dunder_all is public_name_list, and a recipe name list is not that README parse",
        ),
    },
    Row {
        name: "test_recipes_readme_catalog_matches_registry",
        disposition: Disposition::NotApplicable(
            "docs/recipes/README.md contains 13 deterministic repair recipes, parse_recipes_readme_catalog reads name-only bullets, and assert_catalog_sync succeeds; a recipe name list is not that README parse",
        ),
    },
    Row {
        name: "test_releasing_checklist_recipe_count",
        disposition: Disposition::NotApplicable(
            "RELEASING.md contains the checklist line All 13 repair recipes have synced documentation; no cited vector reads that line",
        ),
    },
    Row {
        name: "test_catalog_lock_catches_missing_recipe",
        disposition: Disposition::NotApplicable(
            "assert_catalog_sync raises AssertionError matching Missing conservative recipes in test_doc when the fake conservative set is only identical-duplicate-collapse; registration_handles_matrix is registration_matrix mode comparable and does not raise, and one name inside the fake partition is not the whole test. Apply refusals of the named salvage recipes are different functions",
        ),
    },
    Row {
        name: "test_catalog_lock_catches_extra_recipe",
        disposition: Disposition::NotApplicable(
            "assert_catalog_sync raises AssertionError matching Unexpected conservative recipes in test_doc after fake-conservative-recipe is added; no cited vector records that name or that AssertionError",
        ),
    },
    Row {
        name: "test_catalog_lock_catches_misclassified_recipe",
        disposition: Disposition::NotApplicable(
            "assert_catalog_sync raises AssertionError matching Salvage recipes misclassified as conservative in test_doc after identical-duplicate-collapse and terminal-suffix-discard swap partitions; registration_handles_matrix records both names on the conservative module, with terminal-suffix-discard salvage_only true, and that success matrix is not this AssertionError. apply_terminal_suffix_discard is a different function",
        ),
    },
    Row {
        name: "test_catalog_lock_catches_mismatched_handled_codes",
        disposition: Disposition::NotApplicable(
            "assert_catalog_sync raises AssertionError matching that torn-terminal-record-discard in test_doc declares handled codes after those codes are set to SL005; recipe_constant_snapshot is mode recipe with handles SL002, recipe_lossy_sets_salvage_flags is recipe_try_new of lossy-conservative with SL005, and neither is assert_catalog_sync. SL005 is not a covered id",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_recipes_directory_exists",
    "test_all_registered_recipes_have_docs",
    "test_no_extra_or_stale_recipe_docs",
    "test_recipe_doc_structure_and_sections",
    "test_recipe_doc_fixture_reference_exists",
    "test_recipe_doc_metadata_matches_registry",
    "test_readme_recipe_catalog_matches_registry",
    "test_recipes_readme_catalog_matches_registry",
    "test_releasing_checklist_recipe_count",
    "test_catalog_lock_catches_missing_recipe",
    "test_catalog_lock_catches_extra_recipe",
    "test_catalog_lock_catches_misclassified_recipe",
    "test_catalog_lock_catches_mismatched_handled_codes",
];

const TOP_LEVEL_ID_PREFIX: &str = "\n      \"id\": \"";

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn manifest_rel(path: &Path) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(root)
        .unwrap_or_else(|_| panic!("vector path {} is outside the manifest", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
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

fn assert_absent(json: &str, label: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !json.contains(needle),
            "{label} unexpectedly contains {needle}"
        );
    }
}

fn assert_no_partition_counts(json: &str, label: &str) {
    assert!(
        !json.contains("\"recipe_count\": 13"),
        "{label} recipe_count 13"
    );
    assert!(
        !json.contains("\"recipe_count\": 6"),
        "{label} recipe_count 6"
    );
    assert!(!json.contains("entire_test"), "{label} entire_test");
}

fn read_vectors(rel: &str, module: &str, recipe: Option<&str>) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(json.contains(&format!("\"module\": \"{module}\"")), "{rel}");
    if let Some(recipe) = recipe {
        assert!(json.contains(&format!("\"recipe\": \"{recipe}\"")), "{rel}");
    }
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

fn object_span<'a>(slice: &'a str, name: &str, next: &str) -> &'a str {
    let key = format!("\"{name}\": {{");
    let start = slice
        .find(&key)
        .unwrap_or_else(|| panic!("missing object {name}"));
    let after = start + key.len();
    let next_key = format!("\"{next}\": {{");
    let end = slice[after..]
        .find(&next_key)
        .map(|offset| after + offset)
        .unwrap_or_else(|| panic!("missing object {next}"));
    &slice[start..end]
}

fn assert_names(slice: &str, label: &str, names: &[&str]) {
    for name in names {
        assert!(slice.contains(name), "{label} is missing {name}");
    }
}

fn collect_vector_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display())) {
        let entry = entry.unwrap_or_else(|err| panic!("read entry in {}: {err}", dir.display()));
        entries.push(entry.path());
    }
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_vector_files(&path, out);
        } else if path.file_name() == Some(OsStr::new("vectors.json")) {
            out.push(path);
        }
    }
}

fn assert_entire_true_file(file: &EntireTrueFile) {
    let json = read_vectors(file.rel, file.module, Some(file.recipe));
    assert_eq!(
        json.matches("\"entire_test\": true").count(),
        file.rows.len(),
        "{}",
        file.rel
    );
    for &(id, construct, function) in file.rows {
        let slice = vector_slice(&json, id);
        assert!(
            slice.contains(&format!("\"type\": \"{construct}\"")),
            "{} {id}",
            file.rel
        );
        assert!(
            slice.contains(&format!("\"fn\": \"{function}\"")),
            "{} {id}",
            file.rel
        );
        assert_eq!(
            slice.matches("\"entire_test\": true").count(),
            1,
            "{} {id}",
            file.rel
        );
        assert!(
            !slice.contains("\"fn\": \"list_recipes\""),
            "{} {id}",
            file.rel
        );
        assert!(
            !slice.contains("\"fn\": \"assert_catalog_sync\""),
            "{} {id}",
            file.rel
        );
        assert!(!slice.contains("docs/recipes"), "{} {id}", file.rel);
        assert!(
            function.starts_with("apply_") || function == "sl001_excisable",
            "{} {id}",
            file.rel
        );
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_registry_doc_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REGISTRY_VECTORS.len(), REGISTRY_VECTOR_COUNT);
    assert_eq!(REPAIR_VECTORS.len(), REPAIR_VECTOR_COUNT);
    assert_eq!(CONSERVATIVE_VECTORS.len(), CONSERVATIVE_VECTOR_COUNT);
    assert_eq!(SALVAGE_VECTORS.len(), SALVAGE_VECTOR_COUNT);
    assert_eq!(SL002_VECTORS.len(), SL002_VECTOR_COUNT);
    assert_eq!(CONSERVATIVE_FNS.len(), 9);
    assert_eq!(CONSERVATIVE_MATRIX_NAMES.len(), 7);
    assert_eq!(SALVAGE_MATRIX_NAMES.len(), 5);
    assert_eq!(COVERED_PAIRS.len(), COVERED_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    let mut covered_ids = BTreeSet::new();
    let mut covered_pairs = Vec::new();
    for row in ROWS {
        assert!(
            names.insert(row.name),
            "duplicate pinned test name {}",
            row.name
        );
        match row.disposition {
            Disposition::Covered { vector_id, needles } => {
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert_ne!(vector_id, "SL001", "{}", row.name);
                assert_ne!(vector_id, "SL002", "{}", row.name);
                assert_ne!(vector_id, "SL005", "{}", row.name);
                assert!(!needles.is_empty(), "{}", row.name);
                assert!(
                    needles
                        .iter()
                        .any(|needle| needle.starts_with("\"type\": \"")),
                    "{} covered row is missing a construct type needle",
                    row.name
                );
                assert!(
                    needles.contains(&"\"entire_test\": true"),
                    "{} covered row is missing entire_test",
                    row.name
                );
                assert!(
                    needles.contains(&"\"assert_count\": 1"),
                    "{} covered row is missing assert_count",
                    row.name
                );
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                covered_pairs.push((row.name, vector_id));
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
    assert_eq!(covered, COVERED_COUNT);
    assert_eq!(not_applicable, PINNED_TEST_COUNT - COVERED_COUNT);
    assert_eq!(covered_pairs.as_slice(), COVERED_PAIRS);
}

#[test]
fn cited_registry_doc_vectors_are_not_entire_pin_tests() {
    let registry = read_vectors(REGISTRY_REL, REGISTRY_MODULE, None);
    assert_top_level_catalog(&registry, "registry", REGISTRY_VECTORS);
    assert_no_partition_counts(&registry, "registry");
    assert_absent(&registry, "registry", DOC_ABSENT);
    assert!(!registry.contains("\"fn\":"), "registry");
    let exports = vector_slice(&registry, "module_all_export_order");
    assert!(exports.contains("\"type\": \"module_all\""));
    assert!(exports.contains("\"list_recipes\""));
    assert!(exports.contains("\"clear_registry\""));
    assert!(!exports.contains("register_all_conservative_recipes"));
    let cleared = vector_slice(&registry, "clear_registry_isolation");
    assert!(cleared.contains("\"type\": \"clear_registry\""));
    assert!(cleared.contains("\"mode\": \"cleared\""));
    assert!(cleared.contains("\"name\": \"synthetic-clear\""));
    assert!(cleared.contains("\"before\": 1"));
    assert!(cleared.contains("\"after\": 0"));
    assert!(!cleared.contains("register_all"));
    let lossy = vector_slice(&registry, "recipe_lossy_sets_salvage_flags");
    assert!(lossy.contains("\"type\": \"recipe_try_new\""));
    assert!(lossy.contains("\"name\": \"lossy-conservative\""));
    assert!(lossy.contains("\"SL005\""));
    assert!(lossy.contains("\"salvage_only\": true"));
    assert!(lossy.contains("\"mode\": \"recipe\""));
    assert!(!lossy.contains("torn-terminal-record-discard"));
    let lookup = vector_slice(&registry, "planner_registry_registration_and_lookup");
    assert!(lookup.contains("\"type\": \"registration_lookup\""));
    assert!(lookup.contains("\"list_names\""));
    assert!(lookup.contains("stub-clean-1"));
    assert!(!lookup.contains("terminal-suffix-discard"));

    let repair = read_vectors(REPAIR_REL, REPAIR_MODULE, None);
    assert_top_level_catalog(&repair, "repair", REPAIR_VECTORS);
    assert_no_partition_counts(&repair, "repair");
    assert_absent(&repair, "repair", DOC_ABSENT);
    assert!(!repair.contains("\"fn\":"), "repair");
    assert!(repair.contains("GAP-repair-package-register-not-called"));
    let names = vector_slice(&repair, "python_dunder_all");
    assert!(names.contains("\"type\": \"public_name_list\""));
    assert!(names.contains("\"list_recipes\""));
    assert!(names.contains("\"clear_registry\""));
    assert!(names.contains("\"register_all_conservative_recipes\""));
    assert!(names.contains("\"register_all_salvage_recipes\""));
    assert!(names.contains("\"register_all_sl002_recipes\""));
    assert!(!names.contains("\"type\": \"register_all\""));
    assert!(!names.contains("docs/recipes"));

    let conservative = read_vectors(CONSERVATIVE_REL, CONSERVATIVE_MODULE, None);
    assert_top_level_catalog(&conservative, "conservative", CONSERVATIVE_VECTORS);
    assert_no_partition_counts(&conservative, "conservative");
    assert_absent(&conservative, "conservative", DOC_ABSENT);
    assert_absent(
        &conservative,
        "conservative",
        &["torn-terminal-record-discard", "orphan-result-drop"],
    );
    assert_eq!(
        conservative.matches("\"recipe_count\": 7").count(),
        2,
        "conservative"
    );
    assert_eq!(
        conservative.matches("\"salvage_only\": true").count(),
        1,
        "conservative"
    );
    let matrix = vector_slice(&conservative, "registration_handles_matrix");
    assert!(matrix.contains("\"type\": \"registration_matrix\""));
    assert!(matrix.contains("\"recipe_count\": 7"));
    assert_names(matrix, "conservative matrix", CONSERVATIVE_MATRIX_NAMES);
    let suffix = object_span(
        matrix,
        "terminal-suffix-discard",
        "identical-duplicate-collapse",
    );
    assert!(suffix.contains("\"SL005\""));
    assert!(suffix.contains("\"salvage_only\": true"));
    assert!(!suffix.contains("\"salvage_only\": false"));
    let collapse = object_span(
        matrix,
        "identical-duplicate-collapse",
        "proven-unique-parent-restore",
    );
    assert!(collapse.contains("\"salvage_only\": false"));
    let register_cons = vector_slice(&conservative, "register_all_idempotent");
    assert!(register_cons.contains("\"type\": \"register_all\""));
    assert!(register_cons.contains("\"recipe_count\": 7"));
    assert!(!register_cons.contains("terminal-suffix-discard"));
    assert!(!register_cons.contains("torn-terminal-record-discard"));
    let fixture = vector_slice(&conservative, "fixture_terminal_suffix_discard");
    assert!(fixture.contains("\"type\": \"fixture_apply\""));
    assert!(fixture.contains("\"fn\": \"apply_terminal_suffix_discard\""));
    assert!(fixture.contains("fixtures/repair/recipe_suffix_discard.json"));
    for &(id, function) in CONSERVATIVE_FNS {
        let slice = vector_slice(&conservative, id);
        assert!(
            slice.contains(&format!("\"fn\": \"{function}\"")),
            "conservative {id}"
        );
        assert!(
            !slice.contains("\"entire_test\": true"),
            "conservative {id}"
        );
    }
    for id in [
        "module_all_export_order",
        "registration_handles_matrix",
        "register_all_idempotent",
    ] {
        assert!(
            !vector_slice(&conservative, id).contains("\"fn\":"),
            "conservative {id}"
        );
    }

    let salvage = read_vectors(SALVAGE_REL, SALVAGE_MODULE, None);
    assert_top_level_catalog(&salvage, "salvage", SALVAGE_VECTORS);
    assert_no_partition_counts(&salvage, "salvage");
    assert_absent(&salvage, "salvage", DOC_ABSENT);
    assert!(!salvage.contains("\"fn\":"), "salvage");
    assert_absent(
        &salvage,
        "salvage",
        &[
            "terminal-suffix-discard",
            "identical-duplicate-collapse",
            "torn-terminal-record-discard",
        ],
    );
    assert_eq!(salvage.matches("\"recipe_count\": 5").count(), 2, "salvage");
    assert_eq!(
        salvage.matches("\"salvage_only\": true").count(),
        5,
        "salvage"
    );
    let salvage_matrix = vector_slice(&salvage, "registration_salvage_matrix");
    assert!(salvage_matrix.contains("\"type\": \"registration_matrix\""));
    assert!(salvage_matrix.contains("\"recipe_count\": 5"));
    assert_names(salvage_matrix, "salvage matrix", SALVAGE_MATRIX_NAMES);
    let register_salv = vector_slice(&salvage, "register_all_idempotent");
    assert!(register_salv.contains("\"type\": \"register_all\""));
    assert!(register_salv.contains("\"recipe_count\": 5"));
    assert!(!register_salv.contains("orphan-result-drop"));
    assert!(vector_slice(&salvage, "sl001_excisable_precondition")
        .contains("\"type\": \"sl001_excisable_precondition\""));

    let sl002 = read_vectors(SL002_REL, SL002_MODULE, None);
    assert_top_level_catalog(&sl002, "sl002", SL002_VECTORS);
    assert_no_partition_counts(&sl002, "sl002");
    assert_absent(&sl002, "sl002", DOC_ABSENT);
    assert!(!sl002.contains("\"fn\":"), "sl002");
    assert!(!sl002.contains("SL005"), "sl002");
    assert_eq!(sl002.matches("SL002").count(), 1, "sl002");
    assert_eq!(
        sl002.matches("torn-terminal-record-discard").count(),
        2,
        "sl002"
    );
    assert_absent(
        &sl002,
        "sl002",
        &[
            "terminal-suffix-discard",
            "identical-duplicate-collapse",
            "orphan-result-drop",
        ],
    );
    let sl002_exports = vector_slice(&sl002, "module_all_export_order");
    assert!(sl002_exports.contains("\"type\": \"module_all\""));
    assert!(sl002_exports.contains("register_all"));
    assert!(sl002_exports.contains("apply_torn_terminal_record_discard"));
    let snapshot = vector_slice(&sl002, "recipe_constant_snapshot");
    assert!(snapshot.contains("\"type\": \"recipe_constant\""));
    assert!(snapshot.contains("\"mode\": \"recipe\""));
    assert!(snapshot.contains("\"name\": \"torn-terminal-record-discard\""));
    assert!(snapshot.contains("\"SL002\""));
    assert!(snapshot.contains("\"lossy\": false"));
    assert!(snapshot.contains("\"salvage_only\": false"));
    assert!(!snapshot.contains("SL005"));
    let register_sl002 = vector_slice(&sl002, "register_all_idempotent");
    assert!(register_sl002.contains("\"type\": \"register_all\""));
    assert!(register_sl002.contains("\"mode\": \"registered\""));
    assert!(register_sl002.contains("\"list_names\""));
    assert!(register_sl002.contains("torn-terminal-record-discard"));
    assert!(!register_sl002.contains("recipe_count"));
    assert!(vector_slice(&sl002, "apply_discards_named_last_event").contains("\"type\": \"apply\""));

    let cited = [
        registry.as_str(),
        repair.as_str(),
        conservative.as_str(),
        salvage.as_str(),
        sl002.as_str(),
    ];
    for json in cited {
        assert!(!json.contains("\"fn\": \"list_recipes\""));
        assert!(!json.contains("\"fn\": \"assert_catalog_sync\""));
        assert!(!json.contains("\"fn\": \"execute\""));
    }

    let mut entire_true_total = 0usize;
    let mut entire_true_rels = BTreeSet::new();
    for file in ENTIRE_TRUE_FILES {
        assert!(entire_true_rels.insert(file.rel), "duplicate {}", file.rel);
        assert!(!file.rows.is_empty(), "{}", file.rel);
        entire_true_total += file.rows.len();
        assert_entire_true_file(file);
    }
    assert_eq!(entire_true_total, 9);

    let mut published = Vec::new();
    collect_vector_files(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parity"),
        &mut published,
    );
    assert!(!published.is_empty());
    let mut saw_entire_true = BTreeSet::new();
    for path in &published {
        let json =
            fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let rel = manifest_rel(path);
        assert!(
            !json.contains("tests/test_registry_docs.py"),
            "{rel} names the pinned module"
        );
        let count = json.matches("\"entire_test\": true").count();
        if count == 0 {
            continue;
        }
        let file = ENTIRE_TRUE_FILES
            .iter()
            .find(|file| file.rel == rel)
            .unwrap_or_else(|| panic!("unexpected entire_test file {rel}"));
        assert_eq!(count, file.rows.len(), "{rel}");
        assert!(saw_entire_true.insert(rel));
    }
    assert_eq!(saw_entire_true.len(), ENTIRE_TRUE_FILES.len());

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let marker = format!("{TOP_LEVEL_ID_PREFIX}{vector_id}\"");
        let mut found = false;
        for json in cited {
            if !json.contains(&marker) {
                continue;
            }
            found = true;
            let slice = vector_slice(json, vector_id);
            assert_eq!(
                slice.matches("\"entire_test\": true").count(),
                1,
                "{}",
                row.name
            );
            for needle in needles {
                assert!(
                    slice.contains(needle),
                    "{} vector {vector_id} is missing {needle}",
                    row.name
                );
            }
        }
        assert!(found, "{} cites missing vector {vector_id}", row.name);
    }
}
