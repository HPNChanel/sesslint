//! Dispositions for the sixteen test functions in pinned
//! `tests/test_api_surface.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (462 splitlines). Exactly
//! sixteen test functions, in module order. One is parametrized:
//! `test_threshold_validation_identical_across_paths` covers eight cells and
//! is one row, not eight. Each row is the whole function. A docstring is not
//! an assertion. A comment is not an assertion. Helpers
//! `_patch_detector_scores` and `_copy_healthy` are not tests.
//! `FIXTURES_ROOT`, `HEALTHY_FIXTURE`, `POLYGLOT_FIXTURE`, `SCAN_DIR`, and
//! `VERIFY_DIR` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these sixteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these sixteen names. An API vector that calls one
//! function is not this whole pytest.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. None of those ids is one of
//! these tests. That old pin is not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `check_file`, `check_dir`,
//! `scan_path`, `repair`, `plan`, `verify`, `build_bundle`, or `precheck`
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 16;
const PINNED_SPLITLINES: usize = 462;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. One of these sixteen functions is parametrized and is
/// still one row. Each row is the whole function. A docstring is not an
/// assertion. A comment is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// An API vector that calls one function is not this whole pytest and is not
/// a Covered source.
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
        name: "test_api_module_exports",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_module_exports: Bundle, PrecheckReason, PrecheckResult, ScanReport, VerifyVerdict, build_bundle, build_internal_error_envelope, check, check_dir, check_file, plan, precheck, repair, validate_session, and verify are a subset of api.__all__ and each is an attribute, and VerifyVerdict is Verdict; missing stop: that subset, those attributes, and that alias together; The check_file contract is not this; test_check_file_contract is that check_file contract",
        ),
    },
    Row {
        name: "test_check_file_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_contract: a path returns a Report whose session id is present, whose assurance is one of A0, A1, A2, A3, or A4, and whose counts are present; the same path as a string returns a Report with that same session id; format canonical returns a Report; profile neutral returns a Report; a missing path raises FileNotFoundError; missing stop: those reports, that session id, that assurance, those counts, and that FileNotFoundError together; The export surface is not this; test_api_module_exports is that export surface",
        ),
    },
    Row {
        name: "test_check_file_purity",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_purity: captured stdout is empty and captured stderr is empty; missing stop: that empty stdout and that empty stderr together; The directory contract is not this; test_check_dir_contract is that directory contract",
        ),
    },
    Row {
        name: "test_check_dir_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_dir_contract: a recursive directory scan is a ScanReport whose total is greater than zero, whose healthy total is at least zero, whose invalid total is at least zero, and whose files are a tuple; a scan with max_files 2, max_bytes 10000, and recursive true is a ScanReport; recursive false raises ValueError; a missing directory raises FileNotFoundError; missing stop: that report, those totals, that tuple, that bounded report, that ValueError, and that FileNotFoundError together; The purity test is not this; test_check_file_purity is that purity test",
        ),
    },
    Row {
        name: "test_repair_and_plan_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_and_plan_contract: plan returns a RepairPlan whose profile is neutral and whose step count is greater than zero; dry_run returns a RepairPlan and a manifest that is None; a non-dry repair returns a RepairPlan, a manifest that is not None, and an existing output file; a non-dry repair with no output path raises ValueError; a missing source raises FileNotFoundError; a vendor source returns a manifest that is not None, whose adapter id is claude-code-jsonl, and an existing output file; emit vendor raises VendorRepairRefused; missing stop: that plan, that None manifest, that written output, those two exceptions, and that vendor manifest together; The directory contract is not this; test_check_dir_contract is that directory contract",
        ),
    },
    Row {
        name: "test_verify_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_contract: verify returns a Verdict whose ok is true and whose to_json value is a string; missing stop: that verdict, that ok flag, and that string together; The bundle contract is not this; test_build_bundle_contract is that bundle contract",
        ),
    },
    Row {
        name: "test_build_bundle_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_build_bundle_contract: build_bundle returns a Bundle whose bundle_version is sesslint.bundle/v1, whose source path equals the input file name, whose source sha256 is a string of length 64, whose source size is an int greater than zero, whose created_by tool is sesslint, whose dict contains report and fixture_skeleton, and whose to_json value is a string; missing stop: that bundle, that version, that path, that digest, that size, that tool, those keys, and that string together; The precheck contract is not this; test_precheck_contract is that precheck contract",
        ),
    },
    Row {
        name: "test_precheck_contract",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_precheck_contract: a present file is a PrecheckResult that is ok, reason clean, exit code 0, and a Report; a missing path is a PrecheckResult that is not ok, reason io-error, exit code 2, and a report that is None; an unknown profile is a PrecheckResult that is not ok, reason usage-error, exit code 2, and a report that is None; an ambiguous file is a PrecheckResult that is not ok, reason detection-failed, exit code 1, a Report at assurance A0, a limitation that names an undetected format, and performed coverage that is empty; missing stop: those four results together; The bundle contract is not this; test_build_bundle_contract is that bundle contract",
        ),
    },
    Row {
        name: "test_api_numeric_range_validation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_numeric_range_validation: for 0, -1, -500, True, and False, check_dir and scan_path each raise ValueError for max_files and for max_bytes; for 0.0, 1.0, -0.5, 1.5, nan, inf, True, and False, check_file and build_bundle each raise ValueError for confidence_min and for margin_min; missing stop: those integer rejects and those float rejects together; The precheck contract is not this; test_precheck_contract is that precheck contract",
        ),
    },
    Row {
        name: "test_check_file_threshold_override_reports_undetected_input_honestly",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_threshold_override_reports_undetected_input_honestly: the default check_file report has no finding whose code is SL302, and the check_file report at confidence_min 0.70 has assurance A0, a limitation that names an undetected format, findings empty, performed coverage empty, and skipped coverage truthy; missing stop: that absent SL302 and those strict fields together; The directory threshold classification is not this; test_check_dir_threshold_override_marks_undetected_files_unsupported is that directory threshold classification",
        ),
    },
    Row {
        name: "test_check_dir_threshold_override_marks_undetected_files_unsupported",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_dir_threshold_override_marks_undetected_files_unsupported: the default directory totals are healthy 2 and invalid 0, and the directory at confidence_min 0.70 has invalid 0 and unsupported 2, and every file has verdict unsupported, findings empty, and detected format None; missing stop: those default totals, those strict totals, and those file fields together; The file threshold report is not this; test_check_file_threshold_override_reports_undetected_input_honestly is that file threshold report",
        ),
    },
    Row {
        name: "test_scan_path_resolves_effective_config_once",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_path_resolves_effective_config_once: a recursive scan of three files has healthy 3 and resolve_effective_config is called once; missing stop: that healthy total and that one call together; The directory threshold classification is not this; test_check_dir_threshold_override_marks_undetected_files_unsupported is that directory threshold classification",
        ),
    },
    Row {
        name: "test_check_unified_forwards_thresholds_to_dir",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_unified_forwards_thresholds_to_dir: check at confidence_min 0.70 returns a ScanReport whose invalid total is 0, whose unsupported total is 1, and whose first file verdict is unsupported; missing stop: that report, those totals, and that verdict together; The eight-cell validation is not this; test_threshold_validation_identical_across_paths is that eight-cell validation",
        ),
    },
    Row {
        name: "test_threshold_validation_identical_across_paths",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_threshold_validation_identical_across_paths: this row covers all eight cells True, the string 0.7, nan, inf, 0.0, 1.0, -0.1, and 1.1, and each cell raises ValueError on check_file, check_dir, and scan_path, and each cell raises ValueError on build_bundle; missing stop: those eight cells and those ValueError raises together; The unified directory check is not this; test_check_unified_forwards_thresholds_to_dir is that unified directory check",
        ),
    },
    Row {
        name: "test_repair_performs_single_detection_with_profile_thresholds",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_performs_single_detection_with_profile_thresholds: the first repair records one detection whose confidence_min is 0.55 and whose margin_min is 0.15, and after that list is cleared the repair with profile claude-strict records one detection whose margin_min is 0.20; missing stop: that first count, those two first thresholds, that second count, and that second margin together; The eight-cell validation is not this; test_threshold_validation_identical_across_paths is that eight-cell validation",
        ),
    },
    Row {
        name: "test_repair_detection_call_count_exactly_once",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_detection_call_count_exactly_once: the detect_format counter equals 1; missing stop: that one call together; The profile threshold detection is not this; test_repair_performs_single_detection_with_profile_thresholds is that profile threshold detection",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_api_module_exports",
    "test_check_file_contract",
    "test_check_file_purity",
    "test_check_dir_contract",
    "test_repair_and_plan_contract",
    "test_verify_contract",
    "test_build_bundle_contract",
    "test_precheck_contract",
    "test_api_numeric_range_validation",
    "test_check_file_threshold_override_reports_undetected_input_honestly",
    "test_check_dir_threshold_override_marks_undetected_files_unsupported",
    "test_scan_path_resolves_effective_config_once",
    "test_check_unified_forwards_thresholds_to_dir",
    "test_threshold_validation_identical_across_paths",
    "test_repair_performs_single_detection_with_profile_thresholds",
    "test_repair_detection_call_count_exactly_once",
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
fn pinned_test_api_surface_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 462);
}

#[test]
fn pinned_test_api_surface_row_count_equals_sixteen() {
    assert_eq!(ROWS.len(), 16);
    assert_eq!(PINNED_TEST_COUNT, 16);
    assert_eq!(PINNED_NAMES.len(), 16);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_api_surface_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 16);
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
    assert_eq!(not_applicable, 16);

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
