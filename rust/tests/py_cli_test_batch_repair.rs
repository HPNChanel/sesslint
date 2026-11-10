//! Dispositions for the fourteen `def test_` functions in pinned
//! `tests/cli/test_batch_repair.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (255 splitlines). Exactly
//! fourteen test functions, in module order. One is parametrized,
//! `test_batch_usage_errors`, with five cells. That function is one row
//! covering every cell. The helpers `_tree` and `_sha` are not tests. Each
//! row is the whole function. `repair_many` is not the CLI. A CLI exit is not
//! a report count. A comment is not an assertion. Fixture bytes and session
//! lines are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these fourteen functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these fourteen functions.
//! `parity/vectors/batch/vectors.json` has sixteen ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `batch_row_to_dict_bare`,
//! `batch_row_to_dict_empty_reason`, `batch_row_to_dict_codes_sorted`,
//! `batch_row_to_dict_optional_fields`, `render_human_empty_reason`,
//! `render_human_with_reason`, `output_for_default_suffix`,
//! `output_for_no_suffix`, `output_for_dotted_suffix`,
//! `output_for_double_extension`, `output_for_relative_mirror`,
//! `repair_many_gap`, `plan_detail_gap`, `resolve_scan_report_files_gap`,
//! `load_batch_schema_gap`, and `get_batch_schema_path`. That old pin is not
//! a Covered source. `resolve_scan_report_files_gap` is not the two-path
//! resolver pytest. `repair_many_gap` is not the mixed-tree pytest. There is
//! no scan.batch corpus. Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call cli, batch, or api functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 14;
const PINNED_SPLITLINES: usize = 255;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `repair_many` is not the CLI. A CLI exit is not a
/// report count. A comment is not an assertion. All five cells of
/// `test_batch_usage_errors` are one row. `not_applicable` names the missing
/// stop and the nearest different test.
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
        name: "test_batch_dir_repairs_only_eligible",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_dir_repairs_only_eligible: repair_many reports repaired 2, skipped 2, both repaired outputs exist, and the outcome set is exactly repaired and skipped; missing stop: that repaired 2, that skipped 2, both repaired outputs, and that outcome set together; All of that is one row; It does not assert the garbage bytes; A comment is not an assertion; repair_many is not the CLI; A CLI exit is not a report count; The CLI mirror test asserts an exit code and is not this call; test_batch_cli_mirrors_structure_and_manifest_dir is that CLI",
        ),
    },
    Row {
        name: "test_batch_cli_mirrors_structure_and_manifest_dir",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_cli_mirrors_structure_and_manifest_dir: the CLI exits 1, both repaired outputs exist, there are two manifests, and each manifest contains output_fingerprint; missing stop: that exit 1, both repaired outputs, those two manifests, and that output_fingerprint key together; It does not assert the fingerprint value; The all-eligible CLI exits 0 and is not this pytest; test_batch_cli_all_eligible_exit_zero is that pytest",
        ),
    },
    Row {
        name: "test_batch_cli_all_eligible_exit_zero",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_cli_all_eligible_exit_zero: the CLI exits 0 and stdout contains 1 repaired; missing stop: that exit 0 and that stdout fragment together; It does not assert that an output file exists; The mixed directory CLI is not this pytest; test_batch_cli_mirrors_structure_and_manifest_dir is that pytest",
        ),
    },
    Row {
        name: "test_batch_files_mode_flat",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_files_mode_flat: the CLI exits 0, the two repaired names are flat, and the first repaired file has an adjacent manifest; missing stop: that exit 0, those two flat names, and that adjacent manifest together; It does not assert the second manifest; The nested directory output is not this pytest; test_batch_cli_mirrors_structure_and_manifest_dir is that pytest",
        ),
    },
    Row {
        name: "test_batch_dry_run_preview_no_writes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_dry_run_preview_no_writes: the CLI exits 1, the output directory does not exist, and stdout contains eligible; missing stop: that exit 1, that output directory that does not exist, and that stdout fragment together; All three are one row; The comment about the skipped files is not an extra assertion; A comment is not an assertion; The writing CLI is not this pytest; test_batch_cli_mirrors_structure_and_manifest_dir is that pytest",
        ),
    },
    Row {
        name: "test_batch_from_scan_report",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_from_scan_report: the CLI exits 1 and the repaired output for the resolvable file exists; missing stop: that exit 1 and that repaired output together; It does not assert the unresolvable reason; A comment is not an assertion; The resolver test is not this CLI; test_resolve_scan_report_files is that resolver",
        ),
    },
    Row {
        name: "test_resolve_scan_report_files",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_resolve_scan_report_files: two paths resolve and the unresolvable list is exactly the hashed ghost path .._aabbccdd/z.jsonl; missing stop: that resolved count of 2 and that unresolvable list together; Both are one row; It does not assert the resolved path strings; resolve_scan_report_files_gap is not this pytest; The from-scan CLI is not this resolver; test_batch_from_scan_report is that CLI",
        ),
    },
    Row {
        name: "test_batch_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_deterministic: the row dictionaries are equal after removing output and manifest, and the file-name hashes are equal; missing stop: both equalities together; Both equalities are one row; The comment about destination directories is not a separate assertion; A comment is not an assertion; It does not assert the hash values; repair_many is not the CLI; The mixed-tree count test is not this pytest; test_batch_dir_repairs_only_eligible is that pytest",
        ),
    },
    Row {
        name: "test_batch_json_summary_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_json_summary_shape: the CLI exits 1, the version is sesslint.batch-repair/v1, the counts are attempted 2, repaired 2, refused 0, and skipped 2, every row outcome is repaired or skipped, and the word payload is absent from every row dump; missing stop: that exit 1, that version, those counts, every row outcome, and that absent word together; All of that is one row; The API count test is not this CLI; test_batch_report_counts is that count test",
        ),
    },
    Row {
        name: "test_batch_usage_errors",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_usage_errors: all five cells exit 2, and each cell's stderr contains its fragment: cannot be combined, --output-dir, --output-dir, single-file, and single-file; missing stop: those five exits and those five fragments together; All five cells are one row; The bare-repair test uses different arguments and is not this pytest; test_repair_no_source_is_usage_error is that bare repair; The two-file test uses different arguments and is not this pytest; test_repair_multi_path_without_output_dir_is_usage_error is that two-file test",
        ),
    },
    Row {
        name: "test_repair_no_source_is_usage_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_no_source_is_usage_error: bare repair exits 2 and stderr contains source path; missing stop: that exit 2 and that stderr fragment together; The five-cell test is not this pytest; test_batch_usage_errors is that five-cell test",
        ),
    },
    Row {
        name: "test_repair_multi_path_without_output_dir_is_usage_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_multi_path_without_output_dir_is_usage_error: two named files without an output directory exit 2 and stderr contains --output-dir; missing stop: that exit 2 and that stderr fragment together; The five-cell test uses different names and is not this pytest; test_batch_usage_errors is that five-cell test",
        ),
    },
    Row {
        name: "test_batch_report_counts",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_batch_report_counts: a missing source has skipped 1, attempted 0, and reason source-missing; missing stop: that skipped 1, that attempted 0, and that reason together; All three are one row; repair_many is not the CLI; A CLI exit is not a report count; The mixed tree has skipped 2 and is not this pytest; test_batch_dir_repairs_only_eligible is that mixed tree",
        ),
    },
    Row {
        name: "test_api_repair_many_exported",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_repair_many_exported: api.repair_many is present, repair_many is in the public list, and BatchRepairReport is in the public list; missing stop: that presence and both public-list memberships together; All three are one row; It does not call the function; The count test is not this pytest; test_batch_report_counts is that count test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_batch_dir_repairs_only_eligible",
    "test_batch_cli_mirrors_structure_and_manifest_dir",
    "test_batch_cli_all_eligible_exit_zero",
    "test_batch_files_mode_flat",
    "test_batch_dry_run_preview_no_writes",
    "test_batch_from_scan_report",
    "test_resolve_scan_report_files",
    "test_batch_deterministic",
    "test_batch_json_summary_shape",
    "test_batch_usage_errors",
    "test_repair_no_source_is_usage_error",
    "test_repair_multi_path_without_output_dir_is_usage_error",
    "test_batch_report_counts",
    "test_api_repair_many_exported",
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

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_cli_test_batch_repair_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 255);
}

#[test]
fn pinned_cli_test_batch_repair_row_count_equals_fourteen() {
    assert_eq!(ROWS.len(), 14);
    assert_eq!(PINNED_TEST_COUNT, 14);
    assert_eq!(PINNED_NAMES.len(), 14);
}

#[test]
fn every_pinned_cli_test_batch_repair_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 14);
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
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
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
    assert_eq!(not_applicable, 14);

    let json = read_vectors(API_VECTORS_REL);
    // `parity/vectors/api/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "api vectors python_commit spacing does not match {needle}"
    );
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
