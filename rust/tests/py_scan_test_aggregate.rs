//! Dispositions for the three `def test_` functions in pinned
//! `tests/scan/test_aggregate.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (66 splitlines). The module
//! covers TASK-024: recursive scan aggregate five-bucket totals, mixed-fixture
//! CLI JSON scan exit code 1, and default recursive directory check on an empty
//! temp dir. This integration test crate links `sesslint-rust-workspace`, whose
//! library exports [`PACKAGE_NAME`] only. It cannot call `sesslint.api.check_dir`,
//! `sesslint.cli.main`, or scan helpers without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 3;
const PINNED_SPLITLINES: usize = 66;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. One bucket count is not the whole pytest. `not_applicable` names the
/// missing stop.
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
        name: "test_aggregate_5_bucket_partitioning",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_aggregate_5_bucket_partitioning calling sesslint.api.check_dir on fixtures/scan/mixed with recursive True asserting ScanReport totals healthy invalid unsupported and unreadable each at least one sum of those four plus skipped equals totals.total totals.total equals len report files and per-file verdict set contains healthy invalid unsupported and unreadable; cli vectors record parser shells removed-command hints removed-flag hints check exit epilog constants verbose settings and main on removed subcommands only not api.check_dir recursive five-bucket partition on mixed fixtures; one bucket count or check_exit_lines note is not that entire integration row; sesslint.api.check_dir is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_scan_mixed_dir_exit_code_1",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_mixed_dir_exit_code_1 calling sesslint.cli.main with check fixtures/scan/mixed --json asserting exit code one parsed stdout json schema_version sesslint.scan-report/v1 totals.total equals len files healthy invalid unsupported unreadable each at least one; cli main vectors are main_removed_formats baseline validate_session init_hooks and formats json with exit two only not check on mixed directory json scan with findings exit one; check_exit_constants vectors document exit code semantics not a mixed-dir scan report; parser probes and bare exit-code vectors are not this mixed-directory JSON scan; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_cli_check_directory_is_recursive_by_default",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_check_directory_is_recursive_by_default calling sesslint.cli.main with check on empty pytest tmp_path directory with no recursive flag asserting exit code zero after readouterr; removed_flag_hint_recursive_short and removed_flag_hint_recursive_long vectors assert hint text when argv contains -r or --recursive not main check success on an empty temporary directory; help vectors and missing-path probes are not this empty-directory check; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_aggregate_5_bucket_partitioning",
    "test_cli_scan_mixed_dir_exit_code_1",
    "test_cli_check_directory_is_recursive_by_default",
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
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
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
fn pinned_scan_test_aggregate_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 66);
}

#[test]
fn pinned_scan_test_aggregate_row_count_equals_three() {
    assert_eq!(ROWS.len(), 3);
    assert_eq!(PINNED_TEST_COUNT, 3);
}

#[test]
fn every_pinned_scan_test_aggregate_test_has_one_disposition() {
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
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_cli_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
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
