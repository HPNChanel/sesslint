//! Dispositions for the twenty-two test functions in pinned
//! `tests/scan/test_incremental.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (311 splitlines). Exactly
//! twenty-two test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helpers `_build_tree`, `_files`, and `_strip_markers` are
//! not tests. `FIXTURES_DIR` and `HEALTHY` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these twenty-two names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these twenty-two names.
//! `parity/vectors/cache/vectors.json` has no `vectors` array at this pin.
//! Its case ids are not these twenty-two names. A cache case is not a
//! Covered source.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. None of those ids is one of
//! these tests. That old pin is not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `scan_path`, `check_dir`,
//! `ScanCache`, `analysis_fingerprint`, `default_cache_dir`, or `main`
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 22;
const PINNED_SPLITLINES: usize = 311;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these twenty-two functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A cache case is not these pytests and is not a Covered source.
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
        name: "test_cold_incremental_byte_identical_to_plain",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cold_incremental_byte_identical_to_plain: the incremental JSON equals the plain JSON; missing stop: that equal JSON together; The warm hit test is not this; test_warm_run_marks_hits_and_matches is that warm hit test",
        ),
    },
    Row {
        name: "test_warm_run_marks_hits_and_matches",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_warm_run_marks_hits_and_matches: every warm file has cache hit, and the files with the cache key removed equal the cold files; The comment is not an assertion; missing stop: that every hit and that stripped equality together; The cold equality test is not this; test_cold_incremental_byte_identical_to_plain is that cold equality test",
        ),
    },
    Row {
        name: "test_no_incremental_flag_means_no_cache",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_incremental_flag_means_no_cache: a later plain scan has no cache key in any file; missing stop: that absent key together; The warm hit test is not this; test_warm_run_marks_hits_and_matches is that warm hit test",
        ),
    },
    Row {
        name: "test_single_file_incremental",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_file_incremental: the cold file cache_hit is false, the warm file cache_hit is true, and the verdicts are equal; It does not assert the verdict string; missing stop: those two flags and that equal verdict together; The tree warm test is not this; test_warm_run_marks_hits_and_matches is that tree warm test",
        ),
    },
    Row {
        name: "test_one_byte_change_invalidates_only_that_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_one_byte_change_invalidates_only_that_file: one file is a miss, its path contains h003.jsonl, and the hit count is the file count minus 1; missing stop: that one miss, that path, and that hit count together; The rule-selection invalidation is not this; test_rule_selection_change_invalidates is that rule-selection invalidation",
        ),
    },
    Row {
        name: "test_rule_selection_change_invalidates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_rule_selection_change_invalidates: a warm scan that ignores SL004 has no cache hit; missing stop: that ignore and that absent hit together; The format invalidation is not this; test_format_change_invalidates is that format invalidation",
        ),
    },
    Row {
        name: "test_format_change_invalidates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_format_change_invalidates: a warm scan with format claude-code-jsonl has no cache hit; missing stop: that format and that absent hit together; The rule-selection invalidation is not this; test_rule_selection_change_invalidates is that rule-selection invalidation",
        ),
    },
    Row {
        name: "test_fingerprint_covers_engine_and_rules",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fingerprint_covers_engine_and_rules: two fingerprints differ, and the first has length 64; The second selects SL001; It does not assert the hex text; missing stop: that inequality and that length together; A scan invalidation is not this function call; test_rule_selection_change_invalidates is that scan invalidation",
        ),
    },
    Row {
        name: "test_corrupt_db_tolerated",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_corrupt_db_tolerated: a non-database cache file still scans 8 files and none is a cache hit; missing stop: that total and that absent hit together; The unwritable-dir test is not this; test_unwritable_cache_dir_tolerated is that unwritable-dir test",
        ),
    },
    Row {
        name: "test_unwritable_cache_dir_tolerated",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unwritable_cache_dir_tolerated: a cache path under an existing file still scans 8 files; It does not assert cache hits; missing stop: that total together; The corrupt-db test is not this; test_corrupt_db_tolerated is that corrupt-db test",
        ),
    },
    Row {
        name: "test_unreadable_verdicts_never_cached",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unreadable_verdicts_never_cached: the bad file verdict is unreadable, its cache_hit is false, and its path is absent from cache_v1; missing stop: that verdict, that false hit, and that absent row together; The privacy-blob test is not this; test_cached_rows_carry_no_session_data is that privacy-blob test",
        ),
    },
    Row {
        name: "test_cache_dir_inside_scanned_tree_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cache_dir_inside_scanned_tree_ignored: the scan total is 8 and the inside cache directory does not exist; missing stop: that total and that absent directory together; The cache-db location test is not this; test_cache_db_lives_in_cache_dir is that cache-db location test",
        ),
    },
    Row {
        name: "test_cache_db_lives_in_cache_dir",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cache_db_lives_in_cache_dir: cache.db is a file in the cache directory; missing stop: that file together; The inside-tree test is not this; test_cache_dir_inside_scanned_tree_ignored is that inside-tree test",
        ),
    },
    Row {
        name: "test_cached_rows_carry_no_session_data",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cached_rows_carry_no_session_data: the result blob lacks payload, content, message_body, and transcript, and it lacks a distinctive prefix of the fixture; missing stop: those four absent words and that absent prefix together; The unreadable-row test is not this; test_unreadable_verdicts_never_cached is that unreadable-row test",
        ),
    },
    Row {
        name: "test_scan_cache_get_put_roundtrip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cache_get_put_roundtrip: the cache is healthy, the stored payload is returned, a different sha misses, and a different fingerprint misses; missing stop: that healthy flag, that equal payload, and those two misses together; The replace test is not this; test_scan_cache_put_replaces_on_content_change is that replace test",
        ),
    },
    Row {
        name: "test_scan_cache_put_replaces_on_content_change",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_cache_put_replaces_on_content_change: the old sha misses and the new sha returns the second value; missing stop: that miss and that second value together; The round-trip test is not this; test_scan_cache_get_put_roundtrip is that round-trip test",
        ),
    },
    Row {
        name: "test_default_cache_dir_env_override",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_default_cache_dir_env_override: default_cache_dir equals the SESSLINT_CACHE_DIR path; missing stop: that equal path together; The scan that uses the env dir is not this; test_env_cache_dir_used_by_scan is that scan that uses the env dir",
        ),
    },
    Row {
        name: "test_env_cache_dir_used_by_scan",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_env_cache_dir_used_by_scan: an incremental scan with no cache_dir argument creates cache.db under SESSLINT_CACHE_DIR; missing stop: that file together; The default_cache_dir equality is not this scan; test_default_cache_dir_env_override is that default_cache_dir equality",
        ),
    },
    Row {
        name: "test_parallel_incremental_combines",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_incremental_combines: a warm scan with jobs 2 has every file as a cache hit; missing stop: that jobs value and that every hit together; The serial warm test is not this; test_warm_run_marks_hits_and_matches is that serial warm test",
        ),
    },
    Row {
        name: "test_cli_incremental_and_cache_dir",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_incremental_and_cache_dir: both JSON scans exit 0, and every file in the second stdout has cache hit; missing stop: those two exits and that every hit together; The human CLI test is not this; test_cli_incremental_human_marks_hits is that human CLI test",
        ),
    },
    Row {
        name: "test_cli_incremental_human_marks_hits",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_incremental_human_marks_hits: the second scan exits 0 and stdout contains [cache-hit]; It does not assert the first exit; missing stop: that exit and that marker together; The JSON CLI test is not this; test_cli_incremental_and_cache_dir is that JSON CLI test",
        ),
    },
    Row {
        name: "test_check_dir_passthrough",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_dir_passthrough: the warm check_dir has every file as a cache hit; missing stop: that every hit together; The scan_path warm test is not this check_dir; test_warm_run_marks_hits_and_matches is that scan_path warm test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_cold_incremental_byte_identical_to_plain",
    "test_warm_run_marks_hits_and_matches",
    "test_no_incremental_flag_means_no_cache",
    "test_single_file_incremental",
    "test_one_byte_change_invalidates_only_that_file",
    "test_rule_selection_change_invalidates",
    "test_format_change_invalidates",
    "test_fingerprint_covers_engine_and_rules",
    "test_corrupt_db_tolerated",
    "test_unwritable_cache_dir_tolerated",
    "test_unreadable_verdicts_never_cached",
    "test_cache_dir_inside_scanned_tree_ignored",
    "test_cache_db_lives_in_cache_dir",
    "test_cached_rows_carry_no_session_data",
    "test_scan_cache_get_put_roundtrip",
    "test_scan_cache_put_replaces_on_content_change",
    "test_default_cache_dir_env_override",
    "test_env_cache_dir_used_by_scan",
    "test_parallel_incremental_combines",
    "test_cli_incremental_and_cache_dir",
    "test_cli_incremental_human_marks_hits",
    "test_check_dir_passthrough",
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
fn pinned_scan_test_incremental_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 311);
}

#[test]
fn pinned_scan_test_incremental_row_count_equals_twenty_two() {
    assert_eq!(ROWS.len(), 22);
    assert_eq!(PINNED_TEST_COUNT, 22);
    assert_eq!(PINNED_NAMES.len(), 22);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_scan_test_incremental_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 22);
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
    assert_eq!(not_applicable, 22);

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
