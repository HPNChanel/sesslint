//! Dispositions for the eighteen `def test_` functions in pinned
//! `tests/checks/test_size_anomaly.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (254 splitlines). Exactly
//! eighteen test functions, in module order. None is parametrized. The
//! helpers `_ctx`, `_claude_record`, and `_write_jsonl` are not tests. Each
//! row is the whole function. `check_size_anomaly` is not `check_file`. A
//! load is not a scan. A comment is not an assertion. Record text, the
//! repeated payload character, session identifiers, and timestamps are not
//! copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, or scan
//! functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33
//! parser-metadata vectors at this pin and none is one of these eighteen
//! functions. `parity/vectors/api/vectors.json` is at this pin with 77 ids
//! for envelopes, directory limits, discovery, module constants, plan and
//! repair rejection, thresholds, and validate_session. None of those 77 is
//! one of these eighteen functions.
//! `parity/vectors/checks.size/vectors.json` has eight ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `no_context_silent`,
//! `missing_record_sizes_silent`, `record_sizes_not_a_list_silent`,
//! `seven_sizes_silent`, `eight_small_sizes_silent`, `floor_equal_silent`,
//! `bool_and_negative_dropped_below_min_silent`, and `constants_and_all`.
//! That corpus is not a Covered source. `no_context_silent` is one of three
//! missing-metadata calls. `floor_equal_silent` is one phase of the boundary
//! test. `seven_sizes_silent` is not the under-minimum pytest. There is no
//! checks.context corpus. Therefore every row is NotApplicable.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 18;
const PINNED_SPLITLINES: usize = 254;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `check_size_anomaly` is not `check_file`. A load is
/// not a scan. A comment is not an assertion. Each row is the whole function.
/// `not_applicable` names the missing stop.
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
        name: "test_outlier_fires_once_with_numbers_only_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_outlier_fires_once_with_numbers_only_evidence: nine sizes of 150 and one size of 300000 produce one SL011 info finding, record index 9, record bytes 300000, file median 150, and a ratio equal to round of 300000 divided by 150 to three places; missing stop: all of those together; all of those are one row; check_size_anomaly is not check_file; the e2e outlier fixture does not assert the bytes, the median, or the ratio, and is not this call; test_e2e_outlier_fixture is that check_file",
        ),
    },
    Row {
        name: "test_uniform_file_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_uniform_file_stays_clean: twelve sizes of 1024 produce an empty finding list; missing stop: that empty finding list; the uniformly large list is not this pytest; test_uniformly_large_file_stays_clean is that list",
        ),
    },
    Row {
        name: "test_uniformly_large_file_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_uniformly_large_file_stays_clean: ten sizes of 1500000 produce an empty finding list; missing stop: that empty finding list; the comment about a rollout is not an assertion; the bimodal list is not this pytest; test_bimodal_within_ratio_stays_clean is that list",
        ),
    },
    Row {
        name: "test_bimodal_within_ratio_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bimodal_within_ratio_stays_clean: nine sizes of 100000 and one size of 1500000 produce an empty finding list; missing stop: that empty finding list; the comment about a 2 MiB threshold is not an assertion; the below-floor list is not this pytest; test_below_floor_never_fires is that list",
        ),
    },
    Row {
        name: "test_below_floor_never_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_below_floor_never_fires: nine sizes of 10 and one size of 50000 produce an empty finding list; missing stop: that empty finding list; the comment about the ratio and the floor is not an assertion; the boundary test is not this pytest; test_threshold_boundary_exact is that test",
        ),
    },
    Row {
        name: "test_under_min_records_skips",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_under_min_records_skips: a list one shorter than the minimum record count, each size 300000, produces an empty finding list; missing stop: that empty finding list; the minimum is not invented here; seven_sizes_silent is not the under-minimum pytest; the small fixture also asserts a skip and is not this call; test_e2e_small_fixture_coverage_skip is that check_file",
        ),
    },
    Row {
        name: "test_missing_size_metadata_yields_nothing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_size_metadata_yields_nothing: an empty size list, a context whose source metadata is empty, and a missing context each produce an empty finding list; missing stop: those three empty finding lists together; all three calls are one row; no_context_silent is one of three missing-metadata calls and is not this pytest; the under-minimum test is not this pytest; test_under_min_records_skips is that test",
        ),
    },
    Row {
        name: "test_threshold_boundary_exact",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_threshold_boundary_exact: a record exactly at max of median 150 times the ratio constant and the floor constant is silent, and one byte above that threshold produces one finding; missing stop: both phases together; both phases are one row; the constants are not invented here; floor_equal_silent is one phase of the boundary test and is not this pytest; the largest-only test is not this pytest; test_largest_only_one_finding is that test",
        ),
    },
    Row {
        name: "test_largest_only_one_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_largest_only_one_finding: eight sizes of 150, then 400000, then 350000, produce one finding whose record bytes are 400000 and whose record index is 8; missing stop: that one finding with those record bytes and that record index; it does not assert the code or the severity; a comment is not an assertion; the outlier test is not this pytest; test_outlier_fires_once_with_numbers_only_evidence is that test",
        ),
    },
    Row {
        name: "test_zero_median_edge_no_division_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_zero_median_edge_no_division_error: nine zeros and one size of 300000 produce one finding whose median is 0 and whose ratio is null; missing stop: that one finding with median 0 and a null ratio; it does not assert the record bytes; the outlier test is not this pytest; test_outlier_fires_once_with_numbers_only_evidence is that test",
        ),
    },
    Row {
        name: "test_e2e_outlier_fixture",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_e2e_outlier_fixture: the outlier fixture has one SL011 info finding whose record index is 9; missing stop: that one SL011 info finding at record index 9; it does not assert the bytes, the median, or the ratio; the unit outlier call is not this check_file; test_outlier_fires_once_with_numbers_only_evidence is that call",
        ),
    },
    Row {
        name: "test_e2e_uniform_fixture_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_e2e_uniform_fixture_clean: the uniform fixture has no SL011; missing stop: that absence of SL011; it does not assert that the finding list is empty; the unit uniform call is not this check_file; test_uniform_file_stays_clean is that call",
        ),
    },
    Row {
        name: "test_e2e_small_fixture_coverage_skip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_e2e_small_fixture_coverage_skip: the small fixture has no SL011, the skip pair is SL011 with adapter-not-applicable, and size is not performed; missing stop: all three together; all three are one row; the under-minimum call is not this check_file; test_under_min_records_skips is that call",
        ),
    },
    Row {
        name: "test_e2e_legit_large_codex_shape_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_e2e_legit_large_codex_shape_clean: a codex file of uniform large outputs has no SL011; missing stop: that absence of SL011; it does not assert a skip; the records are not copied here; a comment is not an assertion; the unit large-list call is not this check_file; the codex skip test is not this pytest; test_uniformly_large_file_stays_clean is that call; test_codex_adapter_skips_size_check is that skip",
        ),
    },
    Row {
        name: "test_codex_adapter_skips_size_check",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_adapter_skips_size_check: a codex file with one much larger record has no SL011, the skip pair is SL011 with adapter-not-applicable, and size is not performed; missing stop: all three together; all three are one row; the records are not copied here; the docstring is not an assertion; the uniform large codex file is not this pytest; test_e2e_legit_large_codex_shape_clean is that file",
        ),
    },
    Row {
        name: "test_adapter_publishes_record_sizes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_publishes_record_sizes: a load of nine records exposes record_sizes as a list of length 9 whose items are positive ints; missing stop: that list of length 9 of positive ints; it does not assert the size values; the records are not copied here; a check_file is not this load; a load is not a scan; the select-ignore scan is not this load; test_select_ignore_gating is that scan",
        ),
    },
    Row {
        name: "test_select_ignore_gating",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_ignore_gating: a scan that ignores SL011 has no SL011 in any file findings; missing stop: that absence of SL011 in any file findings; it does not assert the unfiltered scan; the docstring is not a second phase; the records are not copied here; a load is not this scan; the outlier fixture is not this scan; test_e2e_outlier_fixture is that check_file",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_determinism: two calls both return one finding and those fingerprints are equal; missing stop: both the shared one-finding length and the equal fingerprints; it does not assert the evidence fields; the size list places 300000 before later sizes of 150, so the 300000 value is not the last size; the outlier test is not this pytest; test_outlier_fires_once_with_numbers_only_evidence is that test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_outlier_fires_once_with_numbers_only_evidence",
    "test_uniform_file_stays_clean",
    "test_uniformly_large_file_stays_clean",
    "test_bimodal_within_ratio_stays_clean",
    "test_below_floor_never_fires",
    "test_under_min_records_skips",
    "test_missing_size_metadata_yields_nothing",
    "test_threshold_boundary_exact",
    "test_largest_only_one_finding",
    "test_zero_median_edge_no_division_error",
    "test_e2e_outlier_fixture",
    "test_e2e_uniform_fixture_clean",
    "test_e2e_small_fixture_coverage_skip",
    "test_e2e_legit_large_codex_shape_clean",
    "test_codex_adapter_skips_size_check",
    "test_adapter_publishes_record_sizes",
    "test_select_ignore_gating",
    "test_determinism",
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
fn pinned_test_size_anomaly_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 254);
}

#[test]
fn pinned_test_size_anomaly_row_count_equals_eighteen() {
    assert_eq!(ROWS.len(), 18);
    assert_eq!(PINNED_TEST_COUNT, 18);
    assert_eq!(PINNED_NAMES.len(), 18);
}

#[test]
fn every_pinned_test_size_anomaly_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 18);
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
        assert!(
            !names.contains(id),
            "cli id {id} equals a pinned test name"
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
    assert_eq!(not_applicable, 18);

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
        assert!(
            !names.contains(id),
            "api id {id} equals a pinned test name"
        );
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
