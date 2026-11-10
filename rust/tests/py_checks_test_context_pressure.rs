//! Dispositions for the twenty-two `def test_` functions in pinned
//! `tests/checks/test_context_pressure.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (258 splitlines). Exactly
//! twenty-two test functions, in module order. None is parametrized. The
//! helpers `_ev`, `_ctx`, and `_codes` are not tests. Each row is the whole
//! function. Two phases in one function are one row. Five malformed markers
//! in one function are one row. A direct `check_context_pressure` call is not
//! `load_codex_rollout`. A load is not `check_file`. A silent list is not a
//! finding. A comment is not an assertion. Session lines are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these twenty-two functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these
//! twenty-two functions.
//! `parity/vectors/checks.context_pressure/vectors.json` has five ids pinned
//! to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`:
//! `no_context_pressure_marker_empty_findings`,
//! `headroom_exactly_on_15pct_boundary_empty_findings`,
//! `earlier_tight_then_later_comfortable_empty_findings`,
//! `bool_occupancy_ignored_empty_findings`, and
//! `window_zero_ignored_empty_findings`. That corpus is not a Covered source.
//! `earlier_tight_then_later_comfortable_empty_findings` is only the silent
//! phase of `test_last_marker_wins`, and
//! `bool_occupancy_ignored_empty_findings` is one of five malformed markers.
//! Neither is the whole pytest. Similar names are not these twenty-two
//! functions.
//! `parity/vectors/context/vectors.json` is the same old pin and its
//! context-object cases are not these functions.
//! `parity/vectors/adapters.codex_rollout/vectors.json` is the same old pin
//! and is not a Covered source. Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, or api
//! functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 22;
const PINNED_SPLITLINES: usize = 258;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A direct `check_context_pressure` call is not
/// `load_codex_rollout`. A load is not `check_file`. A silent list is not a
/// finding. A comment is not an assertion. Two phases in one function are one
/// row. Five malformed markers in one function are one row. `not_applicable`
/// names the missing stop and the nearest different test.
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
        name: "test_clean_stream_no_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_clean_stream_no_finding: occupancy 150000 of window 258400 produces an empty finding list; missing stop: that empty finding list; a silent list is not a finding; the exact 15 percent boundary uses different numbers and is not this pytest; test_boundary_exactly_15pct_silent is that boundary",
        ),
    },
    Row {
        name: "test_near_limit_fires_once",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_near_limit_fires_once: the code list is exactly SL207, context_tokens 243127, window_limit 258400, headroom 15273, last_marker_line 5, threshold_source declared-window:15pct-headroom, and source line 5; missing stop: those assertions together; all of those are one row; the fixture near-limit test uses source line 4 and does not assert the token count or the threshold source, and is not this pytest; test_fixture_near_limit_fires is that fixture",
        ),
    },
    Row {
        name: "test_marker_absent_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_marker_absent_silent: two events without a pressure marker produce an empty finding list; missing stop: that empty finding list; a silent list is not a finding; the malformed-marker test is not this pytest; test_malformed_markers_ignored is that test",
        ),
    },
    Row {
        name: "test_boundary_exactly_15pct_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_boundary_exactly_15pct_silent: occupancy 8500 of window 10000 produces an empty finding list; missing stop: that empty finding list; a silent list is not a finding; a comment is not an assertion; the just-below test is not this pytest; test_boundary_just_below_15pct_fires is that test",
        ),
    },
    Row {
        name: "test_boundary_just_below_15pct_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_boundary_just_below_15pct_fires: occupancy 8501 of window 10000 produces a code list of exactly SL207; it does not assert headroom; missing stop: that code list; a comment is not an assertion; the exact boundary is not this pytest; test_boundary_exactly_15pct_silent is that boundary",
        ),
    },
    Row {
        name: "test_over_window_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_over_window_fires: the code list is exactly SL207 and headroom is -1600; missing stop: that code list and that headroom together; the near-limit test has positive headroom and is not this pytest; test_near_limit_fires_once is that test",
        ),
    },
    Row {
        name: "test_last_marker_wins",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_last_marker_wins: both phases are one row; a tight marker followed by recovery is silent; the reverse order fires SL207 on source line 7; missing stop: those two phases together; the window-change test is not this pytest; test_window_changes_last_marker_wins is that test",
        ),
    },
    Row {
        name: "test_window_changes_last_marker_wins",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_window_changes_last_marker_wins: the code list is exactly SL207, window_limit is 121600, and headroom is 11600; missing stop: those three together; the last-marker test does not change the window and is not this pytest; test_last_marker_wins is that test",
        ),
    },
    Row {
        name: "test_malformed_markers_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_markers_ignored: a string occupancy, a string window, a missing window, a bool occupancy, and a zero window all produce an empty finding list; missing stop: those five markers together; all five markers are one row; a silent list is not a finding; one marker is not this pytest; test_marker_without_codex_namespace_ignored is one marker",
        ),
    },
    Row {
        name: "test_marker_without_codex_namespace_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_marker_without_codex_namespace_ignored: context_pressure outside the codex namespace produces an empty finding list; missing stop: that empty finding list; a silent list is not a finding; the malformed markers are inside the namespace; test_malformed_markers_ignored is not this pytest",
        ),
    },
    Row {
        name: "test_adapter_extracts_marker",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_extracts_marker: the near-limit load has two marked events and the last pressure object is occupancy 243127 and window 258400; it does not assert SL207; missing stop: those two marked events and that pressure object together; a load is not check_file; a direct check_context_pressure call is not load_codex_rollout; the lifetime test asserts only occupancy and is not this pytest; test_adapter_lifetime_counters_not_used is that test",
        ),
    },
    Row {
        name: "test_adapter_lifetime_counters_not_used",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_lifetime_counters_not_used: the last occupancy is 243127; the comment about a billing total is not an assertion; missing stop: that occupancy; a load is not check_file; the extract test also asserts the window and is not this pytest; test_adapter_extracts_marker is that test",
        ),
    },
    Row {
        name: "test_adapter_skips_missing_window",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_skips_missing_window: no loaded event has context_pressure; missing stop: that absence on the load; a load is not check_file; the no-window check_file test asserts only that SL207 is absent from findings and is not this load; test_fixture_no_window_silent is that check_file",
        ),
    },
    Row {
        name: "test_fixture_near_limit_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_near_limit_fires: check_file has exactly one SL207, source line 4, and headroom 15273; it does not assert the token count, the window, or the threshold source; missing stop: those three together; a load is not check_file; the unit near-limit test uses line 5 and is not this pytest; test_near_limit_fires_once is that unit test",
        ),
    },
    Row {
        name: "test_fixture_healthy_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_healthy_silent: SL207 is absent from findings and SL207 is in performed; missing stop: those two together; both are one row; the no-window fixture does not assert performed and is not this pytest; test_fixture_no_window_silent is that fixture",
        ),
    },
    Row {
        name: "test_fixture_no_window_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_no_window_silent: SL207 is absent from findings; it does not assert performed; missing stop: that absence of SL207; a load is not check_file; the adapter load is not this check_file; test_adapter_skips_missing_window is that load",
        ),
    },
    Row {
        name: "test_fixture_no_marker_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_no_marker_silent: SL207 is absent from the no-marker fixture; missing stop: that absence of SL207; the no-window fixture is not this pytest; test_fixture_no_window_silent is that fixture",
        ),
    },
    Row {
        name: "test_conformance_corpus_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_conformance_corpus_silent: the conformance healthy file has no SL207; missing stop: that absence of SL207; the SL207 healthy fixture also asserts performed and is not this pytest; test_fixture_healthy_silent is that fixture",
        ),
    },
    Row {
        name: "test_non_codex_adapter_skips",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_codex_adapter_skips: SL207 is skipped with reason adapter-not-applicable; missing stop: the skip and the reason together; both are one row; the select test is not this pytest; test_select_sl207_runs is that test",
        ),
    },
    Row {
        name: "test_select_sl207_runs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_sl207_runs: select SL207 produces a code list of exactly SL207; missing stop: that code list; the ignore test is not this pytest; the unit near-limit call does not pass select and is not this pytest; test_ignore_sl207_suppresses is the ignore test; test_near_limit_fires_once does not pass select",
        ),
    },
    Row {
        name: "test_ignore_sl207_suppresses",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ignore_sl207_suppresses: ignore SL207 leaves SL207 absent from the codes; it does not assert that the code list is empty; missing stop: that absence of SL207; the select test is not this pytest; test_select_sl207_runs is that test",
        ),
    },
    Row {
        name: "test_evidence_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_evidence_content_free: the SL207 evidence dump contains none of session_id, fx207, synthetic, openai, or codex; missing stop: those five absences together; all five absences are one row; the near-limit finding test asserts headroom and is not this pytest; test_fixture_near_limit_fires is that test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_clean_stream_no_finding",
    "test_near_limit_fires_once",
    "test_marker_absent_silent",
    "test_boundary_exactly_15pct_silent",
    "test_boundary_just_below_15pct_fires",
    "test_over_window_fires",
    "test_last_marker_wins",
    "test_window_changes_last_marker_wins",
    "test_malformed_markers_ignored",
    "test_marker_without_codex_namespace_ignored",
    "test_adapter_extracts_marker",
    "test_adapter_lifetime_counters_not_used",
    "test_adapter_skips_missing_window",
    "test_fixture_near_limit_fires",
    "test_fixture_healthy_silent",
    "test_fixture_no_window_silent",
    "test_fixture_no_marker_silent",
    "test_conformance_corpus_silent",
    "test_non_codex_adapter_skips",
    "test_select_sl207_runs",
    "test_ignore_sl207_suppresses",
    "test_evidence_content_free",
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
fn pinned_checks_test_context_pressure_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 258);
}

#[test]
fn pinned_checks_test_context_pressure_row_count_equals_twenty_two() {
    assert_eq!(ROWS.len(), 22);
    assert_eq!(PINNED_TEST_COUNT, 22);
    assert_eq!(PINNED_NAMES.len(), 22);
}

#[test]
fn every_pinned_checks_test_context_pressure_test_has_one_disposition() {
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
    assert_eq!(not_applicable, 22);

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
