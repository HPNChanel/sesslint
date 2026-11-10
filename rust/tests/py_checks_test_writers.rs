//! Dispositions for the nineteen `def test_` functions in pinned
//! `tests/checks/test_writers.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (306 splitlines). Exactly
//! nineteen test functions, in module order. One is parametrized,
//! `test_clean_fixtures_emit_no_sl010_via_api`, with two cells. That function
//! is one row covering both cells. The helpers `_writer_hash`, `_ev`, and
//! `_ctx` are not tests. Each row is the whole function. `run_all_checks` is
//! not `check_file`. `check_writers` is not `load_claude_code`. An empty code
//! list is not an empty SL010 list. A comment is not an assertion. Message
//! text and session identifiers are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these nineteen functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these nineteen
//! functions.
//! `parity/vectors/checks.writers/vectors.json` has seven ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `empty_input_silent`,
//! `three_events_no_writer_extra_silent`,
//! `triple_instance_alpha_synth_lines_123_silent`,
//! `instance_alpha_versions_beta_ordered_silent`,
//! `instance_alpha_version_beta_instance_gamma_ordered_silent`,
//! `two_same_line_instance_then_version_next_line_silent`, and
//! `constants_marker_hashes_silent`. That corpus is not a Covered source.
//! `three_events_no_writer_extra_silent` is not the five-assertion skip pytest.
//! `two_same_line_instance_then_version_next_line_silent` is silent and is not
//! the firing dedup pytest. `checks.runner` and `context` are the same old pin
//! and are not Covered sources. Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, or api
//! functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 19;
const PINNED_SPLITLINES: usize = 306;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `run_all_checks` is not `check_file`. `check_writers`
/// is not `load_claude_code`. An empty code list is not an empty SL010 list.
/// A comment is not an assertion. Both cells of the parametrized function are
/// one row. All five malformed markers are one row. All five skip assertions
/// are one row. `not_applicable` names the missing stop and the nearest
/// different test.
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
        name: "test_upgrade_transition_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_upgrade_transition_stays_clean: run_all_checks on the upgrade fixture has a finding code list that is exactly empty; missing stop: that exactly empty finding code list; It does not assert only SL010; an empty code list is not an empty SL010 list; The parametrized check_file is not this call; test_clean_fixtures_emit_no_sl010_via_api is that check_file",
        ),
    },
    Row {
        name: "test_single_writer_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_writer_stays_clean: run_all_checks on the single-writer fixture has a finding code list that is exactly empty; missing stop: that exactly empty finding code list; an empty code list is not an empty SL010 list; The upgrade fixture is not this pytest; test_upgrade_transition_stays_clean is that pytest",
        ),
    },
    Row {
        name: "test_missing_markers_stay_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_markers_stay_clean: run_all_checks on the basic fixture has a finding code list that is exactly empty; missing stop: that exactly empty finding code list; an empty code list is not an empty SL010 list; The single-writer fixture is not this pytest; test_single_writer_stays_clean is that pytest",
        ),
    },
    Row {
        name: "test_interleaved_fires_once_with_structural_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_interleaved_fires_once_with_structural_evidence: one SL010 warning, source line 4, evidence keys exactly the four-key set, distinct writer count 2, transition count 2, first interleave line 4, and writer hashes equal to the sorted eight-character digests of v:2.0.9 and v:2.1.0; missing stop: that one SL010 warning, that source line, that four-key set, that distinct writer count, that transition count, that first interleave line, and those digests together; All of that is one row; It does not put those version strings in the evidence; The content-free test is not this pytest; test_content_free_no_marker_strings is that pytest",
        ),
    },
    Row {
        name: "test_multi_interleave_still_one_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multi_interleave_still_one_finding: check_writers: five events produce one finding, source line 3, and transition count 4; missing stop: that one finding, that source line, and that transition count together; It does not assert the distinct count or the hashes; The three-record test is not this pytest; test_minimal_three_record_interleave_fires is that pytest",
        ),
    },
    Row {
        name: "test_instance_marker_takes_precedence_over_version",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_instance_marker_takes_precedence_over_version: check_writers: one finding whose writer hashes are the sorted eight-character digests of i:proc-a and i:proc-b; missing stop: that one finding and those writer hashes together; It does not assert the line or the transition count; The same-version gap test is not this pytest; test_same_version_same_instance_pair_no_fire is that pytest",
        ),
    },
    Row {
        name: "test_same_version_same_instance_pair_no_fire",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_same_version_same_instance_pair_no_fire: check_writers: the same version, a record with no marker, then the same version again, produce an empty finding list; missing stop: that empty finding list; The comment is not an assertion; The two-record alternation has two versions and is not this pytest; test_two_record_alternation_does_not_fire is that pytest",
        ),
    },
    Row {
        name: "test_minimal_three_record_interleave_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_minimal_three_record_interleave_fires: check_writers: three events produce one finding whose transition count is 2; missing stop: that one finding and that transition count together; It does not assert the source line; The five-event test is not this pytest; test_multi_interleave_still_one_finding is that pytest",
        ),
    },
    Row {
        name: "test_two_record_alternation_does_not_fire",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_two_record_alternation_does_not_fire: check_writers: two different versions produce an empty finding list; missing stop: that empty finding list; The three-record return is not this pytest; test_minimal_three_record_interleave_fires is that pytest",
        ),
    },
    Row {
        name: "test_multi_event_record_deduped_per_line",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_multi_event_record_deduped_per_line: check_writers: two events on one line and then two later events produce one finding whose distinct writer count is 2; missing stop: that one finding and that distinct writer count together; It does not assert the transition count; The comment is not an extra assertion; two_same_line_instance_then_version_next_line_silent is silent and is not the firing dedup pytest; The three-record test is not this pytest; test_minimal_three_record_interleave_fires is that pytest",
        ),
    },
    Row {
        name: "test_malformed_writer_shapes_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_writer_shapes_ignored: check_writers: a usable version, a non-string version, a non-mapping marker, a blank version, and the same usable version produce an empty finding list; missing stop: that empty finding list after those five markers; All five markers are one row; The comment is not an assertion; The same-version gap test is not this pytest; test_same_version_same_instance_pair_no_fire is that pytest",
        ),
    },
    Row {
        name: "test_non_claude_events_skip_adapter_not_applicable",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_claude_events_skip_adapter_not_applicable: three events without writer markers, passed to run_all_checks without an adapter argument, yield no SL010, SL010 is not performed, writers is not performed, and both skip pairs are adapter-not-applicable; missing stop: those five assertions together; The helper still marks the events as claude-code-jsonl; All five assertions are one row; The name is not an assertion that a different vendor was used; three_events_no_writer_extra_silent is not the five-assertion skip pytest; The select test is not this pytest; test_select_sl010_runs_and_fires is that pytest",
        ),
    },
    Row {
        name: "test_select_sl010_runs_and_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_sl010_runs_and_fires: check_file select SL010 makes the finding codes exactly SL010; missing stop: that exact SL010 finding-code list; run_all_checks is not check_file; The ignore test is not this pytest; test_ignore_sl010_suppresses is that pytest; The interleaved evidence test is not this pytest; test_interleaved_fires_once_with_structural_evidence is that pytest",
        ),
    },
    Row {
        name: "test_ignore_sl010_suppresses",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ignore_sl010_suppresses: check_file ignore SL010 makes the finding codes exactly empty; missing stop: that exactly empty finding code list; an empty code list is not an empty SL010 list; The select test is not this pytest; test_select_sl010_runs_and_fires is that pytest",
        ),
    },
    Row {
        name: "test_determinism_replay_identical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_determinism_replay_identical: two check_file calls have equal SL010 findings and equal fingerprints; missing stop: both equalities together; Both equalities are one row; The evidence test is not this pytest; test_interleaved_fires_once_with_structural_evidence is that pytest",
        ),
    },
    Row {
        name: "test_content_free_no_marker_strings",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_content_free_no_marker_strings: the dumped report contains neither 2.0.9 nor 2.1.0, and every SL010 writer hash has length 8 and is hexadecimal; missing stop: those absent version strings and that hexadecimal hash length together; All of that is one row; The interleaved test asserts the specific digests and is not this pytest; test_interleaved_fires_once_with_structural_evidence is that pytest",
        ),
    },
    Row {
        name: "test_adapter_populates_writer_extra",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_populates_writer_extra: load_claude_code: the first writer is version 2.0.9 with a null instance, the second is version 2.0.10 with a null instance, and the third writer is absent; missing stop: those three writer records together; All three records are one row; A check_file is not this load; The flag test is not this pytest; test_adapter_sets_writer_markers_source_flag is that pytest",
        ),
    },
    Row {
        name: "test_adapter_sets_writer_markers_source_flag",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_sets_writer_markers_source_flag: the interleaved load sets writer_markers true; missing stop: that writer_markers flag; It does not assert the writer extras; The populate test is not this pytest; test_adapter_populates_writer_extra is that load",
        ),
    },
    Row {
        name: "test_clean_fixtures_emit_no_sl010_via_api",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_clean_fixtures_emit_no_sl010_via_api: both cells, sl010_upgrade and sl010_single_writer, have a finding code list that is exactly empty; missing stop: that exactly empty finding code list for both cells; Both cells are one row; an empty code list is not an empty SL010 list; The run_all_checks upgrade test is not this check_file; test_upgrade_transition_stays_clean is that run_all_checks",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_upgrade_transition_stays_clean",
    "test_single_writer_stays_clean",
    "test_missing_markers_stay_clean",
    "test_interleaved_fires_once_with_structural_evidence",
    "test_multi_interleave_still_one_finding",
    "test_instance_marker_takes_precedence_over_version",
    "test_same_version_same_instance_pair_no_fire",
    "test_minimal_three_record_interleave_fires",
    "test_two_record_alternation_does_not_fire",
    "test_multi_event_record_deduped_per_line",
    "test_malformed_writer_shapes_ignored",
    "test_non_claude_events_skip_adapter_not_applicable",
    "test_select_sl010_runs_and_fires",
    "test_ignore_sl010_suppresses",
    "test_determinism_replay_identical",
    "test_content_free_no_marker_strings",
    "test_adapter_populates_writer_extra",
    "test_adapter_sets_writer_markers_source_flag",
    "test_clean_fixtures_emit_no_sl010_via_api",
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
fn pinned_checks_test_writers_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 306);
}

#[test]
fn pinned_checks_test_writers_row_count_equals_nineteen() {
    assert_eq!(ROWS.len(), 19);
    assert_eq!(PINNED_TEST_COUNT, 19);
    assert_eq!(PINNED_NAMES.len(), 19);
}

#[test]
fn every_pinned_checks_test_writers_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 19);
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
    assert_eq!(not_applicable, 19);

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
