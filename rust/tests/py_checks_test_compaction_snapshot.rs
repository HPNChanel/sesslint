//! Dispositions for the twenty-three `def test_` functions in pinned
//! `tests/checks/test_compaction_snapshot.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (424 splitlines). Exactly
//! twenty-three test functions, in module order. None is parametrized. The
//! helpers `_ev`, `_ctx`, `_boundary`, and `_rollout` are not tests. The
//! fixture path constants and the imports are not tests. Each row is the
//! whole function. A direct `check_compaction_snapshot` call is not
//! `run_all_checks`. `run_all_checks` is not `load_codex_rollout`.
//! `load_codex_rollout` is not `check_file`. A silent list is not a finding.
//! A comment is not an assertion. Rollout records and the planted text are
//! not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, or api
//! functions without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33
//! parser-metadata vectors at this pin and none is one of these twenty-three
//! functions. `parity/vectors/api/vectors.json` is at this pin with 77 ids
//! for envelopes, directory limits, discovery, module constants, plan and
//! repair rejection, thresholds, and validate_session. None of those 77 is
//! one of these twenty-three functions.
//! `parity/vectors/checks.compaction_snapshot/vectors.json` has seven ids
//! pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `module_dunder_all`,
//! `no_codex_marker_empty_findings`, `same_type_same_call_id_empty_findings`,
//! `snapshot_only_id_empty_findings`,
//! `durable_absent_from_snapshot_empty_findings`,
//! `guardian_items_tuple_not_list_empty_findings`, and
//! `non_string_kind_not_boundary_empty_findings`. That corpus is not a
//! Covered source. Similar names are not these twenty-three functions.
//! `checks.runner`, `adapters.codex_rollout`, and `profiles.builtin` are the
//! same old pin and are not Covered sources. Therefore every row is
//! NotApplicable.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 23;
const PINNED_SPLITLINES: usize = 424;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A direct `check_compaction_snapshot` call is not
/// `run_all_checks`. `run_all_checks` is not `load_codex_rollout`.
/// `load_codex_rollout` is not `check_file`. A silent list is not a finding.
/// A comment is not an assertion. `not_applicable` names the missing stop.
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
        name: "test_agreeing_snapshot_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_agreeing_snapshot_silent: a message and a function call whose snapshot types and call id agree produce an empty finding list; missing stop: that empty finding list; a silent list is not a finding; the snapshot-only-id test is not this pytest; test_snapshot_only_ids_silent is that test",
        ),
    },
    Row {
        name: "test_snapshot_only_ids_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_snapshot_only_ids_silent: snapshot ids absent from the stream stay silent; missing stop: that silence; a silent list is not a finding; a comment is not an assertion; the agreeing test is not this pytest; test_agreeing_snapshot_silent is that test",
        ),
    },
    Row {
        name: "test_intra_snapshot_orphan_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_intra_snapshot_orphan_silent: an output inside the snapshot without its call stays silent; the check does not pair inside the snapshot; missing stop: that silence; a silent list is not a finding; the snapshot-only-id test is not this pytest; test_snapshot_only_ids_silent is that test",
        ),
    },
    Row {
        name: "test_no_snapshot_marker_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_snapshot_marker_silent: a boundary whose codex marker has durable true and no guardian items stays silent; missing stop: that silence; a silent list is not a finding; the empty guardian list is not this pytest; test_empty_snapshot_silent is that list",
        ),
    },
    Row {
        name: "test_empty_snapshot_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_empty_snapshot_silent: an empty guardian item list stays silent; missing stop: that silence; a silent list is not a finding; the no-marker test is not this pytest; test_no_snapshot_marker_silent is that test",
        ),
    },
    Row {
        name: "test_type_mismatch_fires_once",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_type_mismatch_fires_once: one SL208 warning, divergence type-mismatch, item id msg_a, occurrences 2, snapshot type reasoning, and stream type message; missing stop: all of those together; all of those are one row; two identical snapshot rows are still one finding; the correlation test is not this pytest; test_correlation_mismatch_fires is that test",
        ),
    },
    Row {
        name: "test_correlation_mismatch_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_correlation_mismatch_fires: one finding, divergence correlation-mismatch, snapshot correlator c9, and stream correlator c1; it does not assert the code or the severity; missing stop: those evidence fields together; the presence-mismatch test has a null stream correlator and is not this pytest; test_correlation_presence_mismatch_fires is that test",
        ),
    },
    Row {
        name: "test_correlation_presence_mismatch_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_correlation_presence_mismatch_fires: one finding, divergence correlation-mismatch, snapshot correlator c9, and stream correlator null; missing stop: those evidence fields together; it does not assert the code or the severity; a comment is not an assertion; the value-mismatch test is not this pytest; test_correlation_mismatch_fires is that test",
        ),
    },
    Row {
        name: "test_future_item_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_future_item_fires: one finding, divergence future-item, item id msg_late, boundary index 0, and item index 1; missing stop: those evidence fields together; a comment is not an assertion; the three-kind test is not this pytest; test_all_three_kinds_emit_together is that test",
        ),
    },
    Row {
        name: "test_id_reuse_does_not_mask_or_false_flag",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_id_reuse_does_not_mask_or_false_flag: the same id before and after the boundary stays silent; missing stop: that silence; a silent list is not a finding; a comment is not an assertion; the future-item test is not this pytest; test_future_item_fires is that test",
        ),
    },
    Row {
        name: "test_all_three_kinds_emit_together",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_all_three_kinds_emit_together: the finding count is 3 and the divergence set is type-mismatch, correlation-mismatch, and future-item; missing stop: the count and the set together; all three kinds are one row; a comment is not an assertion; one kind is not this pytest; test_future_item_fires is one kind",
        ),
    },
    Row {
        name: "test_malformed_markers_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_markers_ignored: a non-list marker, a junk list, and items without string ids all stay silent; missing stop: all three markers together; all three markers are one row; a silent list is not a finding; the empty-snapshot test is not this pytest; test_empty_snapshot_silent is that test",
        ),
    },
    Row {
        name: "test_no_markers_at_all_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_markers_at_all_silent: events with no codex marker stay silent; missing stop: that silence; a silent list is not a finding; the durable-true marker is not this pytest; test_no_snapshot_marker_silent is that marker",
        ),
    },
    Row {
        name: "test_empty_events_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_empty_events_silent: an empty event list stays silent; missing stop: that silence; a silent list is not a finding; the no-marker test is not this pytest; test_no_markers_at_all_silent is that test",
        ),
    },
    Row {
        name: "test_runner_skips_on_non_codex_adapter",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runner_skips_on_non_codex_adapter: a canonical adapter yields no SL208 and the skip reason is adapter-not-applicable; missing stop: both together; both are one row; a direct check_compaction_snapshot call is not run_all_checks; the codex runner test is not this pytest; test_runner_performs_on_codex is that test",
        ),
    },
    Row {
        name: "test_runner_performs_on_codex",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runner_performs_on_codex: SL208 is in performed and at least one SL208 finding is present; missing stop: both together; both are one row; a direct check_compaction_snapshot call is not run_all_checks; the skip test is not this pytest; test_runner_skips_on_non_codex_adapter is that test",
        ),
    },
    Row {
        name: "test_deselected_sl208_marks_deselected_skip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_deselected_sl208_marks_deselected_skip: ignoring SL208 yields no SL208 finding and the skip reason is deselected; missing stop: both together; both are one row; a comment is not an assertion; the adapter-not-applicable skip is not this pytest; test_runner_skips_on_non_codex_adapter is that skip",
        ),
    },
    Row {
        name: "test_adapter_projects_guardian_items",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_projects_guardian_items: a raw rollout load projects guardian_items_total 3, two items, and keeps the call id on the call event; the non-dict history entry is not projected; missing stop: those projections together; run_all_checks is not load_codex_rollout; the records are not copied here; the content test is not this pytest; test_adapter_never_projects_snapshot_content is that test",
        ),
    },
    Row {
        name: "test_adapter_never_projects_snapshot_content",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_never_projects_snapshot_content: the planted text is absent from the projected items, and the projected item keeps only the id, the type, and a null call id; missing stop: that absence together with that projected item; the planted text is not copied here; the projection-count test is not this pytest; test_snapshot_cap_bounds_projection is that test",
        ),
    },
    Row {
        name: "test_snapshot_cap_bounds_projection",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_snapshot_cap_bounds_projection: 600 history items project 512 items, the total is 600, and truncated is true; missing stop: all three together; all three are one row; the projection-content test is not this pytest; test_adapter_never_projects_snapshot_content is that test",
        ),
    },
    Row {
        name: "test_e2e_fixture_fires_via_check_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_e2e_fixture_fires_via_check_file: check_file of the type-mismatch fixture has at least one SL208; it does not assert the count or the evidence fields; missing stop: that presence of SL208; load_codex_rollout is not check_file; a direct check_compaction_snapshot call is not check_file; the unit type-mismatch test is not this pytest; test_type_mismatch_fires_once is that unit test",
        ),
    },
    Row {
        name: "test_e2e_healthy_fixture_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_e2e_healthy_fixture_silent: check_file of the healthy fixture has no SL208; it does not assert that every other code is absent; missing stop: that absence of SL208; the firing fixture is not this pytest; test_e2e_fixture_fires_via_check_file is that fixture",
        ),
    },
    Row {
        name: "test_fixture_files_exist",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_files_exist: the four fixture paths are files; it does not load them; missing stop: those four paths together; test_e2e_fixture_fires_via_check_file is not this pytest; test_e2e_healthy_fixture_silent is not this pytest",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_agreeing_snapshot_silent",
    "test_snapshot_only_ids_silent",
    "test_intra_snapshot_orphan_silent",
    "test_no_snapshot_marker_silent",
    "test_empty_snapshot_silent",
    "test_type_mismatch_fires_once",
    "test_correlation_mismatch_fires",
    "test_correlation_presence_mismatch_fires",
    "test_future_item_fires",
    "test_id_reuse_does_not_mask_or_false_flag",
    "test_all_three_kinds_emit_together",
    "test_malformed_markers_ignored",
    "test_no_markers_at_all_silent",
    "test_empty_events_silent",
    "test_runner_skips_on_non_codex_adapter",
    "test_runner_performs_on_codex",
    "test_deselected_sl208_marks_deselected_skip",
    "test_adapter_projects_guardian_items",
    "test_adapter_never_projects_snapshot_content",
    "test_snapshot_cap_bounds_projection",
    "test_e2e_fixture_fires_via_check_file",
    "test_e2e_healthy_fixture_silent",
    "test_fixture_files_exist",
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
fn pinned_test_compaction_snapshot_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 424);
}

#[test]
fn pinned_test_compaction_snapshot_row_count_equals_twenty_three() {
    assert_eq!(ROWS.len(), 23);
    assert_eq!(PINNED_TEST_COUNT, 23);
    assert_eq!(PINNED_NAMES.len(), 23);
}

#[test]
fn every_pinned_test_compaction_snapshot_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 23);
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
            "cli id {id} is one of the twenty-three functions"
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
    assert_eq!(not_applicable, 23);

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
            "api id {id} is one of the twenty-three functions"
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
