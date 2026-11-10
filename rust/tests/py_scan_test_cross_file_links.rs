//! Dispositions for the twenty-two test functions in pinned
//! `tests/scan/test_cross_file_links.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (364 splitlines). Exactly
//! twenty-two test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Helpers `_sl401` and `_write_session` are not tests.
//! `FIXTURES_DIR` and `LINKAGE` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these twenty-two names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these twenty-two names. `discover_claude_symlink` is
//! discovery. It is not a scan link.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `session_link_wire_round_trip` builds one SessionLink wire. It is not the
//! FileResult round trip, and that old pin is not a Covered source.
//! `parity/vectors/finding/vectors.json` has 22 ids,
//! `parity/vectors/checks.graph/vectors.json` has 20 ids, and
//! `parity/vectors/adapters.codex_rollout/vectors.json` has 30 ids, all on
//! that old pin. Those corpora are not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `scan_path`, `check_file`,
//! `SessionLink`, or `FileResult` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 22;
const PINNED_SPLITLINES: usize = 364;
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
/// `session_link_wire_round_trip` builds one SessionLink wire. It is not the
/// FileResult round trip and it is not these pytests.
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
        name: "test_intact_chain_emits_nothing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_intact_chain_emits_nothing: a recursive scan of the chain fixture has an empty SL401 list; missing stop: that empty list together; The missing-middle warning is not this; test_missing_middle_warns_on_child is that missing-middle warning",
        ),
    },
    Row {
        name: "test_missing_middle_warns_on_child",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_middle_warns_on_child: one SL401 on the child file has severity WARNING, resolution missing, target sess-b, link_kind session_ref, and candidate_count 0; missing stop: that one hit and those five evidence facts together; The ambiguous warning is not this; test_ambiguous_target_warns is that ambiguous warning",
        ),
    },
    Row {
        name: "test_ambiguous_target_warns",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ambiguous_target_warns: one SL401 on the child file has severity WARNING, resolution ambiguous, and candidate_count 2; it does not assert the target; missing stop: that one hit and those three facts together; The missing-middle warning is not this; test_missing_middle_warns_on_child is that missing-middle warning",
        ),
    },
    Row {
        name: "test_outside_scan_root_is_info_unresolved",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_outside_scan_root_is_info_unresolved: one SL401 has severity INFO, resolution unresolved, a target that is not the path-like fixture, and truncated true; missing stop: that one hit, that INFO, that unresolved resolution, that absent path echo, and that truncated flag together; The head-ref test is not this; test_head_ref_resolves_against_tip_only is that head-ref test",
        ),
    },
    Row {
        name: "test_head_ref_resolves_against_tip_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_head_ref_resolves_against_tip_only: one file has an empty SL401 list and the other file has one SL401 with severity INFO, resolution unresolved, and link_kind head_ref; it does not assert the word missing; the comments naming the tip and the mid-file id are not assertions; missing stop: that empty list and that one unresolved head_ref together; The outside-root test is not this; test_outside_scan_root_is_info_unresolved is that outside-root test",
        ),
    },
    Row {
        name: "test_check_single_file_never_emits_sl401",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_single_file_never_emits_sl401: check_file on the missing child has no SL401; it does not scan a directory; missing stop: that absent code together; The single-file scan is not this check_file; test_single_file_scan_emits_no_sl401 is that single-file scan",
        ),
    },
    Row {
        name: "test_single_file_scan_emits_no_sl401",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_file_scan_emits_no_sl401: scan_path of that same file has an empty SL401 list; missing stop: that empty list together; The check_file test is not this scan; test_check_single_file_never_emits_sl401 is that check_file test",
        ),
    },
    Row {
        name: "test_ignore_gate_suppresses_sl401",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ignore_gate_suppresses_sl401: a recursive scan with ignore SL401 has an empty SL401 list; missing stop: that ignore and that empty list together; The select-gate test is not this; test_select_gate_suppresses_sl401 is that select-gate test",
        ),
    },
    Row {
        name: "test_select_gate_suppresses_sl401",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_gate_suppresses_sl401: a recursive scan selecting SL001 and SL002 has an empty SL401 list; it does not assert that SL001 or SL002 is present; missing stop: that select list and that empty SL401 list together; The ignore-gate test is not this; test_ignore_gate_suppresses_sl401 is that ignore-gate test",
        ),
    },
    Row {
        name: "test_parallel_scan_resolves_links",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_parallel_scan_resolves_links: a recursive scan with jobs 4 has one SL401 on the child file and resolution missing; it does not assert severity; missing stop: that jobs value, that one hit, and that missing resolution together; The serial missing-middle test is not this; test_missing_middle_warns_on_child is that serial missing-middle test",
        ),
    },
    Row {
        name: "test_findings_deterministic_order",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_findings_deterministic_order: two scans have equal SL401 evidence lists, and the link_index values are 0 then 1; it does not assert the targets; missing stop: that equal evidence and those two indexes together; The self-link test is not this; test_self_link_is_resolved_not_flagged is that self-link test",
        ),
    },
    Row {
        name: "test_self_link_is_resolved_not_flagged",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_self_link_is_resolved_not_flagged: a session whose parent id is its own id has an empty SL401 list; missing stop: that empty list together; The stem-fallback test is not this; test_stem_fallback_resolution is that stem-fallback test",
        ),
    },
    Row {
        name: "test_stem_fallback_resolution",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stem_fallback_resolution: a child whose parent id is the parent filename stem has an empty SL401 list; missing stop: that empty list together; The self-link test is not this; test_self_link_is_resolved_not_flagged is that self-link test",
        ),
    },
    Row {
        name: "test_links_bounded_and_structural",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_links_bounded_and_structural: SessionLink to_dict equals kind session_ref, line 1, record_id c1, and target sess-b, and from_dict returns the same link; missing stop: that exact dict and that equal restored link together; session_link_wire_round_trip is on the old pin and is not this pytest; The FileResult round trip is not this; test_wire_round_trip_preserves_links is that FileResult round trip",
        ),
    },
    Row {
        name: "test_wire_round_trip_preserves_links",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_wire_round_trip_preserves_links: FileResult.from_wire preserves links, session_id, and tip_id; it does not assert those values; missing stop: those three equal fields together; The SessionLink dict test is not this; test_links_bounded_and_structural is that SessionLink dict test",
        ),
    },
    Row {
        name: "test_codex_forked_from_id_extracted",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_forked_from_id_extracted: one SL401 has link_kind session_ref, target thread-parent, and resolution missing; missing stop: that one hit and those three facts together; The parent-thread resolution is not this; test_codex_parent_thread_id_resolves_via_meta_id is that parent-thread resolution",
        ),
    },
    Row {
        name: "test_codex_parent_thread_id_resolves_via_meta_id",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_parent_thread_id_resolves_via_meta_id: two rollout files, the child links to the parent meta id, and the SL401 list is empty; the docstring counts are not assertions; missing stop: that empty list together; The missing-parent test is not this; test_codex_missing_parent_still_fires is that missing-parent test",
        ),
    },
    Row {
        name: "test_codex_missing_parent_still_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_missing_parent_still_fires: one SL401 has resolution missing; missing stop: that one hit and that missing resolution together; The resolved parent-thread test is not this; test_codex_parent_thread_id_resolves_via_meta_id is that resolved parent-thread test",
        ),
    },
    Row {
        name: "test_codex_first_session_meta_wins_session_id",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_first_session_meta_wins_session_id: the SL401 list is empty and the child file session_id is its first meta id; the docstring counts are not assertions; missing stop: that empty list and that first meta id together; The filename-stem resolution is not this; test_codex_link_resolves_via_filename_uuid is that filename-stem resolution",
        ),
    },
    Row {
        name: "test_codex_link_resolves_via_filename_uuid",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_codex_link_resolves_via_filename_uuid: the parent header has no usable id, the child links to the parent filename stem, and the SL401 list is empty; missing stop: that empty list together; The first-meta test is not this; test_codex_first_session_meta_wins_session_id is that first-meta test",
        ),
    },
    Row {
        name: "test_scan_report_dict_shape_unchanged",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_report_dict_shape_unchanged: every file dict lacks links, session_id, and tip_id; it does not assert the other keys; missing stop: those three absent keys together; The wire round trip is not this; test_wire_round_trip_preserves_links is that wire round trip",
        ),
    },
    Row {
        name: "test_missing_fixture_targets_record_coordinates",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_missing_fixture_targets_record_coordinates: the child SL401 source record_id is c1 and the line is 1; missing stop: that record id and that line together; The missing-middle severity test is not this coordinate check; test_missing_middle_warns_on_child is that missing-middle severity test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_intact_chain_emits_nothing",
    "test_missing_middle_warns_on_child",
    "test_ambiguous_target_warns",
    "test_outside_scan_root_is_info_unresolved",
    "test_head_ref_resolves_against_tip_only",
    "test_check_single_file_never_emits_sl401",
    "test_single_file_scan_emits_no_sl401",
    "test_ignore_gate_suppresses_sl401",
    "test_select_gate_suppresses_sl401",
    "test_parallel_scan_resolves_links",
    "test_findings_deterministic_order",
    "test_self_link_is_resolved_not_flagged",
    "test_stem_fallback_resolution",
    "test_links_bounded_and_structural",
    "test_wire_round_trip_preserves_links",
    "test_codex_forked_from_id_extracted",
    "test_codex_parent_thread_id_resolves_via_meta_id",
    "test_codex_missing_parent_still_fires",
    "test_codex_first_session_meta_wins_session_id",
    "test_codex_link_resolves_via_filename_uuid",
    "test_scan_report_dict_shape_unchanged",
    "test_missing_fixture_targets_record_coordinates",
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
fn pinned_scan_test_cross_file_links_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 364);
}

#[test]
fn pinned_scan_test_cross_file_links_row_count_equals_twenty_two() {
    assert_eq!(ROWS.len(), 22);
    assert_eq!(PINNED_TEST_COUNT, 22);
    assert_eq!(PINNED_NAMES.len(), 22);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_scan_test_cross_file_links_test_has_one_disposition() {
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
