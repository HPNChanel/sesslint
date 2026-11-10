//! Dispositions for the nineteen test functions in pinned
//! `tests/test_triage.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (393 splitlines). Exactly
//! nineteen test functions, in module order. Eight are parametrized. A
//! parametrized function is one row covering every parameter cell, including
//! `test_incomplete_registry_copy_never_verified` with two parametrize
//! decorators. Each row is the whole function. A docstring is not an
//! assertion. A comment is not an assertion. Helpers `session`, `canonical`,
//! `event`, `validate`, and `registry` are not tests. `ROOT`, `BASE`, and
//! `SCHEMA` are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these nineteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these nineteen names. An API vector that calls one
//! function is not this whole pytest.
//! `parity/vectors/triage/vectors.json`,
//! `parity/vectors/cli.triage/vectors.json`, and
//! `parity/vectors/state_db/vectors.json` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. A report vector that only
//! builds one preview is not the whole pytest. That old pin is not a Covered
//! source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `triage`, `latest_session`,
//! `read_codex_state`, or `main` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 19;
const PINNED_SPLITLINES: usize = 393;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A parametrized function is one row covering every
/// parameter cell, including a function with two parametrize decorators.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A report vector that only builds one preview is not the whole pytest.
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
        name: "test_healthy_pure_and_api_parity",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_healthy_pure_and_api_parity: status is checked, exit code is 0, source sha256 equals the digest of the source bytes, api json equals triage json, the source bytes are unchanged, the mtime is unchanged, the directory contains only the source, captured stdout and stderr are empty, TriageReport is exported, and the report is that exported type; missing stop: that status, that exit code, that digest, that json equality, those unchanged bytes, that mtime, that directory, that empty capture, that export, and that type together; The unhealthy-state row is not this; test_states_are_not_silently_healthy is that unhealthy-state row",
        ),
    },
    Row {
        name: "test_states_are_not_silently_healthy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_states_are_not_silently_healthy: this row covers all five cells, status unsupported, then blocked, then blocked, then needs-attention, then needs-attention, and every cell has exit code 1; missing stop: those five statuses and those exit codes together; The limit and unreadable distinction is not this; test_limit_and_unreadable_are_distinct is that limit and unreadable distinction",
        ),
    },
    Row {
        name: "test_limit_and_unreadable_are_distinct",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_limit_and_unreadable_are_distinct: the limited result is skipped, its source sha256 is absent, and its previews are empty; a missing path and a directory are each unreadable with exit code 2; missing stop: that skipped triple and those two unreadable results together; The incomplete-coverage row is not this; test_incomplete_coverage_never_checked is that incomplete-coverage row",
        ),
    },
    Row {
        name: "test_incomplete_coverage_never_checked",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_incomplete_coverage_never_checked: this row covers both cells cap-exceeded with skipped and version-gated with unsupported, and each cell has that status, assurance A0, empty previews, and a missing-evidence code of coverage; missing stop: those two cells, that assurance, those empty previews, and that coverage code together; The torn-preview comparison is not this; test_torn_preview_same_snapshot_and_explicit_comparison is that torn-preview comparison",
        ),
    },
    Row {
        name: "test_torn_preview_same_snapshot_and_explicit_comparison",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_torn_preview_same_snapshot_and_explicit_comparison: salvage preview policies are conservative then salvage, every preview source sha256 equals the report source sha256, the first preview step count is greater than zero, and the default triage has one preview; a report vector that only builds one preview is not this whole pytest; missing stop: those two policies, that shared digest, that step count, and that one preview together; The single-decode count is not this; test_only_one_decode_and_no_preview_reopen is that single-decode count",
        ),
    },
    Row {
        name: "test_only_one_decode_and_no_preview_reopen",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_only_one_decode_and_no_preview_reopen: the decode count is 1; missing stop: that one decode together; The withheld-preview row is not this; test_source_changed_after_load_withholds_preview is that withheld-preview row",
        ),
    },
    Row {
        name: "test_source_changed_after_load_withholds_preview",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_source_changed_after_load_withholds_preview: this row covers both metadata-restore cells false and true; the mutated bytes differ and keep the same length, the status is unstable, the previews are empty, and the assurance is A0; missing stop: those two cells, that mutation, that status, those empty previews, and that assurance together; The graph-impact row is not this; test_graph_impact_and_private_output is that graph-impact row",
        ),
    },
    Row {
        name: "test_graph_impact_and_private_output",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_graph_impact_and_private_output: SL004 is present, affected events are at least 2, outside mapped impact is at most 1, both rendered outputs omit the payload text, the event-id text, the session-id text, the directory text, and the source name, and the impact limitation contains the replay-safety sentence; missing stop: that code, those two impact bounds, those absent texts, and that limitation together; The side-effect row is not this; test_unknown_side_effects_do_not_offer_execution is that side-effect row",
        ),
    },
    Row {
        name: "test_unknown_side_effects_do_not_offer_execution",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_side_effects_do_not_offer_execution: this row covers both checkpoint-loss cells false and true; SL102 is present; the true cell also has SL203 and status blocked; the false cell has status needs-attention; no preview has a step count; the first next-action id is verify-external-state; missing stop: those two cells, those codes, those statuses, that empty step count, and that action id together; The latest-session row is not this; test_latest_excludes_auxiliary_and_subagents is that latest-session row",
        ),
    },
    Row {
        name: "test_latest_excludes_auxiliary_and_subagents",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_latest_excludes_auxiliary_and_subagents: this row covers both agent cells codex and claude; the latest session equals the primary session, and the latest json command exits 0; missing stop: those two cells, that primary session, and that exit 0 together; The closed-copy membership is not this; test_registry_copy_membership_no_writes is that closed-copy membership",
        ),
    },
    Row {
        name: "test_registry_copy_membership_no_writes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_registry_copy_membership_no_writes: native state status is membership-matches, the directory bytes are unchanged, and after a wal sidecar the status is unverified; missing stop: that membership status, those unchanged bytes, and that unverified status together; The live registry refusal is not this; test_live_registry_refused is that live registry refusal",
        ),
    },
    Row {
        name: "test_live_registry_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_live_registry_refused: native state status is unverified; missing stop: that unverified status together; The crosswired-row check is not this; test_crosswired_registry_rows_do_not_match is that crosswired-row check",
        ),
    },
    Row {
        name: "test_crosswired_registry_rows_do_not_match",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_crosswired_registry_rows_do_not_match: native state status is membership-mismatch and the report status is not checked; missing stop: that mismatch and that status together; The hard link is not this; test_registry_hard_link_is_not_a_closed_copy is that hard link",
        ),
    },
    Row {
        name: "test_registry_hard_link_is_not_a_closed_copy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_registry_hard_link_is_not_a_closed_copy: a hard-linked state copy has native state status unverified; missing stop: that unverified status together; The closed copy is not this; test_registry_copy_membership_no_writes is that closed copy",
        ),
    },
    Row {
        name: "test_registry_query_work_is_bounded",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_registry_query_work_is_bounded: membership is not complete and the schema note is query-limit; missing stop: that incomplete membership and that schema note together; The incomplete-copy row is not this; test_incomplete_registry_copy_never_verified is that incomplete-copy row",
        ),
    },
    Row {
        name: "test_incomplete_registry_copy_never_verified",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_incomplete_registry_copy_never_verified: this one row covers every suffix cell wal, shm, and journal and every during-read cell false and true; native state status is unverified and the report status is not checked; missing stop: those six cells, that unverified status, and that report status together; The auxiliary-table bound is not this; test_registry_auxiliary_tables_bounded is that auxiliary-table bound",
        ),
    },
    Row {
        name: "test_registry_auxiliary_tables_bounded",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_registry_auxiliary_tables_bounded: this row covers both table cells for spawn edges and for skipped rollouts; membership is not complete and the schema note is oversized; missing stop: those two cells, that incomplete membership, and that schema note together; The cli usage refusal is not this; test_cli_usage_refused is that cli usage refusal",
        ),
    },
    Row {
        name: "test_cli_usage_refused",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_usage_refused: this row covers all five argv cells, triage with no source, latest alone, an agent alone, a source together with latest and an agent, and a source with include-content, and each cell exits 2; missing stop: those five cells and those exit codes together; The cli json parity is not this; test_cli_json_parity is that cli json parity",
        ),
    },
    Row {
        name: "test_cli_json_parity",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_json_parity: triage json exits 0 and the parsed stdout equals the triage dict; missing stop: that exit 0 and that dict equality together; The cli usage refusal is not this; test_cli_usage_refused is that cli usage refusal",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_healthy_pure_and_api_parity",
    "test_states_are_not_silently_healthy",
    "test_limit_and_unreadable_are_distinct",
    "test_incomplete_coverage_never_checked",
    "test_torn_preview_same_snapshot_and_explicit_comparison",
    "test_only_one_decode_and_no_preview_reopen",
    "test_source_changed_after_load_withholds_preview",
    "test_graph_impact_and_private_output",
    "test_unknown_side_effects_do_not_offer_execution",
    "test_latest_excludes_auxiliary_and_subagents",
    "test_registry_copy_membership_no_writes",
    "test_live_registry_refused",
    "test_crosswired_registry_rows_do_not_match",
    "test_registry_hard_link_is_not_a_closed_copy",
    "test_registry_query_work_is_bounded",
    "test_incomplete_registry_copy_never_verified",
    "test_registry_auxiliary_tables_bounded",
    "test_cli_usage_refused",
    "test_cli_json_parity",
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
fn pinned_test_triage_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 393);
}

#[test]
fn pinned_test_triage_row_count_equals_nineteen() {
    assert_eq!(ROWS.len(), 19);
    assert_eq!(PINNED_TEST_COUNT, 19);
    assert_eq!(PINNED_NAMES.len(), 19);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_triage_test_has_one_disposition() {
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
    assert_eq!(not_applicable, 19);

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
