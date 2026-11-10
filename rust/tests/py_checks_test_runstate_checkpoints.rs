//! Dispositions for the eleven `def test_` functions in pinned
//! `tests/checks/test_runstate_checkpoints.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (374 splitlines). Exactly
//! eleven test functions, in module order. None is parametrized. The helper
//! `_write_canonical_session` is not a test. Each row is the whole function.
//! An API check is not the CLI check. A direct `check_checkpoint_gap` call is
//! not `check_file`. A comment is not an assertion. Message text, session
//! identifiers, tool arguments, and timestamps are not copied here. Asserted
//! record ids and asserted hash strings may be named because they are the
//! assertions.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these eleven functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these eleven
//! functions.
//! `parity/vectors/checks.checkpoint/vectors.json` has ten ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `empty_input_silent`,
//! `constants_and_all`, `fingerprint_sl201_aba`,
//! `checkpoint_before_run_start_silent`, `same_hash_divergence_silent`,
//! `pointerless_compaction_silent`, `duplicated_leaf_silent`,
//! `parent_cycle_silent`, `root_parent_contiguous_silent`, and
//! `codex_rollout_continuation_silent`. That corpus is not a Covered source.
//! `checkpoint_before_run_start_silent` is not both phases of the run_start
//! test. `same_hash_divergence_silent` is not the differing-hash test.
//! `fingerprint_sl201_aba` is not the CLI gap test. Therefore every row is
//! NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, cli, or api functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const PINNED_SPLITLINES: usize = 374;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. An API check is not the CLI check. A direct
/// `check_checkpoint_gap` call is not `check_file`. A comment is not an
/// assertion. The API and the CLI in one function are one row. Both phases of
/// the run_start test are one row. `not_applicable` names the missing stop
/// and the nearest different test.
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
        name: "test_runstate_checkpoint_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_clean: the API findings contain none of SL201, SL202, or SL203, the error count is 0, and the CLI exits 0; missing stop: those three together; all three are one row; it does not assert that every finding is absent; the gap test is not this pytest; test_runstate_checkpoint_sl201_gap_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_sl201_gap_end_to_end",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_sl201_gap_end_to_end: the API has one SL201 error, repairability MANUAL, record id chk_1, expected seq 1, found seq 4, and source run_state, and the CLI exits 1 and its JSON has one SL201 whose found seq is 4; missing stop: those API fields and that CLI exit and JSON together; the API and the CLI are one row; it does not assert the hash strings; fingerprint_sl201_aba is not the CLI gap test; the missing-hash test is not this pytest; test_runstate_checkpoint_sl201_missing_hash_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_sl201_missing_hash_end_to_end",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_sl201_missing_hash_end_to_end: the API has one SL201 whose source is run_state and whose found seq is 0, and the CLI exits 1; missing stop: that source, that found seq, and that CLI exit together; the API and the CLI are one row; it does not assert severity, repairability, or a record id; the gap test is not this pytest; test_runstate_checkpoint_sl201_gap_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_sl202_internal_divergence_end_to_end",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_sl202_internal_divergence_end_to_end: the API has one SL202 error, repairability MANUAL, record id chk_branch_b, seq 1, hash_a aaaa111122223333, hash_b bbbb444455556666, and source run_state, and the CLI exits 1 and its JSON contains some SL202; missing stop: those API fields and that CLI exit and JSON together; the API and the CLI are one row; it does not assert the CLI hash strings; same_hash_divergence_silent is not the differing-hash test; the cross-divergence test is not this pytest; test_runstate_checkpoint_sl202_cross_divergence_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_sl202_cross_divergence_end_to_end",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_sl202_cross_divergence_end_to_end: the API has one SL202, record id chk_event_divergent, seq 1, hash_a 1111111111111111, and hash_b 2222222222222222; missing stop: that one SL202 and those fields together; it does not assert severity, repairability, or a CLI exit; same_hash_divergence_silent is not this differing-hash test; the internal-divergence test is not this pytest; test_runstate_checkpoint_sl202_internal_divergence_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_satisfies_run_start",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_satisfies_run_start: a run_start with an empty context produces some SL201, and the same event with a run-state checkpoint produces no SL201; missing stop: both phases together; both phases are one row; it does not assert the evidence of the firing phase; a check_file is not this direct call; a comment is not an assertion; checkpoint_before_run_start_silent is not both phases of this test; the gap test is not this pytest; test_runstate_checkpoint_sl201_gap_end_to_end is that check_file",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_sl203_unsafe_continuation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_sl203_unsafe_continuation: the API codes contain SL201 and SL203, and the SL203 finding is an error, repairability MANUAL, record id evt_tool_call, and its caused_by contains SL201; missing stop: those codes and that SL203 finding together; all of that is one row; it does not assert a CLI exit; the gap test is not this pytest; test_runstate_checkpoint_sl201_gap_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_openai_agents_format",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_openai_agents_format: the openai-agents file has one SL201 whose found seq is 4; missing stop: that one SL201 and that found seq; it does not assert expected seq, source, or a CLI exit; the canonical gap test is not this pytest; test_runstate_checkpoint_sl201_gap_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_unordered_gap_detected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_unordered_gap_detected: the API has one SL201, expected seq 3, found seq 5, and record id chk_rev_2; missing stop: that one SL201 and those three fields together; it does not assert the source field; the ordered gap test is not this pytest; test_runstate_checkpoint_sl201_gap_end_to_end is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_reverse_clean_bridged",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_reverse_clean_bridged: the SL201 count is 0; missing stop: that SL201 count; it does not assert that every other code is absent; the comment about the bridge is not an assertion; the clean test also asserts the error count and the CLI exit and is not this pytest; test_runstate_checkpoint_clean is that test",
        ),
    },
    Row {
        name: "test_runstate_checkpoint_falsy_id_preserved",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_runstate_checkpoint_falsy_id_preserved: the API has one SL201 whose record id is the string 0; missing stop: that one SL201 and that record id together; it does not assert the seq numbers; the ordered gap test is not this pytest; test_runstate_checkpoint_sl201_gap_end_to_end is that test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_runstate_checkpoint_clean",
    "test_runstate_checkpoint_sl201_gap_end_to_end",
    "test_runstate_checkpoint_sl201_missing_hash_end_to_end",
    "test_runstate_checkpoint_sl202_internal_divergence_end_to_end",
    "test_runstate_checkpoint_sl202_cross_divergence_end_to_end",
    "test_runstate_checkpoint_satisfies_run_start",
    "test_runstate_checkpoint_sl203_unsafe_continuation",
    "test_runstate_checkpoint_openai_agents_format",
    "test_runstate_checkpoint_unordered_gap_detected",
    "test_runstate_checkpoint_reverse_clean_bridged",
    "test_runstate_checkpoint_falsy_id_preserved",
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
fn pinned_checks_test_runstate_checkpoints_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 374);
}

#[test]
fn pinned_checks_test_runstate_checkpoints_row_count_equals_eleven() {
    assert_eq!(ROWS.len(), 11);
    assert_eq!(PINNED_TEST_COUNT, 11);
    assert_eq!(PINNED_NAMES.len(), 11);
}

#[test]
fn every_pinned_checks_test_runstate_checkpoints_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 11);
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
    assert_eq!(not_applicable, 11);

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
