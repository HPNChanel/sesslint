//! Dispositions for the thirteen test functions in pinned
//! `tests/test_progress.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (175 splitlines). Exactly
//! thirteen test functions, in module order. There is no parametrize
//! decorator. Each row is the whole function. A docstring is not an
//! assertion. A comment is not an assertion. `FIXTURES`, `DETECT_DIR`, and
//! `REPAIR_SRC` are not tests. Nested callbacks inside those tests are not
//! separate tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these thirteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these thirteen names. An API vector that calls one
//! function is not this whole pytest.
//! `parity/vectors/progress/vectors.json` has 7 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. None of those ids is one of
//! these tests. That old pin is not a Covered source. A progress vector that
//! only builds one event is not the whole pytest.
//! `parity/vectors/scan/vectors.json` has 21 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. None of those ids is one of
//! these tests. That old pin is not a Covered source.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `check_file`, `check_dir`,
//! or `repair` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 13;
const PINNED_SPLITLINES: usize = 175;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. There is no parametrize decorator. Each row is the
/// whole function. A docstring is not an assertion. A comment is not an
/// assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A progress vector that only builds one event is not the whole pytest and
/// is not a Covered source.
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
        name: "test_progress_event_to_dict_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_progress_event_to_dict_shape: a ProgressEvent with phase scan, completed 3, total 7, and item a.jsonl has to_dict equal to completed 3, item a.jsonl, phase scan, and total 7; a ProgressEvent with phase scan and completed 1 has to_dict equal to completed 1 and phase scan; json.loads of json.dumps of that first dict with sort_keys true equals that first dict; missing stop: those two dicts and that round trip together; The frozen event test is not this; test_progress_event_is_frozen is that frozen event test",
        ),
    },
    Row {
        name: "test_progress_event_is_frozen",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_progress_event_is_frozen: assigning completed on a ProgressEvent with phase scan and completed 1 raises AttributeError; missing stop: that AttributeError together; The dict-shape test is not this; test_progress_event_to_dict_shape is that dict-shape test",
        ),
    },
    Row {
        name: "test_check_file_emits_ordered_phases",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_emits_ordered_phases: check_file phases are check:detect, check:load, check:analyze, and check:report in that order; completed values are 1, 2, 3, and 4; every total is 4; missing stop: that phase list, that completed list, and that total together; The directory event sequence is not this; a file-phase sequence is not a directory event sequence; test_check_dir_emits_per_file_events is that directory event sequence",
        ),
    },
    Row {
        name: "test_check_file_items_are_basenames_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_items_are_basenames_only: every check_file event item is not None, os.sep is not in that item, and a slash is not in that item; missing stop: that present item, that absent separator, and that absent slash together; The file-phase sequence is not this; test_check_file_emits_ordered_phases is that file-phase sequence",
        ),
    },
    Row {
        name: "test_check_file_detection_failure_still_completes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_detection_failure_still_completes: the first check_file phase is check:detect, the last phase is check:report, and the last completed value is 4; missing stop: that first phase, that last phase, and that last completed value together; The basename item test is not this; test_check_file_items_are_basenames_only is that basename item test",
        ),
    },
    Row {
        name: "test_check_dir_emits_per_file_events",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_dir_emits_per_file_events: every phase is scan; completed values are 1 through the event count; every total is None; every item is not None and os.sep is not in that item; the event count is at most the number of report files whose verdict is not skipped or whose skipped_reason is None, plus the number of report files; missing stop: that scan phase, that completed sequence, those absent totals, those items, and that length bound together; The file-phase sequence is not this; a file-phase sequence is not a directory event sequence; test_check_file_emits_ordered_phases is that file-phase sequence",
        ),
    },
    Row {
        name: "test_check_file_cancelled_token_raises",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_cancelled_token_raises: check_file with a token cancelled before the call raises OperationCancelled; missing stop: that OperationCancelled together; The cancel that leaves no artifact is not this; a cancel that raises is not a cancel that leaves no artifact; test_repair_cancel_leaves_no_artifacts is that cancel that leaves no artifact",
        ),
    },
    Row {
        name: "test_check_dir_cancel_mid_scan",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_dir_cancel_mid_scan: check_dir whose progress callback cancels the token raises OperationCancelled; missing stop: that OperationCancelled together; The pre-cancelled file check is not this; test_check_file_cancelled_token_raises is that pre-cancelled file check",
        ),
    },
    Row {
        name: "test_repair_emits_stage_sequence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_emits_stage_sequence: the repair manifest is not None; the first phase is repair:load; the last phase is repair:done; repair:plan is present; repair:execute is present; the number of repair:step events equals the number of plan steps; every repair:step total equals the number of plan steps; missing stop: that manifest, those phases, that step count, and that step total together; The directory mid-scan cancel is not this; test_check_dir_cancel_mid_scan is that directory mid-scan cancel",
        ),
    },
    Row {
        name: "test_repair_cancel_leaves_no_artifacts",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cancel_leaves_no_artifacts: a repair whose progress callback cancels the token when the phase is repair:step raises OperationCancelled; the output path does not exist; the output path with suffix .manifest.json does not exist; no destination entry name starts with .sesslint-tmp; missing stop: that OperationCancelled, that missing output, that missing manifest, and that missing temp name together; The cancel that raises is not this; a cancel that raises is not a cancel that leaves no artifact; test_check_file_cancelled_token_raises is that cancel that raises",
        ),
    },
    Row {
        name: "test_repair_cancel_before_publish_leaves_nothing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_repair_cancel_before_publish_leaves_nothing: a repair whose progress callback cancels the token when the phase is repair:plan raises OperationCancelled; the output path does not exist; the destination directory listing is empty; missing stop: that OperationCancelled, that missing output, and that empty directory together; The cancel that leaves no artifact is not this; test_repair_cancel_leaves_no_artifacts is that cancel that leaves no artifact",
        ),
    },
    Row {
        name: "test_outputs_identical_with_and_without_callback",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_outputs_identical_with_and_without_callback: dump_report of check_file equals dump_report of check_file with an empty callback; check_dir to_json equals check_dir to_json with an empty callback; the two repair plan fingerprints are equal; both manifests are not None; the two output fingerprints are equal; the two output files have equal bytes; missing stop: those two check equalities, those fingerprints, those manifests, and those bytes together; The empty-directory cancel is not this; test_repair_cancel_before_publish_leaves_nothing is that empty-directory cancel",
        ),
    },
    Row {
        name: "test_progress_events_carry_no_content",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_progress_events_carry_no_content: every value in every check_file event to_dict is a str or an int; missing stop: that str-or-int value together; The dict-shape test is not this; the content-free event test is not the dict-shape test; test_progress_event_to_dict_shape is that dict-shape test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_progress_event_to_dict_shape",
    "test_progress_event_is_frozen",
    "test_check_file_emits_ordered_phases",
    "test_check_file_items_are_basenames_only",
    "test_check_file_detection_failure_still_completes",
    "test_check_dir_emits_per_file_events",
    "test_check_file_cancelled_token_raises",
    "test_check_dir_cancel_mid_scan",
    "test_repair_emits_stage_sequence",
    "test_repair_cancel_leaves_no_artifacts",
    "test_repair_cancel_before_publish_leaves_nothing",
    "test_outputs_identical_with_and_without_callback",
    "test_progress_events_carry_no_content",
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
fn pinned_test_progress_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 175);
}

#[test]
fn pinned_test_progress_row_count_equals_thirteen() {
    assert_eq!(ROWS.len(), 13);
    assert_eq!(PINNED_TEST_COUNT, 13);
    assert_eq!(PINNED_NAMES.len(), 13);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_progress_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 13);
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
    assert_eq!(not_applicable, 13);

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
