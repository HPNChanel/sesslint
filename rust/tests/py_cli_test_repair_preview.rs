//! Dispositions for the nine `def test_` functions in pinned
//! `tests/cli/test_repair_preview.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (157 splitlines). Exactly
//! nine test functions, in module order. One is parametrized,
//! `test_preview_conflicts_exit_2`, with four flag cells. That function is one
//! row covering every cell. The helpers `_stage` and `_walk_strings` are not
//! tests. Each row is the whole function. `repair_preview` is not the CLI. A
//! CLI exit is not a document field. A comment is not an assertion. Source
//! lines, fixture bytes, and payload strings are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these nine functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these nine functions.
//! `parity/vectors/preview/vectors.json` has twenty ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `preview_version_constant`,
//! `recipe_actions_declaration_order`, `unknown_recipe_action_drop`,
//! `bounded_id_none_and_empty`, `bounded_id_non_string_absent`,
//! `bounded_id_cap_eighty_scalars`, `bounded_id_known_event`,
//! `deltas_happy_path_maps_recipe_event_and_line`, `missing_finding_uses_sl000`,
//! `duplicate_fingerprint_last_finding_wins`,
//! `source_line_requires_int_at_least_one`,
//! `event_index_requires_int_inside_slice`, `event_id_falls_back_to_record_id`,
//! `sort_is_seq_then_action_then_source_line`,
//! `delta_to_dict_omits_seq_and_absent_optionals`, `blocked_to_dict_key_order`,
//! `counts_first_seen_after_sort_not_alphabetical`,
//! `preview_doc_to_json_indent_sort_keys_ensure_ascii`,
//! `render_human_uses_dashes_for_missing_fields`, and
//! `deltas_do_not_copy_payload_fields`. That old pin is not a Covered source.
//! `unknown_recipe_action_drop`, `deltas_happy_path_maps_recipe_event_and_line`,
//! and `deltas_do_not_copy_payload_fields` are not these nine functions.
//! `parity/vectors/repair/vectors.json` has one id, `python_dunder_all`, at
//! that old pin, and it is not one of these functions. There is no evidence
//! corpus. Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call cli, preview, or api functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 9;
const PINNED_SPLITLINES: usize = 157;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `repair_preview` is not the CLI. A CLI exit is not a
/// document field. A comment is not an assertion. All four cells of
/// `test_preview_conflicts_exit_2` are one row. `not_applicable` names the
/// missing stop and the nearest different test.
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
        name: "test_preview_lists_delta_rows",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_lists_delta_rows: repair_preview returns a PreviewDoc with two steps, the first action is dedupe, the reason code is SL003, the event id is present, and the kind is message, the second action is normalize and the recipe is seq-renumber, and blocked is empty; missing stop: that PreviewDoc, those two steps, that first action, that reason code, that present event id, that kind, that second action, that recipe, and that empty blocked together; All of that is one row; It does not assert the event id string; repair_preview is not the CLI; A CLI exit is not a document field; deltas_happy_path_maps_recipe_event_and_line is not this pytest; The CLI is not this call; test_preview_cli_writes_nothing is that CLI",
        ),
    },
    Row {
        name: "test_preview_cli_writes_nothing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_cli_writes_nothing: the CLI exits 0, stdout contains dedupe and SL003, no manifest file exists, and no repaired jsonl file exists; missing stop: that exit 0, those stdout fragments, that absent manifest, and that absent repaired jsonl together; All of that is one row; It does not assert that a plan file is absent; A comment is not an assertion; The JSON shape test is not this pytest; test_preview_json_shape is that pytest",
        ),
    },
    Row {
        name: "test_preview_json_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_json_shape: the CLI exits 0, the schema is sesslint.preview/v1, the counts are dedupe 1 and normalize 1, the first step action is dedupe, blocked is an empty list, and the word payload is absent from the document dump; missing stop: that exit 0, that schema, those counts, that first action, that empty blocked list, and that absent word together; All of that is one row; The human CLI is not this pytest; test_preview_cli_writes_nothing is that human CLI",
        ),
    },
    Row {
        name: "test_preview_refused_lists_blocked",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_refused_lists_blocked: a file that does not stay valid through the last line exits 1, stdout contains blocked, and no manifest exists; missing stop: that exit 1, that stdout fragment, and that absent manifest together; All of that is one row; It does not assert a blocked code; The healthy preview is not this pytest; test_preview_cli_writes_nothing is that healthy preview",
        ),
    },
    Row {
        name: "test_preview_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_deterministic: the two preview JSON strings are equal; missing stop: that equality of both calls; Both calls are one row; It does not assert the text; repair_preview is not the CLI; A CLI exit is not a document field; The JSON CLI is not this pytest; test_preview_json_shape is that JSON CLI",
        ),
    },
    Row {
        name: "test_preview_conflicts_exit_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_conflicts_exit_2: all four cells, an output path, a plan-out path, emit canonical, and apply-plan, exit 2 and stderr contains the sentence that preview writes nothing; missing stop: those four exits and that sentence together; All four cells are one row; The successful preview is not this pytest; test_preview_cli_writes_nothing is that successful preview",
        ),
    },
    Row {
        name: "test_preview_privacy_no_payload",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_privacy_no_payload: every source string whose length is at least 20 is absent from the preview JSON; missing stop: that walk of absent long source strings; That walk is one row; repair_preview is not the CLI; A CLI exit is not a document field; deltas_do_not_copy_payload_fields is not this pytest; The JSON CLI checks only the word payload and is not this pytest; test_preview_json_shape is that JSON CLI",
        ),
    },
    Row {
        name: "test_api_repair_preview_exported",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_repair_preview_exported: the public call returns a PreviewDoc and repair_preview is in the public list; missing stop: that PreviewDoc and that public-list membership together; Both are one row; It does not assert the step count; repair_preview is not the CLI; A CLI exit is not a document field; The delta-row test is not this pytest; test_preview_lists_delta_rows is that delta-row test",
        ),
    },
    Row {
        name: "test_preview_unknown_recipe_fails_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_preview_unknown_recipe_fails_closed: a synthetic step whose recipe is brand-new-recipe and whose finding fingerprint is fp maps to the action drop; missing stop: that mapping to drop; That mapping is one row; It does not assert that the recipe string is kept; unknown_recipe_action_drop is not this pytest; The two-step fixture preview is not this synthetic step; test_preview_lists_delta_rows is that two-step fixture preview",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_preview_lists_delta_rows",
    "test_preview_cli_writes_nothing",
    "test_preview_json_shape",
    "test_preview_refused_lists_blocked",
    "test_preview_deterministic",
    "test_preview_conflicts_exit_2",
    "test_preview_privacy_no_payload",
    "test_api_repair_preview_exported",
    "test_preview_unknown_recipe_fails_closed",
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
fn pinned_cli_test_repair_preview_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 157);
}

#[test]
fn pinned_cli_test_repair_preview_row_count_equals_nine() {
    assert_eq!(ROWS.len(), 9);
    assert_eq!(PINNED_TEST_COUNT, 9);
    assert_eq!(PINNED_NAMES.len(), 9);
}

#[test]
fn every_pinned_cli_test_repair_preview_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 9);
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
    assert_eq!(not_applicable, 9);

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
