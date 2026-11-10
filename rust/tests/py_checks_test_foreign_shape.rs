//! Dispositions for the eighteen `def test_` functions in pinned
//! `tests/checks/test_foreign_shape.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (317 splitlines). Exactly
//! eighteen test functions, in module order. None is parametrized. The
//! helpers `_ev`, `_ctx`, `_rollout`, `_msg`, and `_reasoning` are not tests.
//! Each row is the whole function. A `check_file` is not `load_codex_rollout`.
//! A load is not `check_foreign_shape`. An empty SL305 list is not an empty
//! findings list. A comment is not an assertion. Message text, session lines,
//! rollout records, timestamps, and encrypted values are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 parser-metadata vectors at this
//! pin and none is one of these eighteen functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these
//! eighteen functions.
//! `parity/vectors/checks.foreign_shape/vectors.json` has five ids pinned
//! to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`:
//! `no_codex_marker_empty_findings`,
//! `reasoning_reasoning_content_shape_string_null_silent`,
//! `unknown_item_type_message_shape_array_silent`,
//! `reasoning_reasoning_content_shape_absent_silent`, and
//! `reasoning_reasoning_content_shape_not_string_silent`. That corpus is not
//! a Covered source. Those similar names are not these eighteen functions.
//! A single shape id is not the two-item silent pytest and is not the
//! five-marker pytest.
//! `checks.durable_prefix`, `checks.runner`, `adapters.codex_rollout`, and
//! `context` are the same old pin and are not Covered sources. Therefore
//! every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call check, adapter, or api
//! functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 18;
const PINNED_SPLITLINES: usize = 317;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A `check_file` is not `load_codex_rollout`. A load is
/// not `check_foreign_shape`. An empty SL305 list is not an empty findings
/// list. A comment is not an assertion. Both reasoning items in one function
/// are one row. Five markers in one function are one row. `not_applicable`
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
        name: "test_conformance_healthy_stays_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_conformance_healthy_stays_clean: the conformance healthy file has no SL305; missing stop: that empty SL305 list; an empty SL305 list is not an empty findings list; the null-content fixture is not this pytest; test_null_content_fixture_clean is that fixture",
        ),
    },
    Row {
        name: "test_null_content_fixture_clean",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_null_content_fixture_clean: the null-content fixture has no SL305; missing stop: that empty SL305 list; an empty SL305 list is not an empty findings list; the constructed absent-and-null test is not this pytest; test_absent_and_null_content_silent is that test",
        ),
    },
    Row {
        name: "test_absent_and_null_content_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_absent_and_null_content_silent: one reasoning item with null content and one reasoning item that omits content produce no SL305; missing stop: that empty SL305 list; both items are one row; an empty SL305 list is not an empty findings list; a comment is not an assertion; a single shape id is not this pytest; the null-content fixture is not this pytest; test_null_content_fixture_clean is that fixture",
        ),
    },
    Row {
        name: "test_non_reasoning_content_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_reasoning_content_ignored: message items that carry content produce no SL305; missing stop: that empty SL305 list; an empty SL305 list is not an empty findings list; a comment is not an assertion; the foreign reasoning fixture is not this pytest; test_foreign_reasoning_fires_once is that fixture",
        ),
    },
    Row {
        name: "test_foreign_reasoning_fires_once",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_foreign_reasoning_fires_once: one SL305 warning, source line 3, shape_violation reasoning-content-non-null, item family reasoning, item count 2, and first ordinal 2; missing stop: those assertions together; all of those are one row; it does not assert the provider hash; the provider-hash test is not this pytest; test_declared_provider_context_in_evidence is that test",
        ),
    },
    Row {
        name: "test_declared_provider_context_in_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_declared_provider_context_in_evidence: the provider hash is a string of length 8 and declared_originator_present is true; missing stop: that string length and that presence together; it does not assert the line, the severity, or the shape; a comment is not an assertion; the fires-once test is not this pytest; test_foreign_reasoning_fires_once is that test",
        ),
    },
    Row {
        name: "test_non_dict_content_shape_fires",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_dict_content_shape_fires: a reasoning item whose content is a string produces exactly one SL305; missing stop: that one SL305; it does not assert the evidence fields; a comment is not an assertion; the foreign fixture is not this pytest; test_foreign_reasoning_fires_once is that fixture",
        ),
    },
    Row {
        name: "test_no_session_meta_no_provider_keys",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_session_meta_no_provider_keys: a file with no session meta produces one SL305, and declared_provider_hash and declared_originator_present are both absent from the evidence; missing stop: that one SL305 and those two absences together; all of that is one row; the provider-hash test is not this pytest; test_declared_provider_context_in_evidence is that test",
        ),
    },
    Row {
        name: "test_mixed_splice_fires_alongside_sl206",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_mixed_splice_fires_alongside_sl206: the mixed fixture contains SL305 and SL206, the SL305 item count is 1, and the SL206 divergence is missing-required-field; missing stop: those three together; all of that is one row; it does not assert that those are the only codes; a comment is not an assertion; the uniform-foreign test is not this pytest; test_uniform_foreign_without_encrypted_silent_sl206 is that test",
        ),
    },
    Row {
        name: "test_uniform_foreign_without_encrypted_silent_sl206",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_uniform_foreign_without_encrypted_silent_sl206: the SL305 code list is exactly SL305 and the SL206 code list is empty; missing stop: those two lists together; both lists are one row; an empty SL206 list is not an empty findings list; a comment is not an assertion; the mixed fixture contains both codes and is not this pytest; test_mixed_splice_fires_alongside_sl206 is that fixture",
        ),
    },
    Row {
        name: "test_no_markers_silent",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_markers_silent: two events without markers produce an empty finding list from check_foreign_shape; missing stop: that empty finding list; a check_file is not this call; the malformed-marker test is not this pytest; test_malformed_markers_ignored is that test",
        ),
    },
    Row {
        name: "test_malformed_markers_ignored",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_markers_ignored: a non-mapping marker, an integer item type, a bool shape, an unrecognized string shape, and a reasoning item without a shape key produce an empty finding list; missing stop: those five markers together; all five markers are one row; a single shape id is not this pytest; the no-marker test is not this pytest; test_no_markers_silent is that test",
        ),
    },
    Row {
        name: "test_non_codex_adapter_skips_rule",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_codex_adapter_skips_rule: a claude adapter yields no SL305, SL305 is not performed, the skip pair is SL305 with adapter-not-applicable, and the skip pair is shape with adapter-not-applicable; missing stop: those four together; all four are one row; the select test is not this pytest; test_select_sl305_runs is that test",
        ),
    },
    Row {
        name: "test_select_sl305_runs",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_sl305_runs: select SL305 makes the finding codes exactly SL305; missing stop: that code list; the ignore test asserts an empty code list and is not this pytest; the fires-once test asserts evidence and is not this pytest; test_ignore_sl305_suppresses is the ignore test; test_foreign_reasoning_fires_once asserts evidence",
        ),
    },
    Row {
        name: "test_ignore_sl305_suppresses",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_ignore_sl305_suppresses: ignore SL305 makes the finding codes exactly empty; missing stop: that empty code list; the select test is not this pytest; test_select_sl305_runs is that test",
        ),
    },
    Row {
        name: "test_determinism_replay_identical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_determinism_replay_identical: two checks of the foreign fixture have equal SL305 findings and equal fingerprints; missing stop: those two equalities together; both equalities are one row; the fires-once test is not this pytest; test_foreign_reasoning_fires_once is that test",
        ),
    },
    Row {
        name: "test_content_free_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_content_free_evidence: the dumped report contains neither reasoning_text nor third-party-syn; every SL305 evidence value is an int, a string, or a bool; and every string other than declared_provider_hash is reasoning-content-non-null or reasoning; missing stop: those absences and those type limits together; None is not an allowed evidence type; all of that is one row; a comment is not an assertion; the provider-hash test is not this pytest; test_declared_provider_context_in_evidence is that test",
        ),
    },
    Row {
        name: "test_adapter_populates_shape_marker",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_adapter_populates_shape_marker: the three reasoning events project reasoning_content_shape array, then null, then absent; missing stop: those three shapes together; the discarded findings are not asserted; all three shapes are one row; a check_file is not this load; a single shape id is not this pytest; the two-item silent test is not this pytest; test_absent_and_null_content_silent is that test",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_conformance_healthy_stays_clean",
    "test_null_content_fixture_clean",
    "test_absent_and_null_content_silent",
    "test_non_reasoning_content_ignored",
    "test_foreign_reasoning_fires_once",
    "test_declared_provider_context_in_evidence",
    "test_non_dict_content_shape_fires",
    "test_no_session_meta_no_provider_keys",
    "test_mixed_splice_fires_alongside_sl206",
    "test_uniform_foreign_without_encrypted_silent_sl206",
    "test_no_markers_silent",
    "test_malformed_markers_ignored",
    "test_non_codex_adapter_skips_rule",
    "test_select_sl305_runs",
    "test_ignore_sl305_suppresses",
    "test_determinism_replay_identical",
    "test_content_free_evidence",
    "test_adapter_populates_shape_marker",
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
fn pinned_checks_test_foreign_shape_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 317);
}

#[test]
fn pinned_checks_test_foreign_shape_row_count_equals_eighteen() {
    assert_eq!(ROWS.len(), 18);
    assert_eq!(PINNED_TEST_COUNT, 18);
    assert_eq!(PINNED_NAMES.len(), 18);
}

#[test]
fn every_pinned_checks_test_foreign_shape_test_has_one_disposition() {
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
