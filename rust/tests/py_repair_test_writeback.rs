//! Dispositions for the fifteen `def test_` functions in pinned
//! `tests/repair/test_writeback.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (274 splitlines). Exactly
//! fifteen test functions. One is parametrized over two prefix cells. The
//! helpers `_record_hash`, `_load`, and `_mk_event` are not tests.
//! `REPO_ROOT`, `FIXTURES`, and `CLAUDE_BASIC` are not tests. A parametrized
//! function is one row covering every cell, not one row per cell. A skip and
//! the assertion that follows it are one row. A docstring is not an
//! assertion. A comment is not an assertion. Record ids, message texts, and
//! session documents are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `emit_vendor_bytes`,
//! `api.repair`, or `api.verify` without a `Cargo.toml` change. This test
//! does not call product functions.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `Disposition::Covered` exists only so a later
//! whole-pytest vector can be claimed. `parity/vectors/cli/vectors.json` has
//! 33 ids at this pin and none of those ids is one of these fifteen
//! functions. `parity/vectors/api/vectors.json` is at this pin with 77 ids
//! for module `sesslint.api`. None of those 77 is one of these fifteen
//! functions. `repair_emit_reject_vendor_space` is a dry-run repair whose
//! emit is a vendor token with a leading space. It is not a write-back.
//!
//! `parity/vectors/repair.writeback/vectors.json` has 9 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `identity_passthrough`,
//! `drops_line_when_all_events_dropped`, `refuses_synthesized_event_r1`,
//! `refuses_reorder_r5`, `refuses_single_doc_json_r6`,
//! `refuses_unsupported_format_r6`, `preserves_interior_cr_parametrize`,
//! `drop_lines_discards_torn_record`, and `keeps_uninterpreted_lines`. That
//! old pin is not a Covered source. It has no partial-line R2 vector, no
//! rewritten-event R3 vector, no source-drift R4 vector, and no `api.repair`
//! or `api.verify` vector. An `e91d50b2` corpus is not a Covered source.
//!
//! `parity/vectors/repair.errors/vectors.json` pins
//! `vendor_projection_refused_default`, `vendor_projection_refused_reason_r1`,
//! `vendor_projection_refused_explicit_empty_reason`,
//! `vendor_repair_refused_default`, and `vendor_repair_refused_custom_code`
//! to that old pin. They construct exceptions. They do not call
//! `emit_vendor_bytes`.
//!
//! `parity/vectors/adapters.claude_code/vectors.json` has 27 ids,
//! `parity/vectors/canonical/vectors.json` has 12 ids,
//! `parity/vectors/repair.executor/vectors.json` has 17 ids,
//! `parity/vectors/repair/vectors.json` has 1 id, and
//! `parity/vectors/cli.repair/vectors.json` has 1 id, all on that old pin.
//! None of those old-pin corpora is a Covered source.
//!
//! Therefore every row is NotApplicable. `not_applicable` names the missing
//! stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 15;
const PINNED_SPLITLINES: usize = 274;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A docstring is not an assertion. A comment is not an
/// assertion. A parametrized function is one row covering every cell. A skip
/// and the assertion that follows it are one row. `not_applicable` names the
/// missing stop.
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
        name: "test_writeback_identity_passthrough",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_identity_passthrough: emit_vendor_bytes returns bytes equal to the source, dropped_lines is 0, retained_lines equals the source splitline count, and emitted_sha256 equals the sha256 of the source. It does not assert the hash string. missing stop: that byte identity, that zero drop, that retained count, and that hash equality together. The drop-one-line test is not this. test_writeback_drops_line_when_all_events_dropped is the drop-one-line test and is not this. identity_passthrough is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_drops_line_when_all_events_dropped",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_drops_line_when_all_events_dropped: the last event line is removed, the output equals the remaining source lines joined, dropped_lines is 1, and retained_lines is the splitline count minus 1. missing stop: that removed line, that joined remainder, and those two counts together. The identity passthrough is not this. test_writeback_identity_passthrough is the identity passthrough and is not this. drops_line_when_all_events_dropped is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_refuses_synthesized_event_r1",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_refuses_synthesized_event_r1: an extra event with no source line makes emit_vendor_bytes raise VendorProjectionRefused with reason R1. missing stop: that raise and that R1 together. A constructed VendorProjectionRefused is not this call. The partial-line refusal is not this. test_writeback_refuses_partial_line_r2 is the partial-line refusal and is not this. vendor_projection_refused_default constructs VendorProjectionRefused and is not this call. vendor_projection_refused_reason_r1 constructs VendorProjectionRefused and is not this call. vendor_projection_refused_explicit_empty_reason constructs VendorProjectionRefused and is not this call. vendor_repair_refused_default and vendor_repair_refused_custom_code construct exceptions and do not call emit_vendor_bytes and are not this call. refuses_synthesized_event_r1 is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_refuses_partial_line_r2",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_refuses_partial_line_r2: the host skip and the raise are one row. When the second source line yields fewer than two events the test skips. Otherwise the survivors keep the first line and only the first event of the second line, and the reason is R2. missing stop: that skip and that R2 together. The synthesized-event refusal is not this. test_writeback_refuses_synthesized_event_r1 is the synthesized-event refusal and is not this. The old pin has no partial-line R2 vector and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_refuses_rewritten_event_r3",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_refuses_rewritten_event_r3: the last event is copied with a different parent id and emit_vendor_bytes raises VendorProjectionRefused with reason R3. missing stop: that rewritten parent and that R3 together. The source-drift refusal is not this. test_writeback_refuses_source_drift_r4 is the source-drift refusal and is not this. The old pin has no rewritten-event R3 vector and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_refuses_source_drift_r4",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_refuses_source_drift_r4: one id token in the source bytes is replaced after the load, the bytes differ, and the reason is R4. missing stop: that changed source and that R4 together. The rewritten-event refusal is not this. test_writeback_refuses_rewritten_event_r3 is the rewritten-event refusal and is not this. The old pin has no source-drift R4 vector and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_refuses_reorder_r5",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_refuses_reorder_r5: the host skip and the raise are one row. When there are fewer than two events the test skips. Otherwise the last event is moved first and the reason is R5. missing stop: that skip and that R5 together. The single-document refusal is not this. test_writeback_refuses_single_doc_json_r6 is the single-document refusal and is not this. refuses_reorder_r5 is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_refuses_single_doc_json_r6",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_refuses_single_doc_json_r6: a single-document export passed as openai-agents raises VendorProjectionRefused with reason R6. The synthetic event uses source line 4. missing stop: that format and that R6 together. The unsupported-format refusal is not this. test_writeback_refuses_unsupported_format_r6 is the unsupported-format refusal and is not this. refuses_single_doc_json_r6 is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_single_jsonl_record_and_interior_cr_are_preserved",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_jsonl_record_and_interior_cr_are_preserved: one row for both prefix cells. Each cell loads one event, the output equals the input bytes, retained_lines is 1, and dropped_lines is 0. missing stop: that one event, that byte identity, and those two counts together for both prefixes. The identity passthrough of the basic fixture is not this one-record row. test_writeback_identity_passthrough is the identity passthrough of the basic fixture and is not this one-record row. preserves_interior_cr_parametrize is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_refuses_unsupported_format_r6",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_refuses_unsupported_format_r6: emit format bogus-format raises VendorProjectionRefused with reason R6. missing stop: that format and that R6 together. The single-document R6 test is not this. test_writeback_refuses_single_doc_json_r6 is the single-document R6 test and is not this. refuses_unsupported_format_r6 is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_drop_lines_discards_torn_record",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_drop_lines_discards_torn_record: the load has some SL002, the torn line is the maximum SL002 source line, drop_lines contains that line, the output equals the healthy fixture bytes, and dropped_lines is 1. missing stop: that SL002, that dropped line, that healthy output, and that count together. The api.repair torn test is not this emit call. test_api_repair_vendor_torn_writeback is the api.repair torn test and is not this emit call. drop_lines_discards_torn_record is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_writeback_keeps_uninterpreted_lines",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_writeback_keeps_uninterpreted_lines: the healthy fixture plus a trailing newline is emitted unchanged. The comment is not an assertion. It does not assert the counts. missing stop: that unchanged padded source together. The torn drop is not this keep. test_writeback_drop_lines_discards_torn_record is the torn drop and is not this keep. keeps_uninterpreted_lines is on the old pin and is not a Covered source",
        ),
    },
    Row {
        name: "test_api_repair_vendor_torn_writeback",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_repair_vendor_torn_writeback: api.repair writes a file, the manifest is present, adapter_id is claude-code-jsonl, the output bytes equal the healthy fixture, and dropped_lines is 1. It does not assert the plan object. missing stop: that file, that adapter, that healthy output, and that count together. The emit_vendor_bytes torn drop is not this api.repair. test_writeback_drop_lines_discards_torn_record is the emit_vendor_bytes torn drop and is not this api.repair. The old pin has no api.repair vector and is not a Covered source",
        ),
    },
    Row {
        name: "test_api_repair_vendor_emit_canonical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_repair_vendor_emit_canonical: api.repair with emit canonical has adapter_id canonical, and the first output line has schema_version sesslint.session/v1. It does not assert the rest of the header. missing stop: that adapter and that schema version together. The vendor write-back repair is not this canonical emit. test_api_repair_vendor_torn_writeback is the vendor write-back repair and is not this canonical emit. The old pin has no api.repair vector and is not a Covered source",
        ),
    },
    Row {
        name: "test_api_verify_vendor_pair",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_api_verify_vendor_pair: api.repair then api.verify on the torn source, the output, and the adjacent manifest has verdict.ok true. It does not assert the output bytes. missing stop: that verify call and that ok flag together. The canonical emit is not this verify. test_api_repair_vendor_emit_canonical is the canonical emit and is not this verify. The old pin has no api.verify vector and is not a Covered source",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_writeback_identity_passthrough",
    "test_writeback_drops_line_when_all_events_dropped",
    "test_writeback_refuses_synthesized_event_r1",
    "test_writeback_refuses_partial_line_r2",
    "test_writeback_refuses_rewritten_event_r3",
    "test_writeback_refuses_source_drift_r4",
    "test_writeback_refuses_reorder_r5",
    "test_writeback_refuses_single_doc_json_r6",
    "test_single_jsonl_record_and_interior_cr_are_preserved",
    "test_writeback_refuses_unsupported_format_r6",
    "test_writeback_drop_lines_discards_torn_record",
    "test_writeback_keeps_uninterpreted_lines",
    "test_api_repair_vendor_torn_writeback",
    "test_api_repair_vendor_emit_canonical",
    "test_api_verify_vendor_pair",
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
fn pinned_repair_test_writeback_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 274);
}

#[test]
fn pinned_repair_test_writeback_row_count_equals_fifteen() {
    assert_eq!(ROWS.len(), 15);
    assert_eq!(PINNED_TEST_COUNT, 15);
    assert_eq!(PINNED_NAMES.len(), 15);
}

#[test]
fn every_pinned_repair_test_writeback_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 15);
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
    // `parity/vectors/cli/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "cli vectors python_commit spacing does not match {needle}"
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
    assert_eq!(not_applicable, 15);

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
