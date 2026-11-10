//! Dispositions for the eleven `def test_` functions in pinned
//! `tests/adapters/test_modern_metadata.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (173 splitlines). Exactly
//! eleven test functions, in module order. Five are parametrized: the
//! identifier keys, every `SESSION_METADATA_TYPES` member, the system
//! subtypes, the unknown-metadata vendors, and the nested-semantics vendors
//! with fields. That last function is the one with two parametrize
//! decorators. A parametrized function is one row covering every cell. The
//! `FIXTURES` path and the imports are not tests. Each row is the whole
//! function. A detect is not a load. A load is not check_file. check_file is
//! not repair. One vendor is not both vendors. One field is not all five
//! fields. One phase is not the three-phase function. Session lines, tool
//! output, and fixture bytes are not copied here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call adapter or api functions
//! without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin, including every cell. `parity/vectors/cli/vectors.json`
//! has 33 parser-metadata vectors at this pin and none is one of these
//! functions. `parity/vectors/api/vectors.json` is at this pin with 77 ids
//! for envelopes, directory limits, discovery, module constants, plan and
//! repair rejection, thresholds, and validate_session. None of those 77 is
//! one of these eleven functions.
//! `parity/vectors/adapters.metadata/vectors.json` has 123 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`, including bookkeeping keys,
//! semantic keys, and `tracker_exactly_thirty_two_groups`. That corpus is not
//! a Covered source. `adapters.claude_code`, `adapters.codex_rollout`, and
//! `adapters.detect` are the same old pin and are not Covered sources.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const PINNED_SPLITLINES: usize = 173;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin, including every cell. A detect is not a load. A load
/// is not check_file. check_file is not repair. One vendor is not both
/// vendors. One field is not all five fields. One phase is not the
/// three-phase function. `not_applicable` names the missing stop.
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
        name: "test_session_identifier_alone_cannot_select_a_vendor",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_session_identifier_alone_cannot_select_a_vendor: both keys, sessionId and session_id, are one row; detect_format is None, the limitation starts with Unsupported:, and findings are empty; missing stop: those assertions together; both keys are one row; one key is not both keys; a detect is not a load; the custom-title detection is not this pytest; test_known_claude_metadata_can_identify_a_session is that detection",
        ),
    },
    Row {
        name: "test_known_claude_metadata_can_identify_a_session",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_known_claude_metadata_can_identify_a_session: a custom-title record detects as claude-code-jsonl; it does not assert findings; missing stop: that detection; that detection is the row; a detect is not a load; the identifier-only test is not this pytest; test_session_identifier_alone_cannot_select_a_vendor is that test; the record is not copied here",
        ),
    },
    Row {
        name: "test_known_claude_metadata_is_not_a_graph_node",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_known_claude_metadata_is_not_a_graph_node: every member of SESSION_METADATA_TYPES is one row, the eleven sorted members agent-name, atis-latch, cost-state, custom-title, file-history-delta, file-history-snapshot, last-prompt, mode, permission-mode, pr-link, and queue-operation; the user event id remains and there are no findings; missing stop: every member together with the remaining user event id and empty findings; one member is not this pytest; a load is not check_file; a metadata record that has its own uuid is not this pytest; test_known_metadata_with_uuid_preserves_chain_node is that record; the user line is not copied here",
        ),
    },
    Row {
        name: "test_known_metadata_with_uuid_preserves_chain_node",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_known_metadata_with_uuid_preserves_chain_node: a queue-operation record with a uuid is one opaque event and there are no findings; missing stop: that opaque event together with empty findings; that record is the row; a load is not check_file; the graph-node test is not this pytest; test_known_claude_metadata_is_not_a_graph_node is that test",
        ),
    },
    Row {
        name: "test_claude_compaction_uses_logical_parent_and_opaque_attachment",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_claude_compaction_uses_logical_parent_and_opaque_attachment: the load has no SL302, and the last two events are a compaction boundary then an opaque attachment with their fixture parents; the check has none of SL004, SL006, SL007, or SL302; missing stop: both calls together; both calls are one row; a load is not check_file; the native continuation test is not this pytest; test_claude_native_compaction_allows_fully_paired_continuation is that test; the fixture is not copied here",
        ),
    },
    Row {
        name: "test_claude_native_compaction_allows_fully_paired_continuation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_claude_native_compaction_allows_fully_paired_continuation: three phases are one row; the complete file has no SL102 or SL203 and skips SL203 with reason adapter-not-applicable; after a torn append, repair writes the complete bytes back and the manifest is present; after the result row is removed, check finds SL102; missing stop: those three phases together; one phase is not this pytest; one phase is not the three-phase function; check_file is not repair; the fixture compaction test is not this pytest; test_claude_compaction_uses_logical_parent_and_opaque_attachment is that test; the records are not copied here",
        ),
    },
    Row {
        name: "test_system_metadata_is_transparent_to_tool_pairing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_system_metadata_is_transparent_to_tool_pairing: both subtypes, stop_hook_summary and local_command, are one row; a claude-strict check finds neither SL107 nor SL302; missing stop: both subtypes together; both subtypes are one row; one subtype is not both subtypes; the unknown-metadata advisory is not this pytest; test_unknown_metadata_is_bounded_info is that advisory",
        ),
    },
    Row {
        name: "test_unknown_metadata_is_bounded_info",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_metadata_is_bounded_info: both vendors are one row; each report has one SL306 at info, the count is 2 for claude and 1 for codex, SL302 is absent, and the planted word is absent from the evidence; missing stop: both vendors together; one vendor is not both vendors; a load is not check_file; the nested-field test is not this pytest; test_unknown_record_with_nested_semantics_stays_critical is that load; the fixture is not copied here",
        ),
    },
    Row {
        name: "test_unknown_record_with_nested_semantics_stays_critical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_record_with_nested_semantics_stays_critical: both vendors and all five fields, id, parentUuid, call_id, content, and critical_state, are one row of ten cells; each load finds SL302 and not SL306; missing stop: those ten cells together; one vendor is not both vendors; one field is not all five fields; a load is not check_file; the bounded-info test is not this pytest; test_unknown_metadata_is_bounded_info is that check; the nested record is not copied here",
        ),
    },
    Row {
        name: "test_retained_context_is_opaque_non_durable_and_does_not_pair",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_retained_context_is_opaque_non_durable_and_does_not_pair: the third event is opaque, actor system, correlation id none, the codex durable flag is false, and questions are absent from the payload; the load has no SL302; the openai-strict check has none of SL101, SL102, SL107, or SL302; missing stop: both calls together; both calls are one row; a load is not check_file; the tracker bound is not this pytest; test_unknown_type_groups_have_a_fixed_memory_bound is that tracker; the fixture is not copied here",
        ),
    },
    Row {
        name: "test_unknown_type_groups_have_a_fixed_memory_bound",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_unknown_type_groups_have_a_fixed_memory_bound: two hundred notes produce 33 findings whose counts sum to 200; missing stop: both numbers together; both numbers are one row; a vector about thirty-two groups is not this pytest; tracker_exactly_thirty_two_groups is not this pytest",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_session_identifier_alone_cannot_select_a_vendor",
    "test_known_claude_metadata_can_identify_a_session",
    "test_known_claude_metadata_is_not_a_graph_node",
    "test_known_metadata_with_uuid_preserves_chain_node",
    "test_claude_compaction_uses_logical_parent_and_opaque_attachment",
    "test_claude_native_compaction_allows_fully_paired_continuation",
    "test_system_metadata_is_transparent_to_tool_pairing",
    "test_unknown_metadata_is_bounded_info",
    "test_unknown_record_with_nested_semantics_stays_critical",
    "test_retained_context_is_opaque_non_durable_and_does_not_pair",
    "test_unknown_type_groups_have_a_fixed_memory_bound",
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
fn pinned_test_modern_metadata_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 173);
}

#[test]
fn pinned_test_modern_metadata_row_count_equals_eleven() {
    assert_eq!(ROWS.len(), 11);
    assert_eq!(PINNED_TEST_COUNT, 11);
    assert_eq!(PINNED_NAMES.len(), 11);
}

#[test]
fn every_pinned_test_modern_metadata_test_has_one_disposition() {
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
            "cli id {id} is one of the eleven functions"
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
        assert!(
            !names.contains(id),
            "api id {id} is one of the eleven functions"
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
