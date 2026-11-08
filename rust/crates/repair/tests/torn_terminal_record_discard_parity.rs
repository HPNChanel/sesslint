//! Parity for torn-terminal-record-discard against pinned Python vectors.
//!
//! Expected values are the pin's results. No pinned test is only this
//! function, so covered_count stays 0. A plan, a fixture diff, a payload,
//! and a kept SessionEvent copy are not covered.

use model::canonical::{
    SessionEvent, CANONICAL_JSON_BYTES_UNAVAILABLE, NORMALIZE_CANONICAL_UNAVAILABLE,
};
use model::events::{EventField, EventMapping, EventValue};
use repair::planner::{
    plan, PlanPolicy, PlanProfile, SourceHashEvent, EMPTY_EVENTS_HASH,
    RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
};
use repair::recipes_sl002::{
    affected_region_torn_terminal_record_discard, apply_torn_terminal_record_discard,
    recipe_torn_terminal_record_discard, StepParams, StepScalar, TornDiscardError,
    TornTerminalStep, AFFECTED_REGION_UNAVAILABLE,
};
use repair::registry::CallableId;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_NAME: &str = "vectors.json";
const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PY_SHA: &str = "535f3226281b68d39c62508d88afe3d85b9231c19f247246a0a939542f7e82a8";
const EXPECTED_VECTOR_COUNT: usize = 25;
const EXPECTED_COVERED: usize = 0;
const EXPECTED_NOT_APPLICABLE: usize = 22;
const EXPECTED_VECTORS_SHA256: &str =
    "012b8ce665fb902f160f9f05cd97a039a7309ec20a6df9bbc38bf92e73612d3c";
const EXPECTED_COVERAGE_SHA256: &str =
    "340acead6410f0180a6b958defe65f00fe67640e20f605be7746d13390c8fe74";
const FN: &str = "apply_torn_terminal_record_discard";
const RECIPE_FN: &str = "RECIPE_TORN_TERMINAL_RECORD_DISCARD";
const POP_MESSAGE: &str = "pop from empty list";
const GAP_CANONICAL: &str = "GAP-torn-terminal-record-discard-canonical";
const GAP_COPY: &str = "GAP-torn-terminal-record-discard-session-copy";
const GAP_PAYLOAD: &str = "GAP-torn-terminal-record-discard-payload";
const GAP_FLOAT: &str = "GAP-torn-terminal-record-discard-float-target";
const GAP_MISSING: &str = "GAP-torn-terminal-record-discard-missing-attr";
const GAP_SWEEP: &str = "GAP-torn-terminal-record-discard-sweep";
const GAP_DICT: &str = "GAP-torn-terminal-record-discard-dict-fallback";
const SEAM_REGION: &str = AFFECTED_REGION_UNAVAILABLE;
const SEAM_DETERMINISM: &str = "sesslint.determinism.canonical_json_bytes is not available";
const SEAM_REGISTER: &str = RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE;
const VECTOR_IDS: [&str; 25] = [
    "recipe_torn_terminal_record_discard",
    "discard_named_last",
    "reader_minted_keeps",
    "shared_id_discards_last",
    "shared_id_index_zero_keeps",
    "bool_cut_keeps",
    "bool_true_discards_index_one",
    "bool_false_clears_singleton",
    "bool_true_keeps_singleton",
    "not_mapping_keeps",
    "other_target_keeps",
    "ignores_region_fallback",
    "duplicate_cut_last_wins",
    "float_cut_keeps",
    "string_cut_keeps",
    "list_cut_keeps",
    "cut_past_end_keeps",
    "negative_cut_keeps",
    "target_mismatch_keeps",
    "missing_cut_keeps",
    "null_cut_keeps",
    "empty_no_cut_keeps",
    "empty_zero_is_not_pop",
    "other_target_empty_is_not_pop",
    "empty_pop",
];
const COVERAGE_TESTS: [&str; 22] = [
    "tests/io/test_hostile.py::test_canonical_torn_final_repairable",
    "tests/io/test_hostile.py::test_hostile_repair_refusal_on_non_repairable",
    "tests/test_sl001_sl002.py::test_sl002_repair_round_trip",
    "tests/test_e2e_cycle.py::test_e2e_cycle_canonical_torn_terminal_record",
    "tests/test_e2e_cycle.py::test_e2e_vendor_format_writeback",
    "tests/cli/test_repair_cli.py::test_repair_cli_sl002_success",
    "tests/repair/test_torn_tail_identity.py::test_canonical_torn_tail_keeps_event_with_same_id",
    "tests/repair/test_torn_tail_identity.py::test_vendor_torn_tail_keeps_line_with_same_id",
    "tests/fuzz/test_repair_invariants.py::test_conservative_torn_tail_preserves_every_unique_decodable_record",
    "tests/repair/test_scoped_abstention.py::test_positive_e2e_realistic_tool_session_repaired",
    "tests/adapters/test_codex_rollout.py::test_repair_auto_emits_vendor_writeback",
    "tests/repair/test_writeback.py::test_api_repair_vendor_torn_writeback",
    "tests/repair/test_writeback.py::test_api_repair_vendor_emit_canonical",
    "tests/repair/test_writeback.py::test_api_verify_vendor_pair",
    "tests/repair/test_snapshot_consistency.py::test_write_back_keeps_line_the_current_bytes_no_longer_flag",
    "tests/repair/test_scoped_abstention.py::test_scenario_2_dangling_call_in_truncated_region",
    "tests/fuzz/test_repair_invariants.py::test_resealed_tampered_plan_is_refused_at_every_public_execution_boundary",
    "tests/export/test_export.py::test_export_refuses_torn_final",
    "tests/repair/test_scoped_abstention.py::test_region_functions_totality_fuzz",
    "tests/adapters/test_claude_code.py::test_torn_tail_SL002",
    "tests/adapters/test_claude_code.py::test_regression_encoding_sl001_mid_and_sl002_tail",
    "tests/repair/test_scoped_abstention.py::test_scenario_4_ambiguous_call_adjacent_but_outside_region_boundary_pin",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseKind {
    Recipe,
    Ok,
    Index,
}

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

#[derive(Debug, Clone)]
struct CoverageRow {
    test: String,
    column: String,
    status: String,
    note: String,
    vector_id_null: bool,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../parity/recipes/torn-terminal-record-discard")
}

fn read_lf(path: &Path) -> String {
    let raw = std::fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains(&b'\r'), "{} contains CR", path.display());
    let text =
        String::from_utf8(raw).unwrap_or_else(|err| panic!("utf-8 {}: {err}", path.display()));
    for seam in [
        SEAM_REGION,
        SEAM_DETERMINISM,
        SEAM_REGISTER,
        CANONICAL_JSON_BYTES_UNAVAILABLE,
        NORMALIZE_CANONICAL_UNAVAILABLE,
        "Python str(float) is not representable",
        "Python str() of this event field is not representable",
    ] {
        assert!(!text.contains(seam), "{} stores {seam}", path.display());
    }
    assert!(
        !text.contains("sesslint-wt"),
        "{} stores a worktree path",
        path.display()
    );
    assert!(
        !text.contains("FOR_WORK"),
        "{} stores a checkout path",
        path.display()
    );
    assert!(
        !text.contains("02694d5"),
        "{} names the wrong pin",
        path.display()
    );
    assert!(
        !text.contains("\"payload\""),
        "{} stores a payload field",
        path.display()
    );
    assert!(
        !text.contains("0 diff"),
        "{} claims a zero diff",
        path.display()
    );
    assert!(
        !text.contains(EMPTY_EVENTS_HASH),
        "{} stores a fingerprint",
        path.display()
    );
    assert!(
        !contains_sbp(&text),
        "{} stores an sbp hash",
        path.display()
    );
    text
}

fn contains_sbp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(rel) = text[start..].find("sbp_") {
        let at = start + rel + 4;
        if bytes[at..].len() >= 40
            && bytes[at..at + 40]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return true;
        }
        start = at;
    }
    false
}

#[test]
fn torn_terminal_record_discard_parity_vectors() {
    let dir = parity_dir();
    let vectors_raw = read_lf(&dir.join(VECTORS_NAME));
    let digest = sha256_hex(vectors_raw.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256");
    for gap in [
        GAP_CANONICAL,
        GAP_COPY,
        GAP_PAYLOAD,
        GAP_FLOAT,
        GAP_MISSING,
        GAP_SWEEP,
        GAP_DICT,
    ] {
        assert!(vectors_raw.contains(gap), "{gap}");
    }
    let cases = parse_cases(&vectors_raw).unwrap_or_else(|err| panic!("parse vectors: {err}"));
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT);
    assert_eq!(VECTOR_IDS.len(), EXPECTED_VECTOR_COUNT);
    let mut entire = 0_usize;
    let mut recipes = 0_usize;
    let mut oks = 0_usize;
    let mut indexes = 0_usize;
    for (case, ident) in cases.iter().zip(VECTOR_IDS) {
        assert_eq!(case.id, ident);
        assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
        entire += usize::from(bool_field(&case.construct, "entire_test").expect("entire_test"));
        match assert_case(case) {
            CaseKind::Recipe => recipes += 1,
            CaseKind::Ok => oks += 1,
            CaseKind::Index => indexes += 1,
        }
    }
    assert_eq!(entire, EXPECTED_COVERED);
    assert_eq!(recipes, 1);
    assert_eq!(oks, 23);
    assert_eq!(indexes, 1);
    assert_manifest(&read_lf(&dir.join("manifest.json")), &digest);
    assert_provenance(&read_lf(&dir.join("PROVENANCE.json")));
    assert_bool_is_not_int();
    assert_no_float_target(&cases);
    assert_no_invented_errors(&cases);
}

#[test]
fn torn_terminal_record_discard_coverage_names_the_gaps() {
    let dir = parity_dir();
    let raw = read_lf(&dir.join("coverage.json"));
    assert_eq!(sha256_hex(raw.as_bytes()), EXPECTED_COVERAGE_SHA256);
    let (covered, rows) = parse_coverage(&raw).unwrap_or_else(|err| panic!("coverage: {err}"));
    assert_eq!(covered, EXPECTED_COVERED);
    assert_eq!(rows.len(), EXPECTED_NOT_APPLICABLE);
    assert_eq!(COVERAGE_TESTS.len(), EXPECTED_NOT_APPLICABLE);
    for (row, test) in rows.iter().zip(COVERAGE_TESTS) {
        assert_eq!(row.test, test);
        assert_eq!(row.column, "column_0");
        assert_eq!(row.status, "not_applicable");
        assert!(row.vector_id_null, "{}", row.test);
        assert!(!row.note.is_empty(), "{}", row.test);
        assert!(!row.note.contains("0 diff"), "{}", row.test);
        assert!(!row.note.contains(SEAM_REGION), "{}", row.test);
        assert!(!row.test.contains("test_sl001_excision"), "{}", row.test);
        assert!(!row.test.contains("torn-record-excision"), "{}", row.test);
    }
    note_has(
        &rows,
        "tests/repair/test_torn_tail_identity.py::test_canonical_torn_tail_keeps_event_with_same_id",
        "target_index is None",
    );
    note_has(
        &rows,
        "tests/repair/test_scoped_abstention.py::test_scenario_2_dangling_call_in_truncated_region",
        "before apply_torn_terminal_record_discard",
    );
    note_has(
        &rows,
        "tests/fuzz/test_repair_invariants.py::test_resealed_tampered_plan_is_refused_at_every_public_execution_boundary",
        "before apply_torn_terminal_record_discard",
    );
    note_has(
        &rows,
        "tests/repair/test_scoped_abstention.py::test_region_functions_totality_fuzz",
        "five-function",
    );
    note_has(
        &rows,
        "tests/export/test_export.py::test_export_refuses_torn_final",
        "does not call",
    );
    note_has(
        &rows,
        "tests/io/test_hostile.py::test_hostile_repair_refusal_on_non_repairable",
        "skips it",
    );
    note_has(
        &rows,
        "tests/repair/test_scoped_abstention.py::test_scenario_4_ambiguous_call_adjacent_but_outside_region_boundary_pin",
        "not called",
    );
    assert!(!raw.contains("\"status\": \"covered\""));
    let vectors = read_lf(&dir.join(VECTORS_NAME));
    assert!(vectors.contains("torn-record-excision"));
    assert!(!vectors.contains("apply_torn_record_excision"));
}

#[test]
fn torn_terminal_record_discard_session_copy_is_not_ok() {
    let err = apply_torn_terminal_record_discard(
        vec![EventValue::from_session(sample_session())],
        int_step(0, 0),
    )
    .expect_err("session copy");
    assert!(matches!(err, TornDiscardError::Copy(_)));
    assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
    assert!(err.source().is_some());
    assert_ne!(err.to_string(), POP_MESSAGE);
}

#[test]
fn torn_terminal_record_discard_other_is_a_different_error() {
    let err = apply_torn_terminal_record_discard(vec![EventValue::Other], int_step(0, 0))
        .expect_err("other");
    assert!(matches!(err, TornDiscardError::Copy(_)));
    assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
    assert_ne!(err.to_string(), POP_MESSAGE);
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(raw.contains(GAP_DICT));
    assert!(!raw.contains("\"error_type\": \"ValueError\""));
    assert!(!raw.contains("\"error_type\": \"TypeError\""));
    assert!(!raw.contains("\"error_type\": \"AttributeError\""));
}

#[test]
fn torn_terminal_record_discard_plan_is_not_a_fingerprint() {
    let findings: &[model::finding::Finding] = &[];
    let session = [SourceHashEvent::Session(Box::new(sample_session()))];
    let session_err = plan(
        findings,
        &session,
        &PlanProfile::str_value("neutral"),
        None,
        &PlanPolicy::str_value("conservative"),
        false,
        None,
    )
    .expect_err("session plan");
    assert_eq!(session_err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE);
    assert_ne!(session_err.to_string(), EMPTY_EVENTS_HASH);
    assert!(!session_err.to_string().contains("diff"));
    let empty_err = plan(
        findings,
        &[],
        &PlanProfile::str_value("neutral"),
        None,
        &PlanPolicy::str_value("conservative"),
        false,
        None,
    )
    .expect_err("empty plan");
    assert_eq!(
        empty_err.to_string(),
        RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
    );
    assert_ne!(empty_err.to_string(), EMPTY_EVENTS_HASH);
    assert_ne!(empty_err.to_string().len(), 64);
}

#[test]
fn torn_terminal_record_discard_float_target_is_not_claimed() {
    let kept = apply_torn_terminal_record_discard(two_events(), other_step(1))
        .expect("float-shaped target keeps");
    assert_eq!(kept.len(), 2);
    let empty = apply_torn_terminal_record_discard(Vec::new(), other_step(-1))
        .expect("float-shaped empty target is Ok");
    assert!(empty.is_empty());
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(raw.contains(GAP_FLOAT));
    assert!(raw.contains(GAP_MISSING));
}

#[test]
fn torn_terminal_record_discard_region_is_not_this_function() {
    let err = affected_region_torn_terminal_record_discard(int_step(1, 1), two_events())
        .expect_err("region");
    assert_eq!(err.to_string(), AFFECTED_REGION_UNAVAILABLE);
    let recipe = recipe_torn_terminal_record_discard().expect("recipe");
    assert_ne!(recipe.apply(), recipe.affected_region());
}

fn note_has(rows: &[CoverageRow], test: &str, needle: &str) {
    let row = rows.iter().find(|item| item.test == test).expect(test);
    assert!(row.note.contains(needle), "{test} missing {needle}");
}

fn sample_session() -> SessionEvent {
    SessionEvent::new(
        "evt-kept",
        None,
        0,
        "1970-01-01T00:00:00Z",
        "user",
        "message",
    )
}

fn int_step(target: i64, cut: i64) -> TornTerminalStep {
    TornTerminalStep {
        target_index: StepScalar::Int(target),
        params: StepParams::Mapping(EventMapping::new(vec![(
            "cut_index".to_owned(),
            EventField::Int(cut),
        )])),
    }
}

fn other_step(cut: i64) -> TornTerminalStep {
    TornTerminalStep {
        target_index: StepScalar::Other,
        params: StepParams::Mapping(EventMapping::new(vec![(
            "cut_index".to_owned(),
            EventField::Int(cut),
        )])),
    }
}

fn two_events() -> Vec<EventValue> {
    vec![
        EventValue::Mapping(message_event("evt-a", 0)),
        EventValue::Mapping(message_event("evt-b", 1)),
    ]
}

fn message_event(id: &str, seq: i64) -> EventMapping {
    EventMapping::new(vec![
        ("id".to_owned(), EventField::Str(id.to_owned())),
        ("kind".to_owned(), EventField::Str("message".to_owned())),
        ("seq".to_owned(), EventField::Int(seq)),
    ])
}

fn assert_case(case: &VectorCase) -> CaseKind {
    let kind = string_field(&case.construct, "type").expect("type");
    match kind.as_str() {
        "recipe_constant" => {
            assert_recipe(case);
            CaseKind::Recipe
        }
        "apply_ok" => {
            assert_apply_ok(case);
            CaseKind::Ok
        }
        "apply_index_error" => {
            assert_apply_index(case);
            CaseKind::Index
        }
        other => panic!("{} unexpected construct {other}", case.id),
    }
}

fn assert_recipe(case: &VectorCase) {
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), RECIPE_FN);
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "recipe"
    );
    let recipe = recipe_torn_terminal_record_discard().expect("recipe");
    assert_eq!(
        recipe.name(),
        string_field(&case.expected, "name").expect("name")
    );
    let handles = string_array(&case.expected, "handles").expect("handles");
    assert_eq!(recipe.handles(), handles.as_slice());
    let preconditions = string_array(&case.expected, "preconditions").expect("preconditions");
    assert_eq!(recipe.preconditions(), preconditions.as_slice());
    assert_eq!(
        recipe.lossy(),
        bool_field(&case.expected, "lossy").expect("lossy")
    );
    assert_eq!(
        recipe.salvage_only(),
        bool_field(&case.expected, "salvage_only").expect("salvage")
    );
    assert_eq!(
        recipe.min_policy(),
        string_field(&case.expected, "min_policy").expect("policy")
    );
    assert_eq!(
        recipe.version(),
        string_field(&case.expected, "version").expect("version")
    );
    assert_eq!(
        recipe.excludes_execution_dependence(),
        bool_field(&case.expected, "excludes_execution_dependence").expect("excludes")
    );
    assert!(bool_field(&case.expected, "apply_present").expect("apply_present"));
    assert!(bool_field(&case.expected, "affected_region_present").expect("region_present"));
    assert_eq!(
        recipe.apply(),
        Some(CallableId::from_fn(apply_torn_terminal_record_discard))
    );
    assert_eq!(
        recipe.affected_region(),
        Some(CallableId::from_fn(
            affected_region_torn_terminal_record_discard
        ))
    );
}

fn assert_apply_ok(case: &VectorCase) {
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), FN);
    assert_eq!(
        usize_field(&case.construct, "assert_count").expect("assert_count"),
        1
    );
    assert_eq!(string_field(&case.expected, "mode").expect("mode"), "ok");
    let events = decode_events(array_field(&case.construct, "events").expect("events"));
    let step = decode_step(object_field(&case.construct, "step").expect("step"));
    let got = apply_torn_terminal_record_discard(events.clone(), step.clone())
        .unwrap_or_else(|err| panic!("{} returned {err}", case.id));
    let want = array_field(&case.expected, "events_out").expect("events_out");
    assert_mappings(&got, want);
    assert!(got.len() <= events.len(), "{}", case.id);
    assert_named_ok(case.id.as_str(), &events, &step, &got);
}

fn assert_named_ok(id: &str, events: &[EventValue], step: &TornTerminalStep, got: &[EventMapping]) {
    match id {
        "discard_named_last"
        | "shared_id_discards_last"
        | "bool_true_discards_index_one"
        | "duplicate_cut_last_wins" => {
            assert_eq!(got.len() + 1, events.len(), "{id}");
        }
        "bool_false_clears_singleton" => {
            assert_eq!(events.len(), 1);
            assert!(got.is_empty());
            assert!(matches!(step.target_index, StepScalar::Bool(false)));
        }
        "bool_cut_keeps" => {
            assert!(matches!(cut_field(step), Some(EventField::Bool(_))));
            assert_eq!(got.len(), events.len());
        }
        "bool_true_keeps_singleton" => {
            assert!(matches!(step.target_index, StepScalar::Bool(true)));
            assert_eq!(got.len(), events.len());
        }
        "float_cut_keeps" => {
            assert!(matches!(cut_field(step), Some(EventField::Float(_))));
            assert_eq!(got.len(), events.len());
        }
        "list_cut_keeps" => {
            assert!(matches!(cut_field(step), Some(EventField::List(_))));
            assert_eq!(got.len(), events.len());
        }
        "string_cut_keeps" => {
            assert!(matches!(cut_field(step), Some(EventField::Str(_))));
            assert_eq!(got.len(), events.len());
        }
        "null_cut_keeps" => {
            assert!(matches!(cut_field(step), Some(EventField::Null)));
            assert_eq!(got.len(), events.len());
        }
        "not_mapping_keeps" | "empty_no_cut_keeps" => {
            assert!(matches!(step.params, StepParams::NotMapping));
        }
        "other_target_keeps" | "other_target_empty_is_not_pop" => {
            assert!(matches!(step.target_index, StepScalar::Other));
        }
        "reader_minted_keeps" => {
            assert!(matches!(step.target_index, StepScalar::None));
            assert_eq!(got.len(), events.len());
        }
        "empty_zero_is_not_pop" => {
            assert!(events.is_empty());
            assert!(got.is_empty());
            assert!(matches!(step.target_index, StepScalar::Int(0)));
            assert!(matches!(cut_field(step), Some(EventField::Int(0))));
        }
        "missing_cut_keeps" => {
            assert!(cut_field(step).is_none());
            assert_eq!(got.len(), events.len());
        }
        _ => {}
    }
    if id == "duplicate_cut_last_wins" {
        let StepParams::Mapping(params) = &step.params else {
            panic!("duplicate cut params");
        };
        let cuts = params
            .entries()
            .iter()
            .filter(|(key, _)| key == "cut_index")
            .count();
        assert_eq!(cuts, 2);
        assert!(matches!(params.get("cut_index"), Some(EventField::Int(1))));
    }
}

fn assert_apply_index(case: &VectorCase) {
    assert_eq!(case.id, "empty_pop");
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), FN);
    assert_eq!(
        usize_field(&case.construct, "assert_count").expect("assert_count"),
        1
    );
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "index_error"
    );
    assert_eq!(
        string_field(&case.expected, "error_type").expect("error_type"),
        "IndexError"
    );
    assert_eq!(
        string_field(&case.expected, "message").expect("message"),
        POP_MESSAGE
    );
    let events = decode_events(array_field(&case.construct, "events").expect("events"));
    assert!(events.is_empty());
    let step = decode_step(object_field(&case.construct, "step").expect("step"));
    assert!(matches!(step.target_index, StepScalar::Int(-1)));
    assert!(matches!(cut_field(&step), Some(EventField::Int(-1))));
    let err = apply_torn_terminal_record_discard(events, step).expect_err("empty pop");
    assert!(matches!(err, TornDiscardError::EmptyPop));
    assert_eq!(err.to_string(), POP_MESSAGE);
    assert!(err.source().is_none());
}

fn cut_field(step: &TornTerminalStep) -> Option<&EventField> {
    match &step.params {
        StepParams::Mapping(mapping) => mapping.get("cut_index"),
        StepParams::NotMapping => None,
    }
}

fn assert_no_float_target(cases: &[VectorCase]) {
    for case in cases {
        if case.id == "recipe_torn_terminal_record_discard" {
            continue;
        }
        let step = object_field(&case.construct, "step").expect("step");
        let target = as_object(field_ref(step, "target_index"), "target").expect("target");
        assert_ne!(
            string_field(target, "t").expect("target tag"),
            "float",
            "{}",
            case.id
        );
    }
}

fn assert_no_invented_errors(cases: &[VectorCase]) {
    for case in cases {
        let mode = string_field(&case.expected, "mode").expect("mode");
        assert!(
            matches!(mode.as_str(), "ok" | "recipe" | "index_error"),
            "{}",
            case.id
        );
        if let Some(kind) = optional_string(&case.expected, "error_type") {
            assert_eq!(kind, "IndexError");
            assert_eq!(case.id, "empty_pop");
        }
    }
}

fn assert_manifest(raw: &str, digest: &str) {
    let (value, rest) =
        parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("manifest: {err}"));
    assert!(rest.trim().is_empty(), "manifest trailing");
    let obj = as_object(&value, "manifest").expect("manifest object");
    assert_eq!(
        usize_field(obj, "vector_count").expect("vector_count"),
        EXPECTED_VECTOR_COUNT
    );
    assert_eq!(
        string_field(obj, "vectors_sha256").expect("vectors_sha256"),
        digest
    );
    assert_eq!(
        string_field(obj, "generator").expect("generator"),
        "rust/parity/recipes/torn-terminal-record-discard/generate"
    );
    assert_eq!(string_field(obj, "python_commit").expect("pin"), PIN);
    assert_eq!(
        string_field(obj, "recipes_sl002_py_sha256").expect("py sha"),
        PY_SHA
    );
    assert_eq!(
        string_field(obj, "recipe").expect("recipe"),
        "torn-terminal-record-discard"
    );
    assert_gap_list(obj);
}

fn assert_provenance(raw: &str) {
    let (value, rest) =
        parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("provenance: {err}"));
    assert!(rest.trim().is_empty(), "provenance trailing");
    let obj = as_object(&value, "provenance").expect("provenance object");
    assert!(!bool_field(obj, "contains_real_data").expect("contains_real_data"));
    assert_eq!(string_field(obj, "origin").expect("origin"), "synthetic");
    assert_eq!(string_field(obj, "python_commit").expect("pin"), PIN);
    let description = string_field(obj, "description").expect("description");
    assert!(description.contains("Synthetic"));
    assert!(description.contains("No fixture diff is stored"));
    assert!(!description.contains("0 diff"));
    assert_gap_list(obj);
}

fn assert_bool_is_not_int() {
    let tagged = JsonValue::Object(vec![
        ("t".to_owned(), JsonValue::Str("int".to_owned())),
        ("v".to_owned(), JsonValue::Bool(true)),
    ]);
    let obj = as_object(&tagged, "int").expect("int object");
    let err = int_field(obj, "v").expect_err("bool is not an int");
    assert!(err.to_string().contains("bool is not an int"));
}

fn assert_gap_list(obj: &[(String, JsonValue)]) {
    let gaps = array_field(obj, "known_parity_gaps").expect("known_parity_gaps");
    let mut saw = [false; 7];
    let names = [
        GAP_CANONICAL,
        GAP_COPY,
        GAP_PAYLOAD,
        GAP_FLOAT,
        GAP_MISSING,
        GAP_SWEEP,
        GAP_DICT,
    ];
    assert_eq!(gaps.len(), names.len());
    for gap in gaps {
        let JsonValue::Str(text) = gap else {
            panic!("gap must be a string");
        };
        assert!(!text.contains(SEAM_REGION), "{text}");
        assert!(!text.contains(SEAM_DETERMINISM), "{text}");
        assert!(!text.contains(SEAM_REGISTER), "{text}");
        assert!(!text.contains(CANONICAL_JSON_BYTES_UNAVAILABLE), "{text}");
        assert!(!text.contains(NORMALIZE_CANONICAL_UNAVAILABLE), "{text}");
        assert!(!text.contains("0 diff"), "{text}");
        assert!(!text.contains(EMPTY_EVENTS_HASH), "{text}");
        for (flag, name) in saw.iter_mut().zip(names) {
            *flag |= text.contains(name);
        }
    }
    assert!(saw.iter().all(|flag| *flag));
}

fn assert_mappings(got: &[EventMapping], want: &[JsonValue]) {
    assert_eq!(got.len(), want.len());
    for (event, tag) in got.iter().zip(want) {
        let EventField::Mapping(expected) = decode_field(tag).expect("mapped event") else {
            panic!("expected a map");
        };
        assert!(
            event.get("payload").is_none(),
            "session payload in a vector"
        );
        if let Some(EventField::Str(id)) = event.get("id") {
            assert!(id.starts_with("evt-"), "{id}");
        }
        assert_eq!(event, &expected);
    }
}

fn decode_events(items: &[JsonValue]) -> Vec<EventValue> {
    items
        .iter()
        .map(|item| {
            let EventField::Mapping(mapping) = decode_field(item).expect("event map") else {
                panic!("event must be a map");
            };
            assert!(
                mapping.get("payload").is_none(),
                "session payload in a vector"
            );
            EventValue::Mapping(mapping)
        })
        .collect()
}

fn decode_step(step: &[(String, JsonValue)]) -> TornTerminalStep {
    TornTerminalStep {
        target_index: decode_scalar(field_ref(step, "target_index")),
        params: decode_params(field_ref(step, "params")),
    }
}

fn decode_scalar(value: &JsonValue) -> StepScalar {
    let obj = as_object(value, "target_index").expect("target object");
    match string_field(obj, "t").expect("target tag").as_str() {
        "null" => StepScalar::None,
        "int" => StepScalar::Int(int_field(obj, "v").expect("target int")),
        "bool" => StepScalar::Bool(bool_field(obj, "v").expect("target bool")),
        "other" => StepScalar::Other,
        "float" => panic!("float target is a named gap"),
        other => panic!("target tag {other}"),
    }
}

fn decode_params(value: &JsonValue) -> StepParams {
    let obj = as_object(value, "params").expect("params object");
    match string_field(obj, "t").expect("params tag").as_str() {
        "not_mapping" => StepParams::NotMapping,
        "map" => {
            let pairs = decode_entries(array_field(obj, "entries").expect("entries"))
                .expect("param entries");
            StepParams::Mapping(EventMapping::new(pairs))
        }
        other => panic!("params tag {other}"),
    }
}

fn decode_field(value: &JsonValue) -> Result<EventField, ParseError> {
    let obj = as_object(value, "field")?;
    match string_field(obj, "t")?.as_str() {
        "null" => Ok(EventField::Null),
        "bool" => Ok(EventField::Bool(bool_field(obj, "v")?)),
        "int" => Ok(EventField::Int(int_field(obj, "v")?)),
        "float" => Ok(EventField::Float(float_field(obj, "v")?)),
        "str" => Ok(EventField::Str(string_field(obj, "v")?)),
        "map" => {
            let pairs = decode_entries(array_field(obj, "entries")?)?;
            Ok(EventField::Mapping(EventMapping::new(pairs)))
        }
        "list" => {
            let mut items = Vec::new();
            for item in array_field(obj, "items")? {
                items.push(decode_field(item)?);
            }
            Ok(EventField::List(items))
        }
        other => Err(ParseError {
            message: format!("unknown tag {other}"),
        }),
    }
}

fn decode_entries(entries: &[JsonValue]) -> Result<Vec<(String, EventField)>, ParseError> {
    let mut out = Vec::new();
    for row in entries {
        let JsonValue::Array(pair) = row else {
            return Err(ParseError {
                message: "entry pair must be an array".into(),
            });
        };
        if pair.len() != 2 {
            return Err(ParseError {
                message: "entry pair length".into(),
            });
        }
        let JsonValue::Str(key) = &pair[0] else {
            return Err(ParseError {
                message: "entry key must be a string".into(),
            });
        };
        out.push((key.clone(), decode_field(&pair[1])?));
    }
    Ok(out)
}

fn parse_cases(input: &str) -> Result<Vec<VectorCase>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let root = as_object(&value, "root")?;
    assert_eq!(
        string_field(root, "schema")?,
        "sesslint.parity-module-vectors/v1"
    );
    assert_eq!(
        string_field(root, "module")?,
        "sesslint.repair.recipes_sl002"
    );
    assert_eq!(string_field(root, "python_commit")?, PIN);
    assert_eq!(
        string_field(root, "recipe")?,
        "torn-terminal-record-discard"
    );
    assert_eq!(string_field(root, "recipes_sl002_py_sha256")?, PY_SHA);
    let items = array_field(root, "vectors")?;
    let mut cases = Vec::new();
    for item in items {
        let obj = as_object(item, "vector")?;
        cases.push(VectorCase {
            id: string_field(obj, "id")?,
            construct: object_field(obj, "construct")?.to_vec(),
            expected: object_field(obj, "expected")?.to_vec(),
        });
    }
    assert_gap_list(root);
    Ok(cases)
}

fn parse_coverage(input: &str) -> Result<(usize, Vec<CoverageRow>), ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "coverage trailing".into(),
        });
    }
    let root = as_object(&value, "coverage")?;
    assert_eq!(
        string_field(root, "module")?,
        "sesslint.repair.recipes_sl002"
    );
    assert_eq!(
        string_field(root, "recipe")?,
        "torn-terminal-record-discard"
    );
    assert_eq!(string_field(root, "python_commit")?, PIN);
    assert_eq!(string_field(root, "test_file")?, "tests");
    let covered = usize_field(root, "covered_count")?;
    let not_applicable = usize_field(root, "not_applicable_count")?;
    assert_eq!(not_applicable, EXPECTED_NOT_APPLICABLE);
    let mut rows = Vec::new();
    for item in array_field(root, "rows")? {
        let obj = as_object(item, "row")?;
        let vector_id_null = matches!(field_ref(obj, "vector_id"), JsonValue::Null);
        rows.push(CoverageRow {
            test: string_field(obj, "test")?,
            column: string_field(obj, "column")?,
            status: string_field(obj, "status")?,
            note: string_field(obj, "note")?,
            vector_id_null,
        });
    }
    Ok((covered, rows))
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be an object"),
        }),
    }
}

fn field_ref<'a>(obj: &'a [(String, JsonValue)], key: &str) -> &'a JsonValue {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, value)) => value,
        None => panic!("missing {key}"),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, value)) => as_object(value, key),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
    }
}

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.as_slice()),
        Some(_) => Err(ParseError {
            message: format!("{key} must be an array"),
        }),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Str(text))) => Ok(text.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be a string"),
        }),
    }
}

fn optional_string(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        _ => None,
    }
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => Ok(text.clone()),
            JsonValue::Bool(_) | JsonValue::Number(_) => Err(ParseError {
                message: format!("{key} bool is not a string"),
            }),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
            }),
        })
        .collect()
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(value))) => Ok(*value),
        Some((_, JsonValue::Number(_))) => Err(ParseError {
            message: format!("{key} bool is not an int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be a bool"),
        }),
    }
}

fn int_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(_))) => Err(ParseError {
            message: format!("{key} bool is not an int"),
        }),
        Some((_, JsonValue::Number(text))) => text.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be an int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be an int"),
        }),
    }
}

fn float_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(_))) => Err(ParseError {
            message: format!("{key} bool is not a float"),
        }),
        Some((_, JsonValue::Number(text))) => text.parse::<f64>().map_err(|_| ParseError {
            message: format!("{key} must be a float"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be a float"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(_))) => Err(ParseError {
            message: format!("{key} bool is not an int"),
        }),
        Some((_, JsonValue::Number(text))) => text.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be an unsigned integer"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be a number"),
        }),
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(text, rest)| (JsonValue::Str(text), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(rest) = input.strip_prefix(word) {
        Ok((value, rest))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let bytes = input.as_bytes();
    let mut idx = 0_usize;
    if bytes.first() == Some(&b'-') {
        idx = 1;
    }
    let digit_start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == digit_start {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        let frac_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == frac_start {
            return Err(ParseError {
                message: "invalid number".into(),
            });
        }
    }
    if idx < bytes.len() && (bytes[idx] == b'e' || bytes[idx] == b'E') {
        idx += 1;
        if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
            idx += 1;
        }
        let exp_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == exp_start {
            return Err(ParseError {
                message: "invalid number".into(),
            });
        }
    }
    Ok((JsonValue::Number(input[..idx].to_owned()), &input[idx..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = input[1..].trim_start();
    let mut items = Vec::new();
    if let Some(tail) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), tail));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), tail));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = input[1..].trim_start();
    let mut items = Vec::new();
    if let Some(tail) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), tail));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        if !rest.starts_with(':') {
            return Err(ParseError {
                message: "expected : in object".into(),
            });
        }
        rest = rest[1..].trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), tail));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or } in object".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => return Ok((out, &input[idx + 2..])),
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, item)| item).collect();
                        if hex.len() != 4 || !hex.chars().all(|item| item.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad unicode escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad unicode value".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode scalar".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(nibble(byte >> 4));
            out.push(nibble(byte & 0x0f));
        }
        out
    }

    fn nibble(value: u8) -> char {
        match value {
            0..=9 => char::from(b'0' + value),
            10..=15 => char::from(b'a' + value - 10),
            _ => '?',
        }
    }
}

#[allow(clippy::too_many_lines)]
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0_u32; 64];
        for (idx, word) in chunk.chunks(4).enumerate().take(16) {
            w[idx] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for idx in 16..64 {
            let s0 =
                w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
            let s1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
            w[idx] = w[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(w[idx - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for idx in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[idx])
                .wrapping_add(w[idx]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0_u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(&sha256(data))
}
