//! Parity for terminal-suffix-discard against pinned Python vectors.
//!
//! Expected values are the pin's results. A covered row is one whole
//! `apply_terminal_suffix_discard` refusal test. Fixture output, a planner
//! result, a payload-bearing checkpoint, and a non-string suffix kind stay
//! uncovered.

use model::canonical::CANONICAL_JSON_BYTES_UNAVAILABLE;
use model::events::{
    EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
    PYTHON_STR_UNREPRESENTABLE,
};
use repair::planner::{plan, PlanPolicy, PlanProfile, SourceHashEvent};
use repair::recipes_conservative::{
    apply_terminal_suffix_discard, recipe_terminal_suffix_discard, terminal_suffix_discard,
    ConservativeError, IndexValue, ParamMap, RecipeStep,
};
use repair::registry::CallableId;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_NAME: &str = "vectors.json";
const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PY_SHA: &str = "06c439a569ceb6aebad8bf4afa0c65a3a28c78819e14ecf1df66df11c73620c0";
const EXPECTED_VECTOR_COUNT: usize = 9;
const EXPECTED_COVERED: usize = 2;
const EXPECTED_NOT_APPLICABLE: usize = 33;
const EXPECTED_VECTORS_SHA256: &str =
    "a4dd2862720eb8a50ed6dd4d52f24222632da3a0fc138c81b712d8c03f686922";
const TEST_FILE: &str = "tests/repair/test_recipes_conservative.py";
const FIXTURE_TEST: &str =
    "tests/repair/test_recipes_conservative.py::test_terminal_suffix_discard_fixture";
const CHECKPOINT_TEST: &str =
    "tests/repair/test_recipes_conservative.py::test_suffix_discard_refusal_checkpoint_in_suffix";
const ENTRY_TEST: &str =
    "tests/repair/test_recipes_conservative.py::test_terminal_suffix_discard_sl005_entry_index";
const MULTISET_TEST: &str =
    "tests/repair/test_recipes_conservative.py::test_no_synthetic_success_multiset_proof";
const REGISTER_TEST: &str =
    "tests/repair/test_recipes_conservative.py::test_conservative_recipes_registration_and_handles";
const GAP_REGION: &str = "GAP-terminal-suffix-discard-affected-region";
const GAP_CANONICAL: &str = "GAP-terminal-suffix-discard-canonical";
const GAP_PAYLOAD: &str = "GAP-terminal-suffix-discard-payload";
const GAP_KIND: &str = "GAP-terminal-suffix-discard-kind";
const SEAM_REGION: &str = "sesslint.policy.abstention.AffectedRegion is not available";
const SEAM_DETERMINISM: &str = "sesslint.determinism.canonical_json_bytes is not available";
const FIXTURE_NOTE: &str = "GAP-terminal-suffix-discard-canonical blocks canonical_json_bytes. It is not a successful plan. GAP-terminal-suffix-discard-payload blocks the fixture events. They carry a payload. A payload-free result is not this test. The pin succeeds. That success is not replayed. No fingerprint is hashed and no fixture diff is stored. No output bytes are stored.";
const CHECKPOINT_NOTE: &str = "GAP-terminal-suffix-discard-payload blocks the checkpoint refusal. The events carry a payload. This set does not store payload content. A payload-free refusal is not this test.";
const ENTRY_NOTE: &str = "GAP-terminal-suffix-discard-canonical blocks planner.plan. It is not a successful plan. The test calls plan and the apply on the asserted cut succeeds in the pin. A rust seam while the pin succeeds is not coverage. That success is not replayed. No fingerprint is hashed and no output bytes are stored.";
const MULTISET_NOTE: &str = "GAP-terminal-suffix-discard-canonical blocks canonical_json_bytes. It is not a successful plan. One fixture inside a sweep is not the whole test. No fingerprint is hashed and no fixture diff is stored.";
const REGISTER_NOTE: &str = "one recipe inside a registration sweep is not the whole test. different function from apply_terminal_suffix_discard.";
const DIFFERENT_NOTE: &str = "different function from apply_terminal_suffix_discard";
const COVERED: [(&str, &str); 2] = [
    (
        "tests/repair/test_recipes_conservative.py::test_suffix_discard_refusal_empty_session",
        "suffix_discard_refusal_empty_session",
    ),
    (
        "tests/repair/test_recipes_conservative.py::test_suffix_discard_refusal_out_of_bounds",
        "suffix_discard_refusal_out_of_bounds",
    ),
];
const EXTRA_REFUSALS: [&str; 6] = [
    "suffix_refusal_missing_cut",
    "suffix_refusal_negative_cut",
    "suffix_refusal_cut_equals_length",
    "suffix_refusal_empty_events_past_end",
    "suffix_refusal_param_cut_past_end",
    "suffix_refusal_checkpoint",
];

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/recipes/terminal-suffix-discard")
}

fn read_lf(path: &Path) -> String {
    let raw = std::fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains(&b'\r'), "{} contains CR", path.display());
    let text =
        String::from_utf8(raw).unwrap_or_else(|err| panic!("utf-8 {}: {err}", path.display()));
    assert!(
        !text.contains(SEAM_REGION),
        "{} stores the region seam",
        path.display()
    );
    assert!(
        !text.contains(SEAM_DETERMINISM),
        "{} stores the determinism seam",
        path.display()
    );
    assert!(
        !text.contains(CANONICAL_JSON_BYTES_UNAVAILABLE),
        "{} stores the canonical codec seam",
        path.display()
    );
    assert!(
        !text.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE),
        "{} stores the float seam",
        path.display()
    );
    assert!(
        !text.contains(PYTHON_STR_UNREPRESENTABLE),
        "{} stores the str seam",
        path.display()
    );
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
        !text.contains("\"t\": \"bool\""),
        "{} stores a tagged bool",
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
fn terminal_suffix_discard_parity_vectors() {
    let dir = parity_dir();
    let vectors_raw = read_lf(&dir.join(VECTORS_NAME));
    let digest = sha256_hex(vectors_raw.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256");
    assert!(vectors_raw.contains(GAP_REGION));
    assert!(vectors_raw.contains(GAP_CANONICAL));
    assert!(vectors_raw.contains(GAP_PAYLOAD));
    assert!(vectors_raw.contains(GAP_KIND));
    let cases = parse_cases(&vectors_raw).unwrap_or_else(|err| panic!("parse vectors: {err}"));
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT);
    let mut entire = 0_usize;
    for case in &cases {
        assert_case(case);
        if bool_field(&case.construct, "entire_test").expect("entire_test") {
            entire += 1;
            assert!(
                COVERED.iter().any(|(_, vector_id)| *vector_id == case.id),
                "{} is not a whole pinned test",
                case.id
            );
        }
    }
    assert_eq!(entire, EXPECTED_COVERED);
    assert_eq!(COVERED.len(), EXPECTED_COVERED);
    assert_manifest(&read_lf(&dir.join("manifest.json")), &digest);
    assert_provenance(&read_lf(&dir.join("PROVENANCE.json")));
}

#[test]
fn terminal_suffix_discard_coverage_is_whole_refusal_tests() {
    let dir = parity_dir();
    let cases = parse_cases(&read_lf(&dir.join(VECTORS_NAME)))
        .unwrap_or_else(|err| panic!("parse vectors: {err}"));
    let raw = read_lf(&dir.join("coverage.json"));
    let (value, rest) =
        parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("coverage: {err}"));
    assert!(rest.trim().is_empty(), "coverage trailing");
    let obj = as_object(&value, "coverage").expect("coverage object");
    assert_eq!(string_field(obj, "python_commit").expect("pin"), PIN);
    assert_eq!(
        string_field(obj, "test_file").expect("test_file"),
        TEST_FILE
    );
    assert_eq!(
        usize_field(obj, "covered_count").expect("covered_count"),
        EXPECTED_COVERED
    );
    assert_eq!(
        usize_field(obj, "not_applicable_count").expect("not_applicable_count"),
        EXPECTED_NOT_APPLICABLE
    );
    let rows = array_field(obj, "rows").expect("rows");
    assert_eq!(rows.len(), EXPECTED_COVERED + EXPECTED_NOT_APPLICABLE);
    let mut covered = 0_usize;
    for row in rows {
        let row = as_object(row, "row").expect("row");
        let status = string_field(row, "status").expect("status");
        let test = string_field(row, "test").expect("test");
        assert_eq!(string_field(row, "column").expect("column"), "column_0");
        assert!(
            !test.contains("test_region_functions_totality_fuzz"),
            "{test}"
        );
        if status == "covered" {
            covered += 1;
            let vector_id = string_field(row, "vector_id").expect("vector_id");
            assert!(
                COVERED
                    .iter()
                    .any(|(name, ident)| *name == test && *ident == vector_id),
                "{test}"
            );
            assert_eq!(string_field(row, "note").expect("note"), "");
            let case = cases
                .iter()
                .find(|item| item.id == vector_id)
                .expect("vector");
            assert!(bool_field(&case.construct, "entire_test").expect("entire_test"));
            assert_eq!(
                usize_field(&case.construct, "assert_count").expect("assert_count"),
                1
            );
            assert_eq!(
                string_field(&case.construct, "fn").expect("fn"),
                "apply_terminal_suffix_discard"
            );
        } else {
            assert_eq!(status, "not_applicable", "{test}");
            assert!(
                matches!(field_ref(row, "vector_id"), JsonValue::Null),
                "{test}"
            );
            let note = string_field(row, "note").expect("note");
            assert!(!note.is_empty(), "{test}");
            assert!(!note.contains(SEAM_REGION), "{test}");
            assert!(!note.contains(CANONICAL_JSON_BYTES_UNAVAILABLE), "{test}");
            assert!(!note.contains(SEAM_DETERMINISM), "{test}");
            assert!(!note.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE), "{test}");
            assert!(!note.contains(PYTHON_STR_UNREPRESENTABLE), "{test}");
            let expected = match test.as_str() {
                FIXTURE_TEST => FIXTURE_NOTE,
                CHECKPOINT_TEST => CHECKPOINT_NOTE,
                ENTRY_TEST => ENTRY_NOTE,
                MULTISET_TEST => MULTISET_NOTE,
                REGISTER_TEST => REGISTER_NOTE,
                _ => DIFFERENT_NOTE,
            };
            assert_eq!(note, expected, "{test}");
            if test == FIXTURE_TEST || test == MULTISET_TEST || test == ENTRY_TEST {
                assert!(note.contains("not a successful plan"), "{test}");
                assert!(note.contains(GAP_CANONICAL), "{test}");
            }
            if test == FIXTURE_TEST || test == MULTISET_TEST {
                assert!(note.contains("no fixture diff"), "{test}");
            }
            if test == FIXTURE_TEST || test == ENTRY_TEST {
                assert!(note.contains("succeeds"), "{test}");
                assert!(note.contains("not replayed"), "{test}");
            }
            if test == ENTRY_TEST {
                assert!(note.contains("not coverage"), "{test}");
                assert!(note.contains("no output bytes"), "{test}");
            }
            if test == FIXTURE_TEST {
                assert!(note.contains("output bytes"), "{test}");
                assert!(note.contains(GAP_PAYLOAD), "{test}");
                assert!(note.contains("payload"), "{test}");
                assert!(note.contains("not this test"), "{test}");
            }
            if test == CHECKPOINT_TEST {
                assert!(note.contains(GAP_PAYLOAD), "{test}");
                assert!(note.contains("payload"), "{test}");
                assert!(note.contains("not this test"), "{test}");
                assert!(!note.contains("covered"), "{test} must not claim coverage");
            }
        }
    }
    assert_eq!(covered, EXPECTED_COVERED);
    for ident in EXTRA_REFUSALS {
        let case = cases.iter().find(|item| item.id == ident).expect(ident);
        assert!(!bool_field(&case.construct, "entire_test").expect("entire"));
        assert_eq!(
            string_field(&case.construct, "fn").expect("fn"),
            "apply_terminal_suffix_discard"
        );
        let message = string_field(&case.expected, "message").expect("message");
        assert!(message.starts_with("terminal-suffix-discard: "), "{ident}");
        assert!(!message.contains("payload"), "{ident}");
    }
    let checkpoint = cases
        .iter()
        .find(|item| item.id == "suffix_refusal_checkpoint")
        .expect("checkpoint");
    assert!(!bool_field(&checkpoint.construct, "entire_test").expect("entire"));
    assert!(!COVERED
        .iter()
        .any(|(_, ident)| *ident == "suffix_refusal_checkpoint"));
    let recipe = cases
        .iter()
        .find(|item| item.id == "recipe_terminal_suffix_discard")
        .expect("recipe");
    assert!(!bool_field(&recipe.construct, "entire_test").expect("entire"));
}

#[test]
fn terminal_suffix_discard_region_is_absent_and_plan_fails_closed() {
    let recipe = recipe_terminal_suffix_discard().expect("recipe");
    assert!(recipe.affected_region().is_none());
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(raw.contains(GAP_REGION));
    assert!(!raw.contains(SEAM_REGION));
    assert!(!raw.contains("affected_region_present\": true"));

    let mapping = EventMapping::new(vec![
        ("id".to_owned(), EventField::Str("evt-synthetic".to_owned())),
        ("kind".to_owned(), EventField::Str("message".to_owned())),
    ]);
    let planned = plan(
        &[],
        &[SourceHashEvent::Mapping(mapping)],
        &PlanProfile::str_value("neutral"),
        None,
        &PlanPolicy::str_value("conservative"),
        false,
        None,
    );
    let err = match planned {
        Ok(_) => panic!("plan returned Ok"),
        Err(err) => err,
    };
    let text = err.to_string();
    assert_eq!(text, CANONICAL_JSON_BYTES_UNAVAILABLE);
    assert!(!text.contains("diff"), "{text}");
    assert_ne!(text.len(), 64);
    assert!(!raw.contains(CANONICAL_JSON_BYTES_UNAVAILABLE));
    assert!(raw.contains(GAP_CANONICAL));
}

#[test]
fn terminal_suffix_discard_non_int_cut_matches_invalid() {
    let cases = load_cases();
    let invalid = refusal_message(&cases, "suffix_refusal_missing_cut");
    assert_eq!(
        invalid,
        "terminal-suffix-discard: missing or invalid cut index"
    );
    let events = events_of(&cases, "suffix_refusal_missing_cut");
    for target in [
        IndexValue::Bool(true),
        IndexValue::Bool(false),
        IndexValue::Other,
    ] {
        let err = expect_precondition(
            &events,
            target,
            params(&[("cut_index", EventField::Int(1))]),
        );
        assert_eq!(err, invalid);
    }
    for cut in [
        EventField::Bool(true),
        EventField::Bool(false),
        EventField::Float(1.5),
        EventField::Str("skip".to_owned()),
        EventField::List(vec![EventField::Int(1)]),
    ] {
        let err = expect_precondition(&events, IndexValue::None, params(&[("cut_index", cut)]));
        assert_eq!(err, invalid);
    }
    let missing_params = expect_precondition(&events, IndexValue::None, ParamMap::NotMapping);
    assert_eq!(missing_params, invalid);
    let alias = apply_err_alias(&events, IndexValue::None, empty_params());
    assert_eq!(alias, invalid);
}

#[test]
fn terminal_suffix_discard_param_cuts_match_the_pin_messages() {
    let cases = load_cases();
    let empty = refusal_message(&cases, "suffix_discard_refusal_empty_session");
    assert_eq!(
        empty,
        "terminal-suffix-discard: cut at index 0 would empty session (refused)"
    );
    let bounds = refusal_message(&cases, "suffix_discard_refusal_out_of_bounds");
    assert_eq!(
        bounds,
        "terminal-suffix-discard: cut at index 5 >= session length 1"
    );
    let err = expect_precondition(&[], IndexValue::Int(0), empty_params());
    assert_eq!(err, empty);
    let one = events_of(&cases, "suffix_refusal_missing_cut");
    let from_param = expect_precondition(
        &one,
        IndexValue::None,
        params(&[("cut_index", EventField::Int(0))]),
    );
    assert_eq!(from_param, empty);
    let oob = events_of(&cases, "suffix_discard_refusal_out_of_bounds");
    let param_oob = expect_precondition(
        &oob,
        IndexValue::None,
        params(&[("cut_index", EventField::Int(5))]),
    );
    assert_eq!(param_oob, bounds);
}

#[test]
fn terminal_suffix_discard_unrenderable_kind_is_not_claimed() {
    let cases = load_cases();
    let invalid = refusal_message(&cases, "suffix_refusal_missing_cut");
    let checkpoint = refusal_message(&cases, "suffix_refusal_checkpoint");
    let prefix = message_event("evt-keep");
    let float_events = vec![
        prefix.clone(),
        kind_event("evt-tail", EventField::Float(1.5)),
    ];
    let float_err = expect_event(&float_events, IndexValue::Int(1), empty_params());
    assert_eq!(float_err, PYTHON_FLOAT_STR_UNREPRESENTABLE);
    assert_ne!(float_err, invalid);
    assert_ne!(float_err, checkpoint);
    let list_events = vec![
        prefix.clone(),
        kind_event("evt-tail", EventField::List(vec![EventField::Int(1)])),
    ];
    let list_err = expect_event(&list_events, IndexValue::Int(1), empty_params());
    assert_eq!(list_err, PYTHON_STR_UNREPRESENTABLE);
    let map_events = vec![
        prefix,
        kind_event(
            "evt-tail",
            EventField::Mapping(EventMapping::new(vec![(
                "k".to_owned(),
                EventField::Int(1),
            )])),
        ),
    ];
    let map_err = expect_event(&map_events, IndexValue::Int(1), empty_params());
    assert_eq!(map_err, PYTHON_STR_UNREPRESENTABLE);
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(raw.contains(GAP_KIND));
    assert!(raw.contains("pin succeeds"));
    assert!(raw.contains("not coverage"));
    assert!(raw.contains("not replayed"));
    assert!(raw.contains("No output bytes are stored"));
    assert!(!raw.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE));
    assert!(!raw.contains(PYTHON_STR_UNREPRESENTABLE));
    for case in &cases {
        if string_field(&case.construct, "type").expect("type") != "apply_refusal" {
            continue;
        }
        let message = string_field(&case.expected, "message").expect("message");
        assert_ne!(message, float_err);
        assert_ne!(message, list_err);
    }
}

fn load_cases() -> Vec<VectorCase> {
    parse_cases(&read_lf(&parity_dir().join(VECTORS_NAME)))
        .unwrap_or_else(|err| panic!("parse vectors: {err}"))
}

fn refusal_message(cases: &[VectorCase], vector_id: &str) -> String {
    let case = cases
        .iter()
        .find(|item| item.id == vector_id)
        .expect(vector_id);
    string_field(&case.expected, "message").expect("message")
}

fn events_of(cases: &[VectorCase], vector_id: &str) -> Vec<EventValue> {
    let case = cases
        .iter()
        .find(|item| item.id == vector_id)
        .expect(vector_id);
    decode_events(array_field(&case.construct, "events").expect("events"))
}

fn empty_params() -> ParamMap {
    ParamMap::Mapping(EventMapping::new(Vec::new()))
}

fn params(fields: &[(&str, EventField)]) -> ParamMap {
    ParamMap::Mapping(EventMapping::new(
        fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect(),
    ))
}

fn message_event(id: &str) -> EventValue {
    EventValue::Mapping(EventMapping::new(vec![
        ("id".to_owned(), EventField::Str(id.to_owned())),
        ("kind".to_owned(), EventField::Str("message".to_owned())),
        ("seq".to_owned(), EventField::Int(0)),
    ]))
}

fn kind_event(id: &str, kind: EventField) -> EventValue {
    EventValue::Mapping(EventMapping::new(vec![
        ("id".to_owned(), EventField::Str(id.to_owned())),
        ("kind".to_owned(), kind),
        ("seq".to_owned(), EventField::Int(1)),
    ]))
}

fn expect_precondition(events: &[EventValue], target: IndexValue, params: ParamMap) -> String {
    let err = apply_err(events, target, params);
    assert!(matches!(err, ConservativeError::Precondition(_)), "{err}");
    err.to_string()
}

fn expect_event(events: &[EventValue], target: IndexValue, params: ParamMap) -> String {
    let err = apply_err(events, target, params);
    assert!(matches!(err, ConservativeError::Event(_)), "{err}");
    err.to_string()
}

fn apply_err(events: &[EventValue], target: IndexValue, params: ParamMap) -> ConservativeError {
    let step = RecipeStep {
        target_index: target,
        params,
    };
    match apply_terminal_suffix_discard(events, &step) {
        Ok(_) => panic!("apply returned Ok"),
        Err(err) => err,
    }
}

fn apply_err_alias(events: &[EventValue], target: IndexValue, params: ParamMap) -> String {
    let step = RecipeStep {
        target_index: target,
        params,
    };
    let direct = apply_err(events, step.target_index, step.params.clone());
    let alias = match terminal_suffix_discard(events, &step) {
        Ok(_) => panic!("alias returned Ok"),
        Err(err) => err,
    };
    assert_eq!(direct.to_string(), alias.to_string());
    alias.to_string()
}

fn assert_case(case: &VectorCase) {
    let kind =
        string_field(&case.construct, "type").unwrap_or_else(|err| panic!("{}: {err}", case.id));
    match kind.as_str() {
        "recipe_constant" => assert_recipe(case),
        "apply_refusal" => assert_refusal(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_recipe(case: &VectorCase) {
    assert_eq!(case.id, "recipe_terminal_suffix_discard");
    assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
    let recipe =
        recipe_terminal_suffix_discard().unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let expected = &case.expected;
    assert_eq!(string_field(expected, "mode").expect("mode"), "recipe");
    assert_eq!(recipe.name(), string_field(expected, "name").expect("name"));
    let handles = string_array(expected, "handles").expect("handles");
    assert_eq!(recipe.handles(), handles.as_slice(), "{}", case.id);
    let preconditions = string_array(expected, "preconditions").expect("preconditions");
    assert_eq!(
        recipe.preconditions(),
        preconditions.as_slice(),
        "{}",
        case.id
    );
    assert_eq!(
        recipe.lossy(),
        bool_field(expected, "lossy").expect("lossy")
    );
    assert_eq!(
        recipe.salvage_only(),
        bool_field(expected, "salvage_only").expect("salvage_only")
    );
    assert_eq!(
        recipe.min_policy(),
        string_field(expected, "min_policy").expect("min_policy")
    );
    assert_eq!(
        recipe.version(),
        string_field(expected, "version").expect("version")
    );
    assert_eq!(
        recipe.excludes_execution_dependence(),
        bool_field(expected, "excludes_execution_dependence").expect("excludes")
    );
    assert_eq!(
        recipe.apply().is_some(),
        bool_field(expected, "apply_present").expect("apply_present")
    );
    assert!(!bool_field(expected, "affected_region_present").expect("region"));
    assert!(recipe.affected_region().is_none());
    assert_eq!(
        recipe.apply(),
        Some(CallableId::from_fn(apply_terminal_suffix_discard))
    );
}

fn assert_refusal(case: &VectorCase) {
    assert_eq!(
        string_field(&case.construct, "fn").expect("fn"),
        "apply_terminal_suffix_discard"
    );
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "refusal"
    );
    assert_eq!(
        string_field(&case.expected, "error_type").expect("error_type"),
        "PreconditionFailed"
    );
    let message = string_field(&case.expected, "message").expect("message");
    assert!(!message.contains(SEAM_REGION), "{message}");
    assert!(
        !message.contains(CANONICAL_JSON_BYTES_UNAVAILABLE),
        "{message}"
    );
    assert!(!message.contains(SEAM_DETERMINISM), "{message}");
    assert!(
        !message.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE),
        "{message}"
    );
    assert!(!message.contains(PYTHON_STR_UNREPRESENTABLE), "{message}");
    assert!(!message.contains("payload"), "{message}");
    assert!(
        message.starts_with("terminal-suffix-discard: "),
        "{}",
        case.id
    );
    let events = decode_events(array_field(&case.construct, "events").expect("events"));
    let step = decode_step(object_field(&case.construct, "step").expect("step"));
    let applied = apply_terminal_suffix_discard(&events, &step);
    let err = match applied {
        Ok(_) => panic!("proof failed and returned Ok: {message}"),
        Err(err) => err,
    };
    assert!(matches!(err, ConservativeError::Precondition(_)), "{err}");
    assert_eq!(err.to_string(), message);
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
        "rust/parity/recipes/terminal-suffix-discard/generate"
    );
    assert_eq!(string_field(obj, "python_commit").expect("pin"), PIN);
    assert_eq!(
        string_field(obj, "recipes_conservative_py_sha256").expect("py sha"),
        PY_SHA
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
    assert_gap_list(obj);
}

fn assert_gap_list(obj: &[(String, JsonValue)]) {
    let gaps = array_field(obj, "known_parity_gaps").expect("known_parity_gaps");
    let mut saw_region = false;
    let mut saw_canonical = false;
    let mut saw_payload = false;
    let mut saw_kind = false;
    for gap in gaps {
        let JsonValue::Str(text) = gap else {
            panic!("gap must be a string");
        };
        assert!(!text.contains(SEAM_REGION), "{text}");
        assert!(!text.contains(SEAM_DETERMINISM), "{text}");
        assert!(!text.contains(CANONICAL_JSON_BYTES_UNAVAILABLE), "{text}");
        assert!(!text.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE), "{text}");
        assert!(!text.contains(PYTHON_STR_UNREPRESENTABLE), "{text}");
        saw_region |= text.contains(GAP_REGION);
        saw_canonical |= text.contains(GAP_CANONICAL);
        saw_payload |= text.contains(GAP_PAYLOAD);
        saw_kind |= text.contains(GAP_KIND);
    }
    assert!(saw_region && saw_canonical && saw_payload && saw_kind);
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

fn decode_step(step: &[(String, JsonValue)]) -> RecipeStep {
    RecipeStep {
        target_index: decode_index(field_ref(step, "target_index")),
        params: decode_params(field_ref(step, "params")),
    }
}

fn decode_index(value: &JsonValue) -> IndexValue {
    let obj = as_object(value, "target_index").expect("target_index");
    match string_field(obj, "t").expect("index tag").as_str() {
        "null" => IndexValue::None,
        "int" => IndexValue::Int(int_field(obj, "v").expect("index int")),
        "bool" => panic!("bool is not an int"),
        other => panic!("index tag {other} is not an int"),
    }
}

fn decode_params(value: &JsonValue) -> ParamMap {
    match decode_field(value).expect("params") {
        EventField::Mapping(mapping) => ParamMap::Mapping(mapping),
        EventField::Bool(_) => panic!("bool is not an int"),
        _ => ParamMap::NotMapping,
    }
}

fn decode_field(value: &JsonValue) -> Result<EventField, ParseError> {
    let obj = as_object(value, "field")?;
    match string_field(obj, "t")?.as_str() {
        "null" => Ok(EventField::Null),
        "bool" => Err(ParseError {
            message: "bool is not an int".into(),
        }),
        "int" => Ok(EventField::Int(int_field(obj, "v")?)),
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
    assert_eq!(string_field(root, "python_commit")?, PIN);
    assert_eq!(string_field(root, "recipe")?, "terminal-suffix-discard");
    assert_eq!(
        string_field(root, "recipes_conservative_py_sha256")?,
        PY_SHA
    );
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
