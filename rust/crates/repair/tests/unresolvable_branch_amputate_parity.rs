//! Parity for unresolvable-branch-amputate against pinned Python vectors.
//!
//! Expected values are the pin's results. The covered row is the whole
//! four-refusal validation test. A plan, a fixture diff, a payload-bearing
//! success, and a kept SessionEvent copy are not covered.

use model::canonical::{
    SessionEvent, CANONICAL_JSON_BYTES_UNAVAILABLE, NORMALIZE_CANONICAL_UNAVAILABLE,
};
use model::events::{EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE};
use repair::planner::{plan, PlanPolicy, PlanProfile, SourceHashEvent};
use repair::recipes_salvage::{
    apply_unresolvable_branch_amputate, apply_unresolvable_branch_amputate_with_loss,
    recipe_unresolvable_branch_amputate, IndexValue, LossDelta, ParamMap, SalvageError,
    SalvageStep, MAX_COMPONENT_SIZE,
};
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_NAME: &str = "vectors.json";
const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PY_SHA: &str = "ad738eb553cf41d7630fa45223eaac3a21fe13c9b04d0b715f110d594fd92166";
const EXPECTED_VECTOR_COUNT: usize = 24;
const EXPECTED_COVERED: usize = 1;
const EXPECTED_NOT_APPLICABLE: usize = 23;
const EXPECTED_VECTORS_SHA256: &str =
    "83ab479e41b0b8d14cc73e4d6db131f341d641b6d2da5f6d907f31af448a1a3e";
const TEST_FILE: &str = "tests/repair/test_recipes_salvage.py";
const COVERED_TEST: &str =
    "tests/repair/test_recipes_salvage.py::test_amputate_direct_apply_validation";
const COVERED_VECTOR: &str = "amputate_direct_apply_validation";
const FN: &str = "apply_unresolvable_branch_amputate";
const GAP_CANONICAL: &str = "GAP-unresolvable-branch-amputate-canonical";
const GAP_COPY: &str = "GAP-unresolvable-branch-amputate-session-copy";
const GAP_PAYLOAD: &str = "GAP-unresolvable-branch-amputate-payload";
const GAP_BOOL: &str = "GAP-unresolvable-branch-amputate-bool";
const GAP_FLOAT: &str = "GAP-unresolvable-branch-amputate-float";
const GAP_SWEEP: &str = "GAP-unresolvable-branch-amputate-sweep";
const GAP_SIZE: &str = "GAP-unresolvable-branch-amputate-size";
const GAP_ROOT: &str = "GAP-unresolvable-branch-amputate-root-id";
const SEAM_REGION: &str = "sesslint.policy.abstention.AffectedRegion is not available";
const SEAM_DETERMINISM: &str = "sesslint.determinism.canonical_json_bytes is not available";
const FALSE_INDEX: &str = "Invalid target_index False for amputation";
const TRUE_INDEX: &str = "Invalid target_index True for amputation";
const LIST_MESSAGE: &str = "list indices must be integers or slices, not float";
const EMPTY_MESSAGE: &str = "Cannot amputate an empty session";
const ENTIRE_MESSAGE: &str = "Amputating entire session is forbidden";
const CHECKPOINT_MESSAGE: &str = "Branch contains a checkpoint; cannot amputate";
const CONSERVATIVE_TEST: &str =
    "tests/repair/test_recipes_salvage.py::test_conservative_default_blocks_salvage";
const OPT_TEST: &str = "tests/repair/test_recipes_salvage.py::test_salvage_opt_in";
const APPLICATIONS_TEST: &str =
    "tests/repair/test_recipes_salvage.py::test_salvage_recipe_applications";
const ROOT_TEST: &str =
    "tests/repair/test_recipes_salvage.py::test_amputate_resolves_index_from_root_id";
const SIZE_TEST: &str = "tests/repair/test_recipes_salvage.py::test_component_too_large";
const INTERACTING_TEST: &str =
    "tests/repair/test_recipes_salvage.py::test_interacting_multi_fault_session";
const CONSERVATIVE_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks canonical_json_bytes. It is not a successful plan. One fixture inside a sweep is not the whole test. No fingerprint is hashed and no fixture diff is stored.";
const OPT_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks canonical_json_bytes. It is not a successful plan. One recipe inside a sweep is not the whole test. No fingerprint is hashed and no fixture diff is stored. No output bytes are stored.";
const FINGERPRINT_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks canonical_json_bytes. It is not a successful plan. The test compares fingerprints. No fingerprint is hashed and no fixture diff is stored.";
const DUAL_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks canonical_json_bytes. It is not a successful plan. The test compares fingerprints and recomputes one. No fingerprint is hashed and no fixture diff is stored.";
const LOSS_SUMS_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks the plan. It is not a successful plan. The test checks plan loss totals. No fingerprint is hashed and no fixture diff is stored. No output bytes are stored.";
const EMPTY_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks the plan. It is not a successful plan. The test checks a fingerprint length. The empty-session apply refusal is a different test. No fingerprint is hashed.";
const SIZE_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks the plan. It is not a successful plan. GAP-unresolvable-branch-amputate-size blocks planner reason component-too-large. A direct refusal for a component larger than 10000 is not this test. GAP-unresolvable-branch-amputate-payload blocks the constructed events. They carry a payload. A payload-free result is not this test. No fingerprint is hashed.";
const APPLICATIONS_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks the plan. It is not a successful plan. GAP-unresolvable-branch-amputate-session-copy blocks the kept SessionEvent. The pin succeeds. A rust seam while the pin succeeds is not coverage. That success is not replayed. GAP-unresolvable-branch-amputate-payload blocks the fixture events. They carry a payload. A payload-free result is not this test. GAP-unresolvable-branch-amputate-sweep blocks the loss check. A successful amputate that also checks loss, plan, or canonical bytes is not covered by the event list alone. One recipe inside a sweep is not the whole test. No fingerprint is hashed and no fixture diff is stored. No output bytes are stored.";
const ROOT_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks the plan. It is not a successful plan. GAP-unresolvable-branch-amputate-root-id blocks the planned int index. A params root_id success is not this test. GAP-unresolvable-branch-amputate-session-copy blocks the kept SessionEvent. The pin succeeds. A rust seam while the pin succeeds is not coverage. That success is not replayed. GAP-unresolvable-branch-amputate-payload blocks the fixture events. They carry a payload. A payload-free result is not this test. No fingerprint is hashed and no fixture diff is stored. No output bytes are stored.";
const INTERACTING_NOTE: &str = "GAP-unresolvable-branch-amputate-canonical blocks the plan. It is not a successful plan. GAP-unresolvable-branch-amputate-sweep blocks two recipes. One recipe inside a sweep is not the whole test. GAP-unresolvable-branch-amputate-payload blocks the constructed events. They carry a payload. A payload-free result is not this test. No fingerprint is hashed and no fixture diff is stored. No output bytes are stored.";
const DIFFERENT_NOTE: &str = "different function from apply_unresolvable_branch_amputate";
const VECTOR_IDS: [&str; 24] = [
    "recipe_unresolvable_branch_amputate",
    "amputate_direct_apply_validation",
    "amputate_refusal_negative_index",
    "amputate_refusal_missing_index",
    "amputate_refusal_true_index_len_one",
    "amputate_refusal_marker_param",
    "amputate_refusal_unknown_root",
    "amputate_refusal_falsy_bool_root",
    "amputate_refusal_null_params",
    "amputate_refusal_entire_pair",
    "amputate_refusal_checkpoint_with_keeper",
    "amputate_refusal_out_of_range_before_float_id",
    "amputate_type_string_index",
    "amputate_type_list_index",
    "amputate_type_dict_index",
    "amputate_type_in_range_float",
    "amputate_refusal_component_too_large",
    "amputate_ok_component",
    "amputate_ok_root_id",
    "amputate_ok_int_ignores_root_id",
    "amputate_ok_record_id_zero",
    "amputate_ok_bool_root_id",
    "amputate_ok_float_root_falls_through",
    "amputate_ok_cycle",
];

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../parity/recipes/unresolvable-branch-amputate")
}

fn read_lf(path: &Path) -> String {
    let raw = std::fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains(&b'\r'), "{} contains CR", path.display());
    let text =
        String::from_utf8(raw).unwrap_or_else(|err| panic!("utf-8 {}: {err}", path.display()));
    for seam in [
        SEAM_REGION,
        SEAM_DETERMINISM,
        CANONICAL_JSON_BYTES_UNAVAILABLE,
        NORMALIZE_CANONICAL_UNAVAILABLE,
        PYTHON_FLOAT_STR_UNREPRESENTABLE,
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
fn unresolvable_branch_amputate_parity_vectors() {
    let dir = parity_dir();
    let vectors_raw = read_lf(&dir.join(VECTORS_NAME));
    let digest = sha256_hex(vectors_raw.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256");
    for gap in [
        GAP_CANONICAL,
        GAP_COPY,
        GAP_PAYLOAD,
        GAP_BOOL,
        GAP_FLOAT,
        GAP_SWEEP,
        GAP_SIZE,
        GAP_ROOT,
    ] {
        assert!(vectors_raw.contains(gap), "{gap}");
    }
    for banned in ["c1-1", "c1-2", "c1-3", "c2-1", "c2-2", "-1.5", "9.0", "1.5"] {
        assert!(!vectors_raw.contains(banned), "{banned}");
    }
    assert!(!vectors_raw.contains(FALSE_INDEX));
    let cases = parse_cases(&vectors_raw).unwrap_or_else(|err| panic!("parse vectors: {err}"));
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT);
    let mut entire = 0_usize;
    for (case, ident) in cases.iter().zip(VECTOR_IDS) {
        assert_eq!(case.id, ident);
        assert_case(case);
        if bool_field(&case.construct, "entire_test").expect("entire_test") {
            entire += 1;
            assert_eq!(case.id, COVERED_VECTOR);
        }
    }
    assert_eq!(entire, EXPECTED_COVERED);
    assert_manifest(&read_lf(&dir.join("manifest.json")), &digest);
    assert_provenance(&read_lf(&dir.join("PROVENANCE.json")));
    assert_bool_is_not_int();
}

#[test]
fn unresolvable_branch_amputate_coverage_names_the_gaps() {
    let dir = parity_dir();
    let cases = parse_cases(&read_lf(&dir.join(VECTORS_NAME)))
        .unwrap_or_else(|err| panic!("parse vectors: {err}"));
    let covered = cases
        .iter()
        .find(|case| case.id == COVERED_VECTOR)
        .expect("covered");
    assert!(bool_field(&covered.construct, "entire_test").expect("entire"));
    assert_eq!(
        usize_field(&covered.construct, "assert_count").expect("asserts"),
        4
    );
    assert_eq!(
        array_field(&covered.construct, "calls")
            .expect("calls")
            .len(),
        4
    );
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
    let mut covered_rows = 0_usize;
    for row in rows {
        let row = as_object(row, "row").expect("row");
        let status = string_field(row, "status").expect("status");
        let test = string_field(row, "test").expect("test");
        assert_eq!(string_field(row, "column").expect("column"), "column_0");
        let note = string_field(row, "note").expect("note");
        assert_eq!(note, expected_note(&test), "{test}");
        if status == "covered" {
            covered_rows += 1;
            assert_eq!(test, COVERED_TEST);
            assert_eq!(
                string_field(row, "vector_id").expect("vector_id"),
                COVERED_VECTOR
            );
            assert!(note.is_empty(), "{test}");
        } else {
            assert_eq!(status, "not_applicable", "{test}");
            assert!(
                matches!(field_ref(row, "vector_id"), JsonValue::Null),
                "{test}"
            );
            assert!(!note.is_empty(), "{test}");
            assert!(!note.contains(SEAM_DETERMINISM), "{test}");
            assert!(!note.contains(CANONICAL_JSON_BYTES_UNAVAILABLE), "{test}");
            assert!(!note.contains("0 diff"), "{test}");
        }
        if note.contains(GAP_CANONICAL) {
            assert!(note.contains("not a successful plan"), "{test}");
        }
        if test == APPLICATIONS_TEST || test == OPT_TEST || test == CONSERVATIVE_TEST {
            assert!(note.contains("no fixture diff"), "{test}");
            assert!(note.contains(GAP_CANONICAL), "{test}");
        }
        if test == APPLICATIONS_TEST || test == ROOT_TEST {
            assert!(note.contains("pin succeeds"), "{test}");
            assert!(note.contains("not coverage"), "{test}");
            assert!(note.contains("not replayed"), "{test}");
            assert!(
                note.contains("not the whole test") || test == ROOT_TEST,
                "{test}"
            );
            assert!(note.contains("No output bytes are stored"), "{test}");
            assert!(note.contains(GAP_PAYLOAD), "{test}");
            assert!(note.contains(GAP_COPY), "{test}");
        }
        if test == APPLICATIONS_TEST {
            assert!(
                note.contains("not covered by the event list alone"),
                "{test}"
            );
            assert!(note.contains(GAP_SWEEP), "{test}");
        }
        if test == ROOT_TEST {
            assert!(note.contains("not this test"), "{test}");
            assert!(note.contains(GAP_ROOT), "{test}");
        }
        if test == SIZE_TEST {
            assert!(note.contains("component-too-large"), "{test}");
            assert!(note.contains("not this test"), "{test}");
            assert!(note.contains(GAP_SIZE), "{test}");
            assert!(note.contains(GAP_PAYLOAD), "{test}");
        }
        if test == INTERACTING_TEST {
            assert!(note.contains("not the whole test"), "{test}");
            assert!(note.contains(GAP_SWEEP), "{test}");
            assert!(note.contains(GAP_PAYLOAD), "{test}");
        }
    }
    assert_eq!(covered_rows, EXPECTED_COVERED);
    assert!(cases
        .iter()
        .filter(|case| {
            let kind = string_field(&case.construct, "type").expect("type");
            kind == "apply_ok" || kind == "apply_size"
        })
        .all(|case| !bool_field(&case.construct, "entire_test").expect("entire")));
}

#[test]
fn unresolvable_branch_amputate_session_copy_and_plan_fail_closed() {
    let cases = load_cases();
    let mut events = events_of(&cases, "amputate_ok_component");
    assert!(events.len() > 1, "the kept call is the first event");
    assert_eq!(mapping_id(&events[0]), "evt-keep");
    events[0] = EventValue::from_session(SessionEvent::new(
        "evt-keep",
        None,
        0,
        "2026-09-05T12:00:00Z",
        "assistant",
        "message",
    ));
    let step = SalvageStep {
        target_index: IndexValue::Int(1),
        params: empty_params(),
    };
    let listed = apply_unresolvable_branch_amputate(&events, &step);
    let detailed = apply_unresolvable_branch_amputate_with_loss(&events, &step);
    match (listed, detailed) {
        (Err(left), Err(right)) => {
            assert_eq!(left.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
            assert_eq!(right.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        }
        (Ok(_), _) | (_, Ok(_)) => panic!("kept SessionEvent was copied"),
    }
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(!raw.contains(NORMALIZE_CANONICAL_UNAVAILABLE));
    assert!(raw.contains(GAP_COPY));

    let planned = plan(
        &[],
        &[SourceHashEvent::Session(Box::new(SessionEvent::new(
            "evt-session",
            None,
            0,
            "2026-09-05T12:00:00Z",
            "user",
            "message",
        )))],
        &PlanProfile::str_value("neutral"),
        None,
        &PlanPolicy::str_value("salvage"),
        true,
        None,
    );
    let err = match planned {
        Ok(_) => panic!("plan returned Ok"),
        Err(err) => err,
    };
    let text = err.to_string();
    assert!(
        text == CANONICAL_JSON_BYTES_UNAVAILABLE || text == SEAM_DETERMINISM,
        "{text}"
    );
    assert!(!text.contains("diff"), "{text}");
    assert_ne!(text.len(), 64);
    assert!(raw.contains(GAP_CANONICAL));
    assert!(!raw.contains(CANONICAL_JSON_BYTES_UNAVAILABLE));
}

#[test]
fn unresolvable_branch_amputate_bool_index_is_not_claimed() {
    let cases = load_cases();
    let events = events_of(&cases, "amputate_ok_component");
    assert!(
        events.len() > 1,
        "the pin indexes True only when length is greater than one"
    );
    let err = expect_precondition(&events, IndexValue::Bool(true), empty_params());
    assert_eq!(err, TRUE_INDEX);
    let false_err = expect_precondition(&events, IndexValue::Bool(false), empty_params());
    assert_eq!(false_err, FALSE_INDEX);
    for case in &cases {
        if string_field(&case.construct, "type").expect("type") == "apply_ok" {
            let step = decode_step_of(case);
            assert!(
                !matches!(step.target_index, IndexValue::Bool(_)),
                "{} stores a bool index success",
                case.id
            );
        }
        assert_ne!(
            stored_message(case).as_deref(),
            Some(FALSE_INDEX),
            "{}",
            case.id
        );
    }
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(raw.contains(GAP_BOOL));
    assert!(!raw.contains(FALSE_INDEX));
    let len_one = events_of(&cases, "amputate_refusal_true_index_len_one");
    assert_eq!(len_one.len(), 1);
    let stored = refusal_message(&cases, "amputate_refusal_true_index_len_one");
    assert_eq!(
        expect_precondition(&len_one, IndexValue::Bool(true), empty_params()),
        stored
    );
    assert_eq!(stored, TRUE_INDEX);
    assert_ne!(stored, FALSE_INDEX);
    let empty: Vec<EventValue> = Vec::new();
    assert_eq!(
        expect_precondition(&empty, IndexValue::Bool(true), empty_params()),
        EMPTY_MESSAGE
    );
    assert_eq!(
        expect_precondition(&empty, IndexValue::Bool(false), empty_params()),
        EMPTY_MESSAGE
    );
}

#[test]
fn unresolvable_branch_amputate_rendered_float_is_not_claimed() {
    let cases = load_cases();
    let notes = events_of(&cases, "amputate_refusal_missing_index");
    assert!(notes.len() > 1, "an in-range zero float needs a session");
    for bits in [(-1.5_f64).to_bits(), 9.0_f64.to_bits()] {
        let err = expect_event(&notes, IndexValue::Float(bits), empty_params());
        assert_eq!(err, PYTHON_FLOAT_STR_UNREPRESENTABLE);
        for case in &cases {
            assert_ne!(
                stored_message(case).as_deref(),
                Some(err.as_str()),
                "{}",
                case.id
            );
        }
    }
    let zero = expect_type(&notes, IndexValue::Float(0.0_f64.to_bits()), empty_params());
    assert_eq!(zero, LIST_MESSAGE);
    assert_ne!(zero, PYTHON_FLOAT_STR_UNREPRESENTABLE);
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(raw.contains(GAP_FLOAT));
    assert!(!raw.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE));
    assert!(!raw.contains("-1.5"));
    assert!(!raw.contains("9.0"));
    assert!(!raw.contains("1.5"));
    let listed = refusal_message(&cases, "amputate_type_in_range_float");
    assert_eq!(listed, LIST_MESSAGE);
    let spanned = events_of(&cases, "amputate_type_in_range_float");
    let err = expect_type(
        &spanned,
        IndexValue::Float(1.0_f64.to_bits()),
        empty_params(),
    );
    assert_eq!(err, listed);
    let float_kind = vec![
        EventValue::Mapping(EventMapping::new(vec![
            ("kind".to_owned(), EventField::Float(1.5)),
            (
                "id".to_owned(),
                EventField::Str("evt-float-kind".to_owned()),
            ),
        ])),
        EventValue::Mapping(EventMapping::new(vec![
            ("kind".to_owned(), EventField::Str("message".to_owned())),
            ("id".to_owned(), EventField::Str("evt-keep".to_owned())),
        ])),
    ];
    let kind_err = expect_event(&float_kind, IndexValue::Int(0), empty_params());
    assert_eq!(kind_err, PYTHON_FLOAT_STR_UNREPRESENTABLE);
    assert!(!raw.contains(kind_err.as_str()));
    let float_id = events_of(&cases, "amputate_refusal_out_of_range_before_float_id");
    let id_err = expect_event(&float_id, IndexValue::Int(0), empty_params());
    assert_eq!(id_err, PYTHON_FLOAT_STR_UNREPRESENTABLE);
    let rooted = vec![
        EventValue::Mapping(EventMapping::new(vec![
            ("kind".to_owned(), EventField::Str("message".to_owned())),
            ("id".to_owned(), EventField::Str("1.5".to_owned())),
        ])),
        EventValue::Mapping(EventMapping::new(vec![
            ("kind".to_owned(), EventField::Str("message".to_owned())),
            ("id".to_owned(), EventField::Str("evt-keep".to_owned())),
        ])),
    ];
    let root_err = expect_event(
        &rooted,
        IndexValue::None,
        ParamMap::Mapping(EventMapping::new(vec![(
            "root_id".to_owned(),
            EventField::Float(1.5),
        )])),
    );
    assert_eq!(root_err, PYTHON_FLOAT_STR_UNREPRESENTABLE);
}

fn load_cases() -> Vec<VectorCase> {
    parse_cases(&read_lf(&parity_dir().join(VECTORS_NAME)))
        .unwrap_or_else(|err| panic!("parse vectors: {err}"))
}

fn expected_note(test: &str) -> &'static str {
    match test.rsplit("::").next().unwrap_or(test) {
        "test_conservative_default_blocks_salvage" => CONSERVATIVE_NOTE,
        "test_salvage_opt_in" => OPT_NOTE,
        "test_fingerprint_differs_by_policy" => FINGERPRINT_NOTE,
        "test_component_too_large" => SIZE_NOTE,
        "test_loss_sums" => LOSS_SUMS_NOTE,
        "test_empty_events_salvage_policy" => EMPTY_NOTE,
        "test_salvage_recipe_applications" => APPLICATIONS_NOTE,
        "test_amputate_resolves_index_from_root_id" => ROOT_NOTE,
        "test_dual_policy_plan_merge_attempt" => DUAL_NOTE,
        "test_interacting_multi_fault_session" => INTERACTING_NOTE,
        "test_amputate_direct_apply_validation" => "",
        "test_acknowledgement"
        | "test_no_shorthand"
        | "test_assurance_lattice"
        | "test_sl203_refusal_beats_salvage"
        | "test_loss_key_injection_rejected"
        | "test_invalid_policy_string_rejected"
        | "test_torn_compaction_direct_apply_validation"
        | "test_truncate_direct_apply_validation"
        | "test_salvage_vendor_free"
        | "test_orphan_result_drop_plans_and_applies"
        | "test_orphan_result_drop_conservative_blocks"
        | "test_orphan_result_drop_resolves_by_params"
        | "test_orphan_result_drop_direct_apply_refusals" => DIFFERENT_NOTE,
        other => panic!("unclassified pinned test {other}"),
    }
}

fn stored_message(case: &VectorCase) -> Option<String> {
    string_field(&case.expected, "message").ok()
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

fn expect_precondition(events: &[EventValue], target: IndexValue, params: ParamMap) -> String {
    let err = apply_err(events, target, params);
    assert!(matches!(err, SalvageError::Precondition(_)), "{err}");
    err.to_string()
}

fn expect_event(events: &[EventValue], target: IndexValue, params: ParamMap) -> String {
    let err = apply_err(events, target, params);
    assert!(matches!(err, SalvageError::Event(_)), "{err}");
    err.to_string()
}

fn expect_type(events: &[EventValue], target: IndexValue, params: ParamMap) -> String {
    let err = apply_err(events, target, params);
    assert!(matches!(err, SalvageError::Type(_)), "{err}");
    err.to_string()
}

fn apply_err(events: &[EventValue], target: IndexValue, params: ParamMap) -> SalvageError {
    let step = SalvageStep {
        target_index: target,
        params,
    };
    match apply_unresolvable_branch_amputate(events, &step) {
        Ok(_) => panic!("apply returned Ok"),
        Err(err) => err,
    }
}

fn assert_case(case: &VectorCase) {
    let kind =
        string_field(&case.construct, "type").unwrap_or_else(|err| panic!("{}: {err}", case.id));
    match kind.as_str() {
        "recipe_constant" => assert_recipe(case),
        "apply_refusals" => assert_refusals(case),
        "apply_refusal" => assert_one_refusal(case),
        "apply_ok" => assert_ok(case),
        "apply_size" => assert_size(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_recipe(case: &VectorCase) {
    assert_eq!(case.id, "recipe_unresolvable_branch_amputate");
    assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
    assert_eq!(
        string_field(&case.construct, "fn").expect("fn"),
        "RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE"
    );
    let recipe =
        recipe_unresolvable_branch_amputate().unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let expected = &case.expected;
    assert_eq!(string_field(expected, "mode").expect("mode"), "recipe");
    assert_eq!(recipe.name(), string_field(expected, "name").expect("name"));
    let handles = string_array(expected, "handles").expect("handles");
    assert_eq!(recipe.handles(), handles.as_slice(), "{}", case.id);
    assert_eq!(handles, ["SL005".to_owned(), "SL006".to_owned()]);
    let preconditions = string_array(expected, "preconditions").expect("preconditions");
    assert_eq!(
        recipe.preconditions(),
        preconditions.as_slice(),
        "{}",
        case.id
    );
    assert_eq!(
        preconditions,
        [
            "salvage_policy".to_owned(),
            "branch_has_no_checkpoint".to_owned()
        ]
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
        bool_field(expected, "apply_present").expect("apply")
    );
    assert!(!bool_field(expected, "affected_region_present").expect("region"));
    assert!(recipe.affected_region().is_none(), "{}", case.id);
}

fn assert_refusals(case: &VectorCase) {
    assert_eq!(case.id, COVERED_VECTOR);
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), FN);
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "refusals"
    );
    assert_eq!(
        string_field(&case.expected, "error_type").expect("error_type"),
        "PreconditionFailed"
    );
    assert!(bool_field(&case.construct, "entire_test").expect("entire_test"));
    let calls = array_field(&case.construct, "calls").expect("calls");
    let assert_count = usize_field(&case.construct, "assert_count").expect("assert_count");
    assert_eq!(calls.len(), assert_count);
    assert_eq!(
        calls.len(),
        4,
        "one refusal inside a sweep is not the whole test"
    );
    let mut messages = Vec::new();
    for call in calls {
        let obj = as_object(call, "call").expect("call");
        let message = string_field(obj, "message").expect("message");
        assert_eq!(
            string_field(obj, "error_type").expect("error_type"),
            "PreconditionFailed"
        );
        assert_refusal(obj, "PreconditionFailed", &message);
        messages.push(message);
    }
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0], EMPTY_MESSAGE);
    assert!(
        messages[1].contains("Invalid target_index"),
        "{}",
        messages[1]
    );
    assert!(messages[1].contains("99"), "{}", messages[1]);
    assert_eq!(messages[2], CHECKPOINT_MESSAGE);
    assert_eq!(messages[3], ENTIRE_MESSAGE);
    assert!(!messages.iter().any(|message| message.contains('.')));
    assert_eq!(
        messages
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
}

fn assert_one_refusal(case: &VectorCase) {
    assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
    assert_eq!(
        usize_field(&case.construct, "assert_count").expect("assert_count"),
        1
    );
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), FN);
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "refusal"
    );
    let error_type = string_field(&case.expected, "error_type").expect("error_type");
    let message = string_field(&case.expected, "message").expect("message");
    assert!(
        error_type == "PreconditionFailed" || error_type == "TypeError",
        "{}",
        case.id
    );
    assert!(!message.contains('.'), "{}", case.id);
    assert_ne!(message, FALSE_INDEX, "{}", case.id);
    assert_refusal(&case.construct, &error_type, &message);
    let step = decode_step_of(case);
    if case.id == "amputate_refusal_true_index_len_one" {
        assert!(matches!(step.target_index, IndexValue::Bool(true)));
        assert_eq!(
            decode_events(array_field(&case.construct, "events").expect("events")).len(),
            1
        );
        assert_eq!(message, TRUE_INDEX);
    }
    if case.id == "amputate_type_in_range_float" {
        assert!(matches!(step.target_index, IndexValue::Float(_)));
        assert_eq!(message, LIST_MESSAGE);
    }
    if case.id == "amputate_type_string_index" {
        assert!(matches!(step.target_index, IndexValue::Other("str")));
    }
    if case.id == "amputate_type_list_index" {
        assert!(matches!(step.target_index, IndexValue::Other("list")));
    }
    if case.id == "amputate_type_dict_index" {
        assert!(matches!(step.target_index, IndexValue::Other("dict")));
    }
    if case.id == "amputate_refusal_marker_param" {
        assert!(matches!(
            param_field(&step, "marker"),
            Some(EventField::Int(1))
        ));
    }
    if case.id == "amputate_refusal_null_params" {
        assert!(matches!(step.params, ParamMap::NotMapping));
    }
    if case.id == "amputate_refusal_falsy_bool_root" {
        assert!(matches!(
            param_field(&step, "root_id"),
            Some(EventField::Bool(false))
        ));
        assert!(matches!(step.target_index, IndexValue::None));
    }
}

fn assert_ok(case: &VectorCase) {
    assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
    assert_eq!(
        usize_field(&case.construct, "assert_count").expect("assert_count"),
        1
    );
    assert_ne!(case.id, COVERED_VECTOR);
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), FN);
    assert_eq!(string_field(&case.expected, "mode").expect("mode"), "ok");
    let events = decode_events(array_field(&case.construct, "events").expect("events"));
    let step = decode_step(object_field(&case.construct, "step").expect("step"));
    assert!(
        !matches!(
            step.target_index,
            IndexValue::Bool(_) | IndexValue::Float(_)
        ),
        "{} stores a bool or float index",
        case.id
    );
    let (out, loss) =
        apply_both(&events, &step).unwrap_or_else(|err| panic!("{} returned {err}", case.id));
    assert!(
        out.len() < events.len(),
        "{} kept the whole session",
        case.id
    );
    assert_mappings(
        &out,
        array_field(&case.expected, "events_out").expect("events_out"),
    );
    assert_loss(&loss, field_ref(&case.expected, "loss"));
    assert_eq!(loss.entries().len(), 1);
    assert_eq!(loss.entries()[0].0, "amputated-branch");
    let got_ids = out.iter().map(mapping_id_of).collect::<Vec<_>>();
    match case.id.as_str() {
        "amputate_ok_component" | "amputate_ok_root_id" => {
            assert_eq!(events.len(), 4, "{}", case.id);
            assert_eq!(got_ids, ["evt-keep", "evt-cp"]);
            assert_eq!(loss.entries()[0].1, 2);
        }
        "amputate_ok_int_ignores_root_id" => {
            assert_eq!(got_ids, ["evt-root", "evt-leaf", "evt-cp"]);
            assert_eq!(loss.entries()[0].1, 1);
            assert!(matches!(step.target_index, IndexValue::Int(0)));
        }
        "amputate_ok_record_id_zero" => {
            assert_eq!(got_ids, ["evt-keep"]);
            assert!(matches!(
                param_field(&step, "record_id"),
                Some(EventField::Int(0))
            ));
        }
        "amputate_ok_bool_root_id" => {
            assert_eq!(got_ids, ["evt-other", "evt-keep"]);
            assert!(matches!(
                param_field(&step, "root_id"),
                Some(EventField::Bool(true))
            ));
            assert!(matches!(step.target_index, IndexValue::None));
        }
        "amputate_ok_float_root_falls_through" => {
            assert_eq!(got_ids, ["evt-keep"]);
            assert!(float_param_is_zero(&step, "root_id"));
            assert!(matches!(
                param_field(&step, "record_id"),
                Some(EventField::Str(text)) if text == "0"
            ));
        }
        "amputate_ok_cycle" => {
            assert_eq!(events.len(), 3);
            assert_eq!(got_ids, ["evt-keep"]);
            assert_eq!(loss.entries()[0].1, 2);
        }
        other => panic!("unexpected success {other}"),
    }
}

fn assert_size(case: &VectorCase) {
    assert_eq!(case.id, "amputate_refusal_component_too_large");
    assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
    assert_eq!(
        usize_field(&case.construct, "assert_count").expect("assert_count"),
        1
    );
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), FN);
    assert_eq!(
        usize_field(&case.construct, "chain").expect("chain"),
        MAX_COMPONENT_SIZE + 1
    );
    assert!(bool_field(&case.construct, "keeper").expect("keeper"));
    assert_eq!(usize_field(&case.construct, "seed").expect("seed"), 0);
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "refusal"
    );
    assert_eq!(
        string_field(&case.expected, "error_type").expect("error_type"),
        "PreconditionFailed"
    );
    let message = string_field(&case.expected, "message").expect("message");
    assert!(!message.contains('.'), "{message}");
    assert!(!message.contains("component-too-large"), "{message}");
    assert!(!message.contains("entire session"), "{message}");
    assert_eq!(
        message,
        format!(
            "Component size ({}) exceeds limit of {MAX_COMPONENT_SIZE}",
            MAX_COMPONENT_SIZE + 1
        )
    );
    let events = oversized_chain();
    assert_eq!(events.len(), MAX_COMPONENT_SIZE + 2);
    let step = SalvageStep {
        target_index: IndexValue::Int(0),
        params: empty_params(),
    };
    let err = match apply_both(&events, &step) {
        Ok(_) => panic!("oversized component was amputated"),
        Err(err) => err,
    };
    assert!(matches!(err, SalvageError::Precondition(_)), "{err}");
    assert_eq!(err.to_string(), message);
}

fn oversized_chain() -> Vec<EventValue> {
    let count = MAX_COMPONENT_SIZE + 1;
    let mut events = Vec::with_capacity(count + 1);
    for index in 0..count {
        let mut entries = vec![
            ("kind".to_owned(), EventField::Str("message".to_owned())),
            ("id".to_owned(), EventField::Str(format!("evt-{index}"))),
        ];
        if index > 0 {
            entries.push((
                "parent_id".to_owned(),
                EventField::Str(format!("evt-{}", index - 1)),
            ));
        }
        events.push(EventValue::Mapping(EventMapping::new(entries)));
    }
    events.push(EventValue::Mapping(EventMapping::new(vec![
        ("kind".to_owned(), EventField::Str("message".to_owned())),
        ("id".to_owned(), EventField::Str("evt-keep".to_owned())),
    ])));
    events
}

fn mapping_id(event: &EventValue) -> String {
    let EventValue::Mapping(mapping) = event else {
        panic!("mapping input");
    };
    mapping_id_of(mapping)
}

fn mapping_id_of(event: &EventMapping) -> String {
    match event.get("id") {
        Some(EventField::Str(text)) => text.clone(),
        other => panic!("id {other:?}"),
    }
}

fn float_param_is_zero(step: &SalvageStep, key: &str) -> bool {
    match param_field(step, key) {
        Some(EventField::Float(number)) => number.to_bits() == 0.0_f64.to_bits(),
        _ => false,
    }
}

fn decode_step_of(case: &VectorCase) -> SalvageStep {
    decode_step(object_field(&case.construct, "step").expect("step"))
}

fn param_field(step: &SalvageStep, key: &str) -> Option<EventField> {
    match &step.params {
        ParamMap::Mapping(mapping) => mapping.get(key).cloned(),
        ParamMap::NotMapping => None,
    }
}

fn assert_refusal(call: &[(String, JsonValue)], error_type: &str, message: &str) {
    assert!(!message.contains(SEAM_REGION), "{message}");
    assert!(!message.contains(SEAM_DETERMINISM), "{message}");
    assert!(
        !message.contains(CANONICAL_JSON_BYTES_UNAVAILABLE),
        "{message}"
    );
    assert!(
        !message.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE),
        "{message}"
    );
    assert!(!message.contains("payload"), "{message}");
    let events = decode_events(array_field(call, "events").expect("events"));
    let step = decode_step(object_field(call, "step").expect("step"));
    let err = match apply_both(&events, &step) {
        Ok(_) => panic!("proof failed and returned Ok: {message}"),
        Err(err) => err,
    };
    match error_type {
        "PreconditionFailed" => assert!(matches!(err, SalvageError::Precondition(_)), "{err}"),
        "TypeError" => assert!(matches!(err, SalvageError::Type(_)), "{err}"),
        other => panic!("unexpected error type {other}"),
    }
    assert_eq!(err.to_string(), message);
}

fn apply_both(
    events: &[EventValue],
    step: &SalvageStep,
) -> Result<(Vec<EventMapping>, LossDelta), SalvageError> {
    let listed = apply_unresolvable_branch_amputate(events, step);
    let detailed = apply_unresolvable_branch_amputate_with_loss(events, step);
    match (listed, detailed) {
        (Ok(list), Ok((out, loss))) => {
            assert_eq!(list, out);
            Ok((out, loss))
        }
        (Err(left), Err(right)) => {
            assert_eq!(left.to_string(), right.to_string());
            Err(left)
        }
        (Ok(_), Err(error)) => panic!("with_loss refused a successful amputate: {error}"),
        (Err(error), Ok(_)) => panic!("amputate refused a with_loss success: {error}"),
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
        "rust/parity/recipes/unresolvable-branch-amputate/generate"
    );
    assert_eq!(string_field(obj, "python_commit").expect("pin"), PIN);
    assert_eq!(
        string_field(obj, "recipes_salvage_py_sha256").expect("py sha"),
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

fn assert_bool_is_not_int() {
    let tagged = JsonValue::Object(vec![
        ("t".to_owned(), JsonValue::Str("int".to_owned())),
        ("v".to_owned(), JsonValue::Bool(true)),
    ]);
    let obj = as_object(&tagged, "int").expect("int object");
    let err = int_field(obj, "v").expect_err("bool is not an int");
    assert!(err.to_string().contains("bool is not an int"));
}

fn assert_loss(loss: &LossDelta, value: &JsonValue) {
    let EventField::Mapping(mapping) = decode_field(value).expect("loss map") else {
        panic!("loss must be a map");
    };
    let want: Vec<(String, i64)> = mapping
        .entries()
        .iter()
        .map(|(key, field)| {
            let EventField::Int(count) = field else {
                panic!("{key} loss bool is not an int");
            };
            (key.clone(), *count)
        })
        .collect();
    assert_eq!(loss.entries(), want.as_slice());
}

fn assert_mappings(got: &[EventMapping], want: &[JsonValue]) {
    assert_eq!(got.len(), want.len());
    for (event, tag) in got.iter().zip(want) {
        let EventField::Mapping(expected) = decode_field(tag).expect("mapped event") else {
            panic!("expected a map");
        };
        assert_eq!(event, &expected);
    }
}

fn assert_gap_list(obj: &[(String, JsonValue)]) {
    let gaps = array_field(obj, "known_parity_gaps").expect("known_parity_gaps");
    let mut saw = [false; 8];
    let names = [
        GAP_CANONICAL,
        GAP_COPY,
        GAP_PAYLOAD,
        GAP_BOOL,
        GAP_FLOAT,
        GAP_SWEEP,
        GAP_SIZE,
        GAP_ROOT,
    ];
    for gap in gaps {
        let JsonValue::Str(text) = gap else {
            panic!("gap must be a string");
        };
        assert!(!text.contains(SEAM_REGION), "{text}");
        assert!(!text.contains(SEAM_DETERMINISM), "{text}");
        assert!(!text.contains(CANONICAL_JSON_BYTES_UNAVAILABLE), "{text}");
        assert!(!text.contains(NORMALIZE_CANONICAL_UNAVAILABLE), "{text}");
        assert!(!text.contains(PYTHON_FLOAT_STR_UNREPRESENTABLE), "{text}");
        assert!(!text.contains("0 diff"), "{text}");
        for (flag, name) in saw.iter_mut().zip(names) {
            *flag |= text.contains(name);
        }
    }
    assert!(saw.iter().all(|flag| *flag));
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

fn decode_step(step: &[(String, JsonValue)]) -> SalvageStep {
    SalvageStep {
        target_index: decode_index(field_ref(step, "target_index")),
        params: decode_params(field_ref(step, "params")),
    }
}

fn decode_index(value: &JsonValue) -> IndexValue {
    match decode_field(value).expect("target_index") {
        EventField::Null => IndexValue::None,
        EventField::Int(number) => IndexValue::Int(number),
        EventField::Bool(flag) => IndexValue::Bool(flag),
        EventField::Float(number) => IndexValue::Float(number.to_bits()),
        EventField::Str(_) => IndexValue::Other("str"),
        EventField::List(_) => IndexValue::Other("list"),
        EventField::Mapping(_) => IndexValue::Other("dict"),
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
    assert_eq!(string_field(root, "python_commit")?, PIN);
    assert_eq!(
        string_field(root, "recipe")?,
        "unresolvable-branch-amputate"
    );
    assert_eq!(string_field(root, "recipes_salvage_py_sha256")?, PY_SHA);
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
