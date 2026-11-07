//! Parity for torn-record-excision against pinned Python vectors.
//!
//! Expected values are the pin's results. A covered row is the whole
//! `sl001_excisable` test. Apply refusals fail closed. A `SessionEvent` copy
//! and `plan` are not `Ok`, and those paths are not covered.

use model::canonical::{
    SessionEvent, CANONICAL_JSON_BYTES_UNAVAILABLE, NORMALIZE_CANONICAL_UNAVAILABLE,
};
use model::codes::{Repairability, Severity, SL001, SL006};
use model::events::{EventField, EventMapping, EventValue};
use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
use repair::planner::{plan, PlanPolicy, PlanProfile, SourceHashEvent};
use repair::preconditions::PreconditionContext;
use repair::recipes_salvage::{
    apply_torn_record_excision, apply_torn_record_excision_with_loss, recipe_torn_record_excision,
    sl001_excisable, IndexValue, ParamMap, SalvageError, SalvageStep,
};
use repair::registry::CallableId;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_NAME: &str = "vectors.json";
const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_VECTOR_COUNT: usize = 6;
const EXPECTED_COVERED: usize = 1;
const EXPECTED_NOT_APPLICABLE: usize = 6;
const EXPECTED_VECTORS_SHA256: &str =
    "1743e796cc6619f3fe5ecf1c60942cb4294ea11bb320751463c48cac6d391958";
const COVERED_TEST: &str = "tests/repair/test_sl001_excision.py::test_sl001_excisable_precondition";
const COVERED_VECTOR: &str = "sl001_excisable_precondition";
const APPLY_TEST: &str = "tests/repair/test_sl001_excision.py::test_apply_torn_record_excision_validation";
const REPAIR_TEST: &str = "tests/repair/test_sl001_excision.py::test_repair_torn_record_end_to_end";
const GAP_REGION: &str = "GAP-torn-record-excision-affected-region";
const GAP_PLANNER: &str = "GAP-torn-record-excision-planner";
const GAP_COPY: &str = "GAP-torn-record-excision-session-copy";
const SEAM_REGION: &str = "sesslint.policy.abstention.AffectedRegion is not available";
const SEAM_DETERMINISM: &str = "sesslint.determinism.canonical_json_bytes is not available";
const PLACEHOLDER_FINGERPRINT: &str = "0000000000000000";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/recipes/torn-record-excision")
}

fn read_lf(path: &Path) -> String {
    let raw = std::fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        !raw.contains(&b'\r'),
        "{} contains CR",
        path.display()
    );
    let text = String::from_utf8(raw).unwrap_or_else(|err| panic!("utf-8 {}: {err}", path.display()));
    assert!(!text.contains(SEAM_REGION), "{} stores the region seam", path.display());
    assert!(
        !text.contains(SEAM_DETERMINISM),
        "{} stores the determinism seam as an expected value",
        path.display()
    );
    assert!(!text.contains("sesslint-wt"), "{} stores a worktree path", path.display());
    assert!(!text.contains("FOR_WORK"), "{} stores a checkout path", path.display());
    assert!(!text.contains("02694d5"), "{} names the wrong pin", path.display());
    assert!(!contains_sbp(&text), "{} stores an sbp hash", path.display());
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
fn torn_record_excision_parity_vectors() {
    let dir = parity_dir();
    let vectors_raw = read_lf(&dir.join(VECTORS_NAME));
    let digest = sha256_hex(vectors_raw.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256");
    assert!(vectors_raw.contains(GAP_REGION));
    assert!(vectors_raw.contains(GAP_PLANNER));
    assert!(vectors_raw.contains(GAP_COPY));
    let cases = parse_cases(&vectors_raw).unwrap_or_else(|err| panic!("parse vectors: {err}"));
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT);
    for case in &cases {
        assert_case(case);
    }
    assert_manifest(&read_lf(&dir.join("manifest.json")), &digest);
    assert_provenance(&read_lf(&dir.join("PROVENANCE.json")));
    assert_bool_is_not_int();
}

#[test]
fn torn_record_excision_coverage_is_the_whole_precondition_test() {
    let dir = parity_dir();
    let vectors = parse_cases(&read_lf(&dir.join(VECTORS_NAME)))
        .unwrap_or_else(|err| panic!("parse vectors: {err}"));
    let covered_case = vectors
        .iter()
        .find(|case| case.id == COVERED_VECTOR)
        .expect("covered vector");
    assert!(bool_field(&covered_case.construct, "entire_test").expect("entire_test"));
    assert_eq!(
        usize_field(&covered_case.construct, "assert_count").expect("assert_count"),
        10
    );
    let raw = read_lf(&dir.join("coverage.json"));
    let (value, rest) = parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("coverage: {err}"));
    assert!(rest.trim().is_empty(), "coverage trailing");
    let obj = as_object(&value, "coverage").expect("coverage object");
    assert_eq!(string_field(obj, "python_commit").expect("pin"), PIN);
    assert_eq!(
        string_field(obj, "test_file").expect("test_file"),
        "tests/repair/test_sl001_excision.py"
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
        if status == "covered" {
            covered += 1;
            assert_eq!(test, COVERED_TEST);
            assert_eq!(string_field(row, "vector_id").expect("vector_id"), COVERED_VECTOR);
            assert_eq!(string_field(row, "note").expect("note"), "");
        } else {
            assert_eq!(status, "not_applicable", "{test}");
            assert!(matches!(field_ref(row, "vector_id"), JsonValue::Null), "{test}");
            let note = string_field(row, "note").expect("note");
            assert!(!note.is_empty(), "{test}");
            assert!(!note.contains(SEAM_REGION), "{test}");
            assert!(!note.contains(SEAM_DETERMINISM), "{test}");
            if test == APPLY_TEST {
                assert!(note.contains("not the whole test"), "{test}");
                assert!(note.contains("SessionEvent"), "{test}");
                assert!(note.contains(GAP_COPY), "{test}");
            }
            if test == REPAIR_TEST {
                assert!(note.contains("no fixture diff"), "{test}");
                assert!(note.contains("multi-assert sweep"), "{test}");
            }
            if test.contains("::test_plan_") {
                assert!(note.contains("not a successful plan"), "{test}");
                assert!(note.contains("One example inside a sweep is not the whole test"), "{test}");
                assert!(note.contains("no fixture diff"), "{test}");
                assert!(note.contains(GAP_PLANNER), "{test}");
            }
        }
    }
    assert_eq!(covered, EXPECTED_COVERED);
    assert!(vectors.iter().any(|case| case.id == "apply_torn_record_excision_refusals"));
    let refusals = vectors
        .iter()
        .find(|case| case.id == "apply_torn_record_excision_refusals")
        .expect("refusals");
    assert!(!bool_field(&refusals.construct, "entire_test").expect("entire"));
    assert_eq!(array_field(&refusals.construct, "calls").expect("calls").len(), 7);
}

#[test]
fn torn_record_excision_session_copy_and_plan_fail_closed() {
    let event = EventValue::from_session(SessionEvent::new(
        "msg-0",
        None,
        0,
        "2026-09-05T12:00:00Z",
        "user",
        "message",
    ));
    let step = SalvageStep {
        target_index: IndexValue::None,
        params: ParamMap::Mapping(EventMapping::new(vec![
            ("line".to_owned(), EventField::Int(3)),
            ("record_ordinal".to_owned(), EventField::Int(2)),
            ("byte_offset".to_owned(), EventField::Int(120)),
            ("byte_end".to_owned(), EventField::Int(210)),
            ("record_id".to_owned(), EventField::Str("msg-torn".to_owned())),
        ])),
    };
    let copied = apply_torn_record_excision(vec![event.clone()], step.clone());
    let err = match copied {
        Ok(_) => panic!("SessionEvent copy returned Ok"),
        Err(err) => err,
    };
    assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
    let with_loss = apply_torn_record_excision_with_loss(std::slice::from_ref(&event), &step);
    let err = match with_loss {
        Ok(_) => panic!("SessionEvent with_loss returned Ok"),
        Err(err) => err,
    };
    assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);

    let planned = plan(
        &[],
        &[SourceHashEvent::Session(Box::new(SessionEvent::new(
            "msg-0",
            None,
            0,
            "2026-09-05T12:00:00Z",
            "user",
            "message",
        )))],
        &PlanProfile::str_value("neutral"),
        None,
        &PlanPolicy::Str("salvage".to_owned()),
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
}

#[test]
fn torn_record_excision_region_is_not_constructed() {
    let recipe = recipe_torn_record_excision().unwrap_or_else(|err| panic!("{err}"));
    assert!(recipe.affected_region().is_none());
    assert_eq!(
        recipe.apply(),
        Some(CallableId::from_fn(apply_torn_record_excision))
    );
    let raw = read_lf(&parity_dir().join(VECTORS_NAME));
    assert!(!raw.contains(SEAM_REGION));
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").unwrap_or_else(|err| panic!("{}: {err}", case.id));
    match kind.as_str() {
        "recipe_constant" => assert_recipe(case),
        "sl001_excisable" => assert_precondition(case),
        "apply_refusals" => assert_refusals(case),
        "apply_mixed" => assert_mixed(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_recipe(case: &VectorCase) {
    let recipe = recipe_torn_record_excision().unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let expected = &case.expected;
    assert_eq!(string_field(expected, "mode").expect("mode"), "recipe");
    assert_eq!(recipe.name(), string_field(expected, "name").expect("name"));
    let handles = string_array(expected, "handles").expect("handles");
    assert_eq!(recipe.handles(), handles.as_slice(), "{}", case.id);
    let preconditions = string_array(expected, "preconditions").expect("preconditions");
    assert_eq!(recipe.preconditions(), preconditions.as_slice(), "{}", case.id);
    assert_eq!(recipe.lossy(), bool_field(expected, "lossy").expect("lossy"));
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
    assert!(
        !bool_field(expected, "affected_region_present").expect("region"),
        "a region row is not covered"
    );
    assert!(recipe.affected_region().is_none(), "{}", case.id);
    assert_eq!(
        recipe.apply(),
        Some(CallableId::from_fn(apply_torn_record_excision))
    );
}

fn assert_precondition(case: &VectorCase) {
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), "sl001_excisable");
    assert_eq!(string_field(&case.expected, "mode").expect("mode"), "bools");
    let checks = array_field(&case.construct, "checks").expect("checks");
    let values = array_field(&case.expected, "values").expect("values");
    let assert_count = usize_field(&case.construct, "assert_count").expect("assert_count");
    assert_eq!(checks.len(), values.len(), "{}", case.id);
    assert_eq!(checks.len(), assert_count, "{}", case.id);
    assert!(assert_count > 1, "{} is one example", case.id);
    let mut saw_true = false;
    let mut saw_false = false;
    for (check, flag) in checks.iter().zip(values) {
        let obj = as_object(check, "check").expect("check");
        let want = bool_field_value(flag).unwrap_or_else(|err| panic!("{}: {err}", case.id));
        let got = run_check(obj);
        assert_eq!(got, want, "{}", case.id);
        saw_true |= got;
        saw_false |= !got;
    }
    if case.id == COVERED_VECTOR {
        assert!(saw_true && saw_false, "covered sweep collapsed to one outcome");
    }
    if case.id == "sl001_bool_span_is_not_an_int" {
        assert!(saw_true && saw_false, "bool span was not distinguished from an int");
        assert_bool_span_tags(checks);
    }
}

fn assert_bool_span_tags(checks: &[JsonValue]) {
    let keys = ["byte_offset", "byte_end", "record_ordinal"];
    for (index, key) in keys.iter().enumerate() {
        let obj = as_object(&checks[index], "span").expect("span");
        let evidence = decode_field(field_ref(obj, "evidence")).expect("evidence");
        let EventField::Mapping(mapping) = evidence else {
            panic!("evidence map");
        };
        match mapping.get(key) {
            Some(EventField::Bool(true)) => {}
            Some(EventField::Int(_)) => panic!("{key} bool span was stored as an int"),
            other => panic!("{key} span tag {other:?}"),
        }
    }
    let control = as_object(&checks[3], "control").expect("control");
    let evidence = decode_field(field_ref(control, "evidence")).expect("evidence");
    let EventField::Mapping(mapping) = evidence else {
        panic!("control map");
    };
    assert!(matches!(mapping.get("byte_offset"), Some(EventField::Int(0))));
    assert!(matches!(mapping.get("record_ordinal"), Some(EventField::Int(1))));
}

fn run_check(obj: &[(String, JsonValue)]) -> bool {
    let finding = build_finding(obj);
    let events = decode_events(array_field(obj, "events").expect("events"));
    let profile = string_field(obj, "profile").expect("profile");
    let source_hash = string_field(obj, "source_hash").expect("source_hash");
    let policy = string_field(obj, "policy").expect("policy");
    let ctx = PreconditionContext {
        findings: std::slice::from_ref(&finding),
        events: &events,
        profile: &profile,
        source_hash: &source_hash,
        finding: Some(&finding),
        policy: &policy,
        acknowledge_side_effects: bool_field(obj, "acknowledge_side_effects").expect("ack"),
    };
    sl001_excisable(&ctx)
}

fn build_finding(obj: &[(String, JsonValue)]) -> Finding {
    let code = string_field(obj, "code").expect("code");
    assert!(code == SL001 || code == SL006, "{code}");
    let line = optional_line(field_ref(obj, "line"));
    let record_id = optional_record_id(field_ref(obj, "record_id"));
    let source = SourceRef::try_new(
        string_field(obj, "path").expect("path").as_str(),
        line,
        record_id.as_deref(),
    )
    .unwrap_or_else(|err| panic!("source: {err}"));
    let severity = if code == SL006 {
        Severity::Warning
    } else {
        Severity::Error
    };
    Finding::try_new(FindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(Repairability::Manual),
        message: PyValue::string("synthetic parity marker"),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string(PLACEHOLDER_FINGERPRINT),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::None,
        evidence: decode_py(field_ref(obj, "evidence")),
    })
    .unwrap_or_else(|err| panic!("finding: {err}"))
}

fn optional_line(value: &JsonValue) -> Option<SourceLine> {
    let obj = as_object(value, "line").expect("line");
    match string_field(obj, "t").expect("line tag").as_str() {
        "null" => None,
        "int" => Some(SourceLine::Int(int_field(obj, "v").expect("line int"))),
        "bool" => panic!("bool is not an int"),
        other => panic!("line tag {other}"),
    }
}

fn optional_record_id(value: &JsonValue) -> Option<String> {
    let obj = as_object(value, "record_id").expect("record_id");
    match string_field(obj, "t").expect("record tag").as_str() {
        "null" => None,
        "str" => Some(string_field(obj, "v").expect("record str")),
        "bool" | "int" => panic!("bool is not an int"),
        other => panic!("record tag {other}"),
    }
}

fn assert_refusals(case: &VectorCase) {
    assert_eq!(
        string_field(&case.construct, "fn").expect("fn"),
        "apply_torn_record_excision"
    );
    assert_eq!(string_field(&case.expected, "mode").expect("mode"), "refusals");
    assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
    let calls = array_field(&case.construct, "calls").expect("calls");
    assert!(calls.len() > 1, "{} is one example", case.id);
    for call in calls {
        let obj = as_object(call, "call").expect("call");
        if case.id == "apply_bool_span_and_line" {
            assert_bool_param_is_not_int(obj);
        }
        assert_refusal(obj);
    }
}

fn assert_bool_param_is_not_int(call: &[(String, JsonValue)]) {
    let step = decode_step(object_field(call, "step").expect("step"));
    let ParamMap::Mapping(mapping) = &step.params else {
        panic!("params");
    };
    let line = mapping.get("line");
    let offset = mapping.get("byte_offset");
    let bool_line = matches!(line, Some(EventField::Bool(true)));
    let bool_span = matches!(offset, Some(EventField::Bool(true)));
    assert!(bool_line || bool_span, "expected a bool line or a bool span");
    assert!(!matches!(line, Some(EventField::Int(1))) || !bool_line);
    assert!(!matches!(offset, Some(EventField::Int(1))));
}

fn assert_mixed(case: &VectorCase) {
    assert_eq!(case.id, "apply_record_id_bool_is_not_int");
    assert!(!bool_field(&case.construct, "entire_test").expect("entire_test"));
    let calls = array_field(&case.construct, "calls").expect("calls");
    assert_eq!(calls.len(), 2);
    let refused = as_object(&calls[0], "refused").expect("refused");
    let step = decode_step(object_field(refused, "step").expect("step"));
    match param_field(&step, "record_id") {
        Some(EventField::Bool(true)) => {}
        Some(EventField::Int(_)) => panic!("bool record id was stored as an int"),
        other => panic!("record id {other:?}"),
    }
    assert_refusal(refused);
    let kept = as_object(&calls[1], "kept").expect("kept");
    match param_field(&decode_step(object_field(kept, "step").expect("step")), "record_id") {
        Some(EventField::Int(1)) => {}
        other => panic!("int record id {other:?}"),
    }
    assert_ok(kept);
}

fn param_field(step: &SalvageStep, key: &str) -> Option<EventField> {
    match &step.params {
        ParamMap::Mapping(mapping) => mapping.get(key).cloned(),
        ParamMap::NotMapping => None,
    }
}

fn assert_refusal(call: &[(String, JsonValue)]) {
    assert_eq!(string_field(call, "error_type").expect("error_type"), "PreconditionFailed");
    let message = string_field(call, "message").expect("message");
    assert!(!message.contains(SEAM_REGION), "{message}");
    assert!(!message.contains(SEAM_DETERMINISM), "{message}");
    let events = decode_events(array_field(call, "events").expect("events"));
    let step = decode_step(object_field(call, "step").expect("step"));
    let applied = apply_torn_record_excision(events.clone(), step.clone());
    let err = match applied {
        Ok(_) => panic!("proof failed and returned Ok: {message}"),
        Err(err) => err,
    };
    assert!(matches!(err, SalvageError::Precondition(_)), "{err}");
    assert_eq!(err.to_string(), message);
    let with_loss = apply_torn_record_excision_with_loss(&events, &step);
    let err = match with_loss {
        Ok(_) => panic!("with_loss returned Ok: {message}"),
        Err(err) => err,
    };
    assert_eq!(err.to_string(), message);
}

fn assert_ok(call: &[(String, JsonValue)]) {
    assert_eq!(string_field(call, "mode").expect("mode"), "ok");
    let events = decode_events(array_field(call, "events").expect("events"));
    let step = decode_step(object_field(call, "step").expect("step"));
    let out = apply_torn_record_excision(events.clone(), step.clone())
        .unwrap_or_else(|err| panic!("int record id was refused: {err}"));
    let (copied, loss) = apply_torn_record_excision_with_loss(&events, &step)
        .unwrap_or_else(|err| panic!("with_loss refused an int record id: {err}"));
    assert_eq!(out, copied);
    assert_mappings(&out, array_field(call, "events_out").expect("events_out"));
    let want_loss = decode_loss(field_ref(call, "loss"));
    assert_eq!(loss.entries(), want_loss.as_slice());
}

fn decode_loss(value: &JsonValue) -> Vec<(String, i64)> {
    let EventField::Mapping(mapping) = decode_field(value).expect("loss map") else {
        panic!("loss must be a map");
    };
    mapping
        .entries()
        .iter()
        .map(|(key, field)| {
            let EventField::Int(count) = field else {
                panic!("{key} loss bool is not an int");
            };
            (key.clone(), *count)
        })
        .collect()
}

fn assert_manifest(raw: &str, digest: &str) {
    let (value, rest) = parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("manifest: {err}"));
    assert!(rest.trim().is_empty(), "manifest trailing");
    let obj = as_object(&value, "manifest").expect("manifest object");
    assert_eq!(usize_field(obj, "vector_count").expect("vector_count"), EXPECTED_VECTOR_COUNT);
    assert_eq!(string_field(obj, "vectors_sha256").expect("vectors_sha256"), digest);
    assert_eq!(
        string_field(obj, "generator").expect("generator"),
        "rust/parity/recipes/torn-record-excision/generate"
    );
    assert_eq!(string_field(obj, "python_commit").expect("pin"), PIN);
    assert_gap_list(obj);
}

fn assert_provenance(raw: &str) {
    let (value, rest) =
        parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("provenance: {err}"));
    assert!(rest.trim().is_empty(), "provenance trailing");
    let obj = as_object(&value, "provenance").expect("provenance object");
    assert!(!bool_field(obj, "contains_real_data").expect("contains_real_data"));
    assert_eq!(string_field(obj, "origin").expect("origin"), "synthetic");
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

fn decode_events(items: &[JsonValue]) -> Vec<EventValue> {
    items.iter().map(decode_event).collect()
}

fn decode_event(value: &JsonValue) -> EventValue {
    let obj = as_object(value, "event").expect("event");
    match string_field(obj, "t").expect("event tag").as_str() {
        "session" => EventValue::from_session(decode_session(obj)),
        "map" => {
            let EventField::Mapping(mapping) = decode_field(value).expect("event map") else {
                panic!("event must be a map");
            };
            EventValue::Mapping(mapping)
        }
        other => panic!("event tag {other}"),
    }
}

fn decode_session(obj: &[(String, JsonValue)]) -> SessionEvent {
    let parent = match string_field(object_field(obj, "parent_id").expect("parent"), "t")
        .expect("parent tag")
        .as_str()
    {
        "null" => None,
        "str" => Some(string_field(object_field(obj, "parent_id").expect("parent"), "v").expect("parent str")),
        "bool" | "int" => panic!("bool is not an int"),
        other => panic!("parent tag {other}"),
    };
    let mut event = SessionEvent::new(
        string_field(obj, "id").expect("id"),
        parent,
        int_tag(field_ref(obj, "seq")).expect("seq"),
        string_field(obj, "ts").expect("ts"),
        string_field(obj, "actor").expect("actor"),
        string_field(obj, "kind").expect("kind"),
    );
    event.payload = match decode_field(field_ref(obj, "payload")).expect("payload") {
        EventField::Mapping(mapping) => mapping.to_payload(),
        _ => panic!("payload must be a map"),
    };
    event
}

fn decode_step(step: &[(String, JsonValue)]) -> SalvageStep {
    SalvageStep {
        target_index: decode_index(field_ref(step, "target_index")),
        params: decode_params(field_ref(step, "params")),
    }
}

fn decode_index(value: &JsonValue) -> IndexValue {
    let obj = as_object(value, "target_index").expect("target_index");
    match string_field(obj, "t").expect("index tag").as_str() {
        "null" => IndexValue::None,
        "int" => IndexValue::Int(int_field(obj, "v").expect("index int")),
        "bool" => IndexValue::Bool(bool_field(obj, "v").expect("index bool")),
        other => panic!("index tag {other} is not an int"),
    }
}

fn decode_params(value: &JsonValue) -> ParamMap {
    match decode_field(value).expect("params") {
        EventField::Mapping(mapping) => ParamMap::Mapping(mapping),
        _ => ParamMap::NotMapping,
    }
}

fn decode_py(value: &JsonValue) -> PyValue {
    let obj = as_object(value, "py").expect("py");
    match string_field(obj, "t").expect("py tag").as_str() {
        "null" => PyValue::None,
        "bool" => PyValue::bool_value(bool_field(obj, "v").expect("py bool")),
        "int" => PyValue::int(int_field(obj, "v").expect("py int")),
        "str" => PyValue::string(string_field(obj, "v").expect("py str")),
        "map" => PyValue::map(decode_py_entries(array_field(obj, "entries").expect("entries"))),
        "list" => {
            let items = array_field(obj, "items")
                .expect("items")
                .iter()
                .map(decode_py)
                .collect();
            PyValue::list(items)
        }
        other => panic!("py tag {other}"),
    }
}

fn decode_py_entries(entries: &[JsonValue]) -> Vec<(PyValue, PyValue)> {
    let mut out = Vec::new();
    for row in entries {
        let JsonValue::Array(pair) = row else {
            panic!("entry pair must be an array");
        };
        if pair.len() != 2 {
            panic!("entry pair length");
        }
        let JsonValue::Str(key) = &pair[0] else {
            panic!("entry key must be a string");
        };
        out.push((PyValue::string(key.clone()), decode_py(&pair[1])));
    }
    out
}

fn decode_field(value: &JsonValue) -> Result<EventField, ParseError> {
    let obj = as_object(value, "field")?;
    match string_field(obj, "t")?.as_str() {
        "null" => Ok(EventField::Null),
        "bool" => Ok(EventField::Bool(bool_field(obj, "v")?)),
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

fn int_tag(value: &JsonValue) -> Result<i64, ParseError> {
    let obj = as_object(value, "int tag")?;
    if string_field(obj, "t")? != "int" {
        return Err(ParseError {
            message: "tag is not int".into(),
        });
    }
    int_field(obj, "v")
}

fn bool_field_value(value: &JsonValue) -> Result<bool, ParseError> {
    match value {
        JsonValue::Bool(flag) => Ok(*flag),
        JsonValue::Number(_) => Err(ParseError {
            message: "bool is not an int".into(),
        }),
        _ => Err(ParseError {
            message: "value must be a bool".into(),
        }),
    }
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
    let mut saw_region = false;
    let mut saw_planner = false;
    let mut saw_copy = false;
    for gap in gaps {
        let JsonValue::Str(text) = gap else {
            panic!("gap must be a string");
        };
        assert!(!text.contains(SEAM_REGION), "{text}");
        assert!(!text.contains(SEAM_DETERMINISM), "{text}");
        saw_region |= text.contains(GAP_REGION);
        saw_planner |= text.contains(GAP_PLANNER);
        saw_copy |= text.contains(GAP_COPY);
    }
    assert!(saw_region && saw_planner && saw_copy);
}

fn parse_cases(input: &str) -> Result<Vec<VectorCase>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let root = as_object(&value, "root")?;
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

fn array_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [JsonValue], ParseError> {
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
            let s0 = w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
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
