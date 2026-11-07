//! Parity for `apply_orphan_result_drop` against pinned Python vectors.
//!
//! Expected refusals are the pin's results. A covered row is the whole
//! direct-apply refusal test: the same function and a `PreconditionFailed`
//! outcome for every call. The affected-region seam and the planner seam are
//! not covered. A missing `canonical_json_bytes` call stays an error.

use model::canonical::SessionEvent;
use model::events::{
    event_canonical_hash, event_content_fingerprint, EventField, EventMapping, EventValue,
    DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE,
};
use model::finding::Finding;
use repair::planner::{plan, PlanPolicy, PlanProfile, SourceHashEvent};
use repair::recipes_salvage::{
    affected_region_orphan_result_drop, apply_orphan_result_drop, recipe_orphan_result_drop,
    IndexValue, ParamMap, SalvageError, SalvageStep, AFFECTED_REGION_UNAVAILABLE,
};
use repair::registry::CallableId;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_NAME: &str = "vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 4;
const EXPECTED_COVERED: usize = 1;
const EXPECTED_NOT_APPLICABLE: usize = 23;
const EXPECTED_VECTORS_SHA256: &str =
    "4671f902a84061964b7d97ffb18d3c697622e3ddae61e5b7d8ec9c75e12a77e9";
const GAP_REGION: &str = "GAP-orphan-result-drop-affected-region";
const GAP_PLANNER: &str = "GAP-orphan-result-drop-planner";
const SEAM: &str = "sesslint.policy.abstention.AffectedRegion is not available";
const DETERMINISM_SEAM: &str = "sesslint.determinism.canonical_json_bytes is not available";
const COVERED_VECTOR: &str = "orphan_result_drop_direct_apply_refusals";
const BOOL_VECTOR: &str = "orphan_result_drop_bool_index_is_not_int";
const REGION_VECTOR: &str = "affected_region_orphan_result_drop";
const COVERED_TEST: &str =
    "tests/repair/test_recipes_salvage.py::test_orphan_result_drop_direct_apply_refusals";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/recipes/orphan-result-drop")
}

fn read_lf(path: &Path) -> String {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains('\r'), "{} contains CR", path.display());
    assert!(!raw.contains(SEAM), "{} stores the region seam", path.display());
    assert!(
        !raw.contains(DETERMINISM_SEAM),
        "{} stores the canonical_json_bytes seam",
        path.display()
    );
    assert!(!raw.contains("sesslint-wt"), "{} stores a worktree path", path.display());
    assert!(!raw.contains("FOR_WORK"), "{} stores a checkout path", path.display());
    assert!(!raw.contains("0 diff"), "{} claims a zero diff", path.display());
    assert!(!contains_sbp(&raw), "{} stores an sbp hash", path.display());
    raw
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

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[test]
fn orphan_result_drop_parity_vectors() {
    let dir = parity_dir();
    let vectors_raw = read_lf(&dir.join(VECTORS_NAME));
    let coverage_raw = read_lf(&dir.join("coverage.json"));
    let manifest_raw = read_lf(&dir.join("manifest.json"));
    let provenance_raw = read_lf(&dir.join("PROVENANCE.json"));
    let digest = vectors_sha256(vectors_raw.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256");
    assert!(vectors_raw.contains(GAP_REGION));
    assert!(vectors_raw.contains(GAP_PLANNER));
    assert!(!vectors_raw.contains("02694d5"));
    let cases = parse_cases(&vectors_raw).unwrap_or_else(|err| panic!("parse vectors: {err}"));
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT);
    for case in &cases {
        assert_case(case);
    }
    assert_coverage(&coverage_raw);
    assert_manifest(&manifest_raw, &digest);
    assert_provenance(&provenance_raw);
    assert_bool_is_not_int();
}

#[test]
fn missing_canonical_json_bytes_is_not_a_successful_plan() {
    let mapping = EventValue::Mapping(EventMapping::new(vec![
        ("id".to_owned(), EventField::Str("m0".to_owned())),
        ("kind".to_owned(), EventField::Str("message".to_owned())),
    ]));
    let hash_err = event_canonical_hash(&mapping).expect_err("canonical_json_bytes");
    assert_eq!(hash_err.to_string(), DETERMINISM_SEAM);
    assert_eq!(hash_err.to_string(), DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE);
    assert_eq!(hash_err.message(), DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE);
    assert!(!is_sha256_hex(&hash_err.to_string()));
    let fingerprint_err = event_content_fingerprint(&mapping).expect_err("content fingerprint");
    assert_eq!(fingerprint_err.to_string(), DETERMINISM_SEAM);
    assert_eq!(fingerprint_err.message(), DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE);
    assert!(!is_sha256_hex(&fingerprint_err.to_string()));

    let findings: &[Finding] = &[];
    let err = plan(
        findings,
        &orphan_source_events(),
        &PlanProfile::str_value("neutral"),
        None,
        &PlanPolicy::str_value("salvage"),
        true,
        None,
    )
    .expect_err("plan is not successful");
    assert!(!is_sha256_hex(&err.to_string()));
    assert!(!err.to_string().contains("0 diff"));
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").unwrap_or_else(|err| panic!("{}: {err}", case.id));
    match kind.as_str() {
        "recipe_constant" => assert_recipe(case),
        "apply_refusals" => assert_refusals(case),
        "affected_region" => assert_affected_region(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_recipe(case: &VectorCase) {
    let recipe = recipe_orphan_result_drop().unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let expected = &case.expected;
    assert_eq!(string_field(expected, "mode").expect("mode"), "recipe");
    assert_eq!(recipe.name(), string_field(expected, "name").expect("name"));
    assert_eq!(recipe.name(), "orphan-result-drop");
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
    assert_eq!(recipe.version(), string_field(expected, "version").expect("version"));
    assert_eq!(
        recipe.excludes_execution_dependence(),
        bool_field(expected, "excludes_execution_dependence").expect("excludes")
    );
    assert_eq!(
        recipe.apply().is_some(),
        bool_field(expected, "apply_present").expect("apply_present")
    );
    assert_eq!(
        recipe.affected_region().is_some(),
        bool_field(expected, "affected_region_present").expect("region_present")
    );
    assert_eq!(recipe.apply(), Some(CallableId::from_fn(apply_orphan_result_drop)));
    assert_eq!(
        recipe.affected_region(),
        Some(CallableId::from_fn(affected_region_orphan_result_drop))
    );
    assert_ne!(recipe.apply(), recipe.affected_region());
}

fn assert_refusals(case: &VectorCase) {
    assert_eq!(string_field(&case.construct, "fn").expect("fn"), "apply_orphan_result_drop");
    assert_eq!(string_field(&case.construct, "recipe").expect("recipe"), "orphan-result-drop");
    assert_eq!(string_field(&case.expected, "mode").expect("mode"), "precondition");
    assert_eq!(string_field(&case.expected, "error_type").expect("error_type"), "PreconditionFailed");
    assert_eq!(string_field(&case.expected, "fn").expect("expected fn"), "apply_orphan_result_drop");
    let cases = array_field(&case.construct, "cases").expect("cases");
    let outcomes = array_field(&case.expected, "outcomes").expect("outcomes");
    assert_eq!(cases.len(), outcomes.len(), "{}", case.id);
    assert!(cases.len() > 1, "{} is one example, not a whole proof", case.id);
    let mut messages = Vec::new();
    for (item, outcome) in cases.iter().zip(outcomes) {
        messages.push(assert_refusal_row(item, outcome));
    }
    assert_refusal_group(&case.id, cases, &messages);
}

fn assert_refusal_group(case_id: &str, cases: &[JsonValue], messages: &[String]) {
    let labels = labels_of(cases);
    if case_id == COVERED_VECTOR {
        assert_eq!(
            labels.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                "empty_session",
                "invalid_index",
                "not_tool_result",
                "not_orphan",
                "dependent_child",
            ]
        );
    } else if case_id == BOOL_VECTOR {
        assert_eq!(
            labels.iter().map(String::as_str).collect::<Vec<_>>(),
            ["bool_true", "int_one"]
        );
        assert_ne!(messages[0], messages[1], "{case_id}");
        assert!(messages[0].contains("no unambiguous"), "{case_id}");
        assert!(!messages[0].contains("index 1"), "{case_id}");
        assert!(messages[1].contains("not a tool_result"), "{case_id}");
    } else {
        panic!("unexpected refusal vector {case_id}");
    }
}

fn labels_of(cases: &[JsonValue]) -> Vec<String> {
    cases
        .iter()
        .map(|item| string_field(as_object(item, "case").expect("case"), "label").expect("label"))
        .collect()
}

fn assert_refusal_row(item: &JsonValue, outcome: &JsonValue) -> String {
    let row = as_object(item, "case").expect("case");
    let want = as_object(outcome, "outcome").expect("outcome");
    assert_eq!(string_field(want, "mode").expect("mode"), "precondition");
    assert_eq!(string_field(want, "error_type").expect("error_type"), "PreconditionFailed");
    let message = string_field(want, "message").expect("message");
    assert!(!message.is_empty(), "empty refusal");
    assert!(!is_sha256_hex(&message), "refusal message is a fingerprint");
    let label = string_field(row, "label").expect("label");
    let step_obj = object_field(row, "step").expect("step");
    let events = array_field(row, "events").expect("events");
    assert_step_shape(&label, step_obj, events);
    let decoded = decode_events(events);
    let step = decode_step(step_obj);
    match apply_orphan_result_drop(decoded, step) {
        Ok(_) => panic!("{label} returned Ok"),
        Err(SalvageError::Precondition(err)) => assert_eq!(err.to_string(), message, "{label}"),
        Err(other) => panic!("{label} returned {other}, not PreconditionFailed"),
    }
    message
}

fn assert_step_shape(label: &str, step: &[(String, JsonValue)], events: &[JsonValue]) {
    assert_eq!(string_field(step, "recipe").expect("recipe"), "orphan-result-drop");
    assert_eq!(string_field(step, "target_finding_fp").expect("fp"), "fp");
    assert_eq!(int_tag(field_ref(step, "seq")).expect("seq"), 0);
    require_lossy_bool(step);
    require_empty_params(step);
    let index = as_object(field_ref(step, "target_index"), "target_index").expect("index");
    match label {
        "empty_session" => {
            assert_eq!(string_field(index, "t").expect("tag"), "null");
            assert!(events.is_empty(), "{label}");
        }
        "invalid_index" => assert_indexed(index, events, 99, 4),
        "not_tool_result" => assert_indexed(index, events, 0, 4),
        "not_orphan" => assert_indexed(index, events, 2, 4),
        "int_one" => assert_indexed(index, events, 1, 4),
        "dependent_child" => {
            assert_indexed(index, events, 3, 5);
            assert_child(&events[4]);
        }
        "bool_true" => {
            assert_eq!(string_field(index, "t").expect("tag"), "bool");
            assert!(bool_field(index, "v").expect("bool"));
            assert!(int_field(index, "v").is_err(), "bool is not an int");
            assert_eq!(events.len(), 4, "{label}");
        }
        other => panic!("unexpected refusal label {other}"),
    }
}

fn assert_indexed(index: &[(String, JsonValue)], events: &[JsonValue], value: i64, len: usize) {
    assert_eq!(string_field(index, "t").expect("tag"), "int");
    assert_eq!(int_field(index, "v").expect("index"), value);
    assert_eq!(events.len(), len);
}

fn assert_child(event: &JsonValue) {
    let child = as_object(event, "child").expect("child");
    assert_eq!(string_field(child, "id").expect("id"), "ch1");
    assert_eq!(string_field(child, "kind").expect("kind"), "message");
    let parent = as_object(field_ref(child, "parent_id"), "parent").expect("parent");
    assert_eq!(string_field(parent, "t").expect("tag"), "str");
    assert_eq!(string_field(parent, "v").expect("parent id"), "tr_orph");
}

fn require_lossy_bool(step: &[(String, JsonValue)]) {
    let lossy = as_object(field_ref(step, "lossy"), "lossy").expect("lossy");
    assert_eq!(string_field(lossy, "t").expect("tag"), "bool");
    assert!(bool_field(lossy, "v").expect("lossy"));
    assert!(int_field(lossy, "v").is_err(), "bool is not an int");
}

fn require_empty_params(step: &[(String, JsonValue)]) {
    let params = as_object(field_ref(step, "params"), "params").expect("params");
    assert_eq!(string_field(params, "t").expect("tag"), "map");
    assert!(array_field(params, "entries").expect("entries").is_empty());
}

fn assert_affected_region(case: &VectorCase) {
    assert_eq!(case.id, REGION_VECTOR);
    assert_eq!(
        string_field(&case.construct, "fn").expect("fn"),
        "affected_region_orphan_result_drop"
    );
    assert_eq!(string_field(&case.expected, "mode").expect("mode"), "python_region");
    assert_eq!(string_field(&case.expected, "gap_id").expect("gap_id"), GAP_REGION);
    let region = object_field(&case.expected, "region").expect("region");
    assert!(!bool_field(region, "unproven").expect("unproven"));
    let indices = array_field(region, "indices").expect("indices");
    assert_eq!(indices.len(), 1);
    let JsonValue::Number(text) = &indices[0] else {
        panic!("region index bool is not an int");
    };
    assert_eq!(text, "3");
    assert_eq!(string_array(region, "ids").expect("ids"), ["tr_orph".to_owned()]);
    assert!(array_field(region, "ranges").expect("ranges").is_empty());
    let events = decode_events(array_field(&case.construct, "events").expect("events"));
    let step = decode_step(object_field(&case.construct, "step").expect("step"));
    let err = affected_region_orphan_result_drop(step, events).expect_err(&case.id);
    assert_eq!(err.to_string(), SEAM, "{}", case.id);
    assert_eq!(err.to_string(), AFFECTED_REGION_UNAVAILABLE, "{}", case.id);
    assert_eq!(err.message(), AFFECTED_REGION_UNAVAILABLE, "{}", case.id);
}

fn assert_coverage(raw: &str) {
    let (value, rest) = parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("coverage: {err}"));
    assert!(rest.trim().is_empty(), "coverage trailing");
    let obj = as_object(&value, "coverage").expect("coverage object");
    assert_eq!(usize_field(obj, "covered_count").expect("covered_count"), EXPECTED_COVERED);
    assert_eq!(
        usize_field(obj, "not_applicable_count").expect("not_applicable_count"),
        EXPECTED_NOT_APPLICABLE
    );
    let rows = array_field(obj, "rows").expect("rows");
    assert_eq!(rows.len(), EXPECTED_COVERED + EXPECTED_NOT_APPLICABLE);
    let mut covered = 0_usize;
    for row in rows {
        covered += assert_coverage_row(as_object(row, "row").expect("row"));
    }
    assert_eq!(covered, EXPECTED_COVERED);
}

fn assert_coverage_row(obj: &[(String, JsonValue)]) -> usize {
    let status = string_field(obj, "status").expect("status");
    let test = string_field(obj, "test").expect("test");
    assert_eq!(string_field(obj, "column").expect("column"), "column_0");
    let note = string_field(obj, "note").expect("note");
    assert!(!note.contains(SEAM), "{test}");
    assert!(!note.contains(DETERMINISM_SEAM), "{test}");
    assert!(!is_sha256_hex(&note), "{test}");
    if status == "covered" {
        assert_eq!(test, COVERED_TEST);
        assert_eq!(string_field(obj, "vector_id").expect("vector_id"), COVERED_VECTOR);
        assert_eq!(note, "");
        assert!(!test.contains("affected_region"), "{test}");
        return 1;
    }
    assert_eq!(status, "not_applicable", "{test}");
    assert!(matches!(field_ref(obj, "vector_id"), JsonValue::Null), "{test}");
    assert!(!note.is_empty(), "{test}");
    assert_named_gap(&test, &note);
    0
}

fn assert_named_gap(test: &str, note: &str) {
    if test.ends_with("test_orphan_result_drop_plans_and_applies") {
        assert!(note.contains("not a successful plan"), "{test}");
        assert!(note.contains("apply_orphan_result_drop_with_loss"), "{test}");
        assert!(note.contains("not the entire test"), "{test}");
    }
    if test.ends_with("test_orphan_result_drop_conservative_blocks") {
        assert!(note.contains("not a successful plan"), "{test}");
        assert!(note.contains("zero steps are not a diff"), "{test}");
        assert!(note.contains("not the entire test"), "{test}");
    }
    if test.ends_with("test_orphan_result_drop_resolves_by_params") {
        assert!(note.contains("mixes a successful drop"), "{test}");
        assert!(note.contains("not the entire test"), "{test}");
    }
    if test.ends_with("test_fingerprint_differs_by_policy") {
        assert!(note.contains("no fingerprint"), "{test}");
    }
}

fn assert_manifest(raw: &str, digest: &str) {
    let (value, rest) = parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("manifest: {err}"));
    assert!(rest.trim().is_empty(), "manifest trailing");
    let obj = as_object(&value, "manifest").expect("manifest object");
    assert_eq!(usize_field(obj, "vector_count").expect("vector_count"), EXPECTED_VECTOR_COUNT);
    assert_eq!(string_field(obj, "vectors_sha256").expect("vectors_sha256"), digest);
    assert_eq!(
        string_field(obj, "generator").expect("generator"),
        "rust/parity/recipes/orphan-result-drop/generate"
    );
    assert_eq!(string_field(obj, "recipe").expect("recipe"), "orphan-result-drop");
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

fn orphan_source_events() -> Vec<SourceHashEvent> {
    [
        source_event("m0", None, 0, "user", "message", None),
        source_event("tc1", Some("m0"), 1, "assistant", "tool_call", Some("corr-ok")),
        source_event("tr1", Some("tc1"), 2, "tool", "tool_result", Some("corr-ok")),
        source_event("tr_orph", Some("m0"), 3, "tool", "tool_result", Some("corr-orphan")),
    ]
    .into_iter()
    .collect()
}

fn source_event(
    id: &str,
    parent: Option<&str>,
    seq: i64,
    actor: &str,
    kind: &str,
    correlation: Option<&str>,
) -> SourceHashEvent {
    let mut event = SessionEvent::new(
        id,
        parent.map(ToOwned::to_owned),
        seq,
        "2026-09-05T12:00:00Z",
        actor,
        kind,
    );
    event.correlation_id = correlation.map(ToOwned::to_owned);
    SourceHashEvent::Session(Box::new(event))
}

fn decode_events(items: &[JsonValue]) -> Vec<EventValue> {
    items
        .iter()
        .map(|item| EventValue::from_session(decode_session(as_object(item, "event").expect("event"))))
        .collect()
}

fn decode_session(obj: &[(String, JsonValue)]) -> SessionEvent {
    assert_eq!(string_field(obj, "t").expect("form"), "session");
    let mut event = SessionEvent::new(
        string_field(obj, "id").expect("id"),
        optional_string(field_ref(obj, "parent_id")),
        int_tag(field_ref(obj, "seq")).expect("seq"),
        string_field(obj, "ts").expect("ts"),
        string_field(obj, "actor").expect("actor"),
        string_field(obj, "kind").expect("kind"),
    );
    event.correlation_id = optional_string(field_ref(obj, "correlation_id"));
    event
}

fn optional_string(value: &JsonValue) -> Option<String> {
    let obj = as_object(value, "optional").expect("optional");
    match string_field(obj, "t").expect("tag").as_str() {
        "null" => None,
        "str" => Some(string_field(obj, "v").expect("text")),
        "bool" | "int" => panic!("bool is not a string"),
        other => panic!("unsupported optional tag {other}"),
    }
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
        other => panic!("unsupported index tag {other}"),
    }
}

fn decode_params(value: &JsonValue) -> ParamMap {
    match decode_field(value).expect("params") {
        EventField::Mapping(mapping) => ParamMap::Mapping(mapping),
        _ => ParamMap::NotMapping,
    }
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

fn assert_gap_list(obj: &[(String, JsonValue)]) {
    let gaps = array_field(obj, "known_parity_gaps").expect("known_parity_gaps");
    let mut saw_region = false;
    let mut saw_planner = false;
    for gap in gaps {
        let JsonValue::Str(text) = gap else {
            panic!("gap must be a string");
        };
        assert!(!text.contains(SEAM), "{text}");
        assert!(!text.contains(DETERMINISM_SEAM), "{text}");
        assert!(!is_sha256_hex(text), "{text}");
        saw_region |= text.contains(GAP_REGION);
        saw_planner |= text.contains(GAP_PLANNER);
    }
    assert!(saw_region);
    assert!(saw_planner);
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

fn vectors_sha256(data: &[u8]) -> String {
    hex::encode(&sha256(data))
}
