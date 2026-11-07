//! Parity for `sesslint.repair.recipes_salvage` against pinned Python vectors.

use model::canonical::SessionEvent;
use model::codes::{Repairability, Severity, SL001, SL005, SL006, SL101, SL102, SL108};
use model::events::{EventField, EventMapping, EventValue};
use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
use repair::preconditions::PreconditionContext;
use repair::recipes_salvage::{
    affected_region_orphan_result_drop, apply_orphan_result_drop,
    apply_torn_compaction_project, apply_torn_record_excision, apply_torn_record_excision_with_loss,
    apply_side_effect_unknown_truncate, apply_unresolvable_branch_amputate, register_all,
    sl001_excisable, IndexValue, ParamMap, SalvageError, SalvageStep, ALL,
    AFFECTED_REGION_UNAVAILABLE,
};
use repair::registry::{clear_registry, get_recipe, list_recipes, recipes_for, Recipe};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

const VECTORS_REL: &str = "../../parity/vectors/repair.recipes_salvage/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 11;
const EXPECTED_VECTORS_SHA256: &str =
    "95ab68d4cb28d530e399c6cbaf8e4a7c9ad12351653d000953a7c0b77605acbc";
const GAP_ORPHAN_REGION: &str = "GAP-recipes-salvage-affected-region-orphan";
const SEAM: &str = "sesslint.policy.abstention.AffectedRegion is not available";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn isolate() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_registry();
    guard
}

fn read_lf(path: &PathBuf) -> String {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains('\r'), "{} contains CR", path.display());
    assert!(!raw.contains(SEAM), "{} stores the Rust seam sentence", path.display());
    assert!(!raw.contains("sesslint-wt"), "{} stores a worktree path", path.display());
    assert!(!raw.contains("FOR_WORK"), "{} stores a checkout path", path.display());
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

#[test]
fn recipes_salvage_module_parity_vectors() {
    let path = vectors_path();
    let raw = read_lf(&path);
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert!(
        normalized.contains(GAP_ORPHAN_REGION),
        "vectors must record the orphan affected-region gap"
    );
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );
    let cases =
        parse_document(&normalized).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
    }
}


fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => {
            let names = string_array(&case.expected, "names").expect("names");
            let want: Vec<&str> = names.iter().map(String::as_str).collect();
            assert_eq!(ALL.as_ref(), want.as_slice(), "{}", case.id);
        }
        "register_all" => assert_register_all(case),
        "registration_matrix" => assert_registration_matrix(case),
        "sl001_excisable_precondition" => assert_sl001_excisable(case),
        "apply_torn_record_excision_validation" => assert_excision_validation(case),
        "amputate_direct_apply_validation" => assert_amputate_validation(case),
        "torn_compaction_direct_apply_validation" => assert_compaction_validation(case),
        "truncate_direct_apply_validation" => assert_truncate_validation(case),
        "orphan_result_drop_resolves_by_params" => assert_orphan_resolves(case),
        "orphan_result_drop_direct_apply_refusals" => assert_orphan_refusals(case),
        "affected_region_orphan_gap" => assert_affected_region_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_register_all(case: &VectorCase) {
    let _guard = isolate();
    register_all().unwrap_or_else(|err| panic!("{}: {err}", case.id));
    register_all().unwrap_or_else(|err| panic!("{} second: {err}", case.id));
    let pin = object_field(&case.expected, "pin").expect("pin");
    assert_eq!(
        list_recipes().len(),
        usize_field(pin, "recipe_count").expect("recipe_count"),
        "{}",
        case.id
    );
}

fn assert_registration_matrix(case: &VectorCase) {
    let _guard = isolate();
    register_all().unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let pin = object_field(&case.expected, "pin").expect("pin");
    assert_eq!(
        list_recipes().len(),
        usize_field(pin, "recipe_count").expect("recipe_count"),
        "{}",
        case.id
    );
    let recipes_obj = object_field(pin, "recipes").expect("recipes");
    for (name, meta_value) in recipes_obj {
        let meta = as_object(meta_value, "recipe meta").expect("recipe meta");
        let recipe = get_recipe(name).unwrap_or_else(|| panic!("{} missing {name}", case.id));
        assert_recipe_meta(&case.id, name, &recipe, meta);
    }
    let rf = object_field(pin, "recipes_for").expect("recipes_for");
    assert_recipes_for(rf, "SL001", SL001, &case.id);
    assert_recipes_for(rf, "SL005", SL005, &case.id);
    assert_recipes_for(rf, "SL006", SL006, &case.id);
    assert_recipes_for(rf, "SL101", SL101, &case.id);
    assert_recipes_for(rf, "SL102", SL102, &case.id);
    assert_recipes_for(rf, "SL108", SL108, &case.id);
}

fn assert_recipe_meta(case_id: &str, name: &str, recipe: &Recipe, meta: &[(String, JsonValue)]) {
    assert_eq!(recipe.name(), name, "{case_id}");
    let handles = string_array(meta, "handles").expect("handles");
    assert_eq!(recipe.handles().to_vec(), handles, "{case_id} {name}");
    let preconds = string_array(meta, "preconditions").expect("preconditions");
    assert_eq!(recipe.preconditions().to_vec(), preconds, "{case_id} {name}");
    assert_eq!(
        recipe.lossy(),
        bool_field(meta, "lossy").expect("lossy"),
        "{case_id} {name}"
    );
    assert_eq!(
        recipe.salvage_only(),
        bool_field(meta, "salvage_only").expect("salvage_only"),
        "{case_id} {name}"
    );
}

fn assert_recipes_for(obj: &[(String, JsonValue)], key: &str, code: &str, case_id: &str) {
    let want = string_array(obj, key).expect(key);
    let got: Vec<String> = recipes_for(code).iter().map(|r| r.name().to_owned()).collect();
    assert_eq!(got, want, "{case_id} recipes_for {code}");
}

fn assert_sl001_excisable(case: &VectorCase) {
    let pin = object_field(&case.expected, "pin").expect("pin");
    let want = bool_array(pin, "values").expect("values");
    let got = sl001_excisable_checks();
    assert_eq!(got, want, "{}", case.id);
}

fn sl001_excisable_checks() -> Vec<bool> {
    let events = vec![sl001_msg(0, None), sl001_msg(2, None)];
    let f = sl001_finding(None, None, None);
    let mut out = vec![
        sl001_excisable(&sl001_ctx(&f, &events)),
        sl001_excisable(&sl001_ctx(
            &sl001_finding(None, None, Some(evidence_map(&[
                ("reason", PyValue::string("size_limit_exceeded")),
                ("limit", PyValue::int(10)),
            ]))),
            &events,
        )),
        sl001_excisable(&sl001_ctx(&sl001_finding(Some(None), None, None), &events)),
    ];
    for bad in [
        evidence_map(&[("byte_end", PyValue::int(10)), ("record_ordinal", PyValue::int(1))]),
        evidence_map(&[
            ("byte_offset", PyValue::int(5)),
            ("record_ordinal", PyValue::int(1)),
        ]),
        evidence_map(&[
            ("byte_offset", PyValue::int(0)),
            ("byte_end", PyValue::int(9)),
            ("record_ordinal", PyValue::int(0)),
        ]),
        evidence_map(&[
            ("byte_offset", PyValue::int(9)),
            ("byte_end", PyValue::int(9)),
            ("record_ordinal", PyValue::int(1)),
        ]),
        evidence_map(&[
            ("byte_offset", PyValue::string("x")),
            ("byte_end", PyValue::int(9)),
            ("record_ordinal", PyValue::int(1)),
        ]),
    ] {
        out.push(sl001_excisable(&sl001_ctx(&sl001_finding(None, None, Some(bad)), &events)));
    }
    let dependent = vec![sl001_msg(0, None), sl001_msg(2, None), sl001_msg(3, Some("msg-torn"))];
    out.push(sl001_excisable(&sl001_ctx(&f, &dependent)));
    let f_other = parity_finding(
        SL006,
        Severity::Warning,
        Repairability::Manual,
        Some(3),
        None,
        evidence_map(&[
            ("byte_offset", PyValue::int(120)),
            ("byte_end", PyValue::int(210)),
            ("record_ordinal", PyValue::int(2)),
        ]),
    );
    out.push(sl001_excisable(&sl001_ctx(&f_other, &events)));
    out
}

fn sl001_ctx<'a>(finding: &'a Finding, events: &'a [EventValue]) -> PreconditionContext<'a> {
    PreconditionContext {
        findings: std::slice::from_ref(finding),
        events,
        profile: "neutral",
        source_hash: "0000000000000000000000000000000000000000000000000000000000000000",
        finding: Some(finding),
        policy: "salvage",
        acknowledge_side_effects: true,
    }
}

fn sl001_msg(seq: i64, parent: Option<&str>) -> EventValue {
    let mut entries = vec![
        ("id", EventField::Str(format!("msg-{seq}"))),
        (
            "kind",
            EventField::Str("message".into()),
        ),
        (
            "seq",
            EventField::Int(seq),
        ),
    ];
    if let Some(parent_id) = parent {
        entries.push(("parent_id", EventField::Str(parent_id.to_owned())));
    }
    EventValue::Mapping(EventMapping::new(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    ))
}

fn sl001_finding(
    line: Option<Option<i64>>,
    record_id: Option<Option<&str>>,
    evidence: Option<PyValue>,
) -> Finding {
    let line_val = match line {
        None => Some(3),
        Some(None) => None,
        Some(Some(n)) => Some(n),
    };
    let record = match record_id {
        None => Some("msg-torn"),
        Some(None) => None,
        Some(Some(rid)) => Some(rid),
    };
    let evidence = evidence.unwrap_or_else(|| {
        evidence_map(&[
            ("byte_offset", PyValue::int(120)),
            ("byte_end", PyValue::int(210)),
            ("record_ordinal", PyValue::int(2)),
        ])
    });
    parity_finding(
        SL001,
        Severity::Error,
        Repairability::Manual,
        line_val,
        record,
        evidence,
    )
}

fn parity_finding(
    code: &str,
    severity: Severity,
    repairability: Repairability,
    line: Option<i64>,
    record_id: Option<&str>,
    evidence: PyValue,
) -> Finding {
    let source = SourceRef::try_new("sess.jsonl", line.map(SourceLine::Int), record_id).expect("source");
    Finding::try_new(FindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(repairability),
        message: PyValue::string("synthetic parity marker"),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string("0123456789abcdef"),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::None,
        evidence,
    })
    .expect("finding")
}

fn pmap(entries: Vec<(&str, EventField)>) -> ParamMap {
    ParamMap::Mapping(EventMapping::new(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    ))
}

fn evidence_map(entries: &[(&str, PyValue)]) -> PyValue {
    PyValue::map(
        entries
            .iter()
            .map(|(k, v)| (PyValue::string(*k), v.clone()))
            .collect(),
    )
}

fn assert_excision_validation(case: &VectorCase) {
    let pin = object_field(&case.expected, "pin").expect("pin");
    let success = object_field(pin, "success").expect("success");
    let events = vec![sl001_msg(0, None), sl001_msg(2, None)];
    let step = torn_excision_step();
    let (out, loss) = apply_torn_record_excision_with_loss(&events, &step)
        .unwrap_or_else(|err| panic!("{} success: {err}", case.id));
    assert_eq!(loss.entries(), &[("torn-record".to_owned(), 1)], "{}", case.id);
    let want_ids = string_array(success, "ids").expect("ids");
    let got_ids: Vec<String> = out
        .iter()
        .filter_map(|row| match row.get("id") {
            Some(EventField::Str(text)) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(got_ids, want_ids, "{}", case.id);
    assert_eq!(
        apply_torn_record_excision(events.clone(), step.clone()).expect("plain"),
        out,
        "{}",
        case.id
    );
    let want_refusals = string_array(pin, "refusals").expect("refusals");
    let mut got_refusals = Vec::new();
    match apply_torn_record_excision(vec![], step.clone()) {
        Ok(_) => panic!("{} expected empty refusal", case.id),
        Err(err) => got_refusals.push(precondition_message(&err)),
    }
    for bad in torn_bad_params() {
        match apply_torn_record_excision(events.clone(), bad) {
            Ok(_) => panic!("{} expected refusal", case.id),
            Err(err) => got_refusals.push(precondition_message(&err)),
        }
    }
    let dependent = vec![
        sl001_msg(0, None),
        sl001_msg(2, None),
        sl001_msg(3, Some("msg-torn")),
    ];
    match apply_torn_record_excision(dependent, step) {
        Ok(_) => panic!("{} expected dependent refusal", case.id),
        Err(err) => got_refusals.push(precondition_message(&err)),
    }
    assert_eq!(got_refusals, want_refusals, "{}", case.id);
}

fn torn_excision_step() -> SalvageStep {
    SalvageStep {
        target_index: IndexValue::None,
        params: pmap(vec![
            ("line", EventField::Int(3)),
            ("record_ordinal", EventField::Int(2)),
            ("byte_offset", EventField::Int(120)),
            ("byte_end", EventField::Int(210)),
            ("record_id", EventField::Str("msg-torn".into())),
        ]),
    }
}

fn torn_bad_params() -> Vec<SalvageStep> {
    vec![
        SalvageStep {
            target_index: IndexValue::None,
            params: pmap(vec![
                ("record_ordinal", EventField::Int(2)),
                ("byte_offset", EventField::Int(1)),
                ("byte_end", EventField::Int(5)),
            ]),
        },
        SalvageStep {
            target_index: IndexValue::None,
            params: pmap(vec![
                ("line", EventField::Int(0)),
                ("record_ordinal", EventField::Int(2)),
                ("byte_offset", EventField::Int(1)),
                ("byte_end", EventField::Int(5)),
            ]),
        },
        SalvageStep {
            target_index: IndexValue::None,
            params: pmap(vec![
                ("line", EventField::Int(3)),
                ("record_ordinal", EventField::Int(0)),
                ("byte_offset", EventField::Int(1)),
                ("byte_end", EventField::Int(5)),
            ]),
        },
        SalvageStep {
            target_index: IndexValue::None,
            params: pmap(vec![
                ("line", EventField::Int(3)),
                ("record_ordinal", EventField::Int(2)),
                ("byte_offset", EventField::Int(5)),
                ("byte_end", EventField::Int(5)),
            ]),
        },
        SalvageStep {
            target_index: IndexValue::None,
            params: pmap(vec![
                ("line", EventField::Str("3".into())),
                ("record_ordinal", EventField::Int(2)),
                ("byte_offset", EventField::Int(1)),
                ("byte_end", EventField::Int(5)),
            ]),
        },
    ]
}

fn assert_amputate_validation(case: &VectorCase) {
    assert_precondition_messages(case, run_amputate_refusals());
}

fn run_amputate_refusals() -> Vec<String> {
    let step = SalvageStep {
        target_index: IndexValue::Int(0),
        params: pmap(vec![]),
    };
    let mut messages = Vec::new();
    push_precondition(&mut messages, apply_unresolvable_branch_amputate(&[], &step));
    let ev = EventValue::from_session(SessionEvent::new(
        "m0",
        None,
        0,
        "2026-09-05T12:00:00Z",
        "user",
        "message",
    ));
    push_precondition(
        &mut messages,
        apply_unresolvable_branch_amputate(
            std::slice::from_ref(&ev),
            &SalvageStep {
                target_index: IndexValue::Int(99),
                params: pmap(vec![]),
            },
        ),
    );
    let ev_cp = EventValue::from_session(SessionEvent::new(
        "cp1",
        None,
        0,
        "2026-09-05T12:00:00Z",
        "system",
        "checkpoint",
    ));
    let ev_ch = EventValue::from_session(SessionEvent::new(
        "ch1",
        Some("cp1".into()),
        1,
        "2026-09-05T12:00:01Z",
        "user",
        "message",
    ));
    push_precondition(
        &mut messages,
        apply_unresolvable_branch_amputate(
            &[ev_cp, ev_ch],
            &SalvageStep {
                target_index: IndexValue::Int(1),
                params: pmap(vec![]),
            },
        ),
    );
    push_precondition(
        &mut messages,
        apply_unresolvable_branch_amputate(
            std::slice::from_ref(&ev),
            &SalvageStep {
                target_index: IndexValue::Int(0),
                params: pmap(vec![]),
            },
        ),
    );
    messages
}

fn assert_compaction_validation(case: &VectorCase) {
    assert_precondition_messages(case, run_compaction_refusals());
}

fn run_compaction_refusals() -> Vec<String> {
    let step = SalvageStep {
        target_index: IndexValue::Int(0),
        params: pmap(vec![]),
    };
    let mut messages = Vec::new();
    push_precondition(&mut messages, apply_torn_compaction_project(&[], &step));
    let ev_msg = EventValue::from_session(SessionEvent::new(
        "m0",
        None,
        0,
        "2026-09-05T12:00:00Z",
        "user",
        "message",
    ));
    push_precondition(
        &mut messages,
        apply_torn_compaction_project(std::slice::from_ref(&ev_msg), &step),
    );
    let ev_cb = EventValue::from_session(SessionEvent::new(
        "cb0",
        Some("m0".into()),
        1,
        "2026-09-05T12:00:01Z",
        "system",
        "compaction_boundary",
    ));
    push_precondition(
        &mut messages,
        apply_torn_compaction_project(
            &[ev_msg, ev_cb],
            &SalvageStep {
                target_index: IndexValue::Int(1),
                params: pmap(vec![]),
            },
        ),
    );
    messages
}

fn assert_truncate_validation(case: &VectorCase) {
    assert_precondition_messages(case, run_truncate_refusals());
}

fn run_truncate_refusals() -> Vec<String> {
    let step = SalvageStep {
        target_index: IndexValue::Int(0),
        params: pmap(vec![]),
    };
    let mut messages = Vec::new();
    push_precondition(&mut messages, apply_side_effect_unknown_truncate(&[], &step));
    let ev = EventValue::from_session(SessionEvent::new(
        "m0",
        None,
        0,
        "2026-09-05T12:00:00Z",
        "user",
        "message",
    ));
    push_precondition(
        &mut messages,
        apply_side_effect_unknown_truncate(std::slice::from_ref(&ev), &step),
    );
    push_precondition(
        &mut messages,
        apply_side_effect_unknown_truncate(
            std::slice::from_ref(&ev),
            &SalvageStep {
                target_index: IndexValue::Int(5),
                params: pmap(vec![]),
            },
        ),
    );
    messages
}

fn assert_orphan_resolves(case: &VectorCase) {
    let pin = object_field(&case.expected, "pin").expect("pin");
    let events = orphan_session_events();
    let by_corr = SalvageStep {
        target_index: IndexValue::None,
        params: pmap(vec![(
            "correlation_id",
            EventField::Str("corr-orphan".into()),
        )]),
    };
    let out = apply_orphan_result_drop(events.clone(), by_corr.clone()).expect("corr");
    assert_event_ids(&out, &string_array(pin, "ids_by_corr").expect("ids_by_corr"), &case.id);
    let by_id = SalvageStep {
        target_index: IndexValue::None,
        params: pmap(vec![("result_id", EventField::Str("tr_orph".into()))]),
    };
    let out2 = apply_orphan_result_drop(events.clone(), by_id).expect("id");
    assert_event_ids(&out2, &string_array(pin, "ids_by_id").expect("ids_by_id"), &case.id);
    let mut amb = events.clone();
    amb.push(orphan_tool_result("tr_orph2", "m0", 4));
    let err = apply_orphan_result_drop(amb, by_corr.clone()).expect_err("ambiguous");
    assert_eq!(
        precondition_message(&err),
        string_field(pin, "ambiguous").expect("ambiguous"),
        "{}",
        case.id
    );
}

fn assert_orphan_refusals(case: &VectorCase) {
    assert_precondition_messages(case, run_orphan_refusals());
}

fn run_orphan_refusals() -> Vec<String> {
    let events = orphan_session_events();
    let base = |index: IndexValue| SalvageStep {
        target_index: index,
        params: pmap(vec![]),
    };
    let mut messages = Vec::new();
    push_precondition(
        &mut messages,
        apply_orphan_result_drop(vec![], base(IndexValue::None)),
    );
    push_precondition(
        &mut messages,
        apply_orphan_result_drop(events.clone(), base(IndexValue::Int(99))),
    );
    push_precondition(
        &mut messages,
        apply_orphan_result_drop(events.clone(), base(IndexValue::Int(0))),
    );
    push_precondition(
        &mut messages,
        apply_orphan_result_drop(events.clone(), base(IndexValue::Int(2))),
    );
    let mut with_child = events.clone();
    with_child.push(orphan_mapping(
        "message",
        "ch1",
        Some("tr_orph"),
        None,
    ));
    push_precondition(
        &mut messages,
        apply_orphan_result_drop(with_child, base(IndexValue::Int(3))),
    );
    messages
}

fn assert_affected_region_gap(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "gap",
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "gap_id").expect("gap_id"),
        GAP_ORPHAN_REGION,
        "{}",
        case.id
    );
    let _region_obj = object_field(&case.expected, "region").expect("region documents Python");
    let events = decode_events(case);
    let step = decode_salvage_step(case);
    let err = affected_region_orphan_result_drop(step, events).expect_err(&case.id);
    assert_eq!(err.to_string(), AFFECTED_REGION_UNAVAILABLE, "{}", case.id);
    assert_eq!(err.message(), AFFECTED_REGION_UNAVAILABLE);
}

fn assert_precondition_messages(case: &VectorCase, got: Vec<String>) {
    let pin = object_field(&case.expected, "pin").expect("pin");
    let want = string_array(pin, "messages").expect("messages");
    assert_eq!(got, want, "{}", case.id);
}

fn push_precondition(messages: &mut Vec<String>, result: Result<Vec<EventMapping>, SalvageError>) {
    match result {
        Ok(_) => messages.push("unexpected success".into()),
        Err(err) => messages.push(precondition_message(&err)),
    }
}

fn precondition_message(err: &SalvageError) -> String {
    match err {
        SalvageError::Precondition(pf) => pf.to_string(),
        other => other.to_string(),
    }
}

fn assert_event_ids(events: &[EventMapping], want: &[String], case_id: &str) {
    let got: Vec<String> = events
        .iter()
        .filter_map(|row| match row.get("id") {
            Some(EventField::Str(text)) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(got, want, "{case_id}");
}

fn orphan_session_events() -> Vec<EventValue> {
    vec![
        orphan_mapping("message", "m0", None, None),
        orphan_mapping("tool_call", "tc1", Some("m0"), Some("corr-ok")),
        orphan_mapping("tool_result", "tr1", Some("tc1"), Some("corr-ok")),
        orphan_mapping("tool_result", "tr_orph", Some("m0"), Some("corr-orphan")),
    ]
}

fn orphan_mapping(kind: &str, id: &str, parent: Option<&str>, corr: Option<&str>) -> EventValue {
    let mut entries = vec![("kind", EventField::Str(kind.to_owned())), ("id", EventField::Str(id.to_owned()))];
    if let Some(parent_id) = parent {
        entries.push(("parent_id", EventField::Str(parent_id.to_owned())));
    }
    if let Some(correlation_id) = corr {
        entries.push((
            "correlation_id",
            EventField::Str(correlation_id.to_owned()),
        ));
    }
    EventValue::Mapping(EventMapping::new(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    ))
}

fn orphan_tool_result(id: &str, parent: &str, _seq: i64) -> EventValue {
    orphan_mapping("tool_result", id, Some(parent), Some("corr-orphan"))
}

fn decode_events(case: &VectorCase) -> Vec<EventValue> {
    let items = array_field(&case.construct, "events").expect("events");
    items
        .iter()
        .map(|item| decode_event_value(item).unwrap_or_else(|err| panic!("{}: {err}", case.id)))
        .collect()
}

fn decode_event_value(value: &JsonValue) -> Result<EventValue, ParseError> {
    let obj = as_object(value, "event")?;
    if string_field(obj, "t").ok().as_deref() == Some("session") {
        return decode_session_event(obj).map(EventValue::from_session);
    }
    let entries = array_field(obj, "entries")?;
    let pairs = decode_mapping_entries(entries)?;
    Ok(EventValue::Mapping(EventMapping::new(pairs)))
}

fn decode_session_event(obj: &[(String, JsonValue)]) -> Result<SessionEvent, ParseError> {
    let id = string_field(obj, "id")?;
    let parent = optional_string_or_null_field(obj, "parent_id")?;
    let seq = i64_field(obj, "seq")?;
    let ts = string_field(obj, "ts")?;
    let actor = string_field(obj, "actor")?;
    let kind = string_field(obj, "kind")?;
    let mut event = SessionEvent::new(id, parent, seq, ts, actor, kind);
    if let Ok(corr) = string_field(obj, "correlation_id") {
        event.correlation_id = Some(corr);
    }
    Ok(event)
}

fn decode_mapping_entries(entries: &[JsonValue]) -> Result<Vec<(String, EventField)>, ParseError> {
    let mut out = Vec::new();
    for row in entries {
        let JsonValue::Array(pair) = row else {
            return Err(ParseError {
                message: "entry pair must be array".into(),
            });
        };
        if pair.len() != 2 {
            return Err(ParseError {
                message: "entry pair length".into(),
            });
        }
        let JsonValue::Str(key) = &pair[0] else {
            return Err(ParseError {
                message: "entry key must be string".into(),
            });
        };
        let field = decode_event_field(&pair[1])?;
        out.push((key.clone(), field));
    }
    Ok(out)
}

fn decode_event_field(value: &JsonValue) -> Result<EventField, ParseError> {
    let obj = as_object(value, "field")?;
    let kind = string_field(obj, "t")?;
    match kind.as_str() {
        "null" => Ok(EventField::Null),
        "bool" => Ok(EventField::Bool(bool_field(obj, "v")?)),
        "int" => Ok(EventField::Int(i64_field(obj, "v")?)),
        "float" => Ok(EventField::Float(f64_field(obj, "v")?)),
        "str" => Ok(EventField::Str(string_field(obj, "v")?)),
        _ => Err(ParseError {
            message: format!("unsupported field tag {kind}"),
        }),
    }
}

fn decode_salvage_step(case: &VectorCase) -> SalvageStep {
    let step_obj = object_field(&case.construct, "step").expect("step");
    let target = decode_index_value(
        step_obj
            .iter()
            .find(|(k, _)| k == "target_index")
            .map(|(_, v)| v)
            .expect("target_index"),
    );
    let params_node = step_obj
        .iter()
        .find(|(k, _)| k == "params")
        .map(|(_, v)| v)
        .expect("params");
    let params = decode_param_map(params_node).expect("params");
    SalvageStep {
        target_index: target,
        params,
    }
}

fn decode_index_value(value: &JsonValue) -> IndexValue {
    let obj = match value {
        JsonValue::Object(entries) => entries,
        _ => panic!("target_index must be object"),
    };
    let kind = string_field(obj, "t").expect("target tag");
    match kind.as_str() {
        "null" => IndexValue::None,
        "int" => IndexValue::Int(i64_field(obj, "v").expect("int")),
        "bool" => IndexValue::Bool(bool_field(obj, "v").expect("bool")),
        other => panic!("unsupported target tag {other}"),
    }
}

fn decode_param_map(value: &JsonValue) -> Result<ParamMap, ParseError> {
    let obj = as_object(value, "params")?;
    let kind = string_field(obj, "t")?;
    if kind == "not_mapping" {
        return Ok(ParamMap::NotMapping);
    }
    if kind != "map" {
        return Err(ParseError {
            message: format!("bad params tag {kind}"),
        });
    }
    let entries = array_field(obj, "entries")?;
    let pairs = decode_mapping_entries(entries)?;
    Ok(ParamMap::Mapping(EventMapping::new(pairs)))
}

fn bool_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<bool>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Bool(value) => Ok(*value),
            _ => Err(ParseError {
                message: format!("{key} entries must be bool"),
            }),
        })
        .collect()
}
fn optional_string_or_null_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn f64_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<f64>().map_err(|_| ParseError {
            message: format!("{key} must be float"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be int"),
        }),
        Some((_, JsonValue::Str(s))) => s.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(&sha256(bytes))
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
        0x6a09e667_u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
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

// --- minimal JSON (vectors.json only) ---

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn parse_document(input: &str) -> Result<Vec<VectorCase>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let JsonValue::Object(root) = value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let vectors = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    items.iter().map(parse_vector_case).collect()
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    match &value.1 {
        JsonValue::Array(items) => Ok(items.as_slice()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        Some((_, JsonValue::Number(n))) => Ok(n.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
            }),
        })
        .collect()
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(value))) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be unsigned integer"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
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
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
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
    let num = input[..idx].to_string();
    Ok((JsonValue::Number(num), &input[idx..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
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
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
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
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, c)| c).collect();
                        if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad \\u escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".into(),
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
