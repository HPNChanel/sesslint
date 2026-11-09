//! Parity for `sesslint.repair.recipes_conservative` against pinned Python vectors.

use model::codes::{SL003, SL004, SL005, SL101, SL104, SL108, SL203};
use model::events::{EventField, EventMapping, EventValue};
use repair::recipes_conservative::{
    apply_compaction_projection_reunion, apply_duplicate_projection_removal,
    apply_identical_duplicate_collapse, apply_proven_unique_parent_restore,
    apply_terminal_suffix_discard, register_all, ConservativeError, IndexValue, ParamMap,
    RecipeStep, ALL,
};
use repair::registry::{clear_registry, get_recipe, list_recipes, recipes_for};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

const VECTORS_REL: &str = "../../parity/vectors/repair.recipes_conservative/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 12;
const EXPECTED_VECTORS_SHA256: &str =
    "56d83b9843c19d8a11a75c1167918d66d870e3f534af6e1569b876957cd36b40";
const GAP_AFFECTED_REGION: &str = "GAP-recipes-conservative-affected-region";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn isolate() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_registry();
    guard
}

#[test]
fn recipes_conservative_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert!(
        normalized.contains(GAP_AFFECTED_REGION),
        "vectors must record the affected-region gap"
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
        "module_all" => assert_module_all(case),
        "registration_matrix" => assert_registration_matrix(case),
        "register_all" => assert_register_all(case),
        "fixture_apply" => assert_fixture_apply(case),
        "fixture_parent_restore" => assert_fixture_parent_restore(case),
        "apply" => assert_apply(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_all(case: &VectorCase) {
    let pin = object_field(&case.expected, "pin").expect("pin");
    let names = string_array(pin, "names").expect("names");
    let want: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(ALL.as_ref(), want.as_slice(), "{}", case.id);
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
    for (name, value) in recipes_obj {
        let meta = as_object(value, "recipe meta").expect("recipe meta");
        let recipe = get_recipe(name).unwrap_or_else(|| panic!("{} missing {name}", case.id));
        let handles = string_array(meta, "handles").expect("handles");
        assert_eq!(recipe.handles().to_vec(), handles, "{} {name}", case.id);
        let preconds = string_array(meta, "preconditions").expect("preconditions");
        assert_eq!(recipe.preconditions().to_vec(), preconds, "{} {name}", case.id);
        assert_eq!(
            recipe.lossy(),
            bool_field(meta, "lossy").expect("lossy"),
            "{} {name}",
            case.id
        );
        assert_eq!(
            recipe.salvage_only(),
            bool_field(meta, "salvage_only").expect("salvage_only"),
            "{} {name}",
            case.id
        );
    }
    let rf = object_field(pin, "recipes_for").expect("recipes_for");
    assert_recipes_for(rf, "SL003", SL003, &case.id);
    assert_recipes_for(rf, "SL004", SL004, &case.id);
    assert_recipes_for(rf, "SL005", SL005, &case.id);
    assert_recipes_for(rf, "SL104", SL104, &case.id);
    assert_recipes_for(rf, "SL108", SL108, &case.id);
    assert_recipes_for(rf, "SL203", SL203, &case.id);
    assert_recipes_for(rf, "SL101", SL101, &case.id);
}

fn assert_recipes_for(
    obj: &[(String, JsonValue)],
    key: &str,
    code: &str,
    case_id: &str,
) {
    let want = string_array(obj, key).expect(key);
    let got: Vec<String> = recipes_for(code).iter().map(|r| r.name().to_owned()).collect();
    assert_eq!(got, want, "{case_id} recipes_for {code}");
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

fn assert_fixture_apply(case: &VectorCase) {
    let rel = string_field(&case.construct, "fixture").expect("fixture");
    let data = load_fixture_json(&rel).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let events = plain_events_from_json(fixture_field(&data, "input_events").expect("input_events"))
        .expect("input_events");
    let step = recipe_step_from_fixture_step(fixture_field(&data, "step").expect("step")).expect("step");
    let fn_name = string_field(&case.construct, "fn").expect("fn");
    let out = dispatch_apply(&fn_name, &events, &step).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let pin = object_field(&case.expected, "pin").expect("pin");
    assert_pin_ok(&case.id, &out, pin);
    if bool_field(&case.construct, "loss").unwrap_or(false) {
        assert_eq!(
            events.len() - out.len(),
            usize_field(pin, "loss_count").expect("loss_count"),
            "{}",
            case.id
        );
    }
}

fn assert_fixture_parent_restore(case: &VectorCase) {
    let rel = string_field(&case.construct, "fixture").expect("fixture");
    let data = load_fixture_json(&rel).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let pin = object_field(&case.expected, "pin").expect("pin");
    let happy = object_field(&data, "happy_path").expect("happy_path");
    let events = plain_events_from_json(fixture_field(happy, "input_events").expect("input_events"))
        .expect("happy input");
    let step = recipe_step_from_fixture_step(fixture_field(happy, "step").expect("step")).expect("happy step");
    let out = apply_proven_unique_parent_restore(&events, &step)
        .unwrap_or_else(|err| panic!("{} happy: {err}", case.id));
    let happy_pin = object_field(pin, "happy").expect("happy");
    assert_pin_ok(&case.id, &out, happy_pin);
    let ambig = object_field(&data, "refusal_ambiguous").expect("refusal_ambiguous");
    let events_a =
        plain_events_from_json(fixture_field(ambig, "input_events").expect("input_events"))
            .expect("ambig input");
    let step_a = recipe_step_from_fixture_step(fixture_field(ambig, "step").expect("step"))
        .expect("ambig step");
    let err = apply_proven_unique_parent_restore(&events_a, &step_a).expect_err(&case.id);
    let ambig_pin = object_field(pin, "ambiguous").expect("ambiguous");
    let want = string_field(ambig_pin, "message").expect("message");
    assert_precondition_display(&err, &want, &case.id);
}

fn assert_apply(case: &VectorCase) {
    let fn_name = string_field(&case.construct, "fn").expect("fn");
    let events = events_from_construct(case).expect("events");
    let step = recipe_step_from_construct(case).expect("step");
    let pin = object_field(&case.expected, "pin").expect("pin");
    if let Ok(mode) = string_field(pin, "mode") {
        if mode == "precondition" {
            let err = dispatch_apply(&fn_name, &events, &step).expect_err(&case.id);
            let want = string_field(pin, "message").expect("message");
            assert_precondition_display(&err, &want, &case.id);
            return;
        }
    }
    let out = dispatch_apply(&fn_name, &events, &step).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_pin_ok(&case.id, &out, pin);
}

fn assert_precondition_display(err: &ConservativeError, want: &str, case_id: &str) {
    assert_eq!(err.to_string(), want, "{case_id}");
    assert!(matches!(err, ConservativeError::Precondition(_)), "{case_id}");
}

fn assert_pin_ok(case_id: &str, out: &[EventMapping], pin: &[(String, JsonValue)]) {
    let ids = optional_string_ids(out);
    let want_ids: Vec<Option<String>> = string_array(pin, "ids")
        .expect("ids")
        .into_iter()
        .map(Some)
        .collect();
    assert_eq!(ids, want_ids, "{case_id}");
    assert_eq!(
        out.len(),
        usize_field(pin, "len").expect("len"),
        "{case_id}"
    );
    if let Ok(child_obj) = object_field(pin, "child_parent") {
        let cid = string_field(child_obj, "id").expect("child id");
        let want_parent = optional_string_or_null_field(child_obj, "parent_id").expect("parent_id");
        let child = out
            .iter()
            .find(|e| event_id_str(e).as_deref() == Some(cid.as_str()))
            .unwrap_or_else(|| panic!("{case_id} missing child {cid}"));
        assert_eq!(event_parent_str(child), want_parent, "{case_id}");
    }
}

fn optional_string_ids(events: &[EventMapping]) -> Vec<Option<String>> {
    events.iter().map(event_id_str).collect()
}

fn event_id_str(event: &EventMapping) -> Option<String> {
    match event.get("id") {
        Some(EventField::Str(text)) => Some(text.clone()),
        Some(EventField::Null) | None => None,
        _ => None,
    }
}

fn event_parent_str(event: &EventMapping) -> Option<String> {
    match event.get("parent_id") {
        Some(EventField::Str(text)) => Some(text.clone()),
        Some(EventField::Null) | None => None,
        _ => None,
    }
}

fn dispatch_apply(
    fn_name: &str,
    events: &[EventValue],
    step: &RecipeStep,
) -> Result<Vec<EventMapping>, ConservativeError> {
    match fn_name {
        "apply_terminal_suffix_discard" => apply_terminal_suffix_discard(events, step),
        "apply_identical_duplicate_collapse" => apply_identical_duplicate_collapse(events, step),
        "apply_proven_unique_parent_restore" => apply_proven_unique_parent_restore(events, step),
        "apply_compaction_projection_reunion" => apply_compaction_projection_reunion(events, step),
        "apply_duplicate_projection_removal" => apply_duplicate_projection_removal(events, step),
        other => Err(ConservativeError::Precondition(repair::recipes_conservative::PreconditionFailed::new(
            format!("unknown fn {other}"),
        ))),
    }
}

fn load_fixture_json(rel: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let path = repo_root().join(rel);
    let raw = std::fs::read_to_string(&path).map_err(|err| ParseError {
        message: format!("read {rel}: {err}"),
    })?;
    let (value, rest) = parse_value(raw.trim()).map_err(|e| ParseError {
        message: format!("{rel}: {}", e.message),
    })?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: format!("trailing json in {rel}"),
        });
    }
    let obj = as_object(&value, "fixture")?;
    Ok(obj.to_vec())
}

fn fixture_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a JsonValue, ParseError> {
    obj.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or_else(|| ParseError {
            message: format!("missing {key}"),
        })
}

fn plain_events_from_json(value: &JsonValue) -> Result<Vec<EventValue>, ParseError> {
    let items = match value {
        JsonValue::Array(items) => items,
        _ => {
            return Err(ParseError {
                message: "events must be array".into(),
            })
        }
    };
    items.iter().map(decode_plain_event).collect()
}

fn decode_plain_event(value: &JsonValue) -> Result<EventValue, ParseError> {
    let obj = as_object(value, "event")?;
    let pairs = json_object_to_fields(obj)?;
    Ok(EventValue::Mapping(EventMapping::new(pairs)))
}

fn json_object_to_fields(obj: &[(String, JsonValue)]) -> Result<Vec<(String, EventField)>, ParseError> {
    let mut pairs = Vec::new();
    for (key, value) in obj {
        pairs.push((key.clone(), json_scalar_to_field(value)?));
    }
    Ok(pairs)
}

fn json_scalar_to_field(value: &JsonValue) -> Result<EventField, ParseError> {
    match value {
        JsonValue::Null => Ok(EventField::Null),
        JsonValue::Bool(b) => Ok(EventField::Bool(*b)),
        JsonValue::Number(n) => {
            let i = n.parse::<i64>().map_err(|_| ParseError {
                message: "int expected".into(),
            })?;
            Ok(EventField::Int(i))
        }
        JsonValue::Str(s) => Ok(EventField::Str(s.clone())),
        JsonValue::Array(items) => {
            let mapped: Result<Vec<EventField>, ParseError> =
                items.iter().map(json_scalar_to_field).collect();
            Ok(EventField::List(mapped?))
        }
        JsonValue::Object(entries) => {
            let inner = json_object_to_fields(entries)?;
            Ok(EventField::Mapping(EventMapping::new(inner)))
        }
    }
}

fn events_from_construct(case: &VectorCase) -> Result<Vec<EventValue>, ParseError> {
    let items = array_field(&case.construct, "events")?;
    items.iter().map(decode_plain_event).collect()
}

fn recipe_step_from_construct(case: &VectorCase) -> Result<RecipeStep, ParseError> {
    let step_obj = object_field(&case.construct, "step")?;
    recipe_step_from_tagged(step_obj)
}

fn recipe_step_from_fixture_step(value: &JsonValue) -> Result<RecipeStep, ParseError> {
    let obj = as_object(value, "step")?;
    let target = match obj.iter().find(|(k, _)| k == "target_index") {
        Some((_, JsonValue::Number(n))) => {
            IndexValue::Int(n.parse::<i64>().map_err(|_| ParseError {
                message: "target_index int".into(),
            })?)
        }
        Some((_, JsonValue::Null)) => IndexValue::None,
        Some((_, JsonValue::Bool(b))) => IndexValue::Bool(*b),
        _ => IndexValue::None,
    };
    let empty_params = JsonValue::Object(Vec::new());
    let params_node = obj
        .iter()
        .find(|(k, _)| k == "params")
        .map(|(_, v)| v)
        .unwrap_or(&empty_params);
    let params = decode_plain_params(params_node)?;
    Ok(RecipeStep { target_index: target, params })
}

fn decode_plain_params(value: &JsonValue) -> Result<ParamMap, ParseError> {
    match value {
        JsonValue::Object(entries) => {
            let pairs = json_object_to_fields(entries)?;
            Ok(ParamMap::Mapping(EventMapping::new(pairs)))
        }
        _ => Ok(ParamMap::NotMapping),
    }
}

fn recipe_step_from_tagged(obj: &[(String, JsonValue)]) -> Result<RecipeStep, ParseError> {
    let ti = obj
        .iter()
        .find(|(k, _)| k == "target_index")
        .map(|(_, v)| v)
        .ok_or_else(|| ParseError {
            message: "target_index".into(),
        })?;
    let target = decode_index_value(ti)?;
    let params_node = obj
        .iter()
        .find(|(k, _)| k == "params")
        .map(|(_, v)| v)
        .ok_or_else(|| ParseError {
            message: "params".into(),
        })?;
    let params = decode_params(params_node)?;
    Ok(RecipeStep { target_index: target, params })
}

fn decode_index_value(value: &JsonValue) -> Result<IndexValue, ParseError> {
    let obj = as_object(value, "target_index")?;
    let tag = string_field(obj, "t")?;
    match tag.as_str() {
        "null" => Ok(IndexValue::None),
        "int" => Ok(IndexValue::Int(i64_field(obj, "v")?)),
        "bool" => Ok(IndexValue::Bool(bool_field(obj, "v")?)),
        _ => Ok(IndexValue::Other),
    }
}

fn decode_params(value: &JsonValue) -> Result<ParamMap, ParseError> {
    let obj = as_object(value, "params")?;
    let tag = string_field(obj, "t")?;
    if tag == "not_mapping" {
        return Ok(ParamMap::NotMapping);
    }
    if tag == "map" {
        let entries = array_field(obj, "entries")?;
        let pairs = decode_tagged_mapping_entries(entries)?;
        return Ok(ParamMap::Mapping(EventMapping::new(pairs)));
    }
    Err(ParseError {
        message: format!("bad params tag {tag}"),
    })
}

fn decode_tagged_mapping_entries(entries: &[JsonValue]) -> Result<Vec<(String, EventField)>, ParseError> {
    let mut out = Vec::new();
    for row in entries {
        let JsonValue::Array(pair) = row else {
            return Err(ParseError {
                message: "entry pair".into(),
            });
        };
        if pair.len() != 2 {
            return Err(ParseError {
                message: "pair len".into(),
            });
        }
        let JsonValue::Str(key) = &pair[0] else {
            return Err(ParseError {
                message: "key".into(),
            });
        };
        let field = decode_tagged_field(&pair[1])?;
        out.push((key.clone(), field));
    }
    Ok(out)
}

fn decode_tagged_field(value: &JsonValue) -> Result<EventField, ParseError> {
    let obj = as_object(value, "field")?;
    let tag = string_field(obj, "t")?;
    match tag.as_str() {
        "null" => Ok(EventField::Null),
        "bool" => Ok(EventField::Bool(bool_field(obj, "v")?)),
        "int" => Ok(EventField::Int(i64_field(obj, "v")?)),
        "str" => Ok(EventField::Str(string_field(obj, "v")?)),
        "map" => {
            let entries = array_field(obj, "entries")?;
            let pairs = decode_tagged_mapping_entries(entries)?;
            Ok(EventField::Mapping(EventMapping::new(pairs)))
        }
        _ => Err(ParseError {
            message: format!("tag {tag}"),
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

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
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
