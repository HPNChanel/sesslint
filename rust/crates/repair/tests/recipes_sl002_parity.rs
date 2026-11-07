//! Parity for `sesslint.repair.recipes_sl002` against pinned Python vectors.

use model::canonical::SessionEvent;
use model::events::{EventField, EventMapping, EventValue};
use repair::recipes_sl002::{
    affected_region_torn_terminal_record_discard, apply_torn_terminal_record_discard,
    recipe_torn_terminal_record_discard, register_all, StepParams, StepScalar, TornDiscardError,
    TornTerminalStep, ALL, AFFECTED_REGION_UNAVAILABLE,
};
use repair::registry::{clear_registry, get_recipe, list_recipes, CallableId, Recipe};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

const VECTORS_REL: &str = "../../parity/vectors/repair.recipes_sl002/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 24;
const EXPECTED_VECTORS_SHA256: &str =
    "900598412013945f8d5496091fa734c9b16d451a2d83b747eea32712d071335a";
const GAP_AFFECTED_REGION: &str = "GAP-recipes-sl002-affected-region";

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

#[test]
fn recipes_sl002_module_parity_vectors() {
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
        "module_all" => {
            let names = string_array(&case.expected, "names").expect("names");
            let want: Vec<&str> = names.iter().map(String::as_str).collect();
            assert_eq!(ALL.as_ref(), want.as_slice(), "{}", case.id);
        }
        "recipe_constant" => {
            let recipe =
                recipe_torn_terminal_record_discard().unwrap_or_else(|err| panic!("{}: {err}", case.id));
            assert_recipe_snapshot(&case.id, &recipe, &case.expected);
        }
        "register_all" => {
            let _guard = isolate();
            register_all().unwrap_or_else(|err| panic!("{}: {err}", case.id));
            assert_eq!(
                bool_field(&case.expected, "present").expect("present"),
                get_recipe("torn-terminal-record-discard").is_some(),
                "{}",
                case.id
            );
            register_all().unwrap_or_else(|err| panic!("{} second: {err}", case.id));
            let names = string_array(&case.expected, "list_names").expect("list_names");
            let got: Vec<String> = list_recipes().iter().map(|r| r.name().to_owned()).collect();
            assert_eq!(got, names, "{}", case.id);
        }
        "apply" => assert_apply(case),
        "affected_region" => assert_affected_region(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_recipe_snapshot(case_id: &str, recipe: &Recipe, expected: &[(String, JsonValue)]) {
    assert_eq!(
        recipe.name(),
        string_field(expected, "name").expect("name"),
        "{case_id}"
    );
    let handles = string_array(expected, "handles").expect("handles");
    assert_eq!(recipe.handles().to_vec(), handles, "{case_id}");
    let preconds = string_array(expected, "preconditions").expect("preconditions");
    assert_eq!(recipe.preconditions().to_vec(), preconds, "{case_id}");
    assert_eq!(
        recipe.lossy(),
        bool_field(expected, "lossy").expect("lossy"),
        "{case_id}"
    );
    assert_eq!(
        recipe.salvage_only(),
        bool_field(expected, "salvage_only").expect("salvage_only"),
        "{case_id}"
    );
    assert_eq!(
        recipe.min_policy(),
        string_field(expected, "min_policy").expect("min_policy"),
        "{case_id}"
    );
    assert_eq!(
        recipe.version(),
        string_field(expected, "version").expect("version"),
        "{case_id}"
    );
    assert_eq!(
        recipe.excludes_execution_dependence(),
        bool_field(expected, "excludes_execution_dependence").expect("excludes"),
        "{case_id}"
    );
    let apply_obj = object_field(expected, "apply").expect("apply");
    assert_eq!(
        recipe.apply().is_some(),
        bool_field(apply_obj, "present").expect("apply.present"),
        "{case_id}"
    );
    let region_obj = object_field(expected, "affected_region").expect("affected_region");
    assert_eq!(
        recipe.affected_region().is_some(),
        bool_field(region_obj, "present").expect("affected_region.present"),
        "{case_id}"
    );
    assert_eq!(
        recipe.apply(),
        Some(CallableId::from_fn(apply_torn_terminal_record_discard))
    );
    assert_eq!(
        recipe.affected_region(),
        Some(CallableId::from_fn(affected_region_torn_terminal_record_discard))
    );
    assert_ne!(recipe.apply(), recipe.affected_region());
}

fn assert_apply(case: &VectorCase) {
    let events = decode_events(case);
    let step = decode_step(case);
    let mode = string_field(&case.expected, "mode").expect("mode");
    if mode == "index_error" {
        let want = string_field(&case.expected, "message").expect("message");
        let err = apply_torn_terminal_record_discard(events, step).expect_err(&case.id);
        assert_eq!(err.to_string(), want, "{}", case.id);
        assert!(matches!(err, TornDiscardError::EmptyPop), "{}", case.id);
        return;
    }
    assert_eq!(mode, "ok", "{}", case.id);
    let out = apply_torn_terminal_record_discard(events, step).unwrap_or_else(|err| {
        panic!("{} apply: {err}", case.id);
    });
    let want_ids = optional_string_array(&case.expected, "ids").expect("ids");
    let got_ids: Vec<Option<String>> = out
        .iter()
        .map(|mapping| match mapping.get("id") {
            Some(EventField::Str(text)) => Some(text.clone()),
            Some(EventField::Null) | None => None,
            Some(other) => Some(format!("{other:?}")),
        })
        .collect();
    assert_eq!(got_ids, want_ids, "{}", case.id);
    if let Ok(len) = usize_field(&case.expected, "len") {
        assert_eq!(out.len(), len, "{}", case.id);
    }
}

fn assert_affected_region(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "gap",
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "gap_id").expect("gap_id"),
        GAP_AFFECTED_REGION,
        "{}",
        case.id
    );
    let _region_obj = object_field(&case.expected, "region").expect("region documents Python");
    let events = decode_events(case);
    let step = decode_step(case);
    let err = affected_region_torn_terminal_record_discard(step, events).expect_err(&case.id);
    assert_eq!(
        err.to_string(),
        AFFECTED_REGION_UNAVAILABLE,
        "{}",
        case.id
    );
    assert_eq!(err.message(), AFFECTED_REGION_UNAVAILABLE);
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
    Ok(SessionEvent::new(id, parent, seq, ts, actor, kind))
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

fn decode_step(case: &VectorCase) -> TornTerminalStep {
    let step_obj = object_field(&case.construct, "step").expect("step");
    let target = decode_step_scalar(
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
    let params = decode_step_params(params_node).expect("params");
    TornTerminalStep { target_index: target, params }
}

fn decode_step_scalar(value: &JsonValue) -> StepScalar {
    let obj = match value {
        JsonValue::Object(entries) => entries,
        _ => panic!("target_index must be tagged object"),
    };
    let kind = obj
        .iter()
        .find(|(k, _)| k == "t")
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
        .expect("target tag");
    match kind.as_str() {
        "null" => StepScalar::None,
        "int" => StepScalar::Int(i64_field(obj, "v").expect("int")),
        "bool" => StepScalar::Bool(bool_field(obj, "v").expect("bool")),
        "other" => StepScalar::Other,
        _ => panic!("unsupported target tag {kind}"),
    }
}

fn decode_step_params(value: &JsonValue) -> Result<StepParams, ParseError> {
    let obj = as_object(value, "params")?;
    let kind = string_field(obj, "t")?;
    if kind == "not_mapping" {
        return Ok(StepParams::NotMapping);
    }
    if kind == "map_entries" {
        let entries = array_field(obj, "entries")?;
        let pairs = decode_mapping_entries(entries)?;
        return Ok(StepParams::Mapping(EventMapping::new(pairs)));
    }
    if kind == "map" {
        let entries = array_field(obj, "entries")?;
        let pairs = decode_mapping_entries(entries)?;
        return Ok(StepParams::Mapping(EventMapping::new(pairs)));
    }
    Err(ParseError {
        message: format!("bad params tag {kind}"),
    })
}

fn optional_string_array(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Vec<Option<String>>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Null => Ok(None),
            JsonValue::Str(s) => Ok(Some(s.clone())),
            _ => Err(ParseError {
                message: format!("{key} entry must be string or null"),
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
