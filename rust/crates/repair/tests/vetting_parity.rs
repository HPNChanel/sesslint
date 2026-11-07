//! Parity for `sesslint.repair.vetting` against pinned Python vectors.

use model::canonical::SessionEvent;
use model::codes::{Repairability, Severity};
use model::events::{EventField, EventMapping};
use model::finding::{Finding, FindingInput, PyValue, SourceRef, SCHEMA_VERSION};
use repair::planner::{
    Blocked, Loss, PlanKey, PlanStep, PlanStepFields, PlanValue, RepairPlan, RepairPlanFields,
    SourceHashEvent, PLAN_VERSION, RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
};
use repair::vetting::{
    vet_plan, VetPlanError, JSON_DUMPS_UNAVAILABLE, _plan_step_identity,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.vetting/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 20;
const EXPECTED_VECTORS_SHA256: &str =
    "d6d19c6d119f170616066be5ab66e9fa5a1d2bcf30dd6f9ca5b44e61d0f7a2f8";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[test]
fn vetting_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert!(
        normalized.contains("GAP-vetting-json-dumps"),
        "vectors must record the json.dumps gap"
    );
    assert!(
        normalized.contains("GAP-vetting-register-all"),
        "vectors must record the register_all gap"
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
        "plan_step_identity" => assert_plan_step_identity(case),
        "vet_plan" => assert_vet_plan(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_plan_step_identity(case: &VectorCase) {
    let step_obj = object_field(&case.construct, "step").expect("step");
    let step = plan_step_from_object(step_obj).expect("plan step");
    let err = _plan_step_identity(&step).expect_err(&case.id);
    let mode = string_field(&case.expected, "mode").expect("mode");
    assert_eq!(mode, "rust_seam", "{}", case.id);
    let seam = string_field(&case.expected, "seam").expect("seam");
    assert_eq!(seam, JSON_DUMPS_UNAVAILABLE, "{}", case.id);
    assert_eq!(err.to_string(), JSON_DUMPS_UNAVAILABLE, "{}", case.id);
    let pin = object_field(&case.expected, "pin").expect("pin");
    let identity = string_field(pin, "identity").expect("pin identity");
    assert!(
        identity.starts_with('{') && identity.ends_with('}'),
        "{} pin identity must be json text",
        case.id
    );
    assert_ne!(
        identity, JSON_DUMPS_UNAVAILABLE,
        "{} pin must not equal the rust seam",
        case.id
    );
}

fn assert_vet_plan(case: &VectorCase) {
    let supplied = supplied_from_construct(&case.construct);
    let findings = vec![marker_finding()];
    let events = events_from_construct(&case.construct);
    let caller = string_field(&case.construct, "caller_hash").expect("caller_hash");
    let ack = bool_field(&case.construct, "acknowledge_side_effects").unwrap_or(false);
    let input_format =
        string_field(&case.construct, "input_format").unwrap_or_else(|_| "canonical".to_owned());
    let err = vet_plan(
        &supplied,
        &findings,
        &events,
        &caller,
        ack,
        &input_format,
    )
    .expect_err(&case.id);
    let mode = string_field(&case.expected, "mode").expect("mode");
    match mode.as_str() {
        "comparable" => assert_comparable_vet_plan(case, &err),
        "rust_seam" => assert_register_all_seam(case, &err),
        "rust_source_hash" => assert_rust_source_hash_seam(case, &err),
        other => panic!("unknown expected mode {other} in {}", case.id),
    }
}

fn assert_comparable_vet_plan(case: &VectorCase, err: &VetPlanError) {
    let want = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), want, "{}", case.id);
    let kind = string_field(&case.expected, "error_type").expect("error_type");
    match kind.as_str() {
        "PlanSourceMismatch" => {
            assert!(
                matches!(err, VetPlanError::PlanSourceMismatch(_)),
                "{}",
                case.id
            );
        }
        "PlanPolicy" => {
            assert!(matches!(err, VetPlanError::Plan(_)), "{}", case.id);
        }
        other => panic!("unsupported comparable error {other} in {}", case.id),
    }
}

fn assert_register_all_seam(case: &VectorCase, err: &VetPlanError) {
    let seam = string_field(&case.expected, "seam").expect("seam");
    assert_eq!(seam, RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE, "{}", case.id);
    let VetPlanError::Plan(inner) = err else {
        panic!("{} expected Plan(register_all), got {err:?}", case.id);
    };
    assert_eq!(inner.to_string(), RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE, "{}", case.id);
    let pin = object_field(&case.expected, "pin").expect("pin");
    let pin_message = string_field(pin, "message").expect("pin message");
    assert_ne!(
        pin_message,
        RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
        "{} pin must differ from rust seam",
        case.id
    );
    assert_ne!(pin_message, err.to_string(), "{}", case.id);
}

fn assert_rust_source_hash_seam(case: &VectorCase, err: &VetPlanError) {
    assert!(
        matches!(err, VetPlanError::SourceHash(_)),
        "{} expected SourceHash, got {err:?}",
        case.id
    );
    let pin = object_field(&case.expected, "pin").expect("pin");
    let pin_message = string_field(pin, "message").expect("pin message");
    assert_ne!(
        pin_message,
        err.to_string(),
        "{} rust source-hash error must differ from pin",
        case.id
    );
}

fn supplied_from_construct(construct: &[(String, JsonValue)]) -> RepairPlan {
    let plan_hash = string_field(construct, "plan_hash").expect("plan_hash");
    let profile = string_field(construct, "profile").expect("profile");
    let policy = string_field(construct, "policy").expect("policy");
    let step_obj = object_field(construct, "step").ok();
    let step = if let Some(obj) = step_obj {
        plan_step_from_object(obj).expect("embedded step")
    } else {
        default_lossy_step()
    };
    RepairPlan::new(RepairPlanFields {
        source_hash: plan_hash,
        profile,
        steps: vec![step],
        blocked: vec![Blocked::new(
            "0123456789abcdef",
            "SL108",
            "synthetic-blocked",
        )],
        loss_accounting: Loss::default(),
        fingerprint: "synthetic-fingerprint".to_owned(),
        version: PLAN_VERSION.to_owned(),
        policy,
    })
}

fn default_lossy_step() -> PlanStep {
    let mut fields =
        PlanStepFields::new(41, "synthetic-recipe", "0123456789abcdef", Some(0));
    fields.lossy = true;
    fields.loss = vec![("discarded-suffix".to_owned(), 2)];
    PlanStep::try_new(fields).expect("step")
}

fn plan_step_from_object(obj: &[(String, JsonValue)]) -> Result<PlanStep, String> {
    let value = JsonValue::Object(obj.to_vec());
    PlanStep::from_dict(&json_to_plan_value(&value)).map_err(|err| err.to_string())
}

fn marker_finding() -> Finding {
    let source =
        SourceRef::try_new("<canonical>", None, Some("rec-synthetic")).expect("source");
    Finding::try_new(FindingInput {
        code: PyValue::string("SL203"),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message: PyValue::string("synthetic target marker"),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string("0123456789abcdef"),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::None,
        evidence: PyValue::None,
    })
    .expect("finding")
}

fn events_from_construct(construct: &[(String, JsonValue)]) -> Vec<SourceHashEvent> {
    let items = array_field(construct, "events").unwrap_or(&[]);
    let mut out = Vec::new();
    for item in items {
        let spec = as_object(item, "event spec").expect("event");
        let kind = string_field(spec, "kind").expect("kind");
        match kind.as_str() {
            "empty" => {}
            "rendered" => {
                let texts = string_array(spec, "texts").expect("texts");
                for text in texts {
                    out.push(SourceHashEvent::Rendered(text));
                }
            }
            "unrenderable" => out.push(SourceHashEvent::Unrenderable),
            "mapping_placeholder" => out.push(SourceHashEvent::Mapping(EventMapping::new(vec![(
                "id".to_owned(),
                EventField::Str("evt-a".to_owned()),
            )]))),
            "session" => {
                let id = string_field(spec, "id").expect("id");
                let parent = optional_string_field(spec, "parent_id")
                    .expect("parent_id")
                    .unwrap_or_default();
                let parent_opt = if parent.is_empty() {
                    None
                } else {
                    Some(parent)
                };
                let seq = i64_field(spec, "seq").unwrap_or(0);
                out.push(SourceHashEvent::Session(Box::new(SessionEvent::new(
                    id,
                    parent_opt,
                    seq,
                    "2024-02-29T00:00:00Z",
                    "assistant",
                    "message",
                ))));
            }
            other => panic!("unknown event kind {other}"),
        }
    }
    out
}

fn json_to_plan_value(value: &JsonValue) -> PlanValue {
    match value {
        JsonValue::Null => PlanValue::none(),
        JsonValue::Bool(flag) => PlanValue::bool_value(*flag),
        JsonValue::Number(raw) => {
            if raw.contains('.') {
                PlanValue::float(
                    raw.parse::<f64>()
                        .unwrap_or_else(|_| panic!("bad float: {raw}")),
                )
            } else {
                PlanValue::int(
                    raw.parse::<i128>()
                        .unwrap_or_else(|_| panic!("bad int: {raw}")),
                )
            }
        }
        JsonValue::Str(text) => PlanValue::str_value(text.clone()),
        JsonValue::Array(items) => {
            PlanValue::list(items.iter().map(json_to_plan_value).collect())
        }
        JsonValue::Object(entries) => PlanValue::map(
            entries
                .iter()
                .map(|(key, item)| (PlanKey::str_key(key.clone()), json_to_plan_value(item)))
                .collect(),
        ),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
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
    match lookup(obj, key) {
        Some(JsonValue::Object(entries)) => Ok(entries),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn array_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [JsonValue], ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Array(items)) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Str(text)) => Ok(text.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            JsonValue::Str(text) => out.push(text.clone()),
            _ => {
                return Err(ParseError {
                    message: format!("{key} entries must be strings"),
                });
            }
        }
    }
    Ok(out)
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Bool(value)) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Number(raw)) => raw.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<String>, ParseError> {
    match lookup(obj, key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Str(text)) => Ok(Some(text.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = skip_ws(input);
    if input.is_empty() {
        return Err(ParseError {
            message: "empty input".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_null(input),
        b't' | b'f' => parse_bool(input),
        b'"' => parse_str(input),
        b'-' | b'0'..=b'9' => parse_number(input),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        _ => Err(ParseError {
            message: "invalid JSON".into(),
        }),
    }
}

fn skip_ws(input: &str) -> &str {
    input.trim_start_matches(|c: char| c.is_ascii_whitespace())
}

fn parse_null(input: &str) -> Result<(JsonValue, &str), ParseError> {
    if let Some(rest) = input.strip_prefix("null") {
        Ok((JsonValue::Null, skip_ws(rest)))
    } else {
        Err(ParseError {
            message: "expected null".into(),
        })
    }
}

fn parse_bool(input: &str) -> Result<(JsonValue, &str), ParseError> {
    if let Some(rest) = input.strip_prefix("true") {
        Ok((JsonValue::Bool(true), skip_ws(rest)))
    } else if let Some(rest) = input.strip_prefix("false") {
        Ok((JsonValue::Bool(false), skip_ws(rest)))
    } else {
        Err(ParseError {
            message: "expected bool".into(),
        })
    }
}

fn parse_str(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let (text, rest) = parse_string(input)?;
    Ok((JsonValue::Str(text), skip_ws(rest)))
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

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    for (idx, ch) in input.char_indices() {
        if ch.is_ascii_digit() || ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E' {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return Err(ParseError {
            message: "bad number".into(),
        });
    }
    Ok((
        JsonValue::Number(input[..end].to_owned()),
        skip_ws(&input[end..]),
    ))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = skip_ws(&input[1..]);
    let mut items = Vec::new();
    if let Some(tail) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), skip_ws(tail)));
    }
    loop {
        let (value, next) = parse_value(rest)?;
        items.push(value);
        rest = skip_ws(next);
        if rest.starts_with(',') {
            rest = skip_ws(rest.strip_prefix(',').unwrap_or_default());
            continue;
        }
        if let Some(tail) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), skip_ws(tail)));
        }
        return Err(ParseError {
            message: "array syntax".into(),
        });
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = skip_ws(&input[1..]);
    let mut entries = Vec::new();
    if let Some(tail) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(entries), skip_ws(tail)));
    }
    loop {
        let (key_value, next) = parse_value(rest)?;
        let JsonValue::Str(key) = key_value else {
            return Err(ParseError {
                message: "object key must be string".into(),
            });
        };
        rest = skip_ws(next);
        let Some(colon_tail) = rest.strip_prefix(':') else {
            return Err(ParseError {
                message: "object colon".into(),
            });
        };
        let (value, next) = parse_value(skip_ws(colon_tail))?;
        entries.push((key, value));
        rest = skip_ws(next);
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(entries), skip_ws(tail)));
        }
        let Some(comma_tail) = rest.strip_prefix(',') else {
            return Err(ParseError {
                message: "object syntax".into(),
            });
        };
        rest = skip_ws(comma_tail);
    }
}
