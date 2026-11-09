//! Parity for `sesslint.repair.planner` against pinned Python vectors.

use repair::planner::{
    compute_events_source_hash, get_plan_schema_path, load_plan_schema, plan, PlanError, PlanKey,
    PlanPolicy, PlanProfile, PlanSchemaError, PlanStep, PlanValue, RepairPlan,
    ALL, ALLOWED_LOSS_CLASSES, EMPTY_EVENTS_HASH, EVENT_DROP_RECIPES, MAX_STEPS,
    NON_EVENT_LOSS_CLASSES, PLAN_VERSION, RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
    SCHEMA_PATH_UNAVAILABLE, SYNTHETIC_STEP_FP,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.planner/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 17;
const EXPECTED_VECTORS_SHA256: &str =
    "8965337365f61136f44c24ca24a6d91237a9da36f42b39279d7bcdaf15f3a54f";

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
fn planner_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert!(
        normalized.contains("GAP-planner-register-all"),
        "vectors must record the register_all gap"
    );
    assert!(
        normalized.contains("GAP-planner-schema-path"),
        "vectors must record the schema path gap"
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

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => {
            let names = string_array(&case.expected, "names").expect("names");
            let want: Vec<&str> = names.iter().map(String::as_str).collect();
            assert_eq!(ALL.as_ref(), want.as_slice(), "{}", case.id);
        }
        "module_constants" => assert_module_constants(case),
        "compute_events_source_hash" => {
            let want = string_field(&case.expected, "digest").expect("digest");
            let got = compute_events_source_hash(&[]).expect("empty events hash");
            assert_eq!(got, want, "{}", case.id);
        }
        "plan_step_from_dict" => assert_plan_step_from_dict(case),
        "repair_plan_from_dict" => assert_repair_plan_from_dict(case),
        "plan_call" => assert_plan_call(case),
        "get_plan_schema_path" => assert_schema_path_gap(case),
        "load_plan_schema" => assert_schema_load_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        i64_field(&case.expected, "max_steps").expect("max_steps"),
        MAX_STEPS,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "plan_version").expect("plan_version"),
        PLAN_VERSION,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "empty_events_hash").expect("empty_events_hash"),
        EMPTY_EVENTS_HASH,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "synthetic_step_fp").expect("synthetic_step_fp"),
        SYNTHETIC_STEP_FP,
        "{}",
        case.id
    );
    let want_allowed = string_array(&case.expected, "allowed_loss_classes").expect("allowed");
    let mut got_allowed: Vec<String> = ALLOWED_LOSS_CLASSES
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
    got_allowed.sort();
    let mut sorted_want = want_allowed.clone();
    sorted_want.sort();
    assert_eq!(got_allowed, sorted_want, "{} allowed_loss", case.id);
    let want_non = string_array(&case.expected, "non_event_loss_classes").expect("non_event");
    let got_non: Vec<String> = NON_EVENT_LOSS_CLASSES
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
    assert_eq!(got_non, want_non, "{} non_event", case.id);
    let want_drop = string_array(&case.expected, "event_drop_recipes").expect("event_drop");
    let mut got_drop: Vec<String> = EVENT_DROP_RECIPES
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
    got_drop.sort();
    let mut sorted_drop = want_drop.clone();
    sorted_drop.sort();
    assert_eq!(got_drop, sorted_drop, "{} event_drop", case.id);
}

fn assert_plan_step_from_dict(case: &VectorCase) {
    let data = json_field(&case.construct, "data").expect("data");
    let value = json_to_plan_value(data);
    let err = PlanStep::from_dict(&value).expect_err(&case.id);
    let want = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), want, "{}", case.id);
}

fn assert_repair_plan_from_dict(case: &VectorCase) {
    let data = json_field(&case.construct, "data").expect("data");
    let value = json_to_plan_value(data);
    let err = RepairPlan::from_dict(&value).expect_err(&case.id);
    let want = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), want, "{}", case.id);
}

fn assert_plan_call(case: &VectorCase) {
    if optional_string_field(&case.construct, "gap").as_deref() == Some("register_all") {
        let profile = optional_string_field(&case.construct, "profile")
            .unwrap_or_else(|| "neutral".to_owned());
        let policy = PlanPolicy::str_value("conservative");
        let err = plan(
            &[],
            &[],
            &PlanProfile::str_value(&profile),
            None,
            &policy,
            false,
            None,
        )
        .expect_err(&case.id);
        assert_eq!(err, PlanError::RegisterAll, "{}", case.id);
        assert_eq!(
            err.to_string(),
            RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
            "{}",
            case.id
        );
        return;
    }
    let policy = plan_policy_from_json(json_field(&case.construct, "policy").expect("policy"));
    let profile = PlanProfile::str_value("neutral");
    let err = plan(&[], &[], &profile, None, &policy, false, None).expect_err(&case.id);
    let want = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), want, "{}", case.id);
}

fn assert_schema_path_gap(case: &VectorCase) {
    let _pin_is_file = bool_field(&case.expected, "is_file").expect("is_file");
    let _pin_suffix = string_field(&case.expected, "suffix").expect("suffix");
    let err = get_plan_schema_path();
    assert_eq!(err, PlanSchemaError, "{}", case.id);
    assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE, "{}", case.id);
    assert!(!err.to_string().contains("sesslint.plan.v1.json"), "{}", case.id);
}

fn assert_schema_load_gap(case: &VectorCase) {
    let _pin_key = string_field(&case.expected, "schema_key").expect("schema_key");
    let _pin_id = string_field(&case.expected, "schema_id").expect("schema_id");
    let _pin_version = string_field(&case.expected, "version_const").expect("version_const");
    let err = load_plan_schema();
    assert_eq!(err, PlanSchemaError, "{}", case.id);
    assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE, "{}", case.id);
}

fn plan_policy_from_json(value: &JsonValue) -> PlanPolicy {
    match value {
        JsonValue::Str(text) => PlanPolicy::str_value(text.clone()),
        JsonValue::Bool(flag) => PlanPolicy::bool_value(*flag),
        JsonValue::Null => PlanPolicy::none(),
        JsonValue::Number(raw) => PlanPolicy::int(
            raw.parse::<i128>()
                .unwrap_or_else(|_| panic!("bad policy int: {raw}")),
        ),
        other => panic!("unsupported policy json: {other:?}"),
    }
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
        JsonValue::Array(items) => PlanValue::list(items.iter().map(json_to_plan_value).collect()),
        JsonValue::Object(entries) => PlanValue::map(
            entries
                .iter()
                .map(|(key, item)| (PlanKey::str_key(key.clone()), json_to_plan_value(item)))
                .collect(),
        ),
    }
}

fn json_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a JsonValue, ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    Ok(&value.1)
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw
            .parse::<i64>()
            .map_err(|_| ParseError {
                message: format!("{key} must be int"),
            }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
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
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Some(s.clone()),
        Some((_, JsonValue::Null)) => None,
        None => None,
        _ => None,
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
    let mut end = 0;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let num = input[..end].to_string();
    Ok((JsonValue::Number(num), &input[end..]))
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
