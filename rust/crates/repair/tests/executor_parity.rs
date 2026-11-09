//! Parity for `sesslint.repair.executor` against pinned Python vectors.

#![allow(clippy::manual_strip)]

use repair::executor::{
    execute, is_live_store_path, load_plan, load_session_source, load_session_source_with_findings,
    load_source_for_format, ExecuteError, LoadPlanError, LoadPlanInput, LoadSessionError,
    RelocateError, SourcePositionError, ALL, SQLITE_MAGIC, _ATOMIC_TEST_HOOKS, _ORIGIN_KEY,
    _STEP_INDEX_LIST_PARAMS, _STEP_INDEX_PARAMS, _relocate_step, _source_positions,
};
use repair::planner::{
    Loss, PlanKey, PlanStep, PlanStepFields, PlanValue, RepairPlan, RepairPlanFields, PLAN_VERSION,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.executor/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 17;
const EXPECTED_VECTORS_SHA256: &str =
    "c6309b15cfab6596b3a38dab649e5d0d26fcd243fad5f8f5aa54f54ac22ca21f";

const SNAPSHOT_INPUT: &str = "sesslint.adapters.load.snapshot_input is not available";
const VENDOR_FORMAT: &str = "sesslint.adapters.load.is_vendor_format is not available";
const FINGERPRINT: &str = "sesslint.repair.fingerprint.compute_plan_fingerprint is not available";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/vectors/repair.executor")
}

fn rel_vector_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from("rust");
    path.push("parity");
    path.push("vectors");
    path.push("repair.executor");
    for part in parts {
        path.push(part);
    }
    path
}

fn resolve_is_live_path(construct: &[(String, JsonValue)]) -> PathBuf {
    let kind = string_field(construct, "type").expect("type");
    assert_eq!(kind, "is_live_store_path");
    if let Ok(fixture) = string_field(construct, "fixture") {
        vector_root().join("fixtures").join(fixture)
    } else {
        PathBuf::from(string_field(construct, "path").expect("path"))
    }
}

fn resolve_session_path(construct: &[(String, JsonValue)]) -> PathBuf {
    if let Ok(fixture) = string_field(construct, "fixture") {
        rel_vector_path(&["fixtures", fixture.as_str()])
    } else {
        PathBuf::from(string_field(construct, "path").expect("path"))
    }
}

fn decode_b64(input: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0_u32;
    let mut bits = 0_u32;
    for ch in input.bytes() {
        let val = if ch == b'=' {
            break;
        } else if let Some(index) = TABLE.iter().position(|&b| b == ch) {
            u32::try_from(index).unwrap_or(0)
        } else if ch.is_ascii_whitespace() {
            continue;
        } else {
            panic!("invalid base64");
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn synthetic_plan(steps: usize, policy: &str) -> RepairPlan {
    let built: Vec<PlanStep> = (0..steps)
        .map(|index| {
            let seq = i128::try_from(index).expect("seq");
            PlanStep::try_new(PlanStepFields::new(
                seq,
                "drop-record",
                format!("synthetic-fp-{index}"),
                None,
            ))
            .expect("step")
        })
        .collect();
    RepairPlan::new(RepairPlanFields {
        source_hash: "synthetic".to_owned(),
        profile: "neutral".to_owned(),
        steps: built,
        blocked: Vec::new(),
        loss_accounting: Loss::default(),
        fingerprint: "deadbeef".to_owned(),
        version: PLAN_VERSION.to_owned(),
        policy: policy.to_owned(),
    })
}

fn salvage_plan_mapping() -> PlanValue {
    let step = PlanValue::map(vec![
        (PlanKey::str_key("seq"), PlanValue::Int(1)),
        (PlanKey::str_key("recipe"), PlanValue::Str("drop-record".into())),
        (
            PlanKey::str_key("target_finding_fp"),
            PlanValue::Str("fp".into()),
        ),
        (PlanKey::str_key("target_index"), PlanValue::Int(0)),
        (PlanKey::str_key("min_policy"), PlanValue::Str("salvage".into())),
        (
            PlanKey::str_key("recipe_version"),
            PlanValue::Str("1.0.0".into()),
        ),
        (PlanKey::str_key("params"), PlanValue::map(vec![])),
        (PlanKey::str_key("lossy"), PlanValue::Bool(true)),
        (
            PlanKey::str_key("loss"),
            PlanValue::map(vec![(PlanKey::str_key("none"), PlanValue::Int(2))]),
        ),
    ]);
    PlanValue::map(vec![
        (
            PlanKey::str_key("version"),
            PlanValue::Str("sesslint.plan/v1".into()),
        ),
        (
            PlanKey::str_key("source_hash"),
            PlanValue::Str("synthetic-rx-p43-hash".into()),
        ),
        (
            PlanKey::str_key("profile"),
            PlanValue::Str("neutral".into()),
        ),
        (PlanKey::str_key("steps"), PlanValue::list(vec![step])),
        (PlanKey::str_key("blocked"), PlanValue::list(vec![])),
        (
            PlanKey::str_key("loss_accounting"),
            PlanValue::map(vec![
                (PlanKey::str_key("total_lost"), PlanValue::Int(0)),
                (
                    PlanKey::str_key("preview"),
                    PlanValue::map(vec![]),
                ),
            ]),
        ),
        (
            PlanKey::str_key("fingerprint"),
            PlanValue::Str("abc".into()),
        ),
        (
            PlanKey::str_key("policy"),
            PlanValue::Str("salvage".into()),
        ),
    ])
}

fn assert_gap_mode(expected: &[(String, JsonValue)], key: &str, mode: &str, case_id: &str) {
    let rust = object_field(expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(rust, "mode").expect("mode"),
        mode,
        "gap mode for {case_id}"
    );
    let _ = key;
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => {
            let names_json = array_field(&case.expected, "names").expect("names");
            let want: Vec<String> = names_json
                .iter()
                .map(|item| match item {
                    JsonValue::Str(s) => s.clone(),
                    _ => panic!("name must be string"),
                })
                .collect();
            assert_eq!(ALL.as_slice(), want.as_slice(), "{}", case.id);
        }
        "sqlite_magic" => {
            let b64 = string_field(&case.expected, "b64").expect("b64");
            let bytes = decode_b64(&b64);
            assert_eq!(bytes, SQLITE_MAGIC, "{}", case.id);
        }
        "module_private_constants" => {
            assert_eq!(
                _ORIGIN_KEY,
                string_field(&case.expected, "origin_key").expect("origin_key"),
                "{}",
                case.id
            );
            assert_string_list(&_STEP_INDEX_PARAMS, case, "step_index_params");
            assert_string_list(&_STEP_INDEX_LIST_PARAMS, case, "step_index_list_params");
            let hook_names: Vec<&str> =
                _ATOMIC_TEST_HOOKS.iter().map(|(name, _)| *name).collect();
            assert_string_list(&hook_names, case, "atomic_hook_keys");
        }
        "is_live_store_path" => {
            let path = resolve_is_live_path(&case.construct);
            let want = bool_field(&case.expected, "value").expect("value");
            assert_eq!(is_live_store_path(&path), want, "{}", case.id);
        }
        "load_session_not_found" => {
            let path = resolve_session_path(&case.construct);
            let want = string_field(&case.expected, "message").expect("message");
            let err = load_session_source(&path).expect_err(&case.id);
            assert_session_not_found(&err, &want, &case.id);
        }
        "load_session_with_findings_not_found" => {
            let path = resolve_session_path(&case.construct);
            let want = string_field(&case.expected, "message").expect("message");
            let data = optional_string_field(&case.construct, "data_b64")
                .ok()
                .flatten()
                .map(|b64| decode_b64(&b64));
            let err = load_session_source_with_findings(&path, data.as_deref())
                .expect_err(&case.id);
            assert_session_not_found(&err, &want, &case.id);
        }
        "load_session_snapshot_seam" => {
            assert!(
                bool_field(&case.expected, "pin_continues").unwrap_or(false),
                "{}",
                case.id
            );
            assert_gap_mode(&case.expected, "snapshot", "snapshot_input_unavailable", &case.id);
            let fixture = string_field(&case.construct, "fixture").expect("fixture");
            let path = vector_root().join("fixtures").join(fixture);
            let err = load_session_source(&path).expect_err(&case.id);
            assert_eq!(err.to_string(), SNAPSHOT_INPUT, "{}", case.id);
            assert!(matches!(err, LoadSessionError::SnapshotInput));
        }
        "load_source_for_format_gap" => {
            assert!(
                bool_field(&case.expected, "pin_imports_adapters").unwrap_or(false),
                "{}",
                case.id
            );
            assert_gap_mode(
                &case.expected,
                "vendor",
                "is_vendor_format_unavailable",
                &case.id,
            );
            let fixture = string_field(&case.construct, "fixture").expect("fixture");
            let path = vector_root().join("fixtures").join(fixture);
            let err = load_source_for_format(&path, None, None).expect_err(&case.id);
            assert_eq!(err.to_string(), VENDOR_FORMAT, "{}", case.id);
            assert!(matches!(err, LoadSessionError::VendorFormat));
        }
        "execute_cap" => {
            let want = string_field(&case.expected, "message").expect("message");
            let err = execute(&synthetic_plan(257, "conservative")).expect_err(&case.id);
            assert_eq!(err.to_string(), want, "{}", case.id);
            assert!(matches!(err, ExecuteError::OutputInvalid(_)));
        }
        "execute_fingerprint_gap" => {
            assert_eq!(
                string_field(&case.expected, "pin_exception").expect("pin_exception"),
                "PlanTampered",
                "{}",
                case.id
            );
            assert_gap_mode(
                &case.expected,
                "fingerprint",
                "fingerprint_unavailable",
                &case.id,
            );
            let err = execute(&synthetic_plan(1, "conservative")).expect_err(&case.id);
            assert_eq!(err.to_string(), FINGERPRINT, "{}", case.id);
            assert!(matches!(err, ExecuteError::FingerprintUnavailable));
        }
        "source_positions_duplicate" => {
            let want = string_field(&case.expected, "message").expect("message");
            let events = vec![
                PlanValue::map(vec![(
                    PlanKey::str_key(_ORIGIN_KEY),
                    PlanValue::Int(1),
                )]),
                PlanValue::map(vec![(
                    PlanKey::str_key(_ORIGIN_KEY),
                    PlanValue::Int(1),
                )]),
            ];
            let err = _source_positions(&events).expect_err(&case.id);
            let SourcePositionError::Duplicate(inner) = err else {
                panic!("{} expected duplicate", case.id);
            };
            assert_eq!(inner.to_string(), want, "{}", case.id);
        }
        "relocate_step_removed" => {
            let want = string_field(&case.expected, "message").expect("message");
            let step = PlanStep::try_new(PlanStepFields::new(
                7,
                "drop-record",
                "fp",
                Some(2),
            ))
            .expect("step");
            let positions = BTreeMap::from([(0, 0), (1, 1)]);
            let err = _relocate_step(&step, &positions, 3).expect_err(&case.id);
            let RelocateError::OutputInvalid(inner) = err else {
                panic!("{} expected OutputInvalid", case.id);
            };
            assert_eq!(inner.to_string(), want, "{}", case.id);
        }
        "load_plan_salvage_policy_mismatch" => {
            let want = string_field(&case.expected, "message").expect("message");
            let mapping = salvage_plan_mapping();
            let err =
                load_plan(LoadPlanInput::Mapping(&mapping), Some("conservative")).expect_err(&case.id);
            let LoadPlanError::Policy(inner) = err else {
                panic!("{} expected PolicyMismatch", case.id);
            };
            assert_eq!(inner.to_string(), want, "{}", case.id);
        }
        other => panic!("unknown construct {other} in {}", case.id),
    }
}

fn portable_message(text: &str) -> String {
    text.replace('\\', "/")
}

fn assert_session_not_found(err: &LoadSessionError, want: &str, case_id: &str) {
    let got = portable_message(&err.to_string());
    let want = portable_message(want);
    assert_eq!(got, want, "{}", case_id);
    assert!(!want.contains("Errno"), "{}", case_id);
    assert!(!want.starts_with('['), "{}", case_id);
    assert!(
        matches!(err, LoadSessionError::FileNotFound(text) if portable_message(text) == want),
        "{}",
        case_id
    );
}

fn assert_string_list(got: &[&str], case: &VectorCase, key: &str) {
    let items = array_field(&case.expected, key).expect(key);
    let want: Vec<String> = items
        .iter()
        .map(|value| match value {
            JsonValue::Str(s) => s.clone(),
            _ => panic!("{} must be strings", key),
        })
        .collect();
    assert_eq!(got.len(), want.len(), "{}", case.id);
    for (index, name) in got.iter().enumerate() {
        assert_eq!(*name, want[index].as_str(), "{}", case.id);
    }
}

#[test]
fn executor_module_parity_vectors() {
    std::env::set_current_dir(repo_root()).expect("chdir repo root");
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert!(
        normalized.contains("GAP-repair-executor-import-stops"),
        "vectors must record the executor import-stop gap"
    );
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );
    let cases = parse_document(&normalized).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
    }
}

use std::collections::BTreeMap;

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&sha256(bytes))
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

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        _ => '?',
    }
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

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string when present"),
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
    let mut end = 0;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b'.' {
        end += 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    if end < bytes.len() && (bytes[end] == b'e' || bytes[end] == b'E') {
        end += 1;
        if end < bytes.len() && (bytes[end] == b'+' || bytes[end] == b'-') {
            end += 1;
        }
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    Ok((
        JsonValue::Number(input[..end].to_owned()),
        &input[end..],
    ))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let rest = input
        .strip_prefix('[')
        .ok_or_else(|| ParseError {
            message: "expected [".into(),
        })?
        .trim_start();
    if rest.starts_with(']') {
        return Ok((JsonValue::Array(vec![]), &rest[1..]));
    }
    let mut items = Vec::new();
    let mut cursor = rest;
    loop {
        let (value, after) = parse_value(cursor)?;
        items.push(value);
        cursor = after.trim_start();
        if let Some(next) = cursor.strip_prefix(',') {
            cursor = next.trim_start();
            continue;
        }
        if let Some(next) = cursor.strip_prefix(']') {
            return Ok((JsonValue::Array(items), next));
        }
        return Err(ParseError {
            message: "expected , or ]".into(),
        });
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let rest = input
        .strip_prefix('{')
        .ok_or_else(|| ParseError {
            message: "expected {".into(),
        })?
        .trim_start();
    if rest.starts_with('}') {
        return Ok((JsonValue::Object(vec![]), &rest[1..]));
    }
    let mut items = Vec::new();
    let mut cursor = rest;
    loop {
        let (key, after_key) = parse_string(cursor)?;
        let after_colon = after_key
            .trim_start()
            .strip_prefix(':')
            .ok_or_else(|| ParseError {
                message: "expected :".into(),
            })?
            .trim_start();
        let (value, after) = parse_value(after_colon)?;
        items.push((key, value));
        cursor = after.trim_start();
        if let Some(next) = cursor.strip_prefix(',') {
            cursor = next.trim_start();
            continue;
        }
        if let Some(next) = cursor.strip_prefix('}') {
            return Ok((JsonValue::Object(items), next));
        }
        return Err(ParseError {
            message: "expected , or }".into(),
        });
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
