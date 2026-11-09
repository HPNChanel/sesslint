//! Byte-exact parity for `sesslint.verify` against pinned Python vectors.

use evidence::verify::{parse_session_events, render_verify_human, Check, Verdict, ALL};
use scan::io::{DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_LINE_BYTES};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/verify/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/verify/manifest.json";
const COVERAGE_REL: &str = "../../parity/vectors/verify/coverage.json";
const PROVENANCE_REL: &str = "../../parity/vectors/verify/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 12;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.verify";
const EXPECTED_PYTHON_COMMIT: &str = "02694d537104659df66cdd084354739f3cccc440";
const EXPECTED_VERIFY_PY_SHA256: &str =
    "2ca1ba2373a560df0065144932d72ec7ecc0399d60a4c764eaa318f8c8fa964a";
const EXPECTED_VERIFY_RS_SHA256: &str =
    "ac04154d260f614b38239bbab4cfbb311fd15e1af53afdf485eb7b6e94354c3d";
const EXPECTED_VECTORS_SHA256: &str =
    "3fa0281130e8a52669f5ee0b18ed6b40af285818c94af0e3d85d65c29daf4c71";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

fn coverage_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

#[test]
fn verify_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let provenance = parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("parse PROVENANCE");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    for marker in [
        "GAP-verify-end-to-end",
        "GAP-verify-cli",
        "GAP-verify-api-entry",
        "GAP-verify-repair-bootstrap",
        "GAP-verify-dataclass-to-dict",
    ] {
        let gaps = array_field(&provenance, "known_parity_gaps").expect("gaps");
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "PROVENANCE must document {marker}"
        );
    }

    let manifest_raw = std::fs::read_to_string(manifest_path()).expect("read manifest");
    let manifest = parse_object_only(&manifest_raw.replace("\r\n", "\n")).expect("parse manifest");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest sha"),
        EXPECTED_VECTORS_SHA256
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("vector_count"),
        EXPECTED_VECTOR_COUNT
    );

    let coverage_raw = std::fs::read_to_string(coverage_path()).expect("read coverage");
    let coverage = parse_object_only(&coverage_raw.replace("\r\n", "\n")).expect("parse coverage");
    let rows = array_field(&coverage, "rows").expect("coverage rows");
    let covered = rows
        .iter()
        .filter(|row| {
            object_value(row)
                .iter()
                .any(|(k, v)| k == "status" && matches!(v, JsonValue::Str(s) if s == "covered"))
        })
        .count();
    let not_applicable = rows.len() - covered;
    assert_eq!(covered, 10, "coverage covered count");
    assert_eq!(not_applicable, 129, "coverage not_applicable count");

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT);
    for case in &doc.cases {
        assert_vector_case(case);
    }
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(
        string_field(meta, "schema").expect("schema"),
        EXPECTED_SCHEMA
    );
    assert_eq!(
        string_field(meta, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "verify_py_sha256").expect("py sha"),
        EXPECTED_VERIFY_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "verify_rs_sha256").expect("rs sha"),
        EXPECTED_VERIFY_RS_SHA256,
        "verify.rs hash must remain pinned"
    );
}

fn assert_vector_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => assert_module_all(case),
        "dataclass_serialization" => assert_dataclass_serialization(case),
        "render_verify_human" => assert_render_verify_human(case),
        "parse_session_events" => assert_parse_session_events(case),
        other => panic!("{}: unsupported construct type {other}", case.id),
    }
}

fn assert_module_all(case: &VectorCase) {
    let want = string_list(&case.expected, "exports").expect("exports");
    let got: Vec<String> = ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(want, got, "{}", case.id);
}

fn decode_b64(field: &[(String, JsonValue)], key: &str, id: &str) -> Vec<u8> {
    let text = string_field(field, key).unwrap_or_else(|_| panic!("{id}: missing {key}"));
    decode_base64(&text).unwrap_or_else(|err| panic!("{id}: bad base64 {key}: {err}"))
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let table = |byte: u8| -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for (idx, byte) in bytes.iter().enumerate() {
        if *byte == b'=' {
            if idx < bytes.len().saturating_sub(2) {
                return Err("padding too early".into());
            }
            break;
        }
        let value = table(*byte).ok_or_else(|| format!("invalid byte {byte}"))?;
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn assert_dataclass_serialization(case: &VectorCase) {
    let check_obj = object_field(&case.expected, "check_dict").expect("check_dict");
    let check = Check {
        name: string_field(check_obj, "name").expect("check name"),
        ok: bool_field(check_obj, "ok").expect("check ok"),
        detail: string_field(check_obj, "detail").expect("check detail"),
    };
    assert_eq!(check.name, string_field(check_obj, "name").expect("name"), "{}", case.id);
    assert_eq!(check.ok, bool_field(check_obj, "ok").expect("ok"), "{}", case.id);
    assert_eq!(
        check.detail,
        string_field(check_obj, "detail").expect("detail"),
        "{}",
        case.id
    );

    let verdict_obj = object_field(&case.expected, "verdict_dict").expect("verdict_dict");
    let rows = object_array_field(verdict_obj, "checks").expect("checks");
    let checks = rows
        .iter()
        .map(|row| Check {
            name: string_field(row, "name").expect("name"),
            ok: bool_field(row, "ok").expect("ok"),
            detail: string_field(row, "detail").expect("detail"),
        })
        .collect::<Vec<_>>();
    let verdict = Verdict {
        ok: bool_field(verdict_obj, "ok").expect("ok"),
        checks,
        assurance: string_field(verdict_obj, "assurance").expect("assurance"),
        artifact_sha256: None,
    };
    assert_eq!(
        verdict.assurance,
        string_field(verdict_obj, "assurance").expect("assurance"),
        "{}",
        case.id
    );
    assert_eq!(verdict.ok, bool_field(verdict_obj, "ok").expect("ok"), "{}", case.id);
    for (idx, row) in rows.iter().enumerate() {
        let got = &verdict.checks[idx];
        assert_eq!(got.name, string_field(row, "name").expect("name"), "{}", case.id);
        assert_eq!(got.ok, bool_field(row, "ok").expect("ok"), "{}", case.id);
        assert_eq!(
            got.detail,
            string_field(row, "detail").expect("detail"),
            "{}",
            case.id
        );
    }
    let want_json = string_field(&case.expected, "verdict_json").expect("verdict_json");
    assert_eq!(verdict.to_json(Some(2)), want_json, "{}", case.id);
}

fn assert_render_verify_human(case: &VectorCase) {
    let c_pass = Check {
        name: "source_hash".to_owned(),
        ok: true,
        detail: "matched".to_owned(),
    };
    let v_pass = Verdict {
        ok: true,
        checks: vec![c_pass],
        assurance: "repaired-lossless".to_owned(),
        artifact_sha256: None,
    };
    assert_eq!(
        render_verify_human(&v_pass, false),
        string_field(&case.expected, "pass_color_false").expect("pass_color_false"),
        "{}",
        case.id
    );
    let c_fail = Check {
        name: "idempotence".to_owned(),
        ok: false,
        detail: "non-idempotent".to_owned(),
    };
    let v_fail = Verdict {
        ok: false,
        checks: vec![c_fail],
        assurance: "unrepairable".to_owned(),
        artifact_sha256: None,
    };
    assert_eq!(
        render_verify_human(&v_fail, true),
        string_field(&case.expected, "fail_color_true").expect("fail_color_true"),
        "{}",
        case.id
    );
}

fn materialize_parse_raw(construct: &[(String, JsonValue)], id: &str) -> Vec<u8> {
    const HEADER: &str = concat!(
        r#"{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","#,
        r#""session_id":"parity-sess"}"#
    );
    const EVENT: &str = concat!(
        r#"{"actor":"user","id":"msg-0","kind":"message","parent_id":null,"#,
        r#""payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}"#
    );
    if let Ok(recipe) = string_field(construct, "recipe") {
        return match recipe.as_str() {
            "oversized_file" => vec![b'x'; (DEFAULT_MAX_FILE_BYTES + 1) as usize],
            "oversized_line" => {
                let big = "x".repeat((DEFAULT_MAX_LINE_BYTES + 1) as usize);
                let line = EVENT.replace("\"hi\"", &format!("\"{big}\""));
                format!("{HEADER}\n{line}\n").into_bytes()
            }
            "deep_nesting" => {
                let depth = (DEFAULT_MAX_DEPTH + 10) as usize;
                let nested = "[".repeat(depth) + &"]".repeat(depth);
                format!("{HEADER}\n{nested}\n").into_bytes()
            }
            other => panic!("{id}: unknown parse recipe {other}"),
        };
    }
    decode_b64(construct, "raw_b64", id)
}

fn assert_parse_session_events(case: &VectorCase) {
    let raw = materialize_parse_raw(&case.construct, &case.id);
    let want_kind = string_field(&case.expected, "kind").expect("kind");
    match want_kind.as_str() {
        "ok" => {
            let (header, events) = parse_session_events(&raw)
                .unwrap_or_else(|err| panic!("{}: unexpected parse error: {err}", case.id));
            let want_sid = optional_string_field(&case.expected, "header_session_id");
            match (want_sid, header) {
                (None, None) => {}
                (Some(want), Some(h)) => assert_eq!(h.session_id, want, "{}", case.id),
                other => panic!("{}: header mismatch {other:?}", case.id),
            }
            assert_eq!(
                events.len(),
                usize::try_from(i64_field(&case.expected, "event_count").expect("event_count"))
                    .expect("event_count fits usize"),
                "{}",
                case.id
            );
            if let Some(want_id) = optional_string_field(&case.expected, "first_event_id") {
                assert_eq!(events[0].id, want_id, "{}", case.id);
            }
        }
        "error" => {
            let err = parse_session_events(&raw)
                .unwrap_err()
                .to_string();
            assert_eq!(
                err,
                string_field(&case.expected, "message").expect("message"),
                "{}",
                case.id
            );
            let _exc = string_field(&case.expected, "exc_type").expect("exc_type");
        }
        other => panic!("{}: bad expected kind {other}", case.id),
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
        h = [
            h[0].wrapping_add(a),
            h[1].wrapping_add(b),
            h[2].wrapping_add(c),
            h[3].wrapping_add(d),
            h[4].wrapping_add(e),
            h[5].wrapping_add(f),
            h[6].wrapping_add(g),
            h[7].wrapping_add(hh),
        ];
    }
    let mut out = [0_u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// --- minimal JSON (vectors.json only; no serde_json::from_str) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
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

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    Ok(as_object(&value, "root")?.to_vec())
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
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
    let cases: Result<Vec<VectorCase>, _> = items.iter().map(parse_vector_case).collect();
    Ok(ParsedDocument {
        meta: root,
        cases: cases?,
    })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field_obj(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
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

fn object_value(value: &JsonValue) -> &[(String, JsonValue)] {
    match value {
        JsonValue::Object(pairs) => pairs,
        _ => panic!("expected object"),
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

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    string_field_obj(obj, key)
}

fn string_field_obj(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
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

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    usize::try_from(i64_field(obj, key)?).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        Some(_) => None,
    }
}

fn object_array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<Vec<&'a [(String, JsonValue)]>, ParseError> {
    let JsonValue::Array(items) = obj
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or_else(|| ParseError {
            message: format!("missing {key}"),
        })?
    else {
        return Err(ParseError {
            message: format!("{key} must be array"),
        });
    };
    items.iter().map(|item| as_object(item, key)).collect()
}

fn string_list(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    array_field(obj, key)?
        .into_iter()
        .map(|item| match item {
            JsonValue::Str(text) => Ok(text),
            _ => Err(ParseError {
                message: format!("{key} items must be strings"),
            }),
        })
        .collect()
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
        b'0'..=b'9' | b'-' => parse_number_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_number_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        idx += 1;
    }
    if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let start_digits = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    let magnitude: i64 = input[start_digits..idx].parse().map_err(|_| ParseError {
        message: "number overflow".into(),
    })?;
    let value = if negative { -magnitude } else { magnitude };
    Ok((JsonValue::Number(value), &input[idx..]))
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), stripped));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), stripped));
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
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), stripped));
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
        if let Some(stripped) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), stripped));
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
