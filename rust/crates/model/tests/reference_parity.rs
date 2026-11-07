//! Parity for `sesslint.reference` against pinned Python vectors.

use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceRef};
use model::reference::{
    reference_equivalent, reference_equivalent_if_clean, DumpCanonicalUnavailable, ALL, MAX_REFERENCE_EVENTS,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/reference/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 12;
const EXPECTED_VECTORS_SHA256: &str =
    "958b5f8e6a0de27b20afe8ffa283544aa617203c18ba9764bf393d4bb927636e";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.reference";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_REFERENCE_PY_SHA256: &str =
    "b2ade3002b062600b5653e85d707c6b1ea4836ce182066da73dc82f7037ffeb5";
const EXPECTED_REFERENCE_RS_SHA256: &str =
    "81a1f10ce7f76b64273facd56c985c6ca281fd6b42ce5da7a6f02c9677dc2d03";

const DUMP_SEAM: &str = "sesslint.adapters.canonical.dump_canonical is not available";

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
fn reference_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );
    let (meta, cases) = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&meta);
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT, "unexpected vector count");
    for case in &cases {
        assert_case(case);
    }
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
        string_field(meta, "reference_py_sha256").expect("reference_py_sha256"),
        EXPECTED_REFERENCE_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "reference_rs_sha256").expect("reference_rs_sha256"),
        EXPECTED_REFERENCE_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert_eq!(gaps.len(), 1, "expected one known parity gap");
    let JsonValue::Str(gap) = &gaps[0] else {
        panic!("gap must be string");
    };
    assert!(
        gap.contains("GAP-reference-dump-canonical"),
        "missing dump gap prose"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => assert_module_exports(case),
        "module_constants" => assert_module_constants(case),
        "reference_equivalent" => assert_reference_equivalent(case),
        "reference_equivalent_if_clean" => assert_reference_equivalent_if_clean(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_module_exports(case: &VectorCase) {
    let names = array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), ALL.len(), "ALL length {}", case.id);
    for (index, item) in names.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{index}] must be string");
        };
        assert_eq!(ALL[index], name.as_str(), "ALL[{index}] {}", case.id);
    }
}

fn assert_module_constants(case: &VectorCase) {
    let want = usize_field(&case.expected, "max_reference_events").expect("max");
    assert_eq!(want, MAX_REFERENCE_EVENTS, "MAX_REFERENCE_EVENTS {}", case.id);
}

fn assert_reference_equivalent(case: &VectorCase) {
    let events_kind = string_field(&case.construct, "events_kind").expect("events_kind");
    if lookup(&case.expected, "rust_assertion").is_some() {
        let _pin = object_field(&case.expected, "pin").expect("pin");
        let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
        assert_dump_gap(case, assertion, events_kind);
        return;
    }
    let want = bool_field(&case.expected, "value").expect("value");
    let got = run_reference_equivalent(&events_kind).expect("bool path");
    assert_eq!(got, want, "reference_equivalent {}", case.id);
}

fn assert_reference_equivalent_if_clean(case: &VectorCase) {
    let events_kind = string_field(&case.construct, "events_kind").expect("events_kind");
    let findings = decode_findings(&case.construct, &case.id);
    if lookup(&case.expected, "rust_assertion").is_some() {
        let _pin = object_field(&case.expected, "pin").expect("pin");
        let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
        assert_dump_gap_if_clean(case, assertion, events_kind, &findings);
        return;
    }
    let want = bool_field(&case.expected, "value").expect("value");
    let got =
        run_reference_equivalent_if_clean(&events_kind, &findings).expect("bool path if_clean");
    assert_eq!(got, want, "reference_equivalent_if_clean {}", case.id);
}

fn assert_dump_gap(
    case: &VectorCase,
    assertion: &[(String, JsonValue)],
    events_kind: String,
) {
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "gap_dump_canonical", "gap mode {}", case.id);
    let err = run_reference_equivalent(events_kind.as_str()).expect_err("expected dump seam");
    assert_dump_seam(err, &case.id);
}

fn assert_dump_gap_if_clean(
    case: &VectorCase,
    assertion: &[(String, JsonValue)],
    events_kind: String,
    findings: &[Finding],
) {
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "gap_dump_canonical", "gap mode {}", case.id);
    let err =
        run_reference_equivalent_if_clean(events_kind.as_str(), findings).expect_err("dump seam");
    assert_dump_seam(err, &case.id);
}

fn assert_dump_seam(err: DumpCanonicalUnavailable, case_id: &str) {
    assert_eq!(err.to_string(), DUMP_SEAM, "seam text {case_id}");
}

fn run_reference_equivalent(events_kind: &str) -> Result<bool, DumpCanonicalUnavailable> {
    match events_kind {
        "none" => reference_equivalent::<u8>(None),
        "empty" => reference_equivalent(Some(&[] as &[u8])),
        "over_cap" => {
            let over: Vec<()> = vec![(); MAX_REFERENCE_EVENTS + 1];
            reference_equivalent(Some(over.as_slice()))
        }
        "foreign" | "fixture_healthy" => {
            let one = [0u8];
            reference_equivalent(Some(&one))
        }
        other => panic!("unknown events_kind {other}"),
    }
}

fn run_reference_equivalent_if_clean(
    events_kind: &str,
    findings: &[Finding],
) -> Result<bool, DumpCanonicalUnavailable> {
    match events_kind {
        "none" => reference_equivalent_if_clean::<u8>(None, findings),
        "empty" => reference_equivalent_if_clean(Some(&[] as &[u8]), findings),
        "over_cap" => {
            let over: Vec<()> = vec![(); MAX_REFERENCE_EVENTS + 1];
            reference_equivalent_if_clean(Some(over.as_slice()), findings)
        }
        "foreign" | "fixture_healthy" => {
            let one = [0u8];
            reference_equivalent_if_clean(Some(&one), findings)
        }
        other => panic!("unknown events_kind {other}"),
    }
}

fn decode_findings(construct: &[(String, JsonValue)], case_id: &str) -> Vec<Finding> {
    let items = array_field(construct, "findings").unwrap_or_default();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let obj = as_object(&item, "finding").expect("finding object");
        let code = string_field(obj, "code").expect("code");
        let severity = string_field(obj, "severity").expect("severity");
        let repairability = string_field(obj, "repairability").expect("repairability");
        let message_template = string_field(obj, "message_template").expect("message_template");
        let source_path = string_field(obj, "source_path").expect("source_path");
        let source = SourceRef::try_new(&source_path, None, None).expect("SourceRef");
        let input = MakeFindingInput {
            code: PyValue::string(code),
            severity: PyValue::string(severity),
            repairability: PyValue::string(repairability),
            message_template: PyValue::string(message_template),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            evidence: PyValue::None,
            fingerprint: PyValue::string("0123456789abcdef".to_owned()),
            adapter_id: None,
            adapter_version: None,
            profile_id: None,
            profile_version: None,
            ordinal: None,
            context: None,
        };
        let finding = make_finding(&input).unwrap_or_else(|err| {
            panic!("make_finding in {case_id}: {err}");
        });
        out.push(finding);
    }
    out
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
    let mut out = [0u8; 32];
    for (index, word) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, value)| value)
}

type DocumentMeta = Vec<(String, JsonValue)>;
type ParsedDocument = (DocumentMeta, Vec<VectorCase>);

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
    let mut meta = root.clone();
    meta.retain(|(key, _)| key != "vectors");
    let cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    Ok((meta, cases))
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let number = i64_field(obj, key)?;
    usize::try_from(number).map_err(|_| ParseError {
        message: format!("{key} out of range"),
    })
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    let first = input.as_bytes()[0];
    match first {
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
    let digits = &input[start_digits..idx];
    let magnitude: i64 = digits.parse().map_err(|_| ParseError {
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
