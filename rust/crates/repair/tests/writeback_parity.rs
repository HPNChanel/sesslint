//! Parity for `sesslint.repair.writeback` (`emit_vendor_bytes`) against pinned Python vectors.

use model::canonical::CANONICAL_JSON_BYTES_UNAVAILABLE;
use repair::planner::HASHLIB_SHA256_UNAVAILABLE;
use repair::writeback::{
    emit_vendor_bytes, RecordHash, SourceLine, WritebackError, WritebackEvent,
};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.writeback/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 9;
const EXPECTED_VECTORS_SHA256: &str =
    "54f5a3a989e4d5bd298d015b8071c5cc17e81b98d4e51fb5b69f7556a1b3d8a8";

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
fn writeback_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert!(
        normalized.contains("GAP-writeback-hashlib"),
        "vectors must record the hashlib gap"
    );
    assert!(
        normalized.contains("GAP-writeback-canonical-record-hash"),
        "vectors must record the canonical record-hash gap"
    );
    assert!(
        normalized.contains("GAP-writeback-r3-with-record-hash"),
        "vectors must record the late-line R3 gap"
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
        "emit_vendor_bytes" => assert_emit_vendor_bytes(case),
        "emit_vendor_bytes_parametrize" => assert_emit_parametrize(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_emit_parametrize(case: &VectorCase) {
    let variants = array_field(&case.construct, "variants").expect("variants");
    assert_eq!(variants.len(), 2, "{} needs both prefixes", case.id);
    for (index, variant) in variants.iter().enumerate() {
        let spec = as_object(variant, "variant").expect("variant object");
        let mut construct = vec![(
            "type".to_owned(),
            JsonValue::Str("emit_vendor_bytes".to_owned()),
        )];
        for key in [
            "source_b64",
            "source_events",
            "output_events",
            "emit_format",
            "drop_lines",
        ] {
            let value = lookup(spec, key).cloned().unwrap_or(JsonValue::Null);
            construct.push((key.to_owned(), value));
        }
        let expected_obj = object_field(spec, "expected").expect("nested expected");
        let nested = VectorCase {
            id: format!("{}[{index}]", case.id),
            construct,
            expected: expected_obj.to_vec(),
        };
        assert_emit_vendor_bytes(&nested);
    }
}

fn assert_emit_vendor_bytes(case: &VectorCase) {
    let source = decode_b64(&string_field(&case.construct, "source_b64").expect("source_b64"));
    let source_events = events_from_json(array_field(&case.construct, "source_events").expect("source_events"));
    let output_events =
        events_from_json(array_field(&case.construct, "output_events").expect("output_events"));
    let format = string_field(&case.construct, "emit_format").expect("emit_format");
    let drop_lines = drop_lines_from_construct(&case.construct);
    let err = emit_vendor_bytes(
        &source,
        &source_events,
        &output_events,
        &format,
        drop_lines.as_ref(),
    )
    .expect_err(&case.id);

    let mode = string_field(&case.expected, "mode").expect("mode");
    match mode.as_str() {
        "comparable" => assert_comparable_refusal(case, &err),
        "rust_seam" => assert_rust_seam(case, &err),
        other => panic!("unknown expected mode {other} in {}", case.id),
    }
}

fn assert_comparable_refusal(case: &VectorCase, err: &WritebackError) {
    let want_msg = string_field(&case.expected, "message").expect("message");
    let want_reason = string_field(&case.expected, "reason").expect("reason");
    let refused = err.refusal().unwrap_or_else(|| panic!("{} expected refusal", case.id));
    assert_eq!(refused.message(), want_msg, "{}", case.id);
    assert_eq!(refused.reason(), want_reason, "{}", case.id);
    assert_eq!(err.to_string(), want_msg, "{}", case.id);
    assert!(
        !err.to_string().contains(want_reason.as_str()),
        "{} display must not include reason code",
        case.id
    );
    let pin = object_field(&case.expected, "pin").expect("pin");
    let pin_reason = string_field(pin, "reason").expect("pin reason");
    assert_eq!(pin_reason, want_reason, "{}", case.id);
    assert_ne!(pin_reason, err.to_string(), "{}", case.id);
}

fn assert_rust_seam(case: &VectorCase, err: &WritebackError) {
    let seam = string_field(&case.expected, "seam").expect("seam");
    assert_eq!(err.to_string(), seam, "{}", case.id);
    assert!(err.refusal().is_none(), "{} refusal must be absent", case.id);
    match seam.as_str() {
        HASHLIB_SHA256_UNAVAILABLE => {
            assert!(
                matches!(err, WritebackError::Hashlib),
                "{} expected Hashlib",
                case.id
            );
        }
        CANONICAL_JSON_BYTES_UNAVAILABLE => {
            assert!(
                matches!(err, WritebackError::Canonical(_)),
                "{} expected Canonical",
                case.id
            );
        }
        other => panic!("unknown seam {other} in {}", case.id),
    }
    let pin = object_field(&case.expected, "pin").expect("pin");
    let pin_mode = string_field(pin, "mode").expect("pin mode");
    assert_eq!(pin_mode, "success", "{}", case.id);
    let pin_digest = string_field(pin, "emitted_sha256").expect("pin emitted_sha256");
    assert!(
        !pin_digest.is_empty() && pin_digest.len() == 64,
        "{} pin digest shape",
        case.id
    );
    assert_ne!(pin_digest, seam, "{}", case.id);
    assert_ne!(pin_digest, err.to_string(), "{}", case.id);
}

fn drop_lines_from_construct(construct: &[(String, JsonValue)]) -> Option<BTreeSet<i128>> {
    match lookup(construct, "drop_lines") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Array(items)) => {
            let mut out = BTreeSet::new();
            for item in items {
                let JsonValue::Number(raw) = item else {
                    panic!("drop_lines entries must be numbers");
                };
                let line = raw
                    .parse::<i128>()
                    .unwrap_or_else(|_| panic!("bad drop line {raw}"));
                out.insert(line);
            }
            Some(out)
        }
        _ => panic!("drop_lines must be array or null"),
    }
}

fn events_from_json(items: &[JsonValue]) -> Vec<WritebackEvent> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let spec = as_object(item, "event").expect("event spec");
        let source_line = source_line_from_json(lookup(spec, "source_line").expect("source_line"));
        let id = optional_string_field(spec, "id").unwrap_or_default();
        let identity = optional_string_field(spec, "identity").unwrap_or_default();
        let record_hash = record_hash_from_json(lookup(spec, "source_record_hash"));
        out.push(WritebackEvent::new(
            source_line,
            id,
            identity,
            record_hash,
        ));
    }
    out
}

fn source_line_from_json(value: &JsonValue) -> SourceLine {
    match value {
        JsonValue::Null => SourceLine::Missing,
        JsonValue::Number(raw) => SourceLine::Int(
            raw.parse::<i128>()
                .unwrap_or_else(|_| panic!("bad source_line {raw}")),
        ),
        JsonValue::Object(entries) => {
            let kind = string_field(entries, "kind").unwrap_or_default();
            match kind.as_str() {
                "bool" => SourceLine::Bool(bool_field(entries, "value").unwrap_or(false)),
                "other" => SourceLine::Other,
                _ => SourceLine::Other,
            }
        }
        _ => SourceLine::Other,
    }
}

fn record_hash_from_json(value: Option<&JsonValue>) -> RecordHash {
    match value {
        None | Some(JsonValue::Null) => RecordHash::Absent,
        Some(JsonValue::Str(text)) => RecordHash::Text(text.clone()),
        _ => RecordHash::NotString,
    }
}

fn decode_b64(text: &str) -> Vec<u8> {
    const TABLE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
        -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];
    let mut out = Vec::new();
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in text.bytes() {
        if byte >= 128 {
            continue;
        }
        let val = TABLE[byte as usize];
        if val < 0 {
            if byte == b'=' {
                break;
            }
            continue;
        }
        buffer = (buffer << 6) | u32::from(val as u8);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
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

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match lookup(obj, key) {
        Some(JsonValue::Str(text)) => Some(text.clone()),
        _ => None,
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Bool(value)) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
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
