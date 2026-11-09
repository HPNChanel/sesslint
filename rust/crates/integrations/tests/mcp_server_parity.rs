//! Byte-exact parity for `sesslint.mcp_server` against pinned Python vectors.

use integrations::mcp_server::{
    handle_line, serve, tools, McpError, MAX_MCP_LINE_BYTES, PROTOCOL_VERSION, SERVER_NAME,
    TOOL_NAMES,
};
use model::version::CLI_VERSION;
use std::fmt;
use std::io::Cursor;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/mcp_server/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/mcp_server/manifest.json";
const COVERAGE_REL: &str = "../../parity/vectors/mcp_server/coverage.json";
const PROVENANCE_REL: &str = "../../parity/vectors/mcp_server/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 24;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.mcp_server";
const EXPECTED_PYTHON_COMMIT: &str = "02694d537104659df66cdd084354739f3cccc440";
const EXPECTED_MCP_PY_SHA256: &str =
    "6fe904b833fcf6529a9645dd67594a16f9dac58a28e553e8d895189704f2300c";
const EXPECTED_MCP_RS_SHA256: &str =
    "0804b9044223b5aa844c5fb3d0f98ca9cee5914b5d03bf387bd28a3a5c64af0b";
const EXPECTED_VECTORS_SHA256: &str =
    "fa05def2a3961354192f8705ec6e6ebaa9cb495505a54ffb481815d30fe40ea5";

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
fn mcp_server_module_parity_vectors() {
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
        "GAP-mcp-server-check-file",
        "GAP-mcp-server-precheck",
        "GAP-mcp-server-scan",
        "GAP-mcp-server-serve-readline",
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
    assert_eq!(covered, 8, "coverage covered count");
    assert_eq!(not_applicable, 21, "coverage not_applicable count");

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
        string_field(meta, "mcp_server_py_sha256").expect("py sha"),
        EXPECTED_MCP_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "mcp_server_rs_sha256").expect("rs sha"),
        EXPECTED_MCP_RS_SHA256,
        "mcp_server.rs hash must remain pinned"
    );
}

fn assert_vector_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "handle_line" => assert_handle_line(case),
        "handle_line_twice" => assert_handle_line_twice(case),
        "serve" => assert_serve(case),
        other => panic!("{}: unsupported construct type {other}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "protocol_version").expect("protocol_version"),
        PROTOCOL_VERSION
    );
    assert_eq!(
        i64_field(&case.expected, "max_mcp_line_bytes").expect("max"),
        i64::try_from(MAX_MCP_LINE_BYTES).expect("max fits i64")
    );
    let want_tools = string_list(&case.expected, "tool_names").expect("tool_names");
    let got_tools: Vec<&str> = TOOL_NAMES.to_vec();
    assert_eq!(want_tools, got_tools, "{}", case.id);
    let want_exports = string_list(&case.expected, "all_exports").expect("all_exports");
    assert_eq!(
        want_exports,
        [
            "PROTOCOL_VERSION",
            "SERVER_INFO",
            "TOOLS",
            "handle_line",
            "serve"
        ],
        "{}",
        case.id
    );
    let info = object_field(&case.expected, "server_info").expect("server_info");
    assert_eq!(
        string_field_obj(info, "name").expect("name"),
        SERVER_NAME
    );
    assert_eq!(
        string_field_obj(info, "version").expect("version"),
        CLI_VERSION
    );
    let listed = tools();
    assert_eq!(listed.len(), 3, "{}", case.id);
    for (tool, name) in listed.iter().zip(TOOL_NAMES.iter()) {
        assert_eq!(
            tool.get("name").and_then(|v| v.as_str()),
            Some(*name),
            "{}",
            case.id
        );
    }
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

fn assert_handle_line(case: &VectorCase) {
    let raw = decode_b64(&case.construct, "raw_b64", &case.id);
    let want_kind = string_field(&case.expected, "kind").expect("kind");
    let got = handle_line(&raw);
    match want_kind.as_str() {
        "none" => assert_eq!(got.unwrap(), None, "{}", case.id),
        "bytes" => {
            let out = got.unwrap_or_else(|err| panic!("{}: handle_line failed: {err:?}", case.id));
            let bytes = out.expect("expected Some bytes");
            let want_sha = string_field(&case.expected, "sha256").expect("sha256");
            assert_eq!(sha256_hex(&bytes), want_sha, "{}", case.id);
            let want_b64 = string_field(&case.expected, "b64").expect("b64");
            let decoded = decode_base64(&want_b64).expect("expected b64");
            assert_eq!(bytes, decoded, "{}", case.id);
        }
        "unsupported" => {
            let message = string_field(&case.expected, "message").expect("message");
            match got {
                Err(McpError::Unsupported(text)) => assert_eq!(text, message, "{}", case.id),
                other => panic!("{}: expected Unsupported, got {other:?}", case.id),
            }
        }
        other => panic!("{}: bad expected kind {other}", case.id),
    }
}

fn assert_handle_line_twice(case: &VectorCase) {
    let raw = decode_b64(&case.construct, "raw_b64", &case.id);
    let first = handle_line(&raw).expect("first").expect("first bytes");
    let second = handle_line(&raw).expect("second").expect("second bytes");
    assert_eq!(first, second, "{}", case.id);
    assert_eq!(
        string_field(&case.expected, "kind").expect("kind"),
        "equal"
    );
}

fn assert_serve(case: &VectorCase) {
    let script = decode_b64(&case.construct, "script_b64", &case.id);
    let mut stdout = Vec::new();
    let code = serve(&mut Cursor::new(script), &mut stdout).expect("serve");
    let want_stdout = decode_b64(&case.expected, "stdout_b64", &case.id);
    assert_eq!(stdout, want_stdout, "{}", case.id);
    assert_eq!(
        sha256_hex(&stdout),
        string_field(&case.expected, "stdout_sha256").expect("stdout sha"),
        "{}",
        case.id
    );
    assert_eq!(
        i64::from(code),
        i64_field(&case.expected, "exit_code").expect("exit_code"),
        "{}",
        case.id
    );
    let lines: Vec<&[u8]> = stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        usize::try_from(i64_field(&case.expected, "reply_count").expect("reply_count")).unwrap(),
        "{}",
        case.id
    );
    let first = std::str::from_utf8(lines[0]).expect("utf8 first line");
    let first_obj = parse_object_only(first).expect("parse first reply");
    match first_obj.iter().find(|(k, _)| k == "id").map(|(_, v)| v) {
        Some(JsonValue::Null) => {}
        other => panic!("{}: parse error id must be null, got {other:?}", case.id),
    }
    let err = object_field(&first_obj, "error").expect("error object");
    let code = i64_field_obj(err, "code").expect("error code");
    assert_eq!(
        code,
        i64_field(&case.expected, "first_error_code").expect("first_error_code"),
        "{}",
        case.id
    );
    let second = std::str::from_utf8(lines[1]).expect("utf8 second line");
    let second_obj = parse_object_only(second).expect("parse second reply");
    assert_eq!(
        i64_field(&second_obj, "id").expect("second id"),
        i64_field(&case.expected, "second_id").expect("second_id"),
        "{}",
        case.id
    );
    let want_empty = bool_field(&case.expected, "second_has_empty_result").expect("empty result");
    let result = object_field(&second_obj, "result").expect("result");
    assert_eq!(result.is_empty(), want_empty, "{}", case.id);
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

fn i64_field_obj(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
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
