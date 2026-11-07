//! Module-surface parity for `sesslint.checks.hygiene` against pinned Python vectors.
//!
//! Compares gate helpers, placeholder checks, and [`SecretScanTracker::evidence_rows`].
//! Does not call [`checks::hygiene::SecretScanTracker::into_findings`] when hits exist.

use std::borrow::Cow;
use std::fmt;
use std::path::PathBuf;

use checks::hygiene::{
    gate_maybe_contains_secret, json_escape_boundary_shadow, kw_assignment_present,
    line_gate_maybe_contains_secret, looks_like_placeholder, short_prefix_present,
    SecretEvidenceRow, SecretScanTracker, GATE_WINDOW_BYTES, MAX_DIGESTS_PER_FINDING,
    MAX_SECRET_FINDINGS_PER_FILE, SECRET_FAMILY_IDS, SECRET_FAMILY_SET_VERSION,
};

const VECTORS_REL: &str = "../../parity/vectors/checks.hygiene/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/checks.hygiene/manifest.json";
const EXPECTED_VECTOR_COUNT: usize = 95;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.checks.hygiene";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CHECKS_HYGIENE_RS_SHA256: &str =
    "e353fd94ef34279648afa57ba9b699a74d47053b9d699064528ee58a6257387c";
const EXPECTED_VECTORS_SHA256: &str =
    "c3d8d1cf30a6cb5b9415fddb77d8dd722c069a58e9291d08b895603ec2111d80";

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

#[test]
fn hygiene_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest_normalized = manifest_raw.replace("\r\n", "\n");
    let manifest = parse_object_only(&manifest_normalized).expect("parse manifest.json");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
        "vectors_sha256 must match generator output"
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT,
        "manifest vector_count"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);

    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );

    for case in &doc.cases {
        assert_case(case);
    }
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
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
        string_field(meta, "checks_hygiene_rs_sha256").expect("checks_hygiene_rs_sha256"),
        EXPECTED_CHECKS_HYGIENE_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter().any(
            |item| matches!(item, JsonValue::Str(s) if s.contains("FINGERPRINT_CODEC_UNAVAILABLE"))
        ),
        "expected fingerprint codec gap in known_parity_gaps"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "hygiene_module_exports" => {
            let py_all = array_field(&case.expected, "python_all").expect("python_all");
            let names: Vec<String> = py_all
                .iter()
                .map(|item| match item {
                    JsonValue::Str(s) => s.clone(),
                    _ => panic!("{}: python_all entry", case.id),
                })
                .collect();
            assert_eq!(
                names,
                [
                    "MAX_DIGESTS_PER_FINDING",
                    "MAX_SECRET_FINDINGS_PER_FILE",
                    "SECRET_FAMILY_IDS",
                    "SECRET_FAMILY_SET_VERSION",
                    "SecretScanTracker",
                ]
                .map(str::to_owned)
                .to_vec(),
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(&case.expected, "SECRET_FAMILY_SET_VERSION").unwrap(),
                SECRET_FAMILY_SET_VERSION,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(&case.expected, "MAX_SECRET_FINDINGS_PER_FILE").unwrap(),
                MAX_SECRET_FINDINGS_PER_FILE,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(&case.expected, "MAX_DIGESTS_PER_FINDING").unwrap(),
                MAX_DIGESTS_PER_FINDING,
                "{}",
                case.id
            );
            assert_eq!(
                usize_field(&case.expected, "GATE_WINDOW_BYTES").unwrap(),
                GATE_WINDOW_BYTES,
                "{}",
                case.id
            );
            assert_eq!(
                usize_field(&case.expected, "SECRET_FAMILY_IDS_len").unwrap(),
                SECRET_FAMILY_IDS.len(),
                "{}",
                case.id
            );
        }
        "hygiene_bool_fn" => {
            let name = string_field(&case.construct, "fn").expect("fn");
            let input_obj = object_field(&case.construct, "input").expect("input");
            let raw = decode_bytes_hex(input_obj).expect("input hex");
            let expected = bool_field(&case.expected, "value").expect("value");
            let got = match name.as_str() {
                "short_prefix_present" => short_prefix_present(&raw),
                "kw_assignment_present" => kw_assignment_present(&raw),
                "looks_like_placeholder" => looks_like_placeholder(&raw),
                other => panic!("{}: unknown fn {other}", case.id),
            };
            assert_eq!(got, expected, "{}", case.id);
        }
        "hygiene_gate" => {
            let input_obj = object_field(&case.construct, "input").expect("input");
            let raw = decode_bytes_hex(input_obj).expect("input hex");
            assert_eq!(
                gate_maybe_contains_secret(&raw),
                bool_field(&case.expected, "gate").expect("gate"),
                "{}",
                case.id
            );
            assert_eq!(
                line_gate_maybe_contains_secret(&raw),
                bool_field(&case.expected, "line_gate").expect("line_gate"),
                "{}",
                case.id
            );
        }
        "hygiene_json_shadow" => {
            let input_obj = object_field(&case.construct, "input").expect("input");
            let raw = decode_bytes_hex(input_obj).expect("input hex");
            let shadow_obj = object_field(&case.expected, "shadow").expect("shadow");
            let expected_shadow = decode_bytes_hex(shadow_obj).expect("shadow hex");
            let expect_borrowed = bool_field(&case.expected, "borrowed").expect("borrowed");
            let out = json_escape_boundary_shadow(&raw);
            assert_eq!(out.as_ref(), expected_shadow.as_slice(), "{}", case.id);
            let borrowed = matches!(out, Cow::Borrowed(_));
            assert_eq!(borrowed, expect_borrowed, "{}", case.id);
            assert_eq!(out.len(), raw.len(), "{}", case.id);
        }
        "hygiene_tracker" => {
            let mut tracker = SecretScanTracker::new();
            run_tracker_feeds(&case.construct, &mut tracker).expect("feeds");
            if let Ok(rows_len) = usize_field(&case.expected, "rows_len") {
                assert_eq!(tracker.evidence_rows().len(), rows_len, "{}", case.id);
            } else if let Ok(rows_json) = array_field(&case.expected, "rows") {
                assert_evidence_rows(&case.id, &tracker.evidence_rows(), &rows_json);
            }
            if let Ok(len) = usize_field(&case.expected, "into_findings_len") {
                let findings = tracker
                    .into_findings("synth.jsonl")
                    .unwrap_or_else(|err| panic!("{}: into_findings: {err}", case.id));
                assert_eq!(findings.len(), len, "{}", case.id);
            }
        }
        "hygiene_tracker_blob" => {
            let blob_recipe = object_field(&case.construct, "blob_recipe").expect("blob_recipe");
            let blob = assemble_blob_recipe(blob_recipe).expect("blob");
            let mut tracker = SecretScanTracker::new();
            tracker.feed_blob(&blob);
            let rows_json = array_field(&case.expected, "rows").expect("rows");
            assert_evidence_rows(&case.id, &tracker.evidence_rows(), &rows_json);
        }
        other => panic!("{}: unknown construct type {other}", case.id),
    }
}

fn run_tracker_feeds(
    construct: &[(String, JsonValue)],
    tracker: &mut SecretScanTracker,
) -> Result<(), ParseError> {
    let feeds = array_field(construct, "feeds")?;
    for feed in &feeds {
        let feed_obj = as_object(feed, "feed")?; // feed is &JsonValue from iter
        let raw = if lookup_field(feed_obj, "raw").is_some() {
            let raw_obj = object_field(feed_obj, "raw")?;
            decode_bytes_hex(raw_obj)?
        } else {
            let recipe = object_field(feed_obj, "recipe")?;
            assemble_recipe(recipe)?
        };
        let line = optional_i64_field(feed_obj, "line")?;
        let ordinal = optional_i64_field(feed_obj, "ordinal")?;
        let byte_offset = optional_i64_field(feed_obj, "byte_offset")?;
        let byte_end = optional_i64_field(feed_obj, "byte_end")?;
        tracker.feed(&raw, line, byte_offset, byte_end, ordinal);
    }
    Ok(())
}

fn assemble_blob_recipe(recipe: &[(String, JsonValue)]) -> Result<Vec<u8>, ParseError> {
    let segments = array_field(recipe, "segments")?;
    let mut out = Vec::new();
    for segment in segments {
        let seg = as_object(&segment, "segment")?;
        if lookup_field(seg, "raw").is_some() {
            out.extend_from_slice(&decode_bytes_hex(object_field(seg, "raw")?)?);
        } else {
            out.extend_from_slice(&assemble_recipe(object_field(seg, "recipe")?)?);
        }
    }
    Ok(out)
}

fn assemble_recipe(recipe: &[(String, JsonValue)]) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::new();
    if lookup_field(recipe, "lead").is_some() {
        let lead_obj = object_field(recipe, "lead")?;
        out.extend_from_slice(&decode_bytes_hex(lead_obj)?);
    }
    if let Ok(pad) = usize_field(recipe, "padding_length") {
        let fill = u8::try_from(i64_field(recipe, "fill_byte")?).map_err(|_| ParseError {
            message: "fill_byte".into(),
        })?;
        out.extend(std::iter::repeat_n(fill, pad));
    }
    if let Ok(hex) = string_field(recipe, "gate_literal_hex") {
        let gate = decode_hex_string(&hex)?;
        out.extend_from_slice(&gate);
    }
    if lookup_field(recipe, "body_length").is_some() {
        let body = usize::try_from(i64_field(recipe, "body_length")?).map_err(|_| ParseError {
            message: "body_length".into(),
        })?;
        let fill = u8::try_from(i64_field(recipe, "fill_byte")?).map_err(|_| ParseError {
            message: "fill_byte".into(),
        })?;
        out.extend(std::iter::repeat_n(fill, body));
    }
    if lookup_field(recipe, "tail").is_some() {
        let tail_obj = object_field(recipe, "tail")?;
        out.extend_from_slice(&decode_bytes_hex(tail_obj)?);
    }
    Ok(out)
}

fn decode_bytes_hex(obj: &[(String, JsonValue)]) -> Result<Vec<u8>, ParseError> {
    let kind = string_field(obj, "kind")?;
    if kind != "bytes_hex" {
        return Err(ParseError {
            message: "expected bytes_hex".into(),
        });
    }
    let hex = string_field(obj, "hex")?;
    if hex.len() % 2 != 0 {
        return Err(ParseError {
            message: "odd hex".into(),
        });
    }
    decode_hex_string(&hex)
}

fn decode_hex_string(hex: &str) -> Result<Vec<u8>, ParseError> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let high = nib_from_hex(bytes[idx])?;
        let low = nib_from_hex(bytes[idx + 1])?;
        out.push((high << 4) | low);
        idx += 2;
    }
    Ok(out)
}

fn nib_from_hex(byte: u8) -> Result<u8, ParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ParseError {
            message: "bad hex digit".into(),
        }),
    }
}

fn assert_evidence_rows(case_id: &str, got: &[SecretEvidenceRow], exp: &[JsonValue]) {
    assert_eq!(got.len(), exp.len(), "{case_id}: row count");
    for (row, item) in got.iter().zip(exp.iter()) {
        let exp_obj = as_object(item, "row").expect("row object");
        assert_eq!(
            row.family,
            string_field(exp_obj, "family").expect("family"),
            "{case_id}"
        );
        assert_eq!(
            row.occurrence_count,
            i64_field(exp_obj, "occurrence_count").expect("occurrence_count"),
            "{case_id}"
        );
        assert_eq!(row.match_len, i64_field(exp_obj, "match_len").expect("match_len"), "{case_id}");
        assert_eq!(row.truncated, bool_field(exp_obj, "truncated").expect("truncated"), "{case_id}");
        assert_eq!(
            row.line_number,
            optional_i64_field(exp_obj, "line").expect("line"),
            "{case_id}"
        );
        assert_eq!(
            row.record_ordinal,
            optional_i64_field(exp_obj, "ordinal").expect("ordinal"),
            "{case_id}"
        );
        assert_eq!(
            row.byte_offset,
            optional_i64_field(exp_obj, "byte_offset").expect("byte_offset"),
            "{case_id}"
        );
        assert_eq!(
            row.byte_end,
            optional_i64_field(exp_obj, "byte_end").expect("byte_end"),
            "{case_id}"
        );
        assert_eq!(
            row.overflow,
            optional_i64_field(exp_obj, "overflow").expect("overflow"),
            "{case_id}"
        );
        let digests = array_field(exp_obj, "match_sha256").expect("match_sha256");
        assert_eq!(row.match_sha256.len(), digests.len(), "{case_id}");
        for (idx, digest) in digests.iter().enumerate() {
            let JsonValue::Str(expected) = digest else {
                panic!("{case_id}: digest[{idx}]");
            };
            assert_eq!(&row.match_sha256[idx], expected, "{case_id}");
        }
    }
}

fn lookup_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<i64>, ParseError> {
    match lookup_field(obj, key) {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Number(n)) => Ok(Some(*n)),
        _ => Err(ParseError {
            message: format!("{key} must be number or null"),
        }),
    }
}

// --- minimal JSON (vectors.json) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Float(f64),
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
        meta: root.clone(),
        cases: cases?,
    })
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

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
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
        b'0'..=b'9' | b'-' => parse_numeric_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_numeric_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
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
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
            return Err(ParseError {
                message: "invalid float".into(),
            });
        }
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let slice = &input[..idx];
        let value: f64 = slice.parse().map_err(|_| ParseError {
            message: "float overflow".into(),
        })?;
        let parsed = if negative { -value } else { value };
        return Ok((JsonValue::Float(parsed), &input[idx..]));
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
