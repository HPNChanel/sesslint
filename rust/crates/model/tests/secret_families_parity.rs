//! Parity for `model::secret_families` search spans against pinned Python `re.search`.

use model::secret_families::{
    search_anthropic_api_key, search_aws_access_key, search_bearer_token,
    search_generic_credential_assignment, search_github_oauth_token, search_github_pat_classic,
    search_github_pat_fine_grained, search_gitlab_pat, search_google_api_key,
    search_huggingface_token, search_jwt, search_npm_token, search_openai_api_key,
    search_openrouter_api_key, search_private_key_block, search_slack_token, search_stripe_key,
    search_stripe_webhook_secret, search_supabase_pat, search_telegram_bot_token, FAMILY_LITERALS,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/secret_families/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/secret_families/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/secret_families/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 127;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.secret_families";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SECRET_FAMILIES_RS_SHA256: &str =
    "23c97443724903cd5f848135e2d83e53d5ec798b865d4874e7d4968f7ac6e59f";
const EXPECTED_VECTORS_SHA256: &str =
    "65291af2e9c6ed0c0c2f9a56743c2d98c910451b7b9b198f832ddc34214badef";

const EXPECTED_LITERAL_KEYS: [&str; 18] = [
    "anthropic-api-key",
    "openai-api-key",
    "openrouter-api-key",
    "github-pat-classic",
    "github-pat-fine-grained",
    "github-oauth-token",
    "stripe-webhook-secret",
    "stripe-key",
    "aws-access-key",
    "google-api-key",
    "slack-token",
    "gitlab-pat",
    "bearer-token",
    "npm-token",
    "huggingface-token",
    "supabase-pat",
    "jwt",
    "private-key-block",
];

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    family: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

#[test]
fn secret_families_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    assert!(!bool_field(
        &parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("parse PROVENANCE"),
        "contains_real_data"
    )
    .expect("contains_real_data"));

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest = parse_object_only(&manifest_raw.replace("\r\n", "\n")).expect("manifest");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("vector_count"),
        EXPECTED_VECTOR_COUNT,
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);

    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "vector count");

    for case in &doc.cases {
        assert_case(case).unwrap_or_else(|err| panic!("{}: {err}", case.id));
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
        string_field(meta, "secret_families_rs_sha256").expect("secret_families_rs_sha256"),
        EXPECTED_SECRET_FAMILIES_RS_SHA256
    );
    let keys = array_field(meta, "family_literal_keys").expect("family_literal_keys");
    assert_eq!(keys.len(), EXPECTED_LITERAL_KEYS.len());
    for (item, expected) in keys.iter().zip(EXPECTED_LITERAL_KEYS.iter()) {
        let JsonValue::Str(s) = item else {
            panic!("family_literal_keys must be strings");
        };
        assert_eq!(s, *expected);
    }
}

fn assert_case(case: &VectorCase) -> Result<(), String> {
    let kind = string_field(&case.construct, "type").map_err(|e| e.to_string())?;
    if kind != "secret_family_search" {
        return Err(format!("unknown construct {kind}"));
    }
    let recipe = object_field(&case.construct, "recipe").map_err(|e| e.to_string())?;
    let family = string_field(recipe, "family").map_err(|e| e.to_string())?;
    if family != case.family {
        return Err(format!(
            "family mismatch id {}: {} vs {}",
            case.id, case.family, family
        ));
    }
    let haystack = assemble_recipe(recipe).map_err(|e| e.to_string())?;
    let got = search_by_family(&family, &haystack).map_err(|e| e.to_string())?;
    let exp_span = field_value(&case.expected, "span");
    match exp_span {
        Some(JsonValue::Null) | None => {
            if got.is_some() {
                return Err(format!("expected no match for {}, got {got:?}", case.id));
            }
        }
        Some(JsonValue::Array(parts)) => {
            if parts.len() != 2 {
                return Err("span must be [start, end]".into());
            }
            let JsonValue::Number(start) = &parts[0] else {
                return Err("span[0]".into());
            };
            let JsonValue::Number(end) = &parts[1] else {
                return Err("span[1]".into());
            };
            let start = usize::try_from(*start).map_err(|_| "span start usize")?;
            let end = usize::try_from(*end).map_err(|_| "span end usize")?;
            match got {
                Some((a, b)) if a == start && b == end => {}
                Some((a, b)) => {
                    return Err(format!(
                        "span mismatch {}: expected ({start},{end}), got ({a},{b})",
                        case.id
                    ));
                }
                None => {
                    return Err(format!(
                        "expected span ({start},{end}) for {}, got None",
                        case.id
                    ));
                }
            }
        }
        other => return Err(format!("bad expected.span: {other:?}")),
    }
    Ok(())
}

type SearchFn = fn(&[u8]) -> Option<(usize, usize)>;

fn search_by_family(name: &str, haystack: &[u8]) -> Result<Option<(usize, usize)>, String> {
    let f: SearchFn = match name {
        "anthropic-api-key" => search_anthropic_api_key,
        "openai-api-key" => search_openai_api_key,
        "openrouter-api-key" => search_openrouter_api_key,
        "github-pat-classic" => search_github_pat_classic,
        "github-pat-fine-grained" => search_github_pat_fine_grained,
        "github-oauth-token" => search_github_oauth_token,
        "stripe-webhook-secret" => search_stripe_webhook_secret,
        "stripe-key" => search_stripe_key,
        "aws-access-key" => search_aws_access_key,
        "google-api-key" => search_google_api_key,
        "slack-token" => search_slack_token,
        "gitlab-pat" => search_gitlab_pat,
        "bearer-token" => search_bearer_token,
        "npm-token" => search_npm_token,
        "huggingface-token" => search_huggingface_token,
        "supabase-pat" => search_supabase_pat,
        "telegram-bot-token" => search_telegram_bot_token,
        "jwt" => search_jwt,
        "private-key-block" => search_private_key_block,
        "generic-credential-assignment" => search_generic_credential_assignment,
        other => return Err(format!("unknown family {other}")),
    };
    Ok(f(haystack))
}

fn assemble_recipe(recipe: &[(String, JsonValue)]) -> Result<Vec<u8>, ParseError> {
    let lead = object_field(recipe, "lead")?;
    let tail = object_field(recipe, "tail")?;
    let mut out = decode_bytes_blob(lead)?;
    let mode = object_field(recipe, "prefix_mode")?;
    out.extend(assemble_prefix_mode(recipe, mode)?);
    let family = string_field(recipe, "family")?;

    if field_value(recipe, "segment_lengths").is_some() {
        let segs = array_field(recipe, "segment_lengths")?;
        if segs.len() != 3 {
            return Err(ParseError {
                message: "segment_lengths must have 3 elements".into(),
            });
        }
        let fill = fill_byte_field(recipe, "fill_byte")?;
        let n1 = usize_field_from_json(&segs[0])?;
        let n2 = usize_field_from_json(&segs[1])?;
        let n3 = usize_field_from_json(&segs[2])?;
        out.extend(std::iter::repeat_n(fill, n1));
        out.push(b'.');
        out.extend(std::iter::repeat_n(fill, n2));
        out.push(b'.');
        out.extend(std::iter::repeat_n(fill, n3));
    } else if family == "generic-credential-assignment" {
        let between = object_field(recipe, "between")?;
        out.extend(decode_bytes_blob(between)?);
        let body_len = usize_field(recipe, "body_length")?;
        let fill = fill_byte_field(recipe, "fill_byte")?;
        out.extend(std::iter::repeat_n(fill, body_len));
    } else {
        let body_opt = recipe
            .iter()
            .find(|(k, _)| k == "body_length")
            .map(|(_, v)| v);
        match body_opt {
            None | Some(JsonValue::Null) => {}
            Some(JsonValue::Number(n)) => {
                let n = usize::try_from(*n).map_err(|_| ParseError {
                    message: "body_length".into(),
                })?;
                let fill_spec = field_value(recipe, "fill_byte").ok_or_else(|| ParseError {
                    message: "fill_byte".into(),
                })?;
                match fill_spec {
                    JsonValue::Str(s) if s == "stripe_alternating" => {
                        out.extend(stripe_alternating_body(n));
                    }
                    _ => {
                        let fill = fill_byte_field(recipe, "fill_byte")?;
                        out.extend(std::iter::repeat_n(fill, n));
                    }
                }
            }
            _ => {
                return Err(ParseError {
                    message: "body_length".into(),
                });
            }
        }
    }
    out.extend(decode_bytes_blob(tail)?);
    Ok(out)
}

fn assemble_prefix_mode(
    recipe: &[(String, JsonValue)],
    mode: &[(String, JsonValue)],
) -> Result<Vec<u8>, ParseError> {
    let kind = string_field(mode, "kind")?;
    match kind.as_str() {
        "family_literal" => {
            let fam = string_field(recipe, "family")?;
            let idx_val = field_value(recipe, "literal_index").ok_or_else(|| ParseError {
                message: "literal_index".into(),
            })?;
            let JsonValue::Number(idx) = idx_val else {
                return Err(ParseError {
                    message: "literal_index must be number".into(),
                });
            };
            let idx = usize::try_from(*idx).map_err(|_| ParseError {
                message: "literal_index".into(),
            })?;
            Ok(literal_prefix(&fam, idx)?.to_vec())
        }
        "family_literal_prefix" => {
            let fam = string_field(mode, "family")?;
            let idx = i64_field_named(mode, "literal_index")?;
            let idx = usize::try_from(idx).map_err(|_| ParseError {
                message: "literal_index".into(),
            })?;
            Ok(literal_prefix(&fam, idx)?.to_vec())
        }
        "concat" => {
            let parts = array_field(mode, "parts")?;
            let mut buf = Vec::new();
            for part in parts {
                let obj = as_object(&part, "concat part")?;
                buf.extend(assemble_concat_part(obj)?);
            }
            Ok(buf)
        }
        "pem_header" => {
            let middle = object_field(mode, "middle")?;
            let mut buf = b"-----BEGIN ".to_vec();
            buf.extend(decode_bytes_blob(middle)?);
            buf.extend(literal_prefix("private-key-block", 0)?);
            Ok(buf)
        }
        "generic" => {
            let keyword = string_field(mode, "keyword")?;
            let bytes = match keyword.as_str() {
                "password" => b"password".as_slice(),
                other => {
                    return Err(ParseError {
                        message: format!("unknown generic keyword {other}"),
                    });
                }
            };
            Ok(bytes.to_vec())
        }
        other => Err(ParseError {
            message: format!("unknown prefix_mode {other}"),
        }),
    }
}

fn assemble_concat_part(part: &[(String, JsonValue)]) -> Result<Vec<u8>, ParseError> {
    let kind = string_field(part, "kind")?;
    match kind.as_str() {
        "bytes_hex" => decode_bytes_blob(part),
        "family_literal_prefix" => {
            let fam = string_field(part, "family")?;
            let idx = i64_field_named(part, "literal_index")?;
            let idx = usize::try_from(idx).map_err(|_| ParseError {
                message: "literal_index".into(),
            })?;
            Ok(literal_prefix(&fam, idx)?.to_vec())
        }
        other => Err(ParseError {
            message: format!("unknown concat part {other}"),
        }),
    }
}

fn literal_prefix(family: &str, index: usize) -> Result<&'static [u8], ParseError> {
    for (name, lits) in FAMILY_LITERALS {
        if *name == family {
            return lits.get(index).copied().ok_or_else(|| ParseError {
                message: format!("literal index {index} for {family}"),
            });
        }
    }
    Err(ParseError {
        message: format!("unknown family {family}"),
    })
}

fn decode_bytes_blob(obj: &[(String, JsonValue)]) -> Result<Vec<u8>, ParseError> {
    let kind = string_field(obj, "kind")?;
    if kind != "bytes_hex" {
        return Err(ParseError {
            message: "expected bytes_hex".into(),
        });
    }
    let hex = string_field(obj, "hex")?;
    decode_hex(&hex)
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, ParseError> {
    if !hex.is_empty() && !hex.len().is_multiple_of(2) {
        return Err(ParseError {
            message: "odd hex length".into(),
        });
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = decode_hex_nibble(bytes[idx])?;
        let lo = decode_hex_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, ParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ParseError {
            message: "bad hex".into(),
        }),
    }
}

fn stripe_alternating_body(length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < length {
        let chunk = (length - out.len()).min(8);
        out.extend(std::iter::repeat_n(b'a', chunk));
        if out.len() < length {
            out.push(b'-');
        }
    }
    out
}

fn fill_byte_field(recipe: &[(String, JsonValue)], key: &str) -> Result<u8, ParseError> {
    let raw = field_value(recipe, key).ok_or_else(|| ParseError {
        message: key.into(),
    })?;
    match raw {
        JsonValue::Null => Err(ParseError {
            message: format!("{key} is null"),
        }),
        JsonValue::Number(n) => u8::try_from(*n).map_err(|_| ParseError {
            message: "fill byte range".into(),
        }),
        _ => Err(ParseError {
            message: "fill_byte must be number".into(),
        }),
    }
}

fn usize_field_from_json(value: &JsonValue) -> Result<usize, ParseError> {
    match value {
        JsonValue::Number(n) => usize::try_from(*n).map_err(|_| ParseError {
            message: "usize".into(),
        }),
        _ => Err(ParseError {
            message: "number expected".into(),
        }),
    }
}

fn field_value<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
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
    let mut cases = Vec::with_capacity(items.len());
    for item in items {
        cases.push(parse_vector_case(item)?);
    }
    Ok(ParsedDocument {
        meta: root.clone(),
        cases,
    })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
    let family = string_field(obj, "family")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        family,
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

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field_named(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn i64_field_named(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

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
