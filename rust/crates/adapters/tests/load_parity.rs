//! Parity for `sesslint.adapters.load` against pinned Python vectors.

use adapters::load::{profile_key_for_format, FORMAT_PROFILE_KEYS, ALL};
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.load/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/adapters.load/PROVENANCE.json";
const EXPECTED_VECTOR_COUNT: usize = 5;
const EXPECTED_VECTORS_SHA256: &str =
    "9c161e5a8c51f2153052dd4f93f6931ded5b900568bdebbd976b432151572c22";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.adapters.load";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_LOAD_PY_SHA256: &str =
    "7347f2916d1d76169b872825f25d4a4dceff7eccc30a9957ba39f13f7ae87e43";
const EXPECTED_LOAD_RS_SHA256: &str =
    "93405357d8b4d823c78ba01731b474e3a4ff2b37ed12f77bec2dddb7349cd2d2";

const BANNED_CHECKOUT_MARK: &str = "FOR_WORK";
const BANNED_SUPABASE_SHAPE: &str = "sbp_";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => assert_module_exports(case),
        "format_profile_keys" => assert_format_profile_keys(case),
        "profile_key_for_format" => assert_profile_key_for_format(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_module_exports(case: &VectorCase) {
    let names = array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), ALL.len(), "ALL length {}", case.id);
    for (index, item) in names.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{index}] must be string in {}", case.id);
        };
        assert_eq!(ALL[index], name.as_str(), "ALL[{index}] {}", case.id);
    }
}

fn assert_format_profile_keys(case: &VectorCase) {
    let entries = array_field(&case.expected, "entries").expect("entries");
    assert_eq!(
        entries.len(),
        FORMAT_PROFILE_KEYS.len(),
        "{} entries",
        case.id
    );
    for (index, item) in entries.iter().enumerate() {
        let pair = array_value(item, "pair").expect("pair array");
        assert_eq!(pair.len(), 2, "pair length {}", case.id);
        let JsonValue::Str(id) = &pair[0] else {
            panic!("format id must be string in {}", case.id);
        };
        let JsonValue::Str(key) = &pair[1] else {
            panic!("profile key must be string in {}", case.id);
        };
        assert_eq!(FORMAT_PROFILE_KEYS[index].0, id.as_str(), "{}", case.id);
        assert_eq!(FORMAT_PROFILE_KEYS[index].1, key.as_str(), "{}", case.id);
    }
}

fn array_value<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [JsonValue], ParseError> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be array"),
        }),
    }
}

fn assert_profile_key_for_format(case: &VectorCase) {
    let format = format_construct_arg(&case.construct);
    let got = profile_key_for_format(format);
    let want = optional_string_field(&case.expected, "result");
    assert_eq!(got.map(str::to_owned), want, "{}", case.id);
}

fn format_construct_arg(construct: &[(String, JsonValue)]) -> Option<&str> {
    match construct.iter().find(|(k, _)| k == "format") {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(text))) => Some(text.as_str()),
        _ => panic!("format must be string or null"),
    }
}

#[test]
fn load_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(!normalized.contains('\r'), "vectors.json must not contain CR");
    assert!(
        !normalized.contains(BANNED_CHECKOUT_MARK),
        "vectors.json must not name checkout paths"
    );
    assert!(
        !normalized.contains(BANNED_SUPABASE_SHAPE),
        "vectors.json must not contain supabase token shape"
    );
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors sha256");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov = parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&prov, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE contains_real_data must be false"
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
        string_field(meta, "load_py_sha256").expect("load_py_sha256"),
        EXPECTED_LOAD_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "load_rs_sha256").expect("load_rs_sha256"),
        EXPECTED_LOAD_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    for prefix in [
        "GAP-load-claude-canonical-no-events",
        "GAP-load-valueerror-repr",
        "GAP-load-payload-content-hash",
    ] {
        assert!(
            gaps.iter().any(|item| {
                matches!(item, JsonValue::Str(text) if text.starts_with(prefix))
            }),
            "expected gap {prefix}"
        );
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => '?',
    }
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
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
    let meta: Vec<(String, JsonValue)> = root
        .iter()
        .filter(|(key, _)| *key != "vectors")
        .cloned()
        .collect();
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
    let cases = items
        .iter()
        .map(parse_vector_case)
        .collect::<Result<_, _>>()?;
    Ok(ParsedDocument { meta, cases })
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
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
    Ok(root)
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
    })
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
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

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Object(items))) => Ok(items),
        Some((_, JsonValue::Null)) => Err(ParseError {
            message: format!("{key} is null"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        Some((_, JsonValue::Null)) => Err(ParseError {
            message: format!("{key} is null"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        _ => panic!("{key} must be string or null"),
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
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    if input.starts_with('-') {
        end = 1;
    }
    let bytes = input.as_bytes();
    while end < bytes.len() {
        let ch = bytes[end];
        if ch.is_ascii_digit() || ch == b'.' || ch == b'e' || ch == b'E' || ch == b'+' || ch == b'-'
        {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    Ok((JsonValue::Number(input[..end].to_owned()), &input[end..]))
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
    let mut chars = input[1..].chars();
    loop {
        let ch = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        if ch == '"' {
            let consumed = input.len() - chars.as_str().len();
            return Ok((out, &input[consumed..]));
        }
        if ch == '\\' {
            let esc = chars.next().ok_or_else(|| ParseError {
                message: "bad escape".into(),
            })?;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() != 4 {
                        return Err(ParseError {
                            message: "bad unicode escape".into(),
                        });
                    }
                    let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                        message: "bad unicode escape".into(),
                    })?;
                    let converted = char::try_from(code).map_err(|_| ParseError {
                        message: "bad unicode scalar".into(),
                    })?;
                    out.push(converted);
                }
                _ => {
                    return Err(ParseError {
                        message: "bad escape".into(),
                    })
                }
            }
        } else {
            out.push(ch);
        }
    }
}
