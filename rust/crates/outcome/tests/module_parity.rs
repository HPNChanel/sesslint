//! Hand-parsed vectors for pinned `sesslint.outcome.verify_outcome`.

use outcome::{
    contract,
    report::{SessionBackend, SessionCheck, SessionCheckError, DEFAULT_MAX_FILE_BYTES},
    snapshot::{self, LoadOptions},
    verify_outcome, AsOf, Input, VerifyError, VerifyOptions,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.outcome";
const EXPECTED_COMMIT: &str = "02694d537104659df66cdd084354739f3cccc440";
const EXPECTED_VECTOR_COUNT: usize = 4818;

#[derive(Debug, Clone)]
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
        self.message.fmt(f)
    }
}

struct VectorCase {
    id: usize,
    input: Vec<(String, JsonValue)>,
    expected: String,
}

struct ParsedVectors {
    cases: Vec<VectorCase>,
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/vectors/outcome")
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

#[test]
fn pinned_outcome_module_vectors_match_exact_bytes() {
    let root = vector_root();
    let raw = std::fs::read(root.join("vectors.json")).expect("vectors.json");
    assert!(!raw.contains(&b'\r'), "vectors.json must be LF-only");
    let manifest = std::fs::read_to_string(root.join("manifest.json")).expect("manifest.json");
    let manifest = parse_object_only(&manifest).expect("manifest");
    assert_eq!(
        string_field(&manifest, "schema").expect("schema"),
        EXPECTED_SCHEMA
    );
    assert_eq!(
        string_field(&manifest, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        string_field(&manifest, "python_commit").expect("python_commit"),
        EXPECTED_COMMIT
    );
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("vectors_sha256"),
        sha256_hex(&raw)
    );
    let provenance = std::fs::read_to_string(root.join("PROVENANCE.json")).expect("PROVENANCE");
    let provenance = parse_object_only(&provenance).expect("PROVENANCE");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data")
    );
    let coverage = std::fs::read_to_string(root.join("coverage.json")).expect("coverage");
    let coverage = parse_object_only(&coverage).expect("coverage");
    assert_eq!(i64_field(&coverage, "covered_count").expect("covered"), 0);
    assert_eq!(
        i64_field(&coverage, "not_applicable_count").expect("not_applicable"),
        59
    );
    let rows = array_field(&coverage, "rows").expect("rows");
    assert_eq!(rows.len(), 59);
  for row in rows {
        let JsonValue::Object(row) = row else {
            panic!("coverage row must be object");
        };
        assert_eq!(string_field(row, "status").expect("status"), "not_applicable");
        assert!(array_field(row, "vector_ids").expect("vector_ids").is_empty());
    }
    let text = std::str::from_utf8(&raw).expect("utf8");
    let parsed = parse_vectors(text).expect("parse vectors");
    assert_eq!(parsed.cases.len(), EXPECTED_VECTOR_COUNT);
    assert_eq!(
        i64_field(&manifest, "vector_count").expect("vector_count") as usize,
        EXPECTED_VECTOR_COUNT
    );
    let fixtures = root.join("fixtures");
    for (idx, case) in parsed.cases.iter().enumerate() {
        assert_eq!(case.id, idx);
        let actual = run_case(&fixtures, &case.input);
        assert_eq!(
            actual.as_bytes(),
            case.expected.as_bytes(),
            "vector {} mismatch",
            case.id
        );
    }
}

fn run_case(fixtures: &Path, input: &[(String, JsonValue)]) -> String {
    let contract_name = string_field(input, "contract").expect("contract");
    let source_name = string_field(input, "source").expect("source");
    let target_name = string_field(input, "target").expect("target");
    let loaded = bool_array_field(input, "loaded").expect("loaded");
    assert_eq!(loaded.len(), 3);
    let contract_path = fixtures.join(&contract_name);
    let source_path = fixtures.join(&source_name);
    let target_path = fixtures.join(&target_name);
    let owned_contract = loaded[0]
        .then(|| contract::load_contract(&contract_path).expect("contract"));
    let owned_source = loaded[1].then(|| {
        snapshot::load_snapshot(&source_path, &LoadOptions::new("source")).expect("source")
    });
    let owned_target = loaded[2].then(|| {
        snapshot::load_snapshot(&target_path, &LoadOptions::new("target")).expect("target")
    });
    let contract = if let Some(value) = owned_contract.as_ref() {
        Input::Value(value)
    } else {
        Input::Path(&contract_path)
    };
    let source = if let Some(value) = owned_source.as_ref() {
        Input::Value(value)
    } else {
        Input::Path(&source_path)
    };
    let target = if let Some(value) = owned_target.as_ref() {
        Input::Value(value)
    } else {
        Input::Path(&target_path)
    };
    let mut options = VerifyOptions {
        hash_keys: bool_field(input, "hash_keys").expect("hash_keys"),
        all_conditions: bool_field(input, "all_conditions").expect("all_conditions"),
        ..Default::default()
    };
    options.as_of = match optional_string_field(input, "as_of").expect("as_of") {
        None => None,
        Some(value) if value == "naive" => Some(AsOf::Naive),
        Some(value) => Some(AsOf::Aware(
            snapshot::parse_instant_str(&value).expect("instant"),
        )),
    };
    let session = string_field(input, "session").expect("session");
    let session_path = fixtures.join("synthetic-session");
    if session == "none" {
        options.session = None;
        wire_verify(verify_outcome(contract, source, target, options))
    } else {
        options.session = Some(&session_path);
        let backend = LinkedBackend {
            fail_os: session == "os",
        };
        wire_verify(outcome::verify_outcome_with(
            contract,
            source,
            target,
            options,
            &backend,
        ))
    }
}

struct LinkedBackend {
    fail_os: bool,
}

impl SessionBackend for LinkedBackend {
    fn check_file(
        &self,
        _: &Path,
        limit: i64,
    ) -> Result<SessionCheck, SessionCheckError> {
        assert_eq!(limit, DEFAULT_MAX_FILE_BYTES);
        if self.fail_os {
            return Err(SessionCheckError::Os);
        }
        let mut by_code = BTreeMap::new();
        by_code.insert("SL001".into(), 2);
        Ok(SessionCheck {
            assurance: "A2".into(),
            total: 2,
            by_code,
            source_fingerprint: Some("a".repeat(64)),
        })
    }
}

fn wire_verify(result: Result<outcome::OutcomeReport<'_>, VerifyError>) -> String {
    match result {
        Ok(report) => wire_object(&[(
            "ok",
            JsonValue::Object(vec![
                ("exit".into(), JsonValue::Number(report.exit_code().to_string())),
                (
                    "human".into(),
                    JsonValue::Str(report.render_human().expect("human")),
                ),
                (
                    "json".into(),
                    JsonValue::Str(report.to_json().expect("json")),
                ),
                (
                    "outcome".into(),
                    JsonValue::Str(report.outcome().into()),
                ),
            ]),
        )]),
        Err(err) => wire_error(&err),
    }
}

fn wire_error(err: &VerifyError) -> String {
    let (name, message) = match err {
        VerifyError::Contract(contract::LoadError::Io(_)) => ("OSError", "io".to_string()),
        VerifyError::Contract(e) => ("ContractError", e.to_string()),
        VerifyError::Source(snapshot::LoadError::Io(_)) | VerifyError::Target(snapshot::LoadError::Io(_)) => {
            ("OSError", "io".to_string())
        }
        VerifyError::Source(e) | VerifyError::Target(e) => ("SnapshotError", e.to_string()),
        VerifyError::Evaluation(e) => ("EvaluationError", e.0.clone()),
        VerifyError::Session(e) => ("EvaluationError", e.to_string()),
    };
    wire_object(&[
        ("error", JsonValue::Str(name.into())),
        ("message", JsonValue::Str(message)),
    ])
}

fn wire_object(pairs: &[(&str, JsonValue)]) -> String {
    let mut parts = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        parts.push(format!("{}:{}", wire_string(key), wire_value(value)));
    }
    format!("{{{}}}", parts.join(","))
}

fn wire_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".into(),
        JsonValue::Bool(v) => v.to_string(),
        JsonValue::Number(n) => n.clone(),
        JsonValue::Str(s) => wire_string(s),
        JsonValue::Array(items) => {
            let body: Vec<_> = items.iter().map(wire_value).collect();
            format!("[{}]", body.join(","))
        }
        JsonValue::Object(pairs) => {
            let body: Vec<_> = pairs
                .iter()
                .map(|(k, v)| format!("{}:{}", wire_string(k), wire_value(v)))
                .collect();
            format!("{{{}}}", body.join(","))
        }
    }
}

fn wire_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_vectors(input: &str) -> Result<ParsedVectors, ParseError> {
    let (meta_value, rest) = parse_value(input)?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing root data".into(),
        });
    }
    let JsonValue::Object(root) = meta_value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let items = array_field(&root, "cases")?;
    let mut cases = Vec::with_capacity(items.len());
    for item in items {
        let JsonValue::Object(obj) = item else {
            return Err(ParseError {
                message: "case must be object".into(),
            });
        };
        let id = usize_field(obj, "id")?;
        let input = object_field(obj, "input")?;
        let expected = string_field(obj, "expected_json")?;
        cases.push(VectorCase { id, input, expected });
    }
    Ok(ParsedVectors { cases })
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Str(s)) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match lookup(obj, key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Str(s)) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Bool(v)) => Ok(*v),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Number(n)) => n.parse().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    i64_field(obj, key).map(|v| v as usize)
}

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Array(items)) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn object_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Object(items)) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn bool_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<bool>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Bool(v) => Ok(*v),
            _ => Err(ParseError {
                message: format!("{key} elements must be bool"),
            }),
        })
        .collect()
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (JsonValue::Object(obj), rest) = parse_value(input)? else {
        return Err(ParseError {
            message: "expected object".into(),
        });
    };
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing data".into(),
        });
    }
    Ok(obj)
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
    input
        .strip_prefix(word)
        .map(|rest| (value, rest))
        .ok_or_else(|| ParseError {
            message: format!("expected {word}"),
        })
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0usize;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b'.' {
        let mut frac = end + 1;
        while frac < bytes.len() && bytes[frac].is_ascii_digit() {
            frac += 1;
        }
        if frac > end + 1 {
            end = frac;
        }
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    Ok((
        JsonValue::Number(input[..end].to_string()),
        &input[end..],
    ))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), stripped));
    }
    loop {
        let (value, after) = parse_value(rest)?;
        items.push(value);
        rest = after.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), stripped));
        }
        rest = rest
            .strip_prefix(',')
            .ok_or_else(|| ParseError {
                message: "expected , or ]".into(),
            })?
            .trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut pairs = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(pairs), stripped));
    }
    loop {
        let (JsonValue::Str(key), after_key) = parse_value(rest)? else {
            return Err(ParseError {
                message: "object key must be string".into(),
            });
        };
        let after = after_key
            .trim_start()
            .strip_prefix(':')
            .ok_or_else(|| ParseError {
                message: "expected :".into(),
            })?
            .trim_start();
        let (value, after_value) = parse_value(after)?;
        pairs.push((key, value));
        rest = after_value.trim_start();
        if let Some(stripped) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(pairs), stripped));
        }
        rest = rest
            .strip_prefix(',')
            .ok_or_else(|| ParseError {
                message: "expected , or }".into(),
            })?
            .trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    while let Some((idx, ch)) = chars.next() {
        match ch {
            '"' => {
                let byte = 1 + idx + ch.len_utf8();
                return Ok((out, &input[byte..]));
            }
            '\\' => {
                let (_, next) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                out.push(match next {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{0008}',
                    'f' => '\u{000C}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => {
                        let hex: String = chars
                            .by_ref()
                            .take(4)
                            .map(|(_, c)| c)
                            .collect();
                        if hex.len() != 4 {
                            return Err(ParseError {
                                message: "short unicode escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad unicode escape".into(),
                        })?;
                        char::from_u32(code).ok_or_else(|| ParseError {
                            message: "bad unicode value".into(),
                        })?
                    }
                    other => other,
                });
            }
            c => out.push(c),
        }
    }
    Err(ParseError {
        message: "unterminated string".into(),
    })
}
