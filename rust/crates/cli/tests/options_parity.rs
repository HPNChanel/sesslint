//! Byte-exact parity for `sesslint.cli._options` against pinned Python vectors.

use cli::options::{
    add_adapter_option, validate_positive_int, validate_unit_interval_float, ArgDefault,
    DefaultKeyword, OptionParser, PositiveIntError, UnitIntervalError, ADAPTER_CHOICES,
};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli._options/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/cli._options/PROVENANCE.json";
const COVERAGE_REL: &str = "../../parity/vectors/cli._options/coverage.json";
const OPTIONS_RS_REL: &str = "src/options.rs";

const EXPECTED_VECTOR_COUNT: usize = 24;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.cli._options";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_OPTIONS_PY_SHA256: &str =
    "4ca584f58db908f9aef026adb87cf51bee6960884699c79fbcd5a9dc29e2f0ea";
const EXPECTED_VECTORS_SHA256: &str =
    "4ad41c00a98a6a78c74d360797a6c6a342872387b3b1a8de47636e8efbca1b62";
const EXPECTED_OPTIONS_RS_SHA256: &str =
    "78efeac3dfa9e2fc4176bf0ad9847eafedc481dafad0b4e06c5a0f8e43ca3e92";

const GAP_POSITIVE_INT_I64: &str = "GAP-options-positive-int-i64";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn coverage_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_REL)
}

fn options_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(OPTIONS_RS_REL)
}

#[test]
fn options_module_parity_vectors() {
    assert_options_rs_unchanged();

    let path = vectors_path();
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains(&b'\r'), "vectors.json must be LF-only");
    assert_eq!(
        sha256_hex(&raw),
        EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator output"
    );

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    assert!(!prov_raw.contains('\r'), "PROVENANCE must be LF-only");
    let provenance = parse_object_only(&prov_raw).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
  let gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    assert!(
        gaps.iter().any(|item| matches!(item, JsonValue::Str(text) if text.contains(GAP_POSITIVE_INT_I64))),
        "PROVENANCE must document i64 gap"
    );

    let cov_raw = std::fs::read_to_string(coverage_path())
        .unwrap_or_else(|err| panic!("read coverage.json: {err}"));
    let coverage = parse_object_only(&cov_raw).expect("parse coverage.json");
    assert_eq!(
        i64_field(&coverage, "covered_count").expect("covered_count"),
        0
    );
    assert_eq!(
        i64_field(&coverage, "not_applicable_count").expect("not_applicable_count"),
        0
    );
    assert!(array_field(&coverage, "rows").expect("rows").is_empty());

    let doc = parse_document_with_meta(std::str::from_utf8(&raw).expect("utf8 vectors"))
        .expect("parse vectors.json");
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

fn assert_options_rs_unchanged() {
    let path = options_rs_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        EXPECTED_OPTIONS_RS_SHA256,
        "options.rs must remain unchanged for this parity card"
    );
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
        string_field(meta, "options_py_sha256").expect("options_py_sha256"),
        EXPECTED_OPTIONS_PY_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter().any(|item| matches!(item, JsonValue::Str(text) if text.contains(GAP_POSITIVE_INT_I64))),
        "vectors.json must list i64 gap"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    let result = string_field(&case.expected, "result").expect("result");
    match (kind.as_str(), result.as_str()) {
        ("validate_positive_int", "ok") => assert_positive_int_ok(case),
        ("validate_positive_int", "error") => assert_positive_int_error(case),
        ("validate_positive_int", "gap") => assert_positive_int_gap(case),
        ("validate_unit_interval_float", "ok") => assert_unit_interval_ok(case),
        ("validate_unit_interval_float", "error") => assert_unit_interval_error(case),
        ("add_adapter_option", "ok") => assert_adapter_option(case),
        (kind, result) => panic!("unexpected ({kind}, {result}) in {}", case.id),
    }
}

fn input_text(case: &VectorCase) -> String {
    string_field(&case.construct, "input").expect("input")
}

fn assert_positive_int_ok(case: &VectorCase) {
    let text = input_text(case);
    let value = validate_positive_int(&text)
        .unwrap_or_else(|err| panic!("validate_positive_int ok for {}: {err}", case.id));
    assert_eq!(
        string_field(&case.expected, "value_kind").expect("value_kind"),
        "int"
    );
    assert_eq!(
        value,
        i64_field(&case.expected, "value").expect("value"),
        "value for {}",
        case.id
    );
}

fn assert_positive_int_error(case: &VectorCase) {
    let text = input_text(case);
    let err = validate_positive_int(&text)
        .expect_err(&format!("expected error for {}", case.id));
    let message = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), message, "message for {}", case.id);
    match message.starts_with("Invalid integer value:") {
        true => assert!(matches!(err, PositiveIntError::Invalid(_))),
        false => assert!(matches!(err, PositiveIntError::NotPositive(_))),
    }
    assert!(err.source().is_none());
}

fn assert_positive_int_gap(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "gap_id").expect("gap_id"),
        GAP_POSITIVE_INT_I64
    );
    let pin = object_field(&case.expected, "pin").expect("pin");
    assert_eq!(
        string_field(pin, "result").expect("pin result"),
        "ok"
    );
    assert_eq!(
        string_field(pin, "value_kind").expect("pin value_kind"),
        "int"
    );
    let pin_value = number_field(pin, "value").expect("pin value");
    assert_eq!(pin_value, "9223372036854775808");
    let err = validate_positive_int(&input_text(case))
        .expect_err(&format!("expected i64 gap error for {}", case.id));
    assert_eq!(err, PositiveIntError::Magnitude);
    assert_eq!(
        err.to_string(),
        "int value does not fit i64",
        "display for {}",
        case.id
    );
    assert!(err.source().is_none());
}

fn assert_unit_interval_ok(case: &VectorCase) {
    let text = input_text(case);
    let value = validate_unit_interval_float(&text)
        .unwrap_or_else(|err| panic!("validate_unit_interval_float ok for {}: {err}", case.id));
    assert_eq!(
        string_field(&case.expected, "value_kind").expect("value_kind"),
        "float"
    );
    let expected_text = string_field(&case.expected, "value").expect("value");
    let expected: f64 = expected_text
        .parse()
        .unwrap_or_else(|_| panic!("float value for {}", case.id));
    assert!(
        (value - expected).abs() < f64::EPSILON,
        "value for {}",
        case.id
    );
}

fn assert_unit_interval_error(case: &VectorCase) {
    let text = input_text(case);
    let err = validate_unit_interval_float(&text)
        .expect_err(&format!("expected error for {}", case.id));
    let message = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), message, "message for {}", case.id);
    match message.starts_with("Invalid float value:") {
        true => assert!(matches!(err, UnitIntervalError::Invalid(_))),
        false => assert!(matches!(err, UnitIntervalError::OutOfRange(_))),
    }
    assert!(err.source().is_none());
}

fn assert_adapter_option(case: &VectorCase) {
    let choices = string_list_field(&case.expected, "choices").expect("choices");
    assert_eq!(
        choices,
        vec![
            "auto".to_string(),
            "canonical".to_string(),
            "claude-code-jsonl".to_string(),
            "codex-rollout".to_string(),
            "openai-agents".to_string(),
        ],
        "choices for {}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "default").expect("default"),
        "argparse.SUPPRESS"
    );
    assert!(
        bool_field(&case.expected, "default_distinct_from_none").expect("distinct none")
    );
    assert!(
        bool_field(&case.expected, "default_distinct_from_false").expect("distinct false")
    );

    let mut parser = OptionParser::new();
    add_adapter_option(&mut parser);
    let decl = parser.find("--adapter").expect("adapter");
    assert_eq!(decl.choices, Some(ADAPTER_CHOICES));
    assert_eq!(
        decl.default_keyword,
        DefaultKeyword::Present(ArgDefault::Suppress)
    );
    assert_eq!(decl.effective_default, ArgDefault::Suppress);
    assert_ne!(ArgDefault::Suppress, ArgDefault::None);
    assert_ne!(ArgDefault::Suppress, ArgDefault::False);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let script = r#"
import hashlib, sys
print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())
"#;
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("python")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python sha256");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(bytes).expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait python sha256");
    assert!(out.status.success(), "python sha256 failed");
    String::from_utf8(out.stdout)
        .expect("utf8 stdout")
        .trim()
        .to_string()
}

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
        f.write_str(&self.message)
    }
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    match value {
        JsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: "root must be object".into(),
        }),
    }
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
    let mut meta = Vec::new();
    let mut cases = Vec::new();
    for (key, item) in &root {
        if key == "vectors" {
            let JsonValue::Array(items) = item else {
                return Err(ParseError {
                    message: "vectors must be array".into(),
                });
            };
            cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
        } else {
            meta.push((key.clone(), item.clone()));
        }
    }
    Ok(ParsedDocument { meta, cases })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object_value(value, "vector case")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
    })
}

fn as_object_value<'a>(
    value: &'a JsonValue,
    label: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{label} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Object(items)) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn array_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Array(items)) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(text))) => Ok(text.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
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

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    number_field(obj, key)?.parse::<i64>().map_err(|_| ParseError {
        message: format!("{key} must fit i64"),
    })
}

fn number_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(n.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn string_list_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| {
            let JsonValue::Str(text) = item else {
                return Err(ParseError {
                    message: format!("{key} item must be string"),
                });
            };
            Ok(text.clone())
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
