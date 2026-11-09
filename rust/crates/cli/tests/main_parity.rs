//! Parity for `sesslint.__main__` (`__main__.py`) against pinned Python vectors.

use cli::json_errors::{error_document, wants_json};
use cli::main__::main as package_main;
use cli::{_removed_command_hint, create_parser};
use std::fmt;
use std::io::Write;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/__main__/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/__main__/PROVENANCE.json";
const COVERAGE_REL: &str = "../../parity/vectors/__main__/coverage.json";
const MAIN_RS_REL: &str = "src/main__.rs";

const EXPECTED_VECTOR_COUNT: usize = 7;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.__main__";
const EXPECTED_PYTHON_COMMIT: &str = "02694d537104659df66cdd084354739f3cccc440";
const EXPECTED_MAIN_PY_SHA256: &str =
    "8417c205b4ef33540fa9ab017c1647889b62fc26056a276e82c99b9658ee19a0";
const EXPECTED_MAIN_RS_SHA256: &str =
    "373706ccb88b2cee397e6d1c41117b335519356f44938d63b66b6639eee55b71";
const EXPECTED_CLI_LIB_RS_SHA256: &str =
    "3d2f3514bd193b4bc7da61ead816a4cbe82ad57ed7a653013ba719b0947ebc66";
const EXPECTED_VECTORS_SHA256: &str =
    "1f44c49500f209c6709225d3573346dd30524ed7e6ff183bfecbab70229f5e22";

const GAP_SYS_FROZEN: &str = "GAP-__main__-sys-frozen";
const GAP_UNPARSED: &str = "GAP-__main__-unparsed-command";

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

fn main_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MAIN_RS_REL)
}

#[test]
fn main_module_parity_vectors() {
    assert_main_rs_unchanged();

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
    let prov_gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    for marker in [GAP_SYS_FROZEN, GAP_UNPARSED] {
        assert!(
            prov_gaps.iter().any(|item| gap_contains(item, marker)),
            "PROVENANCE must document {marker}"
        );
    }

    let cov_raw = std::fs::read_to_string(coverage_path())
        .unwrap_or_else(|err| panic!("read coverage.json: {err}"));
    assert!(!cov_raw.contains('\r'), "coverage must be LF-only");
    let coverage = parse_object_only(&cov_raw).expect("parse coverage.json");
    assert_eq!(
        string_field(&coverage, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        i64_field(&coverage, "covered_count").expect("covered_count"),
        0
    );
    assert_eq!(
        i64_field(&coverage, "not_applicable_count").expect("not_applicable_count"),
        0
    );
    assert!(
        array_field(&coverage, "rows").expect("rows").is_empty(),
        "no pytest rows for __main__"
    );

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

fn assert_main_rs_unchanged() {
    let bytes = std::fs::read(main_rs_path())
        .unwrap_or_else(|err| panic!("read main__.rs: {err}"));
    assert_eq!(
        sha256_hex(&bytes),
        EXPECTED_MAIN_RS_SHA256,
        "main__.rs sha256 must stay pinned"
    );
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
        string_field(meta, "__main___py_sha256").expect("__main___py_sha256"),
        EXPECTED_MAIN_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "main__rs_sha256").expect("main__rs_sha256"),
        EXPECTED_MAIN_RS_SHA256
    );
    assert_eq!(
        string_field(meta, "cli_lib_rs_sha256").expect("cli_lib_rs_sha256"),
        EXPECTED_CLI_LIB_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in [GAP_SYS_FROZEN, GAP_UNPARSED] {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "vectors.json must list {marker}"
        );
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "frozen_gap" => assert_frozen_gap(case),
        "non_frozen_main" => assert_non_frozen_main(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_frozen_gap(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "gap_id").expect("gap_id"),
        GAP_SYS_FROZEN,
        "{}",
        case.id
    );
}

fn expressible_removed_streams(argv: &[&str]) -> (i32, Vec<u8>, Vec<u8>) {
    let hint = _removed_command_hint(argv).expect("removed argv");
    let stderr = format!("{hint}\n").into_bytes();
    let mut stdout = Vec::new();
    if wants_json(argv, None) {
        let doc = error_document(&hint);
        stdout.extend_from_slice(doc.as_bytes());
        stdout.push(b'\n');
    }
    (2, stdout, stderr)
}

fn assert_non_frozen_main(case: &VectorCase) {
    let argv = string_list_field(&case.construct, "argv").expect("argv");
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let want_code = i32_field(&case.expected, "exit_code").expect("exit_code");
    let want_stdout = decode_hex(&string_field(&case.expected, "stdout_hex").expect("stdout_hex"))
        .expect("stdout hex");
    let want_stderr = decode_hex(&string_field(&case.expected, "stderr_hex").expect("stderr_hex"))
        .expect("stderr hex");

    if optional_string_field(&case.expected, "gap_id")
        .expect("gap parse")
        .is_some()
    {
        assert_eq!(
            string_field(&case.expected, "gap_id").expect("gap_id"),
            GAP_UNPARSED,
            "{}",
            case.id
        );
        assert!(want_stderr.windows(6).any(|w| w == b"usage:"), "{}", case.id);
        let rust_message =
            string_field(&case.expected, "rust_message").expect("rust_message for gap");
        let err = package_main(Some(&refs)).expect_err("unparsed must error");
        let configure = create_parser().expect_err("configure");
        assert_eq!(err, configure, "{}", case.id);
        assert_eq!(
            err.unsupported_message(),
            Some(rust_message.as_str()),
            "{}",
            case.id
        );
        assert_ne!(
            err.to_string(),
            String::from_utf8_lossy(&want_stderr),
            "Rust error must not be stored as Python stderr for {}",
            case.id
        );
        assert_eq!(want_code, 2, "python exit for {}", case.id);
        return;
    }

    assert!(
        _removed_command_hint(&argv).is_some(),
        "expressible path must be removed command: {}",
        case.id
    );
    let (code, stdout, stderr) = expressible_removed_streams(&refs);
    assert_eq!(code, want_code, "synthetic exit {}", case.id);
    assert_eq!(stdout, want_stdout, "stdout {}", case.id);
    assert_eq!(stderr, want_stderr, "stderr {}", case.id);
    if case.id.contains("formats") {
        assert!(
            String::from_utf8_lossy(&stderr).contains("doctor  (or:"),
            "registry hint spacing for {}",
            case.id
        );
    }

    let actual_code = package_main(Some(&refs)).expect("package main exit");
    assert_eq!(actual_code, want_code, "package_main code {}", case.id);
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let pair = std::str::from_utf8(&bytes[index..index + 2]).map_err(|err| err.to_string())?;
        let byte = u8::from_str_radix(pair, 16).map_err(|err| err.to_string())?;
        out.push(byte);
        index += 2;
    }
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let script = r#"
import hashlib, sys
print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())
"#;
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
        stdin.write_all(bytes).expect("write sha256 stdin");
    }
    let output = child.wait_with_output().expect("wait sha256");
    assert!(output.status.success(), "python sha256 failed");
    String::from_utf8(output.stdout)
        .expect("utf8 sha256")
        .trim()
        .to_string()
}

#[derive(Debug, Clone)]
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
    let vectors_value = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors_value.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    let meta: Vec<_> = root
        .iter()
        .filter(|(k, _)| *k != "vectors")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    Ok(ParsedDocument { meta, cases })
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: "root must be object".into(),
        }),
    }
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
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
        Some((_, JsonValue::Null)) => Err(ParseError {
            message: format!("{key} is null"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
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
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn i32_field(obj: &[(String, JsonValue)], key: &str) -> Result<i32, ParseError> {
    Ok(i64_field(obj, key)? as i32)
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

fn string_list_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let JsonValue::Str(text) = item else {
            return Err(ParseError {
                message: format!("{key} elements must be strings"),
            });
        };
        out.push(text.clone());
    }
    Ok(out)
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
    let mut end = 0usize;
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
