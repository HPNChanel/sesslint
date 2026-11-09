//! Byte-exact parity for `sesslint.cli._common` against pinned Python vectors.
//!
//! Baseline I/O, write-baseline side effects, and JSON internal-error envelopes
//! are documented in `known_parity_gaps` (not byte-compared on those Rust paths).

use cli::common::{
    format_display_name, handle_internal_error, load_baseline_arg, output_format,
    read_stdin_bytes, rule_codes_arg, should_color, write_baseline_arg, ArgValue, CaughtError,
    CommonArgs, CommonError, FORMAT_DISPLAY_NAMES, DEFAULT_MAX_FILE_BYTES,
};
use cli::errors::CliError;
use std::fmt;
use std::io::Cursor;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli._common/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/cli._common/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 46;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.cli._common";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_COMMON_PY_SHA256: &str =
    "6a4a70e39c95c69817642fe322de72a52c49783be57e47d318d7e6e0097eae2a";

const GAP_LOAD_BASELINE: &str = "GAP-common-load-baseline-set";
const GAP_WRITE_BASELINE: &str = "GAP-common-write-baseline-set";
const GAP_JSON_ENVELOPE: &str = "GAP-common-internal-error-json";

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

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

#[test]
fn cli_common_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        !raw.contains('\r'),
        "vectors.json must be LF-only"
    );

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    assert!(!prov_raw.contains('\r'), "PROVENANCE must be LF-only");
    let provenance = parse_object_only(&prov_raw).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    for marker in [GAP_LOAD_BASELINE, GAP_WRITE_BASELINE, GAP_JSON_ENVELOPE] {
        let gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "PROVENANCE must document {marker}"
        );
    }

    let doc = parse_document_with_meta(&raw).expect("parse vectors.json");
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
        string_field(meta, "common_py_sha256").expect("common_py_sha256"),
        EXPECTED_COMMON_PY_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in [GAP_LOAD_BASELINE, GAP_WRITE_BASELINE, GAP_JSON_ENVELOPE] {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "vectors.json must list {marker}"
        );
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "format_display_names" => assert_format_display_names(case),
        "handle_internal_error" => assert_handle_internal_error(case),
        "should_color" => assert_should_color(case),
        "rule_codes_arg" => assert_rule_codes_arg(case),
        "output_format" => assert_output_format(case),
        "load_baseline_arg" => assert_load_baseline_arg(case),
        "write_baseline_arg" => assert_write_baseline_arg(case),
        "read_stdin_bytes" => assert_read_stdin_bytes(case),
        "default_max_file_bytes" => assert_default_max_file_bytes(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_format_display_names(case: &VectorCase) {
    let rows = array_field(&case.expected, "entries").expect("entries");
    assert_eq!(
        rows.len(),
        FORMAT_DISPLAY_NAMES.len(),
        "FORMAT_DISPLAY_NAMES len for {}",
        case.id
    );
    for (index, row) in rows.iter().enumerate() {
        let obj = as_object(row, "entry").expect("entry object");
        let key = string_field(obj, "key").expect("key");
        let display = string_field(obj, "display").expect("display");
        let (rust_key, rust_display) = FORMAT_DISPLAY_NAMES[index];
        assert_eq!(rust_key, key.as_str(), "key row {index} for {}", case.id);
        assert_eq!(
            format_display_name(rust_key),
            display.as_str(),
            "display row {index} for {}",
            case.id
        );
        assert_eq!(rust_display, display.as_str(), "pair row {index} for {}", case.id);
    }
}

fn assert_handle_internal_error(case: &VectorCase) {
    let err_obj = object_field(&case.construct, "err").expect("err");
    let kind = string_field(err_obj, "kind").expect("err.kind");
    let caught = if kind == "CliError" {
        let code = i32_field(err_obj, "exit_code").expect("exit_code");
        let message = string_field(err_obj, "message").expect("message");
        CaughtError::Usage(CliError::new(code, &message))
    } else {
        let message = string_field(err_obj, "message").expect("message");
        CaughtError::Fault(message)
    };
    let args = common_args_from_optional_object(optional_object_field(&case.construct, "args"));
    let hex = string_field(&case.construct, "error_id_hex").unwrap_or_else(|_| "0123abcd".into());

    if let Ok(raises) = string_field(&case.expected, "raises") {
        assert_eq!(raises, "CliError", "raises kind for {}", case.id);
        let mut stderr = Vec::new();
        let err = handle_internal_error(&caught, args.as_ref(), &hex, &mut stderr).unwrap_err();
        match err {
            CommonError::Usage(cli) => {
                assert_eq!(
                    cli.exit_code(),
                    i32_field(&case.expected, "exit_code").expect("exit_code"),
                    "exit_code for {}",
                    case.id
                );
                assert_eq!(
                    cli.message(),
                    string_field(&case.expected, "message").expect("message"),
                    "message for {}",
                    case.id
                );
            }
            other => panic!("expected usage for {}: {other:?}", case.id),
        }
        assert!(stderr.is_empty(), "stderr for {}", case.id);
        return;
    }

    let mut stderr = Vec::new();
    let code = handle_internal_error(&caught, args.as_ref(), &hex, &mut stderr)
        .unwrap_or_else(|err| panic!("handle_internal_error for {}: {err}", case.id));
    assert_eq!(
        code,
        i32_field(&case.expected, "exit_code").expect("exit_code"),
        "exit_code for {}",
        case.id
    );
    assert_eq!(
        String::from_utf8(stderr).expect("stderr utf8"),
        string_field(&case.expected, "stderr").expect("stderr"),
        "stderr for {}",
        case.id
    );
}

fn assert_should_color(case: &VectorCase) {
    let args = common_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]));
    let isatty = optional_bool_field(&case.construct, "stream_isatty");
    let environ = environ_pairs(&case.construct);
    let expected = bool_field(&case.expected, "value").expect("value");
    assert_eq!(
        should_color(&args, isatty, &environ),
        expected,
        "should_color for {}",
        case.id
    );
}

fn assert_rule_codes_arg(case: &VectorCase) {
    let name = string_field(&case.construct, "name").expect("name");
    let args = if let Ok(steps) = array_field(&case.construct, "args_steps") {
        let mut built = CommonArgs::new();
        for step in steps {
            let step_obj = as_object(step, "args_step").expect("args_step");
            for (key, value) in step_obj {
                built = built.with(key.clone(), json_to_arg_value(value));
            }
        }
        built
    } else {
        common_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]))
    };
    let expected_codes = optional_string_list(&case.expected, "codes");
    let actual = rule_codes_arg(&args, &name);
    assert_eq!(actual, expected_codes, "rule_codes_arg for {}", case.id);
}

fn assert_output_format(case: &VectorCase) {
    let args = common_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]));
    let expected = format_expected_string(&case.expected);
    assert_eq!(output_format(&args), expected, "output_format for {}", case.id);
}

fn format_expected_string(expected: &[(String, JsonValue)]) -> String {
    match expected.iter().find(|(k, _)| k == "format").map(|(_, v)| v) {
        Some(JsonValue::Str(text)) => text.clone(),
        Some(JsonValue::Number(num)) => num.clone(),
        _ => panic!("format must be string or number"),
    }
}

fn assert_load_baseline_arg(case: &VectorCase) {
    let args = common_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]));
    let baseline = load_baseline_arg(&args).expect("load_baseline_arg");
    assert!(
        baseline.is_none(),
        "unset baseline for {}",
        case.id
    );
    assert!(
        case.expected
            .iter()
            .find(|(k, _)| k == "baseline")
            .map(|(_, v)| matches!(v, JsonValue::Null))
            .unwrap_or(false),
        "expected null baseline for {}",
        case.id
    );
}

fn assert_write_baseline_arg(case: &VectorCase) {
    let args = common_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]));
    write_baseline_arg(&args).expect("write_baseline_arg");
    assert!(bool_field(&case.expected, "ok").expect("ok"), "ok for {}", case.id);
}

fn assert_read_stdin_bytes(case: &VectorCase) {
    let hex = string_field(&case.construct, "stdin_hex").unwrap_or_else(|_| String::new());
    let data = decode_hex(&hex).expect("stdin_hex");
    let limit = optional_i64_field(&case.construct, "max_file_bytes");
    let mut reader: Cursor<Vec<u8>> = Cursor::new(data);

    if let Ok(raises) = string_field(&case.expected, "raises") {
        assert_eq!(raises, "ValueError", "raises for {}", case.id);
        let err = read_stdin_bytes(&mut reader, limit).unwrap_err();
        assert_eq!(
            err.to_string(),
            string_field(&case.expected, "message").expect("message"),
            "message for {}",
            case.id
        );
        return;
    }

    let out = read_stdin_bytes(&mut reader, limit).expect("read_stdin_bytes");
    let expected_hex = string_field(&case.expected, "bytes_hex").expect("bytes_hex");
    assert_eq!(
        out,
        decode_hex(&expected_hex).expect("expected bytes"),
        "bytes for {}",
        case.id
    );
}

fn assert_default_max_file_bytes(case: &VectorCase) {
    let expected = i64_field(&case.expected, "value").expect("value");
    assert_eq!(DEFAULT_MAX_FILE_BYTES, expected, "DEFAULT_MAX_FILE_BYTES for {}", case.id);
}

fn common_args_from_optional_object(
    fields: Option<&[(String, JsonValue)]>,
) -> Option<CommonArgs> {
    fields.map(common_args_from_object)
}

fn common_args_from_object(fields: &[(String, JsonValue)]) -> CommonArgs {
    let mut args = CommonArgs::new();
    for (name, value) in fields {
        args = args.with(name.clone(), json_to_arg_value(value));
    }
    args
}

fn json_to_arg_value(value: &JsonValue) -> ArgValue {
    match value {
        JsonValue::Bool(flag) => ArgValue::Bool(*flag),
        JsonValue::Str(text) => ArgValue::Str(text.clone()),
        JsonValue::Number(num) => ArgValue::Int(num.parse().expect("int arg")),
        JsonValue::Null => ArgValue::Bool(false),
        _ => panic!("unsupported arg json value"),
    }
}

fn environ_pairs(construct: &[(String, JsonValue)]) -> Vec<(&str, &str)> {
    let Some(value) = construct.iter().find(|(k, _)| k == "environ").map(|(_, v)| v) else {
        return Vec::new();
    };
    match value {
        JsonValue::Object(fields) => fields
            .iter()
            .map(|(name, val)| match val {
                JsonValue::Str(text) => (name.as_str(), text.as_str()),
                _ => panic!("env value must be string"),
            })
            .collect(),
        JsonValue::Array(rows) => rows
            .iter()
            .map(|row| {
                let JsonValue::Array(pair) = row else {
                    panic!("environ row must be [key, value]");
                };
                let (JsonValue::Str(key), JsonValue::Str(val)) = (&pair[0], &pair[1]) else {
                    panic!("environ pair must be strings");
                };
                (key.as_str(), val.as_str())
            })
            .collect(),
        JsonValue::Null => Vec::new(),
        _ => panic!("environ must be object, array, or null"),
    }
}

fn optional_string_list(obj: &[(String, JsonValue)], key: &str) -> Option<Vec<String>> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Null) | None => None,
        Some(JsonValue::Array(items)) => Some(
            items
                .iter()
                .map(|item| match item {
                    JsonValue::Str(text) => text.clone(),
                    _ => panic!("code must be string"),
                })
                .collect(),
        ),
        _ => panic!("{key} must be null or array"),
    }
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if !hex.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("bad hex at {i}"))
        })
        .collect()
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
    let meta: Vec<(String, JsonValue)> = root
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

fn optional_object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Option<&'a [(String, JsonValue)]> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Null) | None => None,
        Some(JsonValue::Object(fields)) => Some(fields),
        _ => panic!("{key} must be null or object"),
    }
}

fn optional_bool_field(obj: &[(String, JsonValue)], key: &str) -> Option<bool> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Null) => None,
        Some(JsonValue::Bool(value)) => Some(*value),
        None => None,
        _ => panic!("{key} must be null or bool"),
    }
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Option<i64> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Null) | None => None,
        Some(JsonValue::Number(num)) => num.parse().ok(),
        _ => panic!("{key} must be number or null"),
    }
}

// --- minimal JSON (vectors.json only) ---

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

fn i32_field(obj: &[(String, JsonValue)], key: &str) -> Result<i32, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i32>().map_err(|_| ParseError {
            message: format!("{key} must be i32"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
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
