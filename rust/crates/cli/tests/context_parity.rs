//! Byte-exact parity for `sesslint.cli._context` against pinned Python vectors.
//!
//! `build_context` is intentionally out of scope: Python calls `sesslint.config.load_config`;
//! Rust returns `ContextError::Unsupported` at that boundary (see manifest `known_gaps`).

use cli::context::{
    cli_supplied, format_choices, resolve_output_format, ArgValue, CliArgs, CliContext, Parser,
    ParserAction, ProgressCallback, SettingDefault, SettingValue, SCOPED_TO_COMMANDS,
    SETTING_SPECS,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli._context/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 24;

const SYNTHETIC_WARN: &str = "synthetic-warn";
const SYNTHETIC_INFO: &str = "synthetic-info";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "resolve_output_format" => assert_resolve_output_format(case),
        "cli_supplied" => assert_cli_supplied(case),
        "cli_context_channel" => assert_cli_context_channel(case),
        "setting_specs" => assert_setting_specs(case),
        "scoped_commands" => assert_scoped_commands(case),
        "format_choices" => assert_format_choices(case),
        "progress_callback" => assert_progress_callback(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_resolve_output_format(case: &VectorCase) {
    let args = cli_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]));
    let env = env_pairs(object_field(&case.construct, "env").unwrap_or(&[]));
    let sub_spec = optional_string_field(&case.construct, "subparser");
    let sub = sub_spec.as_deref().map(subparser_from_spec);

    let result = string_field(&case.expected, "result").expect("result");
    if result == "error" {
        let expected_code = i32_field(&case.expected, "exit_code").expect("exit_code");
        let expected_message = string_field(&case.expected, "message").expect("message");
        let error = resolve_output_format(&args, &env, None, sub.as_ref()).unwrap_err();
        assert_eq!(
            error.exit_code(),
            expected_code,
            "exit_code for {}",
            case.id
        );
        assert_eq!(error.message(), expected_message, "message for {}", case.id);
        assert_eq!(
            error.to_string(),
            expected_message,
            "display for {}",
            case.id
        );
        return;
    }

    let setting_obj = object_field(&case.expected, "setting").expect("setting");
    let expected_value = json_to_setting_value(
        setting_obj
            .iter()
            .find(|(k, _)| k == "value")
            .map(|(_, v)| v)
            .expect("setting.value"),
    );
    let expected_source = string_field(setting_obj, "source").expect("source");
    let setting = resolve_output_format(&args, &env, None, sub.as_ref())
        .unwrap_or_else(|err| panic!("resolve_output_format for {}: {err}", case.id));
    assert_eq!(setting.value, expected_value, "value for {}", case.id);
    assert_eq!(setting.source, expected_source, "source for {}", case.id);
}

fn assert_cli_supplied(case: &VectorCase) {
    let name = string_field(&case.construct, "name").expect("name");
    let args = cli_args_from_object(object_field(&case.construct, "args").expect("args"));
    let supplied = bool_field(&case.expected, "supplied").expect("supplied");
    let actual = cli_supplied(&args, &name);
    if !supplied {
        assert!(actual.is_none(), "expected unset for {}", case.id);
        return;
    }
    let expected_value = case
        .expected
        .iter()
        .find(|(k, _)| k == "value")
        .map(|(_, v)| v)
        .expect("value");
    let actual = actual.unwrap_or_else(|| panic!("expected supplied for {}", case.id));
    assert_arg_matches_json(actual, expected_value, &case.id);
}

fn assert_cli_context_channel(case: &VectorCase) {
    let quiet = bool_field(&case.construct, "quiet").expect("quiet");
    let verbose = bool_field(&case.construct, "verbose").expect("verbose");
    let channel = string_field(&case.construct, "channel").expect("channel");
    let expected = string_field(&case.expected, "stderr").expect("stderr");

    let mut buf = Vec::new();
    {
        let mut ctx = CliContext::new(quiet, verbose, None, Vec::new(), &mut buf, false);
        match channel.as_str() {
            "error" => {
                let message = string_field(&case.construct, "message").expect("message");
                ctx.error(&message).expect("error");
            }
            "warn" => {
                let message = string_field(&case.construct, "message").expect("message");
                ctx.warn(&message).expect("warn");
            }
            "info" => {
                let message = string_field(&case.construct, "message").expect("message");
                ctx.info(&message).expect("info");
            }
            "debug" => {
                let message = string_field(&case.construct, "message").expect("message");
                ctx.debug(&message).expect("debug");
            }
            "warn_then_info" => {
                ctx.warn(SYNTHETIC_WARN).expect("warn");
                ctx.info(SYNTHETIC_INFO).expect("info");
            }
            other => panic!("unknown channel {other} in {}", case.id),
        }
    }
    assert_eq!(
        String::from_utf8(buf).expect("utf8 stderr"),
        expected,
        "stderr bytes for {}",
        case.id
    );
}

fn assert_setting_specs(case: &VectorCase) {
    let rows = array_field(&case.expected, "rows").expect("rows");
    assert_eq!(rows.len(), SETTING_SPECS.len(), "row count for {}", case.id);
    for (index, row) in rows.iter().enumerate() {
        let JsonValue::Object(row_obj) = row else {
            panic!("row must be object in {}", case.id);
        };
        let spec = &SETTING_SPECS[index];
        assert_eq!(
            string_field(row_obj, "name").expect("name"),
            spec.name,
            "name row {index} for {}",
            case.id
        );
        assert_eq!(
            optional_string_field_obj(row_obj, "env_var").as_deref(),
            spec.env_var,
            "env_var row {index} for {}",
            case.id
        );
        assert_eq!(
            optional_string_field_obj(row_obj, "config_key").as_deref(),
            spec.config_key,
            "config_key row {index} for {}",
            case.id
        );
        assert_default_matches(row_obj, spec.default, index, &case.id);
    }
}

fn assert_default_matches(
    row_obj: &[(String, JsonValue)],
    spec_default: SettingDefault,
    index: usize,
    case_id: &str,
) {
    let fields = object_field(row_obj, "default").expect("default object");
    let kind = string_field(fields, "kind").expect("default.kind");
    match spec_default {
        SettingDefault::None => {
            assert_eq!(kind, "none", "default row {index} for {case_id}");
        }
        SettingDefault::Bool(value) => {
            assert_eq!(kind, "bool", "default row {index} for {case_id}");
            assert_eq!(
                bool_field(fields, "value").expect("default.value"),
                value,
                "default row {index} for {case_id}"
            );
        }
        SettingDefault::Str(value) => {
            assert_eq!(kind, "str", "default row {index} for {case_id}");
            assert_eq!(
                string_field(fields, "value").expect("default.value"),
                value,
                "default row {index} for {case_id}"
            );
        }
        SettingDefault::Int(value) => {
            assert_eq!(kind, "int", "default row {index} for {case_id}");
            assert_eq!(
                i64_field(fields, "value").expect("default.value"),
                value,
                "default row {index} for {case_id}"
            );
        }
    }
}

fn assert_scoped_commands(case: &VectorCase) {
    let commands_obj = object_field(&case.expected, "commands").expect("commands");
    assert_eq!(
        SCOPED_TO_COMMANDS.len(),
        commands_obj.len(),
        "scoped count for {}",
        case.id
    );
    for (name, command_list) in SCOPED_TO_COMMANDS {
        let expected = commands_obj
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("missing scoped key {name} in {}", case.id));
        let JsonValue::Array(items) = expected else {
            panic!("scoped commands must be array for {name} in {}", case.id);
        };
        let expected_cmds: Vec<String> = items
            .iter()
            .map(|item| match item {
                JsonValue::Str(text) => text.clone(),
                _ => panic!("command name must be string in {}", case.id),
            })
            .collect();
        assert_eq!(
            *command_list,
            expected_cmds.iter().map(String::as_str).collect::<Vec<_>>(),
            "commands for {name} in {}",
            case.id
        );
    }
}

fn assert_format_choices(case: &VectorCase) {
    let sub_spec = optional_string_field(&case.construct, "subparser");
    let sub = sub_spec.as_deref().map(subparser_from_spec);
    let actual = format_choices(sub.as_ref());
    let expected = case
        .expected
        .iter()
        .find(|(k, _)| k == "choices")
        .map(|(_, v)| v)
        .expect("choices");
    match expected {
        JsonValue::Null => assert!(actual.is_none(), "choices for {}", case.id),
        JsonValue::Array(items) => {
            let expected: Vec<String> = items
                .iter()
                .map(|item| match item {
                    JsonValue::Str(text) => text.clone(),
                    _ => panic!("choice must be string in {}", case.id),
                })
                .collect();
            assert_eq!(actual, Some(expected), "choices for {}", case.id);
        }
        _ => panic!("choices must be null or array in {}", case.id),
    }
}

fn assert_progress_callback(case: &VectorCase) {
    let quiet = bool_field(&case.construct, "quiet").expect("quiet");
    let verbose = bool_field(&case.construct, "verbose").expect("verbose");
    let isatty = bool_field(&case.construct, "isatty").expect("isatty");
    let args = cli_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]));
    let expected_kind = string_field(&case.expected, "kind").expect("kind");

    let ctx = CliContext::new(quiet, verbose, None, Vec::new(), Vec::new(), isatty);
    let callback = ctx.progress_callback(&args);
    match expected_kind.as_str() {
        "none" => assert!(callback.is_none(), "progress for {}", case.id),
        "ndjson" => assert!(
            matches!(callback, Some(ProgressCallback::Ndjson(_))),
            "progress for {}",
            case.id
        ),
        "tty" => assert!(
            matches!(callback, Some(ProgressCallback::Tty(_))),
            "progress for {}",
            case.id
        ),
        other => panic!("unknown progress kind {other} in {}", case.id),
    }
}

fn subparser_from_spec(spec: &str) -> Parser {
    match spec {
        "format_human_json_ndjson" => format_subparser(&["human", "json", "ndjson"]),
        "format_human_json" => format_subparser(&["human", "json"]),
        "json_only" => json_only_subparser(),
        "no_format" => no_format_subparser(),
        other => panic!("unknown subparser spec {other}"),
    }
}

fn format_subparser(choices: &[&str]) -> Parser {
    Parser {
        actions: vec![ParserAction {
            dest: "output_format".to_string(),
            choices: Some(choices.iter().map(|item| (*item).to_string()).collect()),
            option_strings: vec!["-f".to_string(), "--format".to_string()],
            subparsers: None,
        }],
    }
}

fn json_only_subparser() -> Parser {
    Parser {
        actions: vec![ParserAction {
            dest: "json".to_string(),
            choices: None,
            option_strings: vec!["--json".to_string()],
            subparsers: None,
        }],
    }
}

fn no_format_subparser() -> Parser {
    Parser {
        actions: vec![ParserAction {
            dest: "policy".to_string(),
            choices: Some(vec!["conservative".to_string()]),
            option_strings: vec!["--policy".to_string()],
            subparsers: None,
        }],
    }
}

fn cli_args_from_object(fields: &[(String, JsonValue)]) -> CliArgs {
    let mut args = CliArgs::new();
    for (name, value) in fields {
        args = args.with(name.clone(), json_to_arg_value(value));
    }
    args
}

fn env_pairs(fields: &[(String, JsonValue)]) -> Vec<(&str, &str)> {
    fields
        .iter()
        .filter_map(|(name, value)| match value {
            JsonValue::Str(text) => Some((name.as_str(), text.as_str())),
            _ => None,
        })
        .collect()
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

fn json_to_setting_value(value: &JsonValue) -> SettingValue {
    match value {
        JsonValue::Null => SettingValue::None,
        JsonValue::Bool(flag) => SettingValue::Bool(*flag),
        JsonValue::Str(text) => SettingValue::Str(text.clone()),
        JsonValue::Number(num) => SettingValue::Int(num.parse().expect("int setting")),
        _ => panic!("unsupported setting value json"),
    }
}

fn assert_arg_matches_json(actual: &ArgValue, expected: &JsonValue, case_id: &str) {
    match (actual, expected) {
        (ArgValue::Bool(left), JsonValue::Bool(right)) => {
            assert_eq!(left, right, "bool value for {case_id}");
        }
        (ArgValue::Str(left), JsonValue::Str(right)) => {
            assert_eq!(left, right, "str value for {case_id}");
        }
        (ArgValue::Int(left), JsonValue::Number(right)) => {
            assert_eq!(
                *left,
                right.parse::<i64>().expect("int"),
                "int for {case_id}"
            );
        }
        _ => panic!("type mismatch for {case_id}"),
    }
}

fn optional_string_field_obj(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Null) | None => None,
        Some(JsonValue::Str(text)) => Some(text.clone()),
        _ => panic!("{key} must be null or string"),
    }
}

#[test]
fn context_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let cases = parse_document(&raw).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
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

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Null) | None => None,
        Some(JsonValue::Str(text)) => Some(text.clone()),
        _ => panic!("{key} must be null or string"),
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
