//! Byte-exact parity for `sesslint.cli._output` against pinned Python vectors.

use cli::output::{
    boundaries, emit_text, guard_destination, preflight_report_outputs, ArgValue, OutputArgs,
    OutputContext,
};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VECTORS_REL: &str = "../../parity/vectors/cli._output/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 8;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sesslint-cli-output-parity-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create sandbox");
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn apply_setup(name: &str, root: &Path) {
    match name {
        "minimal_source" => {
            fs::write(root.join("source.jsonl"), b"synthetic-source\n").expect("write source");
        }
        "sessions_artifact" => {
            let sessions = root.join("sessions");
            fs::create_dir_all(&sessions).expect("mkdir sessions");
            fs::write(sessions.join("artifact.json"), b"synthetic-artifact\n")
                .expect("write artifact");
        }
        "sessions_source" => {
            let sessions = root.join("sessions");
            fs::create_dir_all(&sessions).expect("mkdir sessions");
            fs::write(sessions.join("source.jsonl"), b"synthetic-source\n").expect("write source");
        }
        "source_and_hardlink" => {
            let source = root.join("source.jsonl");
            fs::write(&source, b"synthetic-source\n").expect("write source");
            let alias = root.join("alias.jsonl");
            fs::hard_link(&source, &alias).expect("hard link for alias parity vector");
        }
        other => panic!("unknown setup {other}"),
    }
}

fn rel_paths(root: &Path, names: &[String]) -> Vec<PathBuf> {
    names.iter().map(|name| root.join(name)).collect()
}

fn path_display_list(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string())
        })
        .collect()
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "guard_destination" => assert_guard(case),
        "preflight_report_outputs" => assert_preflight(case),
        "emit_text" => assert_emit_text(case),
        "boundaries" => assert_boundaries(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_guard(case: &VectorCase) {
    let setup = string_field(&case.construct, "setup").expect("setup");
    let destination = string_field(&case.construct, "destination").expect("destination");
    let files = string_list_field(&case.construct, "files").expect("files");
    let roots = string_list_field(&case.construct, "roots").expect("roots");
    let sandbox = Sandbox::new(&case.id);
    apply_setup(&setup, sandbox.path());
    let dest = sandbox.path().join(&destination);
    let file_paths = rel_paths(sandbox.path(), &files);
    let root_paths = rel_paths(sandbox.path(), &roots);

    let result = guard_destination(&dest, &file_paths, &root_paths);
    match string_field(&case.expected, "result")
        .expect("result")
        .as_str()
    {
        "error" => {
            let error = result.expect_err(&format!("expected guard error for {}", case.id));
            assert_eq!(
                error.to_string(),
                string_field(&case.expected, "display").expect("display"),
                "display mismatch for {}",
                case.id
            );
            assert_eq!(
                error.exit_code(),
                i32_field(&case.expected, "exit_code").expect("exit_code"),
                "exit_code mismatch for {}",
                case.id
            );
        }
        other => panic!("unexpected expected result {other} for {}", case.id),
    }
}

fn assert_preflight(case: &VectorCase) {
    let setup = string_field(&case.construct, "setup").expect("setup");
    let command = string_field(&case.construct, "command").expect("command");
    let sandbox = Sandbox::new(&case.id);
    apply_setup(&setup, sandbox.path());

    let mut args = OutputArgs {
        command,
        ..OutputArgs::default()
    };
    if let Some(path) = optional_string_field(&case.construct, "path").expect("path parse") {
        args.path = Some(ArgValue::One(sandbox.path().join(path)));
    }
    if let Some(output) = optional_string_field(&case.construct, "output").expect("output parse") {
        args.output = Some(sandbox.path().join(output));
    }

    let result = preflight_report_outputs(&OutputContext::default(), &args);
    match string_field(&case.expected, "result")
        .expect("result")
        .as_str()
    {
        "ok" => {
            result.unwrap_or_else(|err| panic!("expected ok for {}: {err}", case.id));
        }
        "error" => {
            let error = result.expect_err(&format!("expected preflight error for {}", case.id));
            assert_eq!(
                error.to_string(),
                string_field(&case.expected, "display").expect("display"),
                "display mismatch for {}",
                case.id
            );
            assert_eq!(
                error.exit_code(),
                i32_field(&case.expected, "exit_code").expect("exit_code"),
                "exit_code mismatch for {}",
                case.id
            );
        }
        other => panic!("unexpected expected result {other} for {}", case.id),
    }
}

fn assert_emit_text(case: &VectorCase) {
    let text = string_field(&case.construct, "text").expect("text");
    let summary = string_field(&case.construct, "summary").expect("summary");
    let command = string_field(&case.construct, "command").expect("command");
    let args = OutputArgs {
        command,
        ..OutputArgs::default()
    };
    let printed = emit_text(&OutputContext::default(), &args, &text, &[], &summary)
        .unwrap_or_else(|err| panic!("unexpected emit_text error for {}: {err}", case.id));
    assert_eq!(
        printed,
        string_field(&case.expected, "text").expect("text"),
        "stdout payload mismatch for {}",
        case.id
    );
}

fn assert_boundaries(case: &VectorCase) {
    let command = string_field(&case.construct, "command").expect("command");
    let a = string_field(&case.construct, "a").expect("a");
    let b = string_field(&case.construct, "b").expect("b");
    let args = OutputArgs {
        command,
        a: Some(ArgValue::One(PathBuf::from(a))),
        b: Some(ArgValue::One(PathBuf::from(b))),
        ..OutputArgs::default()
    };
    let (files, roots) = boundaries(&OutputContext::default(), &args, &[])
        .unwrap_or_else(|err| panic!("unexpected boundaries error for {}: {err}", case.id));
    assert_eq!(
        path_display_list(&files),
        string_list_field(&case.expected, "files").expect("files"),
        "files mismatch for {}",
        case.id
    );
    assert!(
        roots.is_empty(),
        "roots must be empty for {} (got {:?})",
        case.id,
        roots
    );
}

#[test]
fn cli_output_module_parity_vectors() {
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

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
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
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string when present"),
        }),
    }
}

fn string_list_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    let JsonValue::Array(items) = &value.1 else {
        return Err(ParseError {
            message: format!("{key} must be array"),
        });
    };
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} items must be strings"),
            }),
        })
        .collect()
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
