//! Parity for `sesslint.cli._registry` against pinned Python vectors.
//!
//! `Command::configure` and `Command::run` are documented in `known_parity_gaps`
//! (`GAP-registry-configure-run`); vectors do not assert argparse callable behavior.

use cli::registry::{
    build_dispatch, import_cli_context, Command, Dispatch, RegistryError,
    CLI_CONTEXT_UNAVAILABLE, COMMANDS, REMOVED_COMMANDS, REMOVED_FLAGS,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli._registry/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/cli._registry/PROVENANCE.json";
const COVERAGE_REL: &str = "../../parity/vectors/cli._registry/coverage.json";
const REGISTRY_RS_REL: &str = "src/registry.rs";

const EXPECTED_VECTOR_COUNT: usize = 7;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.cli._registry";
const EXPECTED_PYTHON_COMMIT: &str = "02694d537104659df66cdd084354739f3cccc440";
const EXPECTED_REGISTRY_PY_SHA256: &str =
    "2910fc1fe92693f6fdab90743013798b03c8e0c78e218d5ca765446c4a6f0099";
const EXPECTED_REGISTRY_RS_SHA256: &str =
    "5fa161ff1d3778e28fffadf3e713c5a908fa8be57ee03891f712d6daac987024";
const EXPECTED_VECTORS_SHA256: &str =
    "e1b28d2172dea9ce1c9e19801dae8af030f25fd60d4f47032825d7d60fd828a5";

const GAP_CONFIGURE_RUN: &str = "GAP-registry-configure-run";

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

fn registry_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(REGISTRY_RS_REL)
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

#[test]
fn registry_module_parity_vectors() {
    assert_registry_rs_unchanged();

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
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, GAP_CONFIGURE_RUN)),
        "PROVENANCE must document {GAP_CONFIGURE_RUN}"
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

fn assert_registry_rs_unchanged() {
    let path = registry_rs_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        EXPECTED_REGISTRY_RS_SHA256,
        "registry.rs sha256 must stay pinned"
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
        string_field(meta, "registry_py_sha256").expect("registry_py_sha256"),
        EXPECTED_REGISTRY_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "registry_rs_sha256").expect("registry_rs_sha256"),
        EXPECTED_REGISTRY_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter().any(|item| gap_contains(item, GAP_CONFIGURE_RUN)),
        "vectors.json must list {GAP_CONFIGURE_RUN}"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "commands" => assert_commands(case),
        "removed_commands" => assert_removed_commands(case),
        "removed_flags" => assert_removed_flags(case),
        "build_dispatch" => assert_build_dispatch(case),
        "dispatch_lookup" => assert_dispatch_lookup(case),
        "dispatch_duplicate" => assert_dispatch_duplicate(case),
        "import_cli_context" => assert_import_cli_context(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_commands(case: &VectorCase) {
    let rows = array_field(&case.expected, "rows").expect("rows");
    assert_eq!(rows.len(), COMMANDS.len(), "row count for {}", case.id);
    for (index, row) in rows.iter().enumerate() {
        let obj = as_object(row, "row").expect("row object");
        let name = string_field(obj, "name").expect("name");
        let aliases = string_list_field(obj, "aliases").expect("aliases");
        let command = &COMMANDS[index];
        assert_eq!(command.name, name.as_str(), "name row {index} for {}", case.id);
        assert_eq!(command.aliases.len(), aliases.len(), "alias len {index} for {}", case.id);
        for (alias_index, alias) in command.aliases.iter().enumerate() {
            assert_eq!(
                *alias,
                aliases[alias_index].as_str(),
                "alias {alias_index} row {index} for {}",
                case.id
            );
        }
    }
}

fn assert_removed_commands(case: &VectorCase) {
    let rows = array_field(&case.expected, "entries").expect("entries");
    assert_eq!(
        rows.len(),
        REMOVED_COMMANDS.len(),
        "entries len for {}",
        case.id
    );
    for (index, row) in rows.iter().enumerate() {
        let obj = as_object(row, "entry").expect("entry");
        let key = string_field(obj, "key").expect("key");
        let text = string_field(obj, "text").expect("text");
        let (rust_key, rust_text) = REMOVED_COMMANDS[index];
        assert_eq!(rust_key, key.as_str(), "key row {index} for {}", case.id);
        assert_eq!(rust_text, text.as_str(), "text row {index} for {}", case.id);
    }
}

fn assert_removed_flags(case: &VectorCase) {
    let rows = array_field(&case.expected, "entries").expect("entries");
    assert_eq!(rows.len(), REMOVED_FLAGS.len(), "entries len for {}", case.id);
    for (index, row) in rows.iter().enumerate() {
        let obj = as_object(row, "entry").expect("entry");
        let key = string_field(obj, "key").expect("key");
        let text = string_field(obj, "text").expect("text");
        let (rust_key, rust_text) = REMOVED_FLAGS[index];
        assert_eq!(rust_key, key.as_str(), "key row {index} for {}", case.id);
        assert_eq!(rust_text, text.as_str(), "text row {index} for {}", case.id);
    }
}

fn assert_build_dispatch(case: &VectorCase) {
    let dispatch = build_dispatch();
    let keys = string_list_field(&case.expected, "keys").expect("keys");
    let actual_keys: Vec<String> = dispatch.iter().map(|(key, _)| key.to_string()).collect();
    assert_eq!(actual_keys, keys, "keys for {}", case.id);
    assert_eq!(
        dispatch.len(),
        usize_field(&case.expected, "len").expect("len") as usize,
        "len for {}",
        case.id
    );
    let pairs = array_field(&case.expected, "pairs").expect("pairs");
    assert_eq!(
        dispatch_pairs(&dispatch),
        parse_pair_rows(pairs),
        "pairs for {}",
        case.id
    );
    assert_eq!(dispatch, build_dispatch(), "deterministic for {}", case.id);
}

fn assert_dispatch_lookup(case: &VectorCase) {
    let dispatch = build_dispatch();
    let missing = string_field(&case.construct, "missing_key").expect("missing_key");
    let expected_check = string_field(&case.expected, "check_name").expect("check_name");
    let expected_scan = string_field(&case.expected, "scan_name").expect("scan_name");
    let missing_present = bool_field(&case.expected, "missing_present").expect("missing_present");

    assert_eq!(
        dispatch.get("check").map(|c| c.name),
        Some(expected_check.as_str()),
        "check for {}",
        case.id
    );
    assert_eq!(
        dispatch.get("scan").map(|c| c.name),
        Some(expected_scan.as_str()),
        "scan for {}",
        case.id
    );
    assert_eq!(
        dispatch.get(&missing).is_some(),
        missing_present,
        "missing lookup for {}",
        case.id
    );
}

fn assert_dispatch_duplicate(case: &VectorCase) {
    let first = Command::new("synthetic-keep", &[]);
    let second = Command::new("synthetic-next", &["synthetic-keep", "synthetic-tail"]);
    let pairs_expected = parse_pair_rows(array_field(&case.expected, "pairs").expect("pairs"));
    let actual = dispatch_pairs_for_commands(&[first, second]);
    assert_eq!(actual, pairs_expected, "pairs for {}", case.id);
    assert_eq!(
        actual.len(),
        usize_field(&case.expected, "len").expect("len") as usize,
        "len for {}",
        case.id
    );
}

fn assert_import_cli_context(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "unsupported",
        "mode for {}",
        case.id
    );
    let want = string_field(&case.expected, "message").expect("message");
    match import_cli_context() {
        Err(RegistryError::Unsupported(message)) => {
            assert_eq!(message, want.as_str(), "message for {}", case.id);
            assert_eq!(message, CLI_CONTEXT_UNAVAILABLE);
        }
        Ok(ok) => match ok {},
    }
}

/// Mirrors `registry::dispatch_from` / `insert_dispatch_key` for synthetic vectors only.
fn dispatch_pairs_for_commands(commands: &[Command]) -> Vec<(String, String)> {
    let mut entries: Vec<(&'static str, Command)> = Vec::new();
    for command in commands {
        insert_dispatch_key(&mut entries, command.name, *command);
        for alias in command.aliases {
            insert_dispatch_key(&mut entries, alias, *command);
        }
    }
    entries
        .iter()
        .map(|(key, command)| (key.to_string(), command.name.to_string()))
        .collect()
}

fn insert_dispatch_key(
    entries: &mut Vec<(&'static str, Command)>,
    key: &'static str,
    command: Command,
) {
    if let Some(slot) = entries.iter_mut().find(|(existing, _)| *existing == key) {
        slot.1 = command;
        return;
    }
    entries.push((key, command));
}

fn dispatch_pairs(dispatch: &Dispatch) -> Vec<(String, String)> {
    dispatch
        .iter()
        .map(|(key, command)| (key.to_string(), command.name.to_string()))
        .collect()
}

fn parse_pair_rows(rows: &[JsonValue]) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let obj = as_object(row, "pair").expect("pair object");
        let key = string_field(obj, "key").expect("key");
        let canonical = string_field(obj, "canonical").expect("canonical");
        out.push((key, canonical));
    }
    out
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
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    Ok(i64_field(obj, key)? as usize)
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
