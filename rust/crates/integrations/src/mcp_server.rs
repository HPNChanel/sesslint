//! MCP stdio server (integrations T-01), Python `mcp_server.py`
//! @ 02694d537104659df66cdd084354739f3cccc440 lines 1–374.
//!
//! Typed JSON domain: Unicode scalar strings, finite f64, i64/u64 numbers.
//! Serialization is bounded to 128 containers; Python arbitrary integers,
//! nonfinite floats, lone surrogates and deeper trees are not represented.
//! Unported API/precheck imports return typed Unsupported, never fake success.

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use codec::canonical_codec::{CanonicalCodec, PurePythonCanonicalCodec, Value as CodecValue};
use serde_json::{json, Map, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const SERVER_NAME: &str = "sesslint";
pub const MAX_MCP_LINE_BYTES: usize = 1_048_576;
pub const E_PARSE: i64 = -32700;
pub const E_INVALID_REQUEST: i64 = -32600;
pub const E_METHOD_NOT_FOUND: i64 = -32601;
pub const E_INVALID_PARAMS: i64 = -32602;
pub const E_INTERNAL: i64 = -32603;
pub const FORMATS: [&str; 5] = [
    "auto",
    "claude-code-jsonl",
    "openai-agents",
    "codex-rollout",
    "canonical",
];
pub const TOOL_NAMES: [&str; 3] = ["sesslint_check", "sesslint_precheck", "sesslint_scan"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpError {
    Unsupported(&'static str),
    Serialization,
    /// Python path.exists() errors occur outside the tool exception handler.
    PathIo,
}

impl fmt::Display for McpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported(message) => message,
            Self::Serialization => "MCP JSON serialization outside supported domain",
            Self::PathIo => "MCP path existence check failed",
        })
    }
}
impl std::error::Error for McpError {}

pub fn profiles() -> Vec<String> {
    let mut names: Vec<_> = checks::builtin::REGISTRY
        .entries()
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    names.sort();
    names
}

pub fn server_info() -> Value {
    json!({"name": SERVER_NAME, "version": model::version::CLI_VERSION})
}

pub fn tools() -> Vec<Value> {
    TOOL_NAMES.iter().map(|name| {
        let (title, description) = match *name {
            "sesslint_check" => ("Check session integrity", "Run the full SessLint check on one session file and return the sesslint.report/v1 report as structured content. Read-only; findings are results, not errors."),
            "sesslint_precheck" => ("Zero-exception integrity gate", "Run the one-call precheck gate on one session file: returns {ok, reason, exit_code} plus the report when available. Read-only; never raises."),
            _ => ("Scan a session tree", "Aggregate scan of a session file or directory tree: 5-bucket totals (healthy/invalid/undetected/unreadable/skipped) and per-file verdict counts. Read-only."),
        };
        let mut properties = json!({
            "path": {"type": "string", "description": if *name == "sesslint_scan" {"Session file or directory path."} else {"Session file path."}},
            "profile": {"type": "string", "enum": profiles(), "description": "Validation profile (default: neutral)."},
            "format": {"type": "string", "enum": FORMATS, "description": "Force input adapter (default: auto-detect)."}
        });
        if *name == "sesslint_scan" {
            properties["recursive"] = json!({"type": "boolean", "description": "Recurse into directories (default: true)."});
        }
        json!({"name": name, "title": title, "description": description,
            "inputSchema": {"type": "object", "properties": properties, "required": ["path"], "additionalProperties": false}})
    }).collect()
}

pub fn result(request_id: Value, payload: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": request_id, "result": payload})
}
pub fn error(request_id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})
}

/// Python json.dumps(sort_keys=True): ASCII escapes and default separators.
pub fn python_json(value: &Value) -> Result<String, McpError> {
    fn string(text: &str, out: &mut String) {
        out.push('"');
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0c}' => out.push_str("\\f"),
                ' '..='~' => out.push(ch),
                _ => {
                    for unit in ch.encode_utf16(&mut [0; 2]) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
        }
        out.push('"');
    }
    fn encode(value: &Value, out: &mut String, depth: usize) -> Result<(), McpError> {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::String(s) => string(s, out),
            Value::Number(n) => {
                if n.is_f64() {
                    let f = n.as_f64().ok_or(McpError::Serialization)?;
                    let bytes = PurePythonCanonicalCodec::new()
                        .canonical_json_bytes(&CodecValue::float(f), false)
                        .map_err(|_| McpError::Serialization)?;
                    out.push_str(std::str::from_utf8(&bytes).map_err(|_| McpError::Serialization)?);
                } else {
                    out.push_str(&n.to_string());
                }
            }
            Value::Array(items) => {
                if depth >= 128 {
                    return Err(McpError::Serialization);
                }
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push_str(", ");
                    }
                    encode(item, out, depth + 1)?;
                }
                out.push(']');
            }
            Value::Object(items) => {
                if depth >= 128 {
                    return Err(McpError::Serialization);
                }
                out.push('{');
                let mut entries: Vec<_> = items.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for (i, (key, item)) in entries.into_iter().enumerate() {
                    if i != 0 {
                        out.push_str(", ");
                    }
                    string(key, out);
                    out.push_str(": ");
                    encode(item, out, depth + 1)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    encode(value, &mut out, 0)?;
    Ok(out)
}

pub fn tool_ok(payload: Map<String, Value>) -> Result<Value, McpError> {
    let payload = Value::Object(payload);
    Ok(
        json!({"content": [{"type": "text", "text": python_json(&payload)?}],
        "structuredContent": payload, "isError": false}),
    )
}
pub fn tool_err(reason: &str) -> Value {
    json!({"content": [{"type": "text", "text": reason}], "isError": true})
}

/// Validated arguments cannot be constructed without the ordered checks.
#[derive(Debug, Clone, PartialEq)]
pub struct Arguments {
    raw: Map<String, Value>,
}
impl Arguments {
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.raw
    }
}

pub fn validate_args(tool: &str, arguments: &Value) -> Result<Arguments, String> {
    // Unknown-tool lookup is guarded by dispatch in Python; expose a typed error.
    if !TOOL_NAMES.contains(&tool) {
        return Err("unknown tool".into());
    }
    let empty = Map::new();
    let args = if arguments.is_null() {
        &empty
    } else {
        arguments.as_object().ok_or("arguments must be an object")?
    };
    let mut unknown: Vec<_> = args
        .keys()
        .filter(|key| {
            !(["path", "profile", "format"].contains(&key.as_str())
                || tool == "sesslint_scan" && key.as_str() == "recursive")
        })
        .cloned()
        .collect();
    unknown.sort();
    if !unknown.is_empty() {
        return Err(format!("unknown argument(s): {}", unknown.join(",")));
    }
    if args
        .get("path")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("path is required and must be a string".into());
    }
    if let Some(p) = args.get("profile").filter(|p| !p.is_null()) {
        if p.as_str()
            .is_none_or(|p| checks::builtin::REGISTRY.get(p).is_none())
        {
            return Err(format!("profile must be one of: {}", profiles().join(",")));
        }
    }
    if let Some(f) = args.get("format").filter(|f| !f.is_null()) {
        if !f.as_str().is_some_and(|f| FORMATS.contains(&f)) {
            return Err(format!("format must be one of: {}", FORMATS.join(",")));
        }
    }
    if let Some(r) = args.get("recursive").filter(|r| !r.is_null()) {
        if !r.is_boolean() {
            return Err("recursive must be a boolean".into());
        }
    }
    Ok(Arguments { raw: args.clone() })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolFailure {
    Io,
    Usage,
    Internal,
    Unsupported(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolRequest {
    pub path: PathBuf,
    pub profile: String,
    pub format: Option<String>,
    /// None means explicit JSON null; omission means Some(true).
    pub recursive: Option<bool>,
    pub skip_undetected: bool,
}
#[derive(Debug, Clone, PartialEq)]
pub struct PrecheckResult {
    pub ok: bool,
    pub reason: Value,
    pub exit_code: i64,
    pub report: Option<Map<String, Value>>,
}

/// Late-import seam. Production implementations must return content-free reports.
pub trait ToolBackend {
    fn check_file(&self, _request: &ToolRequest) -> Result<Map<String, Value>, ToolFailure> {
        Err(ToolFailure::Unsupported(
            "sesslint.api.check_file is not available",
        ))
    }
    fn precheck(&self, _request: &ToolRequest) -> Result<PrecheckResult, ToolFailure> {
        Err(ToolFailure::Unsupported(
            "sesslint.precheck.precheck is not available",
        ))
    }
    fn check_dir(&self, _request: &ToolRequest) -> Result<Map<String, Value>, ToolFailure> {
        Err(ToolFailure::Unsupported(
            "sesslint.api.check_dir is not available",
        ))
    }
}
pub struct UnavailableBackend;
impl ToolBackend for UnavailableBackend {}

// Linux/Android and Apple/BSD are the supported Unix errno layouts here.
// Other targets fail closed on an unknown raw errno rather than guessing.
const UNIX_ELOOP: Option<i32> = if cfg!(any(target_os = "linux", target_os = "android")) {
    Some(40)
} else if cfg!(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)) {
    Some(62)
} else {
    None
};

fn ignored_raw_error(code: i32, windows: bool, unix_eloop: Option<i32>) -> bool {
    if windows {
        matches!(
            code,
            2 | 3 | 6 | 15 | 18 | 21 | 53 | 67 | 123 | 161 | 206 | 267 | 1921
        )
    } else {
        matches!(code, 2 | 9 | 20) || unix_eloop == Some(code)
    }
}

fn metadata(path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e)
            if e.raw_os_error()
                .is_some_and(|code| ignored_raw_error(code, cfg!(windows), UNIX_ELOOP)) =>
        {
            Ok(None)
        }
        // Rust rejects an interior NUL before the OS call, as pathlib's ValueError.
        Err(e) if e.raw_os_error().is_none() && e.kind() == std::io::ErrorKind::InvalidInput => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn python_path(text: &str) -> PathBuf {
    // Pathlib removes redundant separators and dot components, but retains '..'.
    let path: PathBuf = Path::new(text)
        .components()
        .filter(|part| !matches!(part, std::path::Component::CurDir))
        .collect();
    if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path
    }
}

pub fn call_tool(name: &str, arguments: &Arguments) -> Result<Value, McpError> {
    call_tool_with(name, arguments, &UnavailableBackend)
}
pub fn call_tool_with(
    name: &str,
    arguments: &Arguments,
    backend: &dyn ToolBackend,
) -> Result<Value, McpError> {
    let args = &arguments.raw;
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or(McpError::Serialization)?;
    let request = ToolRequest {
        path: python_path(path),
        profile: args
            .get("profile")
            .and_then(Value::as_str)
            .unwrap_or("neutral")
            .into(),
        format: args
            .get("format")
            .and_then(Value::as_str)
            .filter(|f| *f != "auto")
            .map(str::to_owned),
        recursive: args.get("recursive").map_or(Some(true), Value::as_bool),
        skip_undetected: true,
    };
    if metadata(&request.path)
        .map_err(|_| McpError::PathIo)?
        .is_none()
    {
        return Ok(tool_err("io-error: path does not exist"));
    }
    if matches!(name, "sesslint_check" | "sesslint_precheck") {
        match metadata(&request.path) {
            Ok(Some(m)) if m.is_file() => {}
            Ok(_) => return Ok(tool_err("usage-error: path is not a file")),
            Err(_) => return Ok(tool_err("io-error")),
        }
    }
    let outcome = match name {
        "sesslint_check" => backend.check_file(&request),
        "sesslint_scan" => backend.check_dir(&request),
        "sesslint_precheck" => backend.precheck(&request).map(|r| {
            let mut payload = Map::new();
            payload.insert("ok".into(), Value::Bool(r.ok));
            payload.insert("reason".into(), r.reason);
            payload.insert("exit_code".into(), r.exit_code.into());
            if let Some(report) = r.report {
                payload.insert("report".into(), Value::Object(report));
            }
            payload
        }),
        _ => return Ok(tool_err("internal-error: unhandled tool")),
    };
    match outcome {
        Ok(payload) => tool_ok(payload),
        Err(ToolFailure::Io) => Ok(tool_err("io-error")),
        Err(ToolFailure::Usage) => Ok(tool_err("usage-error")),
        Err(ToolFailure::Internal) => Ok(tool_err("internal-error")),
        Err(ToolFailure::Unsupported(reason)) => Err(McpError::Unsupported(reason)),
    }
}

pub fn dispatch(message: &Value) -> Result<Option<Value>, McpError> {
    dispatch_with(message, &UnavailableBackend)
}
pub fn dispatch_with(
    message: &Value,
    backend: &dyn ToolBackend,
) -> Result<Option<Value>, McpError> {
    let Some(msg) = message.as_object() else {
        return Ok(None);
    };
    if msg.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Ok(None);
    }
    let has_id = msg.contains_key("id");
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return Ok(has_id.then(|| error(id, E_INVALID_REQUEST, "missing method")));
    };
    if !has_id {
        return Ok(None);
    }
    let response = match method {
        "initialize" => result(
            id,
            json!({"protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": false}}, "serverInfo": server_info()}),
        ),
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({"tools": tools()})),
        "tools/call" => {
            let Some(params) = msg.get("params").and_then(Value::as_object) else {
                return Ok(Some(error(
                    id,
                    E_INVALID_PARAMS,
                    "params must be an object",
                )));
            };
            let Some(name) = params
                .get("name")
                .and_then(Value::as_str)
                .filter(|n| TOOL_NAMES.contains(n))
            else {
                return Ok(Some(error(id, E_INVALID_PARAMS, "unknown tool")));
            };
            match validate_args(name, params.get("arguments").unwrap_or(&Value::Null)) {
                Err(message) => error(id, E_INVALID_PARAMS, &message),
                Ok(args) => result(id, call_tool_with(name, &args, backend)?),
            }
        }
        _ if method.starts_with("notifications/") => return Ok(None),
        _ => error(id, E_METHOD_NOT_FOUND, "method not found"),
    };
    Ok(Some(response))
}

// A nonrecursive syntax pass prevents serde's recursion limit or numeric conversion
// from misclassifying a valid Python JSON value as a protocol parse error.
fn checked_json(raw: &str) -> Result<Option<Value>, McpError> {
    #[derive(Clone, Copy)]
    enum State {
        Root,
        End,
        ArrayFirst,
        ArrayValue,
        ArrayComma,
        ObjectFirst,
        ObjectKey,
        Colon,
        ObjectValue,
        ObjectComma,
    }
    let b = raw.as_bytes();
    let mut normalized = b.to_vec();
    let mut states = vec![State::Root];
    let mut i = 0;
    let mut unsupported = false;
    while let Some(state) = states.pop() {
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        match state {
            State::End => {
                if i != b.len() {
                    return Ok(None);
                }
            }
            State::ArrayFirst if b.get(i) == Some(&b']') => {
                i += 1;
            }
            State::ArrayFirst | State::ArrayValue => {
                states.push(State::ArrayComma);
                states.push(State::Root);
            }
            State::ArrayComma => match b.get(i) {
                Some(b']') => i += 1,
                Some(b',') => {
                    i += 1;
                    states.push(State::ArrayValue);
                }
                _ => return Ok(None),
            },
            State::ObjectFirst if b.get(i) == Some(&b'}') => {
                i += 1;
            }
            State::ObjectFirst | State::ObjectKey => {
                if b.get(i) != Some(&b'"') {
                    return Ok(None);
                }
                states.push(State::Colon);
                states.push(State::Root);
            }
            State::Colon => {
                if b.get(i) != Some(&b':') {
                    return Ok(None);
                }
                i += 1;
                states.push(State::ObjectValue);
            }
            State::ObjectValue => {
                states.push(State::ObjectComma);
                states.push(State::Root);
            }
            State::ObjectComma => match b.get(i) {
                Some(b'}') => i += 1,
                Some(b',') => {
                    i += 1;
                    states.push(State::ObjectKey);
                }
                _ => return Ok(None),
            },
            State::Root => {
                match b.get(i) {
                    Some(b'[') => {
                        i += 1;
                        states.push(State::ArrayFirst);
                        if states.len() > 128 {
                            unsupported = true;
                        }
                    }
                    Some(b'{') => {
                        i += 1;
                        states.push(State::ObjectFirst);
                        if states.len() > 128 {
                            unsupported = true;
                        }
                    }
                    Some(b'"') => {
                        let start = i;
                        i += 1;
                        loop {
                            match b.get(i) {
                                None => return Ok(None),
                                Some(b'"') => {
                                    i += 1;
                                    break;
                                }
                                Some(0..=31) => return Ok(None),
                                Some(b'\\') => {
                                    i += 1;
                                    match b.get(i) {
                                        Some(
                                            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't',
                                        ) => i += 1,
                                        Some(b'u') => {
                                            i += 1;
                                            if i + 4 > b.len()
                                                || !b[i..i + 4].iter().all(u8::is_ascii_hexdigit)
                                            {
                                                return Ok(None);
                                            }
                                            i += 4;
                                        }
                                        _ => return Ok(None),
                                    }
                                }
                                Some(_) => i += 1,
                            }
                        }
                        if serde_json::from_slice::<String>(&b[start..i]).is_err() {
                            unsupported = true;
                        }
                    }
                    Some(_) => {
                        let start = i;
                        while i < b.len()
                            && !matches!(
                                b[i],
                                b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}' | b':'
                            )
                        {
                            i += 1;
                        }
                        if i == start {
                            return Ok(None);
                        }
                        let token = &raw[start..i];
                        if matches!(token, "NaN" | "Infinity" | "-Infinity") {
                            unsupported = true;
                        } else if matches!(token, "true" | "false" | "null") {
                        } else {
                            // Validate the complete number grammar without converting it.
                            let n = token.as_bytes();
                            let mut j = usize::from(n.first() == Some(&b'-'));
                            if n.get(j) == Some(&b'0') {
                                j += 1;
                            } else {
                                let begin = j;
                                while matches!(n.get(j), Some(b'0'..=b'9')) {
                                    j += 1;
                                }
                                if j == begin {
                                    return Ok(None);
                                }
                            }
                            let mut float = false;
                            if n.get(j) == Some(&b'.') {
                                float = true;
                                j += 1;
                                let begin = j;
                                while matches!(n.get(j), Some(b'0'..=b'9')) {
                                    j += 1;
                                }
                                if j == begin {
                                    return Ok(None);
                                }
                            }
                            if matches!(n.get(j), Some(b'e' | b'E')) {
                                float = true;
                                j += 1;
                                if matches!(n.get(j), Some(b'+' | b'-')) {
                                    j += 1;
                                }
                                let begin = j;
                                while matches!(n.get(j), Some(b'0'..=b'9')) {
                                    j += 1;
                                }
                                if j == begin {
                                    return Ok(None);
                                }
                            }
                            if j != n.len() {
                                return Ok(None);
                            }
                            if float {
                                if token.parse::<f64>().map_or(true, |x| !x.is_finite()) {
                                    unsupported = true;
                                }
                            } else if token.starts_with('-') {
                                if token.parse::<i64>().is_err() {
                                    unsupported = true;
                                }
                            } else if token.parse::<u64>().is_err() {
                                unsupported = true;
                            }
                            if token == "-0" {
                                normalized[start] = b' ';
                            }
                        }
                    }
                    None => return Ok(None),
                }
            }
        }
        if states.is_empty() && !matches!(state, State::End) {
            states.push(State::End);
        }
    }
    if unsupported {
        return Err(McpError::Unsupported(
            "MCP JSON value outside supported domain",
        ));
    }
    match serde_json::from_slice(&normalized) {
        Ok(value) => Ok(Some(value)),
        Err(_) => Err(McpError::Unsupported("MCP JSON exceeds parser domain")),
    }
}

fn parse_error_line() -> Result<Vec<u8>, McpError> {
    Ok(format!(
        "{}\n",
        python_json(&error(Value::Null, E_PARSE, "parse error"))?
    )
    .into_bytes())
}

fn starts_with_json_object(text: &str) -> bool {
    text.bytes()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        == Some(b'{')
}

fn python_recursion_ceiling(text: &str) -> bool {
    let bytes = text.as_bytes();
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(bytes.len());
    let depth = bytes[start..]
        .iter()
        .take_while(|byte| **byte == b'[')
        .count();
    depth >= 1000
}

/// Python `bytes.strip()`: space, tab, LF, CR, VT (`0x0B`), and FF (`0x0C`).
fn python_byte_strip(raw: &[u8]) -> &[u8] {
    let is_space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C);
    let start = raw
        .iter()
        .position(|byte| !is_space(*byte))
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|byte| !is_space(*byte))
        .map_or(start, |index| index.saturating_add(1));
    &raw[start..end]
}

/// Process a physical line. Out-of-domain valid Python JSON returns Unsupported.
pub fn handle_line(raw: &[u8]) -> Result<Option<Vec<u8>>, McpError> {
    if raw.len() > MAX_MCP_LINE_BYTES {
        return Ok(Some(parse_error_line()?));
    }
    let raw = python_byte_strip(raw);
    if raw.is_empty() {
        return Ok(None);
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return Ok(Some(parse_error_line()?));
    };
    let message = match checked_json(text) {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(Some(parse_error_line()?)),
        // `_dispatch` drops every non-object. A document Python accepts and then
        // ignores must not abort `serve`. Nesting that raises RecursionError on
        // CPython 3.11.9 (1000) is still the parse-error line.
        Err(McpError::Unsupported(_)) if !starts_with_json_object(text) => {
            if python_recursion_ceiling(text) {
                return Ok(Some(parse_error_line()?));
            }
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    match dispatch(&message)? {
        Some(response) => Ok(Some(format!("{}\n", python_json(&response)?).into_bytes())),
        None => Ok(None),
    }
}

#[derive(Debug)]
pub enum ServeError {
    Io(io::Error),
    Mcp(McpError),
}
impl From<io::Error> for ServeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<McpError> for ServeError {
    fn from(error: McpError) -> Self {
        Self::Mcp(error)
    }
}

// Read at most limit bytes, stopping at LF; consume only what was copied.
fn read_bounded<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    while out.len() < limit {
        let data = reader.fill_buf()?;
        if data.is_empty() {
            break;
        }
        let available = data.len().min(limit - out.len());
        let count = data[..available]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(available, |p| p + 1);
        let end = data[count - 1] == b'\n';
        out.extend_from_slice(&data[..count]);
        reader.consume(count);
        if end {
            break;
        }
    }
    Ok(out)
}

/// Serve bounded newline-delimited requests until EOF. I/O failures propagate.
pub fn serve<R: BufRead, W: Write>(stdin: &mut R, stdout: &mut W) -> Result<i32, ServeError> {
    loop {
        let mut line = read_bounded(stdin, MAX_MCP_LINE_BYTES + 1)?;
        if line.is_empty() {
            return Ok(0);
        }
        let out = if line.len() > MAX_MCP_LINE_BYTES {
            while !line.is_empty() && !line.ends_with(b"\n") {
                line = read_bounded(stdin, MAX_MCP_LINE_BYTES + 1)?;
            }
            Some(parse_error_line()?)
        } else {
            handle_line(&line)?
        };
        if let Some(bytes) = out {
            stdout.write_all(&bytes)?;
            stdout.flush()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn stdio_json_boundaries_and_protocol() {
        let parse = parse_error_line().unwrap();
        for raw in [
            b"\xff".as_slice(),
            b"\xef\xbb\xbf{}",
            b"[1,]",
            b"01",
            b"{\"x\":}",
            b"[".repeat(2000).as_slice(),
        ] {
            assert_eq!(handle_line(raw).unwrap(), Some(parse.clone()));
        }
        for raw in [
            b"18446744073709551616".as_slice(),
            b"NaN",
            b"Infinity",
            b"-Infinity",
            b"1e9999",
            br#""\ud800""#,
        ] {
            assert_eq!(handle_line(raw).unwrap(), None);
        }
        assert_eq!(
            handle_line(format!("{}0{}", "[".repeat(200), "]".repeat(200)).as_bytes()).unwrap(),
            None
        );
        assert_eq!(handle_line(b" \t\n\r\x0b\x0c").unwrap(), None);
        assert_eq!(handle_line(&vec![b' '; MAX_MCP_LINE_BYTES]).unwrap(), None);
        assert_eq!(
            handle_line(&vec![b' '; MAX_MCP_LINE_BYTES + 1]).unwrap(),
            Some(parse)
        );
        assert_eq!(
            handle_line(br#"{"jsonrpc":"2.0","id":-0,"method":"ping"}"#)
                .unwrap()
                .unwrap(),
            b"{\"id\": 0, \"jsonrpc\": \"2.0\", \"result\": {}}\n"
        );
        assert_eq!(
            handle_line(br#"{"jsonrpc":"2.0","id":1.5,"method":"ping","method":"ping"}"#)
                .unwrap()
                .unwrap(),
            b"{\"id\": 1.5, \"jsonrpc\": \"2.0\", \"result\": {}}\n"
        );
    }

    #[test]
    fn stdio_drains_physical_line_and_skips_notifications() {
        let mut input = vec![b' '; MAX_MCP_LINE_BYTES + 1];
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n");
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"ping\"}\n");
        let mut out = Vec::new();
        assert_eq!(serve(&mut io::Cursor::new(input), &mut out).unwrap(), 0);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("-32700"));
        assert!(text.contains("\"id\": 8"));
        assert!(!text.contains("\"id\": 7"));
    }

    struct FailWriter {
        flush: bool,
    }
    impl Write for FailWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.flush {
                Ok(b.len())
            } else {
                Err(io::Error::other("write"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush"))
        }
    }
    struct FailReader;
    impl io::Read for FailReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read"))
        }
    }
    impl BufRead for FailReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("read"))
        }
        fn consume(&mut self, _: usize) {}
    }
    #[test]
    fn stdio_propagates_io_failures() {
        assert!(matches!(
            serve(&mut FailReader, &mut Vec::new()),
            Err(ServeError::Io(_))
        ));
        for flush in [false, true] {
            let mut input = io::Cursor::new(b"?\n");
            assert!(matches!(
                serve(&mut input, &mut FailWriter { flush }),
                Err(ServeError::Io(_))
            ));
        }
        let mut input = io::Cursor::new(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n");
        assert_eq!(
            serve(&mut input, &mut FailWriter { flush: false }).unwrap(),
            0
        );
    }
    fn file() -> String {
        format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))
    }
    fn directory() -> &'static str {
        env!("CARGO_MANIFEST_DIR")
    }
    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }
    fn request(method: Value, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": null, "method": method, "params": params})
    }

    #[test]
    fn envelopes_preserve_ids_and_tool_error_shape() {
        for id in [
            Value::Null,
            json!(false),
            json!([1, "x"]),
            json!({"a": 2}),
            json!(-3.0),
        ] {
            assert_eq!(result(id.clone(), json!(7))["id"], id);
            assert_eq!(error(id.clone(), -1, "bad")["id"], id);
        }
        assert_eq!(
            tool_err("io-error"),
            json!({"content": [{"type": "text", "text": "io-error"}], "isError": true})
        );
    }

    #[test]
    fn python_text_json_unicode_escaping_floats_and_order() {
        let value = json!({"z": [1.0, -0.0, 1e-7, 1e16, 5e-324], "a": "Việt 😀\n\t\r\u{0c}\u{08}\u{007f}\\\"/"});
        assert_eq!(python_json(&value).unwrap(), "{\"a\": \"Vi\\u1ec7t \\ud83d\\ude00\\n\\t\\r\\f\\b\\u007f\\\\\\\"/\", \"z\": [1.0, -0.0, 1e-07, 1e+16, 5e-324]}");
        let output = tool_ok(object(value.clone())).unwrap();
        assert_eq!(output["structuredContent"], value);
        assert_eq!(output["content"][0]["text"], python_json(&value).unwrap());
        assert_eq!(output["isError"], false);
    }

    #[test]
    fn serialization_depth_is_explicit() {
        let mut tree = Value::Null;
        for _ in 0..128 {
            tree = Value::Array(vec![tree]);
        }
        assert!(python_json(&tree).is_ok());
        tree = Value::Array(vec![tree]);
        assert_eq!(python_json(&tree), Err(McpError::Serialization));
    }

    #[test]
    fn validation_order_and_types() {
        let cases = [
            (json!([]), "arguments must be an object"),
            (json!({"z": 0, "a": 0}), "unknown argument(s): a,z"),
            (json!(null), "path is required and must be a string"),
            (json!({"path": ""}), "path is required and must be a string"),
            (json!({"path": true}), "path is required and must be a string"),
            (json!({"path": "x", "profile": false, "format": "bad"}), "profile must be one of: claude-strict,neutral,openai-strict"),
            (json!({"path": "x", "format": 0, "recursive": 1}), "format must be one of: auto,claude-code-jsonl,openai-agents,codex-rollout,canonical"),
            (json!({"path": "x", "recursive": 1}), "recursive must be a boolean"),
        ];
        for (args, expected) in cases {
            assert_eq!(validate_args("sesslint_scan", &args).unwrap_err(), expected);
        }
        for tool in TOOL_NAMES {
            for profile in profiles() {
                for format in FORMATS {
                    let args = json!({"path":" ", "profile": profile, "format": format});
                    assert_eq!(
                        validate_args(tool, &args).unwrap().as_map(),
                        args.as_object().unwrap()
                    );
                }
            }
        }
        assert!(validate_args(
            "sesslint_scan",
            &json!({"path":"x", "profile":null, "format":null, "recursive":null})
        )
        .is_ok());
        assert_eq!(
            validate_args("sesslint_check", &json!({"path":"x", "recursive":true})).unwrap_err(),
            "unknown argument(s): recursive"
        );
        assert_eq!(
            validate_args("unknown", &json!({})).unwrap_err(),
            "unknown tool"
        );
    }

    #[test]
    fn dispatch_drops_notifications_and_bad_envelopes() {
        for msg in [
            Value::Null,
            json!([]),
            json!({"id":1,"method":"ping"}),
            json!({"jsonrpc":2.0,"id":1,"method":"ping"}),
        ] {
            assert_eq!(dispatch(&msg), Ok(None));
        }
        for method in [
            Value::Null,
            json!(3),
            json!("ping"),
            json!("initialize"),
            json!("tools/list"),
            json!("tools/call"),
            json!("unknown"),
        ] {
            assert_eq!(
                dispatch(&json!({"jsonrpc":"2.0","method":method})),
                Ok(None)
            );
        }
        assert_eq!(
            dispatch(&request(json!("notifications/whatever"), Value::Null)),
            Ok(None)
        );
        assert_eq!(
            dispatch(&request(json!(4), Value::Null)).unwrap().unwrap(),
            error(Value::Null, E_INVALID_REQUEST, "missing method")
        );
        assert_eq!(
            dispatch(&request(json!("unknown"), Value::Null))
                .unwrap()
                .unwrap(),
            error(Value::Null, E_METHOD_NOT_FOUND, "method not found")
        );
    }

    #[test]
    fn handshake_ping_and_listing() {
        let init = dispatch(&request(json!("initialize"), json!(false)))
            .unwrap()
            .unwrap();
        assert_eq!(
            init["result"],
            json!({"protocolVersion":"2025-06-18","serverInfo":{"name":"sesslint","version":"0.5.0"},"capabilities":{"tools":{"listChanged":false}}})
        );
        assert_eq!(
            dispatch(&request(json!("ping"), Value::Null))
                .unwrap()
                .unwrap(),
            result(Value::Null, json!({}))
        );
        let listed = dispatch(&request(json!("tools/list"), Value::Null))
            .unwrap()
            .unwrap();
        let schemas = listed["result"]["tools"].as_array().unwrap();
        assert_eq!(
            schemas
                .iter()
                .map(|t| t["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            TOOL_NAMES
        );
        assert_eq!(
            schemas[2]["inputSchema"]["properties"]["recursive"]["type"],
            "boolean"
        );
        assert!(schemas[0]["inputSchema"]["properties"]
            .get("recursive")
            .is_none());
        assert_eq!(
            listed,
            dispatch(&request(json!("tools/list"), Value::Null))
                .unwrap()
                .unwrap()
        );
    }

    #[test]
    fn call_protocol_validation_precedes_io() {
        for (params, message) in [
            (Value::Null, "params must be an object"),
            (json!({"name":0}), "unknown tool"),
            (
                json!({"name":"sesslint_check"}),
                "path is required and must be a string",
            ),
            (
                json!({"name":"sesslint_check","arguments":true}),
                "arguments must be an object",
            ),
        ] {
            assert_eq!(
                dispatch(&request(json!("tools/call"), params))
                    .unwrap()
                    .unwrap(),
                error(Value::Null, E_INVALID_PARAMS, message)
            );
        }
    }

    #[test]
    fn missing_path_and_directories_precede_unavailable_import() {
        for tool in TOOL_NAMES {
            let args = validate_args(
                tool,
                &json!({"path":format!("{}/not-present-mcp-synthetic", file())}),
            )
            .unwrap();
            assert_eq!(
                call_tool(tool, &args),
                Ok(tool_err("io-error: path does not exist"))
            );
            let nul = validate_args(tool, &json!({"path":"nul\u{0}path"})).unwrap();
            assert_eq!(
                call_tool(tool, &nul),
                Ok(tool_err("io-error: path does not exist"))
            );
        }
        for tool in ["sesslint_check", "sesslint_precheck"] {
            let args = validate_args(tool, &json!({"path":directory()})).unwrap();
            assert_eq!(
                call_tool(tool, &args),
                Ok(tool_err("usage-error: path is not a file"))
            );
        }
        let args = validate_args("sesslint_scan", &json!({"path":file()})).unwrap();
        for tool in TOOL_NAMES {
            assert!(matches!(
                call_tool(tool, &args),
                Err(McpError::Unsupported(_))
            ));
        }
        assert_eq!(
            call_tool("unknown", &args),
            Ok(tool_err("internal-error: unhandled tool"))
        );
    }

    struct Backend {
        calls: RefCell<Vec<ToolRequest>>,
        failure: Option<ToolFailure>,
        report: bool,
    }
    impl Backend {
        fn record(&self, request: &ToolRequest) -> Result<(), ToolFailure> {
            self.calls.borrow_mut().push(request.clone());
            match self.failure {
                Some(f) => Err(f),
                None => Ok(()),
            }
        }
    }
    impl ToolBackend for Backend {
        fn check_file(&self, r: &ToolRequest) -> Result<Map<String, Value>, ToolFailure> {
            self.record(r)?;
            Ok(object(json!({"findings":[{"code":"SL102"}]})))
        }
        fn check_dir(&self, r: &ToolRequest) -> Result<Map<String, Value>, ToolFailure> {
            self.record(r)?;
            Ok(object(json!({"totals":{},"files":[]})))
        }
        fn precheck(&self, r: &ToolRequest) -> Result<PrecheckResult, ToolFailure> {
            self.record(r)?;
            Ok(PrecheckResult {
                ok: false,
                reason: json!("invalid"),
                exit_code: 1,
                report: self.report.then(|| object(json!({"findings":[]}))),
            })
        }
    }

    #[test]
    fn injected_backend_success_preserves_findings_and_precheck_optional_report() {
        let backend = Backend {
            calls: RefCell::new(vec![]),
            failure: None,
            report: true,
        };
        for tool in TOOL_NAMES {
            let msg = request(
                json!("tools/call"),
                json!({"name":tool,"arguments":{"path":file()}}),
            );
            let out = dispatch_with(&msg, &backend).unwrap().unwrap();
            assert_eq!(out["result"]["isError"], false);
            assert!(out.get("error").is_none());
            match tool {
                "sesslint_check" => assert_eq!(
                    out["result"]["structuredContent"]["findings"][0]["code"],
                    "SL102"
                ),
                "sesslint_precheck" => assert_eq!(
                    out["result"]["structuredContent"],
                    json!({"ok":false,"reason":"invalid","exit_code":1,"report":{"findings":[]}})
                ),
                _ => assert_eq!(
                    out["result"]["structuredContent"],
                    json!({"totals":{},"files":[]})
                ),
            }
        }
        let backend = Backend {
            report: false,
            ..backend
        };
        let args = validate_args("sesslint_precheck", &json!({"path":file()})).unwrap();
        assert!(
            call_tool_with("sesslint_precheck", &args, &backend).unwrap()["structuredContent"]
                .get("report")
                .is_none()
        );
    }

    #[test]
    fn injected_backend_errors_stay_content_free_tool_results() {
        for (failure, text) in [
            (ToolFailure::Io, "io-error"),
            (ToolFailure::Usage, "usage-error"),
            (ToolFailure::Internal, "internal-error"),
        ] {
            let backend = Backend {
                calls: RefCell::new(vec![]),
                failure: Some(failure),
                report: false,
            };
            for tool in TOOL_NAMES {
                let args = validate_args(tool, &json!({"path":file()})).unwrap();
                assert_eq!(call_tool_with(tool, &args, &backend), Ok(tool_err(text)));
            }
        }
    }

    #[test]
    fn platform_errno_tables_do_not_confuse_linux_and_bsd() {
        for code in [2, 9, 20, 40] {
            assert!(ignored_raw_error(code, false, Some(40)));
        }
        assert!(!ignored_raw_error(62, false, Some(40)));
        for code in [2, 9, 20, 62] {
            assert!(ignored_raw_error(code, false, Some(62)));
        }
        assert!(!ignored_raw_error(40, false, Some(62)));
        for code in [2, 3, 6, 15, 18, 21, 53, 67, 123, 161, 206, 267, 1921] {
            assert!(ignored_raw_error(code, true, None));
        }
        for code in [5, 13, 22, 40, 62] {
            assert!(!ignored_raw_error(code, true, None));
        }
        assert!(!ignored_raw_error(13, false, Some(40)));
        assert!(!ignored_raw_error(22, false, Some(40)));
    }

    #[test]
    fn pathlib_normalization_precedes_stat_and_preserves_parent_components() {
        assert_eq!(python_path("./a//./b/../c/"), PathBuf::from("a/b/../c"));
        assert_eq!(python_path("./."), PathBuf::from("."));
        assert_eq!(python_path("."), PathBuf::from("."));
        let backend = Backend {
            calls: RefCell::new(vec![]),
            failure: None,
            report: false,
        };
        for suffix in ["/", "/.", "//./"] {
            let args = validate_args(
                "sesslint_check",
                &json!({"path":format!("{}{suffix}", file())}),
            )
            .unwrap();
            let output = call_tool_with("sesslint_check", &args, &backend).unwrap();
            assert_eq!(output["isError"], false);
            assert_eq!(
                backend.calls.borrow().last().unwrap().path,
                PathBuf::from(file())
            );
        }
    }

    #[test]
    fn scan_defaults_and_explicit_null_are_distinct() {
        let backend = Backend {
            calls: RefCell::new(vec![]),
            failure: None,
            report: false,
        };
        for (extra, recursive, profile, format) in [
            (json!({}), Some(true), "neutral", None),
            (
                json!({"recursive":null,"profile":null,"format":null}),
                None,
                "neutral",
                None,
            ),
            (
                json!({"recursive":false,"profile":"claude-strict","format":"auto"}),
                Some(false),
                "claude-strict",
                None,
            ),
            (
                json!({"recursive":true,"profile":"openai-strict","format":"canonical"}),
                Some(true),
                "openai-strict",
                Some("canonical"),
            ),
        ] {
            let mut raw = object(extra);
            raw.insert("path".into(), json!(directory()));
            let args = validate_args("sesslint_scan", &Value::Object(raw)).unwrap();
            call_tool_with("sesslint_scan", &args, &backend).unwrap();
            let calls = backend.calls.borrow();
            let actual = calls.last().unwrap();
            assert_eq!(actual.recursive, recursive);
            assert_eq!(actual.profile, profile);
            assert_eq!(actual.format.as_deref(), format);
            assert!(actual.skip_undetected);
        }
    }

    fn parse_line() -> &'static [u8] {
        b"{\"error\": {\"code\": -32700, \"message\": \"parse error\"}, \"id\": null, \"jsonrpc\": \"2.0\"}\n"
    }

    fn with_lf(body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.push(b'\n');
        out
    }

    fn request_line(value: Value) -> Vec<u8> {
        with_lf(python_json(&value).unwrap().as_bytes())
    }

    fn nested_array(depth: usize) -> Vec<u8> {
        let mut raw = Vec::with_capacity(depth * 2 + 1);
        raw.extend(std::iter::repeat_n(b'[', depth));
        raw.push(b'0');
        raw.extend(std::iter::repeat_n(b']', depth));
        raw
    }

    fn serve_out(input: &[u8]) -> (Result<i32, ServeError>, Vec<u8>) {
        let mut output = Vec::new();
        let result = serve(&mut io::Cursor::new(input), &mut output);
        (result, output)
    }

    #[test]
    fn handle_line_matches_pinned_serializer_and_strip() {
        assert_eq!(parse_error_line().unwrap(), parse_line());
        let pairs: &[(&[u8], &[u8])] = &[
            (
                br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
                br#"{"id": 1, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":-0,"method":"ping"}"#,
                br#"{"id": 0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1.0,"method":"ping"}"#,
                br#"{"id": 1.0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":-0.0,"method":"ping"}"#,
                br#"{"id": -0.0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":-0e0,"method":"ping"}"#,
                br#"{"id": -0.0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":0e999,"method":"ping"}"#,
                br#"{"id": 0.0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":-0e999,"method":"ping"}"#,
                br#"{"id": -0.0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1e2,"method":"ping"}"#,
                br#"{"id": 100.0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1e-7,"method":"ping"}"#,
                br#"{"id": 1e-07, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1e-400,"method":"ping"}"#,
                br#"{"id": 0.0, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":5e-324,"method":"ping"}"#,
                br#"{"id": 5e-324, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1e308,"method":"ping"}"#,
                br#"{"id": 1e+308, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}"#,
                br#"{"id": 9007199254740993, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":-9223372036854775808,"method":"ping"}"#,
                br#"{"id": -9223372036854775808, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"ping"}"#,
                br#"{"id": 18446744073709551615, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":false,"method":"ping"}"#,
                br#"{"id": false, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
                br#"{"id": null, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":[1,"x"],"method":"ping"}"#,
                br#"{"id": [1, "x"], "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":{"a":2},"method":"ping"}"#,
                br#"{"id": {"a": 2}, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"\ud83d\ude00","method":"ping"}"#,
                br#"{"id": "\ud83d\ude00", "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                "{\"jsonrpc\":\"2.0\",\"id\":\"Việt\",\"method\":\"ping\"}".as_bytes(),
                br#"{"id": "Vi\u1ec7t", "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                b"\x0b{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\x0c\n",
                br#"{"id": 3, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                b"\r\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\r\n",
                br#"{"id": 2, "jsonrpc": "2.0", "result": {}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
                br#"{"id": 1, "jsonrpc": "2.0", "result": {"capabilities": {"tools": {"listChanged": false}}, "protocolVersion": "2025-06-18", "serverInfo": {"name": "sesslint", "version": "0.5.0"}}}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":7,"method":"bogus/method"}"#,
                br#"{"error": {"code": -32601, "message": "method not found"}, "id": 7, "jsonrpc": "2.0"}"#,
            ),
            (
                br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"sesslint_check","arguments":{}}}"#,
                br#"{"error": {"code": -32602, "message": "path is required and must be a string"}, "id": 9, "jsonrpc": "2.0"}"#,
            ),
        ];
        for (raw, body) in pairs {
            assert_eq!(handle_line(raw).unwrap().unwrap(), with_lf(body));
        }

        let listed = handle_line(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .unwrap()
            .unwrap();
        let expected_list = with_lf(br#"{"id": 2, "jsonrpc": "2.0", "result": {"tools": [{"description": "Run the full SessLint check on one session file and return the sesslint.report/v1 report as structured content. Read-only; findings are results, not errors.", "inputSchema": {"additionalProperties": false, "properties": {"format": {"description": "Force input adapter (default: auto-detect).", "enum": ["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"], "type": "string"}, "path": {"description": "Session file path.", "type": "string"}, "profile": {"description": "Validation profile (default: neutral).", "enum": ["claude-strict", "neutral", "openai-strict"], "type": "string"}}, "required": ["path"], "type": "object"}, "name": "sesslint_check", "title": "Check session integrity"}, {"description": "Run the one-call precheck gate on one session file: returns {ok, reason, exit_code} plus the report when available. Read-only; never raises.", "inputSchema": {"additionalProperties": false, "properties": {"format": {"description": "Force input adapter (default: auto-detect).", "enum": ["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"], "type": "string"}, "path": {"description": "Session file path.", "type": "string"}, "profile": {"description": "Validation profile (default: neutral).", "enum": ["claude-strict", "neutral", "openai-strict"], "type": "string"}}, "required": ["path"], "type": "object"}, "name": "sesslint_precheck", "title": "Zero-exception integrity gate"}, {"description": "Aggregate scan of a session file or directory tree: 5-bucket totals (healthy/invalid/undetected/unreadable/skipped) and per-file verdict counts. Read-only.", "inputSchema": {"additionalProperties": false, "properties": {"format": {"description": "Force input adapter (default: auto-detect).", "enum": ["auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical"], "type": "string"}, "path": {"description": "Session file or directory path.", "type": "string"}, "profile": {"description": "Validation profile (default: neutral).", "enum": ["claude-strict", "neutral", "openai-strict"], "type": "string"}, "recursive": {"description": "Recurse into directories (default: true).", "type": "boolean"}}, "required": ["path"], "type": "object"}, "name": "sesslint_scan", "title": "Scan a session tree"}]}}"#);
        assert_eq!(listed, expected_list);
    }

    #[test]
    fn in_domain_non_requests_emit_nothing_and_invalid_json_is_parse_error() {
        for raw in [
            b"null".as_slice(),
            b"true",
            b"false",
            b"0",
            b"-0",
            b"[]",
            b"{}",
            b"[1,2]",
            b"\"ok\"",
            b"1.0",
            b"0e0",
            b"1e308",
            b"1e-400",
            b"0e999",
            b"-0e999",
            b"-0.0",
            b"18446744073709551615",
            b"-9223372036854775808",
            br#""\ud83d\ude00""#,
            br#""\ud800\ude00""#,
            b" \t\n\r\x0b\x0c",
            b"\x0b{}\x0c",
            b"",
        ] {
            assert_eq!(handle_line(raw).unwrap(), None);
        }
        for raw in [
            b"nope".as_slice(),
            b"+1",
            b"01",
            b"00",
            b"1.",
            b".5",
            b"nan",
            b"+Infinity",
            b"-NaN",
            b"[1,]",
            b"{,}",
            b"{\"a\":1}{\"b\":2}",
            b"[",
            b"\xff",
            b"\xef\xbb\xbf{}",
            "\u{00a0}{}".as_bytes(),
            "\u{2028}".as_bytes(),
            br#""\ud800"["#,
            b"[NaN,]",
            b"NaN x",
        ] {
            assert_eq!(handle_line(raw).unwrap().unwrap(), parse_line());
        }
        assert_eq!(handle_line(&vec![0x0B; MAX_MCP_LINE_BYTES]).unwrap(), None);
        assert_eq!(
            handle_line(&vec![0x0B; MAX_MCP_LINE_BYTES + 1])
                .unwrap()
                .unwrap(),
            parse_line()
        );
    }

    #[test]
    fn out_of_domain_json_follows_dispatch_or_stays_unsupported() {
        for raw in [
            b"NaN".as_slice(),
            b"Infinity",
            b"-Infinity",
            b"1e309",
            b"1e9999",
            b"18446744073709551616",
            b"-9223372036854775809",
            br#""\ud800""#,
            br#""\ud800\ud800""#,
            br#""a\ud800b""#,
            b"[NaN]",
        ] {
            assert_eq!(
                handle_line(raw).unwrap(),
                None,
                "non-object {raw:?} is dropped by _dispatch"
            );
        }
        for raw in [
            br#"{"id":NaN}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":"\ud800"}"#,
            br#"{"jsonrpc":"2.0","id":18446744073709551616,"method":"ping"}"#,
            br#"{"jsonrpc":"2.0","id":1e309,"method":"ping"}"#,
        ] {
            assert!(
                matches!(handle_line(raw), Err(McpError::Unsupported(_))),
                "expected Unsupported for object {raw:?}"
            );
        }
        assert_eq!(handle_line(&nested_array(127)).unwrap(), None);
        assert_eq!(handle_line(&nested_array(128)).unwrap(), None);
        assert_eq!(handle_line(&nested_array(995)).unwrap(), None);
        assert_eq!(
            handle_line(&nested_array(1000)).unwrap().unwrap(),
            parse_line()
        );
        assert_eq!(
            handle_line(&vec![b'['; 2_000]).unwrap().unwrap(),
            parse_line()
        );
    }

    #[test]
    fn tool_calls_keep_import_failures_unsupported_and_path_errors_content_free() {
        let missing = request_line(json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "sesslint_check",
                "arguments": {"path": format!("{}/not-present-mcp-synthetic", file())}
            }
        }));
        assert_eq!(
            handle_line(&missing).unwrap().unwrap(),
            with_lf(br#"{"id": 6, "jsonrpc": "2.0", "result": {"content": [{"text": "io-error: path does not exist", "type": "text"}], "isError": true}}"#)
        );
        let directory_call = request_line(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "sesslint_check", "arguments": {"path": directory()}}
        }));
        assert_eq!(
            handle_line(&directory_call).unwrap().unwrap(),
            with_lf(br#"{"id": 4, "jsonrpc": "2.0", "result": {"content": [{"text": "usage-error: path is not a file", "type": "text"}], "isError": true}}"#)
        );
        for (tool, message) in [
            ("sesslint_check", "sesslint.api.check_file is not available"),
            (
                "sesslint_precheck",
                "sesslint.precheck.precheck is not available",
            ),
            ("sesslint_scan", "sesslint.api.check_dir is not available"),
        ] {
            let call = request_line(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {"path": file()}}
            }));
            assert_eq!(handle_line(&call), Err(McpError::Unsupported(message)));
            let (served, output) = serve_out(&call);
            match served {
                Err(ServeError::Mcp(McpError::Unsupported(actual))) => {
                    assert_eq!(actual, message);
                }
                other => panic!("expected unsupported import, got {other:?}"),
            }
            assert!(output.is_empty());
        }
    }

    #[test]
    fn serve_bounds_lines_flushes_responses_and_stops_on_unsupported() {
        let ping7 = with_lf(br#"{"id": 7, "jsonrpc": "2.0", "result": {}}"#);

        let (empty, empty_out) = serve_out(b"");
        assert_eq!(empty.unwrap(), 0);
        assert!(empty_out.is_empty());

        let (eof, eof_out) = serve_out(br#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#);
        assert_eq!(eof.unwrap(), 0);
        assert_eq!(
            eof_out,
            with_lf(br#"{"id": 5, "jsonrpc": "2.0", "result": {}}"#)
        );

        let mut mixed = b"not json\n\n".to_vec();
        mixed
            .extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
        mixed.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"ping\"}\n");
        let (mixed_result, mixed_out) = serve_out(&mixed);
        assert_eq!(mixed_result.unwrap(), 0);
        let mut expected = parse_line().to_vec();
        expected.extend_from_slice(&with_lf(br#"{"id": 8, "jsonrpc": "2.0", "result": {}}"#));
        assert_eq!(mixed_out, expected);

        let marker = b"SYNTHETIC-OVERSIZE-MARKER";
        let mut oversized = vec![b'{'];
        oversized.extend(std::iter::repeat_n(b'x', MAX_MCP_LINE_BYTES + 32));
        oversized.extend_from_slice(marker);
        oversized.push(b'\n');
        oversized.extend_from_slice(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        oversized.push(b'\n');
        let (over_result, over_out) = serve_out(&oversized);
        assert_eq!(over_result.unwrap(), 0);
        let mut over_expected = parse_line().to_vec();
        over_expected.extend_from_slice(&ping7);
        assert_eq!(over_out, over_expected);
        assert!(!over_out
            .windows(marker.len())
            .any(|window| window == marker));

        let mut at_limit = vec![b' '; MAX_MCP_LINE_BYTES - 1];
        at_limit.push(b'\n');
        at_limit.extend_from_slice(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        at_limit.push(b'\n');
        let (limit_result, limit_out) = serve_out(&at_limit);
        assert_eq!(limit_result.unwrap(), 0);
        assert_eq!(limit_out, ping7);

        let mut over_one = vec![b' '; MAX_MCP_LINE_BYTES];
        over_one.push(b'\n');
        over_one.extend_from_slice(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        over_one.push(b'\n');
        let (over_one_result, over_one_out) = serve_out(&over_one);
        assert_eq!(over_one_result.unwrap(), 0);
        assert_eq!(over_one_out, over_expected);

        let mut drained = vec![b'y'; MAX_MCP_LINE_BYTES + 1];
        drained.extend(std::iter::repeat_n(b'z', 10));
        drained.push(b'\n');
        drained.extend_from_slice(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        drained.push(b'\n');
        let (drained_result, drained_out) = serve_out(&drained);
        assert_eq!(drained_result.unwrap(), 0);
        assert_eq!(drained_out, over_expected);

        let (bare, bare_out) = serve_out(&vec![b'x'; MAX_MCP_LINE_BYTES + 5]);
        assert_eq!(bare.unwrap(), 0);
        assert_eq!(bare_out, parse_line());

        let (nan_first, nan_first_out) =
            serve_out(b"NaN\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        assert_eq!(nan_first.unwrap(), 0);
        assert_eq!(
            nan_first_out,
            with_lf(br#"{"id": 1, "jsonrpc": "2.0", "result": {}}"#)
        );

        let (nan_after, nan_after_out) = serve_out(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\nNaN\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        );
        assert_eq!(nan_after.unwrap(), 0);
        let ping1 = with_lf(br#"{"id": 1, "jsonrpc": "2.0", "result": {}}"#);
        let ping2 = with_lf(br#"{"id": 2, "jsonrpc": "2.0", "result": {}}"#);
        assert_eq!(nan_after_out, [ping1, ping2].concat());
    }

    #[test]
    fn hostile_stdio_bytes_do_not_panic() {
        let mut state = 0xA5A5_1234_u64;
        let mut buf = [0_u8; 96];
        for _ in 0..256 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = (state as usize) % (buf.len() + 1);
            for byte in &mut buf[..len] {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                *byte = (state >> 33) as u8;
            }
            let line = handle_line(&buf[..len]);
            assert!(line.is_ok() || matches!(line, Err(McpError::Unsupported(_))));
            let (served, _) = serve_out(&buf[..len]);
            assert!(served.is_ok() || matches!(served, Err(ServeError::Mcp(_))));
        }
    }
}
