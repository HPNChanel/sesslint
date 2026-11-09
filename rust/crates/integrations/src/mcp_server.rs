//! MCP dispatch (integrations T-01), Python `mcp_server.py` lines 1–320
//! @ 02694d537104659df66cdd084354739f3cccc440. Stdio is a separate card.
//!
//! Typed JSON domain: Unicode scalar strings, finite f64, i64/u64 numbers.
//! Serialization is bounded to 128 containers; Python arbitrary integers,
//! nonfinite floats, lone surrogates and deeper trees are not represented.
//! Unported API/precheck imports return typed Unsupported, never fake success.

use std::fmt;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

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
}
