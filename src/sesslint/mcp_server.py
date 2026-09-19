"""Model Context Protocol stdio server (integrations T-01).

Newline-delimited JSON-RPC 2.0 over stdio, implemented with the stdlib
alone — no MCP SDK, no sockets, no threads. Pinned to protocol revision
``2025-06-18``: one JSON object per line in both directions, no embedded
newlines in messages (https://modelcontextprotocol.io/specification/2025-06-18).

Exposed tools (all read-only, all content-free — same contract as the CLI):

- ``sesslint_check``    — full check report for one session file.
- ``sesslint_precheck`` — the zero-exception gate (ok / reason / exit_code).
- ``sesslint_scan``     — aggregate 5-bucket scan of a file or directory tree.

Check findings are *results*, not protocol errors: a corrupted session is a
successful ``tools/call`` whose structured content reports the findings.
Protocol-level problems (bad JSON, unknown method, invalid params) produce
JSON-RPC error objects; tool-execution problems (missing path, unreadable
file) produce ``isError: true`` results with a content-free reason string.

Determinism: identical request bytes produce identical response bytes — the
server adds no timestamps, ids, or environment data to tool results.

Security posture: stdio only; the server never writes files, never opens
sockets, and performs no ambient filesystem access — tool arguments are the
only filesystem inputs and are validated for existence before dispatch. The
*client* decides which paths are trustworthy (the agent already runs as the
user; exposure equals the CLI's own).
"""

from __future__ import annotations

import json
from typing import Any, BinaryIO

from sesslint._version import CLI_VERSION
from sesslint.profiles.builtin import REGISTRY as PROFILE_REGISTRY

PROTOCOL_VERSION: str = "2025-06-18"
SERVER_NAME: str = "sesslint"

_JSONRPC_VERSION = "2.0"

# JSON-RPC 2.0 error codes (spec-reserved range).
_E_PARSE = -32700
_E_INVALID_REQUEST = -32600
_E_METHOD_NOT_FOUND = -32601
_E_INVALID_PARAMS = -32602
_E_INTERNAL = -32603

_FORMATS = ("auto", "claude-code-jsonl", "openai-agents", "codex-rollout", "canonical")
_PROFILES = tuple(sorted(PROFILE_REGISTRY))

_OBJECT_SCHEMA: dict[str, Any] = {"type": "object"}

_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "sesslint_check": {
        "name": "sesslint_check",
        "title": "Check session integrity",
        "description": (
            "Run the full SessLint check on one session file and return the "
            "sesslint.report/v1 report as structured content. Read-only; "
            "findings are results, not errors."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Session file path."},
                "profile": {
                    "type": "string",
                    "enum": list(_PROFILES),
                    "description": "Validation profile (default: neutral).",
                },
                "format": {
                    "type": "string",
                    "enum": list(_FORMATS),
                    "description": "Force input adapter (default: auto-detect).",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    "sesslint_precheck": {
        "name": "sesslint_precheck",
        "title": "Zero-exception integrity gate",
        "description": (
            "Run the one-call precheck gate on one session file: returns "
            "{ok, reason, exit_code} plus the report when available. "
            "Read-only; never raises."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Session file path."},
                "profile": {
                    "type": "string",
                    "enum": list(_PROFILES),
                    "description": "Validation profile (default: neutral).",
                },
                "format": {
                    "type": "string",
                    "enum": list(_FORMATS),
                    "description": "Force input adapter (default: auto-detect).",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    "sesslint_scan": {
        "name": "sesslint_scan",
        "title": "Scan a session tree",
        "description": (
            "Aggregate scan of a session file or directory tree: 5-bucket "
            "totals (healthy/invalid/undetected/unreadable/skipped) and "
            "per-file verdict counts. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Session file or directory path.",
                },
                "profile": {
                    "type": "string",
                    "enum": list(_PROFILES),
                    "description": "Validation profile (default: neutral).",
                },
                "format": {
                    "type": "string",
                    "enum": list(_FORMATS),
                    "description": "Force input adapter (default: auto-detect).",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Recurse into directories (default: true).",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
}

TOOLS: tuple[dict[str, Any], ...] = tuple(_TOOL_SCHEMAS[name] for name in sorted(_TOOL_SCHEMAS))

SERVER_INFO: dict[str, str] = {"name": SERVER_NAME, "version": CLI_VERSION}


def _result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": _JSONRPC_VERSION, "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": _JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _tool_ok(payload: dict[str, Any]) -> dict[str, Any]:
    """Successful tools/call result: text + structured content (2025-06-18)."""
    return {
        "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
        "structuredContent": payload,
        "isError": False,
    }


def _tool_err(reason: str) -> dict[str, Any]:
    """Tool-execution failure — a result, not a protocol error (spec)."""
    return {
        "content": [{"type": "text", "text": reason}],
        "isError": True,
    }


def _validate_args(tool: str, arguments: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Validate tool arguments; returns (args, error-message)."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return None, "arguments must be an object"
    schema = _TOOL_SCHEMAS[tool]["inputSchema"]
    allowed = set(schema["properties"])
    unknown = sorted(k for k in arguments if k not in allowed)
    if unknown:
        return None, f"unknown argument(s): {','.join(unknown)}"
    path = arguments.get("path")
    if not isinstance(path, str) or not path:
        return None, "path is required and must be a string"
    profile = arguments.get("profile")
    if profile is not None and (not isinstance(profile, str) or profile not in PROFILE_REGISTRY):
        return None, "profile must be one of: " + ",".join(_PROFILES)
    fmt = arguments.get("format")
    if fmt is not None and (not isinstance(fmt, str) or fmt not in _FORMATS):
        return None, "format must be one of: " + ",".join(_FORMATS)
    recursive = arguments.get("recursive")
    if recursive is not None and not isinstance(recursive, bool):
        return None, "recursive must be a boolean"
    return arguments, None


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute one tool; returns the tools/call result payload."""
    from pathlib import Path

    path = Path(arguments["path"])
    profile = arguments.get("profile") or "neutral"
    fmt_arg = arguments.get("format")
    fmt = None if fmt_arg in (None, "auto") else fmt_arg

    if not path.exists():
        return _tool_err("io-error: path does not exist")

    try:
        if name == "sesslint_check":
            if not path.is_file():
                return _tool_err("usage-error: path is not a file")
            from sesslint.api import check_file

            return _tool_ok(check_file(path, format=fmt, profile=profile).to_dict())

        if name == "sesslint_precheck":
            if not path.is_file():
                return _tool_err("usage-error: path is not a file")
            from sesslint.precheck import precheck

            res = precheck(path, profile=profile, format=fmt)
            payload: dict[str, Any] = {
                "ok": res.ok,
                "reason": res.reason,
                "exit_code": res.exit_code,
            }
            if res.report is not None:
                payload["report"] = res.report.to_dict()
            return _tool_ok(payload)

        if name == "sesslint_scan":
            from sesslint.api import check_dir

            return _tool_ok(
                check_dir(
                    path,
                    recursive=arguments.get("recursive", True),
                    format=fmt,
                    profile=profile,
                    skip_undetected=True,
                ).to_dict()
            )
    except OSError:
        return _tool_err("io-error")
    except (ValueError, KeyError, TypeError, AttributeError):
        return _tool_err("usage-error")
    except Exception:
        return _tool_err("internal-error")
    return _tool_err("internal-error: unhandled tool")


def _dispatch(message: Any) -> dict[str, Any] | None:
    """Route one decoded JSON-RPC message; None → no response (notification)."""
    if not isinstance(message, dict) or message.get("jsonrpc") != _JSONRPC_VERSION:
        return None  # cannot even identify an id — spec: drop silently
    method = message.get("method")
    request_id = message.get("id")
    has_id = "id" in message

    if not isinstance(method, str):
        if has_id:
            return _error(request_id, _E_INVALID_REQUEST, "missing method")
        return None

    is_notification = method.startswith("notifications/") or not has_id

    if method == "initialize":
        if not has_id:
            return None
        return _result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": dict(SERVER_INFO),
            },
        )

    if method == "ping":
        if not has_id:
            return None
        return _result(request_id, {})

    if method == "tools/list":
        if not has_id:
            return None
        return _result(request_id, {"tools": [dict(t) for t in TOOLS]})

    if method == "tools/call":
        if not has_id:
            return None
        params = message.get("params")
        if not isinstance(params, dict):
            return _error(request_id, _E_INVALID_PARAMS, "params must be an object")
        name = params.get("name")
        if not isinstance(name, str) or name not in _TOOL_SCHEMAS:
            return _error(request_id, _E_INVALID_PARAMS, "unknown tool")
        args, err = _validate_args(name, params.get("arguments"))
        if err is not None:
            return _error(request_id, _E_INVALID_PARAMS, err)
        assert args is not None
        return _result(request_id, _call_tool(name, args))

    if is_notification:
        return None
    return _error(request_id, _E_METHOD_NOT_FOUND, "method not found")


def handle_line(raw: bytes) -> bytes | None:
    """Process one newline-delimited request; returns response line or None."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        message = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return (json.dumps(_error(None, _E_PARSE, "parse error"), sort_keys=True) + "\n").encode(
            "utf-8"
        )
    response = _dispatch(message)
    if response is None:
        return None
    return (json.dumps(response, sort_keys=True) + "\n").encode("utf-8")


def serve(stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Run the stdio JSON-RPC loop until EOF. Returns the process exit code."""
    while True:
        line = stdin.readline()
        if not line:
            return 0
        out = handle_line(line)
        if out is not None:
            stdout.write(out)
            stdout.flush()


__all__ = [
    "PROTOCOL_VERSION",
    "SERVER_INFO",
    "TOOLS",
    "handle_line",
    "serve",
]
