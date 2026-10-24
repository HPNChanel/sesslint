"""Model Context Protocol stdio server (integrations T-01).

Newline-delimited JSON-RPC 2.0 over stdio, implemented with the stdlib
alone — no MCP SDK, no sockets, no threads. One JSON object per line in both
directions, no embedded newlines in messages.

Two protocol revisions are served side by side (dual-era, per
https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning):

- ``2025-06-18`` (legacy): ``initialize`` handshake, then ``tools/*``. Its
  response bytes are frozen by ``fixtures/mcp/2025-06-18`` — never change them
  (https://modelcontextprotocol.io/specification/2025-06-18).
- ``2026-07-28`` (modern): stateless; every request carries
  ``_meta["io.modelcontextprotocol/protocolVersion"]`` and
  ``.../clientCapabilities``; ``server/discover`` replaces the handshake;
  results carry ``resultType``; list/discover results carry ``ttlMs`` and
  ``cacheScope``; an unsupported version yields ``UnsupportedProtocolVersionError``
  (-32022). Not implemented, by design: Streamable HTTP, ``subscriptions/listen``,
  multi round-trip ``input_required`` results, the tasks extension — the tool
  set is static, read-only and never needs server-to-client interaction.

A request selects the modern era by carrying the protocol-version ``_meta``
key (or by calling ``server/discover``); everything else takes the legacy path.

Exposed tools (all read-only, all content-free — same contract as the CLI):

- ``sesslint_check``    — full check report for one session file.
- ``sesslint_precheck`` — the zero-exception gate (ok / reason / exit_code).
- ``sesslint_scan``     — aggregate 5-bucket scan of a file or directory tree.
- ``sesslint_triage``   — ``sesslint.triage/v1`` diagnosis of one session file
  (same document as ``sesslint triage <path> -f json``; never repairs).

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

PROTOCOL_VERSION: str = "2025-06-18"  # legacy (initialize-based) revision
MODERN_PROTOCOL_VERSION: str = "2026-07-28"  # stateless per-request-_meta revision
SUPPORTED_VERSIONS: tuple[str, ...] = (MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION)
SERVER_NAME: str = "sesslint"

_JSONRPC_VERSION = "2.0"

# JSON-RPC 2.0 error codes (spec-reserved range).
_E_PARSE = -32700
_E_INVALID_REQUEST = -32600
_E_METHOD_NOT_FOUND = -32601
_E_INVALID_PARAMS = -32602
_E_INTERNAL = -32603
# MCP 2026-07-28 error allocation (-32020..-32099 reserved for the spec).
_E_UNSUPPORTED_VERSION = -32022

# 2026-07-28 reserved _meta keys (basic/index#meta).
_META_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
_META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# Caching hints (server/utilities/caching). The tool set is fixed for the life
# of the process and identical for every caller, hence a long TTL and "public".
_CACHE_TTL_MS = 3_600_000
_CACHE_SCOPE = "public"

# A JSON-RPC request is one physical line.  Bound each read so an untrusted
# client cannot make the stdio loop allocate an unbounded buffer.
MAX_MCP_LINE_BYTES: int = 1_048_576

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
            "totals (healthy/invalid/unsupported/unreadable/skipped) and "
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
    "sesslint_triage": {
        "name": "sesslint_triage",
        "title": "Triage a session",
        "description": (
            "Diagnose one session file and explain the next steps: returns the "
            "sesslint.triage/v1 document (the same answer as `sesslint triage "
            "<path> -f json`) as structured content. Conservative defaults; "
            "previews are never applied. Read-only; findings are results, "
            "not errors."
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
}

TOOLS: tuple[dict[str, Any], ...] = tuple(_TOOL_SCHEMAS[name] for name in sorted(_TOOL_SCHEMAS))

SERVER_INFO: dict[str, str] = {"name": SERVER_NAME, "version": CLI_VERSION}


def _result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": _JSONRPC_VERSION, "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": _JSONRPC_VERSION, "id": request_id, "error": error}


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

        if name == "sesslint_triage":
            if not path.is_file():
                return _tool_err("usage-error: path is not a file")
            from sesslint.triage import triage

            triage_report = triage(path, format=fmt, profile=profile)
            if triage_report.status == "unreadable":
                return _tool_err("io-error")
            return _tool_ok(triage_report.to_dict())

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


def _run_tools_call(
    params: Any, *, validation_as_tool_error: bool = False
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate and run one ``tools/call``; returns (result, invalid-params message)."""
    if not isinstance(params, dict):
        return None, "params must be an object"
    name = params.get("name")
    if not isinstance(name, str) or name not in _TOOL_SCHEMAS:
        return None, "unknown tool"
    if validation_as_tool_error and "arguments" in params:
        if not isinstance(params["arguments"], dict):
            return None, "arguments must be an object"
    args, err = _validate_args(name, params.get("arguments"))
    if err is not None:
        if validation_as_tool_error:
            # 2026-07-28 server/tools#error-handling. Do not echo unknown
            # argument names or values into a content-free tool result.
            return _tool_err("usage-error: invalid tool arguments"), None
        return None, err
    assert args is not None
    return _call_tool(name, args), None


def _modern_result(result: dict[str, Any]) -> dict[str, Any]:
    """Stamp a 2026-07-28 result: resultType + serverInfo (basic/index#meta)."""
    return {
        **result,
        "resultType": "complete",
        "_meta": {_META_SERVER_INFO: dict(SERVER_INFO)},
    }


def _dispatch_modern(request_id: Any, method: str, params: Any) -> dict[str, Any]:
    """Serve one stateless 2026-07-28 request (basic/versioning, server/discover)."""
    meta = params.get("_meta") if isinstance(params, dict) else None
    if not isinstance(meta, dict):
        return _error(request_id, _E_INVALID_PARAMS, "params._meta is required")
    requested = meta.get(_META_VERSION)
    if not isinstance(requested, str):
        return _error(request_id, _E_INVALID_PARAMS, f"{_META_VERSION} is required")
    if requested == PROTOCOL_VERSION:
        return _error(
            request_id,
            _E_INVALID_PARAMS,
            "Legacy protocol requires initialize; omit modern protocol metadata",
        )
    if requested != MODERN_PROTOCOL_VERSION:
        return _error(
            request_id,
            _E_UNSUPPORTED_VERSION,
            "Unsupported protocol version",
            {"supported": list(SUPPORTED_VERSIONS), "requested": requested},
        )
    if not isinstance(meta.get(_META_CAPABILITIES), dict):
        return _error(request_id, _E_INVALID_PARAMS, f"{_META_CAPABILITIES} is required")

    if method == "server/discover":
        return _result(
            request_id,
            {
                **_modern_result({}),
                "supportedVersions": list(SUPPORTED_VERSIONS),
                "capabilities": {"tools": {}},
                "ttlMs": _CACHE_TTL_MS,
                "cacheScope": _CACHE_SCOPE,
            },
        )
    if method == "tools/list":
        if params.get("cursor") is not None:
            return _error(request_id, _E_INVALID_PARAMS, "invalid cursor")
        return _result(
            request_id,
            {
                **_modern_result({"tools": [dict(t) for t in TOOLS]}),
                "ttlMs": _CACHE_TTL_MS,
                "cacheScope": _CACHE_SCOPE,
            },
        )
    if method == "tools/call":
        if "inputResponses" in params or "requestState" in params:
            return _error(request_id, _E_INVALID_PARAMS, "no input was requested")
        outcome, err = _run_tools_call(params, validation_as_tool_error=True)
        if err is not None:
            return _error(request_id, _E_INVALID_PARAMS, err)
        assert outcome is not None
        return _result(request_id, _modern_result(outcome))
    # ping and logging/setLevel were removed in 2026-07-28; nothing else is served.
    return _error(request_id, _E_METHOD_NOT_FOUND, "method not found")


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

    params = message.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    modern = method == "server/discover" or (isinstance(meta, dict) and _META_VERSION in meta)
    if modern and method != "initialize":  # initialize always selects the legacy era
        if is_notification:
            return None
        return _dispatch_modern(request_id, method, params)

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
        outcome, err = _run_tools_call(message.get("params"))
        if err is not None:
            return _error(request_id, _E_INVALID_PARAMS, err)
        return _result(request_id, outcome)

    if is_notification:
        return None
    return _error(request_id, _E_METHOD_NOT_FOUND, "method not found")


def handle_line(raw: bytes) -> bytes | None:
    """Process one newline-delimited request; returns response line or None."""
    if len(raw) > MAX_MCP_LINE_BYTES:
        return (json.dumps(_error(None, _E_PARSE, "parse error"), sort_keys=True) + "\n").encode(
            "utf-8"
        )
    raw = raw.strip()
    if not raw:
        return None
    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
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
        line = stdin.readline(MAX_MCP_LINE_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_MCP_LINE_BYTES:
            # Discard the rest of this physical line in bounded reads before
            # accepting the next request; never reinterpret a suffix as JSON.
            while line and not line.endswith(b"\n"):
                line = stdin.readline(MAX_MCP_LINE_BYTES + 1)
            stdout.write(
                (json.dumps(_error(None, _E_PARSE, "parse error"), sort_keys=True) + "\n").encode(
                    "utf-8"
                )
            )
            stdout.flush()
            continue
        out = handle_line(line)
        if out is not None:
            stdout.write(out)
            stdout.flush()


__all__ = [
    "MODERN_PROTOCOL_VERSION",
    "PROTOCOL_VERSION",
    "SUPPORTED_VERSIONS",
    "SERVER_INFO",
    "TOOLS",
    "handle_line",
    "serve",
]
