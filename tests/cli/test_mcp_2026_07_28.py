"""MCP revision ``2026-07-28`` served alongside ``2025-06-18`` (CL-07).

Each test cites the spec section it covers; spec root is
https://modelcontextprotocol.io/specification/2026-07-28/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.mcp_server import (
    MODERN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
    SERVER_INFO,
    SUPPORTED_VERSIONS,
    TOOLS,
    handle_line,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = REPO_ROOT / "fixtures" / "adapters" / "codex" / "healthy_min.jsonl"

V = "io.modelcontextprotocol/protocolVersion"
C = "io.modelcontextprotocol/clientCapabilities"
SI = "io.modelcontextprotocol/serverInfo"


def _meta(version: str = MODERN_PROTOCOL_VERSION, caps: Any = None) -> dict[str, Any]:
    return {V: version, C: {} if caps is None else caps}


def _rpc(method: str, params: dict[str, Any] | None = None, *, rid: Any = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    out = handle_line((json.dumps(msg) + "\n").encode())
    assert out is not None
    return json.loads(out)  # type: ignore[no-any-return]


def _modern(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return _rpc(method, {**(params or {}), "_meta": _meta()})


def test_server_discover_result() -> None:
    """server/discover: supportedVersions, capabilities, serverInfo, caching."""
    r = _modern("server/discover")["result"]
    assert r["resultType"] == "complete"
    assert r["supportedVersions"] == list(SUPPORTED_VERSIONS)
    assert r["supportedVersions"] == ["2026-07-28", "2025-06-18"]
    assert r["capabilities"] == {"tools": {}}
    assert r["_meta"][SI] == SERVER_INFO
    assert r["ttlMs"] >= 0 and r["cacheScope"] == "public"


def test_unsupported_version_error_lists_supported() -> None:
    """basic/versioning#protocol-version-negotiation: -32022 with supported/requested."""
    for method in ("server/discover", "tools/list"):
        resp = _rpc(method, {"_meta": _meta("1900-01-01")})
        assert resp["error"] == {
            "code": -32022,
            "message": "Unsupported protocol version",
            "data": {"supported": ["2026-07-28", "2025-06-18"], "requested": "1900-01-01"},
        }


def test_client_offering_only_unknown_version_gets_no_result() -> None:
    """basic/versioning: a client with no mutual version is told what is supported."""
    resp = _rpc(
        "tools/call", {"name": "sesslint_check", "arguments": {}, "_meta": _meta("3000-01-01")}
    )
    assert "result" not in resp
    assert resp["error"]["code"] == -32022
    assert resp["error"]["data"]["requested"] == "3000-01-01"


def test_retry_with_listed_version_succeeds() -> None:
    """basic/versioning: the client retries with a version from `supported`."""
    bad = _rpc("tools/list", {"_meta": _meta("1900-01-01")})
    chosen = bad["error"]["data"]["supported"][0]
    assert "result" in _rpc("tools/list", {"_meta": _meta(chosen)})


@pytest.mark.parametrize("method", ["server/discover", "tools/list", "tools/call"])
def test_legacy_version_in_meta_requires_initialize(method: str) -> None:
    """basic/versioning#backward-compatibility: legacy needs `initialize`, not _meta."""
    resp = _rpc(method, {"_meta": _meta(PROTOCOL_VERSION)})
    assert "result" not in resp
    assert resp["error"] == {
        "code": -32602,
        "message": "Legacy protocol requires initialize; omit modern protocol metadata",
    }


def test_missing_required_meta_fields_are_invalid_params() -> None:
    """basic/index#meta: missing required per-request fields → -32602."""
    assert _rpc("server/discover")["error"]["code"] == -32602
    assert _rpc("server/discover", {})["error"]["code"] == -32602
    assert _rpc("server/discover", {"_meta": {V: 5}})["error"]["code"] == -32602
    assert _rpc("tools/list", {"_meta": {V: MODERN_PROTOCOL_VERSION}})["error"]["code"] == -32602
    assert (
        _rpc("tools/list", {"_meta": {V: MODERN_PROTOCOL_VERSION, C: []}})["error"]["code"]
        == -32602
    )


def test_tools_list_modern_shape() -> None:
    """server/tools#listing-tools + server/utilities/caching: resultType, ttlMs, cacheScope."""
    r = _modern("tools/list")["result"]
    assert r["resultType"] == "complete"
    assert r["tools"] == [dict(t) for t in TOOLS]
    assert [t["name"] for t in r["tools"]] == sorted(t["name"] for t in r["tools"])
    assert r["ttlMs"] >= 0 and r["cacheScope"] == "public"
    assert "nextCursor" not in r
    assert r["_meta"][SI] == SERVER_INFO


def test_tools_list_rejects_cursor() -> None:
    """server/utilities/pagination: we never issue a cursor, so any cursor is invalid."""
    assert _modern("tools/list", {"cursor": "x"})["error"]["code"] == -32602


def test_tools_call_success_and_tool_error() -> None:
    """server/tools#calling-tools: resultType on success and on isError results."""
    ok = _modern("tools/call", {"name": "sesslint_precheck", "arguments": {"path": str(FIXTURE)}})
    assert ok["result"]["resultType"] == "complete"
    assert ok["result"]["isError"] is False
    assert ok["result"]["structuredContent"]["ok"] is True
    assert ok["result"]["_meta"][SI] == SERVER_INFO
    missing = _modern(
        "tools/call", {"name": "sesslint_check", "arguments": {"path": str(FIXTURE) + ".nope"}}
    )
    assert missing["result"]["resultType"] == "complete"
    assert missing["result"]["isError"] is True


def test_tools_call_protocol_errors() -> None:
    """server/tools#error-handling: unknown tools and malformed requests are protocol errors."""
    assert _modern("tools/call", {"name": "nope"})["error"]["code"] == -32602
    for arguments in (None, [], "not-an-object", 1):
        response = _modern("tools/call", {"name": "sesslint_check", "arguments": arguments})
        assert response["error"]["code"] == -32602


@pytest.mark.parametrize("name", [tool["name"] for tool in TOOLS])
@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"path": ""},
        {"path": []},
        {"path": "x", "profile": "not-a-profile"},
        {"path": "x", "format": "not-a-format"},
        {"path": "x", "PRIVATE-ARGUMENT-MARKER": "PRIVATE-VALUE-MARKER"},
    ],
)
def test_modern_validation_is_a_content_free_tool_result(
    name: str, arguments: dict[str, Any]
) -> None:
    """Valid CallToolRequests with invalid tool input are isError results in 2026."""
    params = {"name": name, "arguments": arguments}
    response = _modern("tools/call", params)
    assert "error" not in response
    assert response["result"] == {
        "content": [{"type": "text", "text": "usage-error: invalid tool arguments"}],
        "isError": True,
        "resultType": "complete",
        "_meta": {SI: SERVER_INFO},
    }
    assert "PRIVATE" not in json.dumps(response)
    assert _rpc("tools/call", params)["error"]["code"] == -32602


def test_tools_call_rejects_unrequested_input_responses() -> None:
    """basic/patterns/mrtr: we never return input_required, so retry state is invalid."""
    for extra in ({"inputResponses": {}}, {"requestState": "abc"}):
        resp = _modern(
            "tools/call", {"name": "sesslint_check", "arguments": {"path": "x"}, **extra}
        )
        assert resp["error"]["code"] == -32602


def test_removed_and_unadvertised_methods_not_found() -> None:
    """Key Changes: ping/logging/setLevel removed; unadvertised features are -32601."""
    for method in ("ping", "logging/setLevel", "resources/list", "prompts/list", "tasks/get"):
        assert _modern(method)["error"]["code"] == -32601


def test_modern_notifications_get_no_response() -> None:
    """basic/transports/stdio: notifications never receive a response."""
    msg = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"_meta": _meta()}}
    assert handle_line((json.dumps(msg) + "\n").encode()) is None


def test_modern_never_writes_requests_or_extra_fields() -> None:
    """basic/transports/stdio: server output is only responses (no server requests)."""
    resp = _modern("tools/list")
    assert set(resp) == {"jsonrpc", "id", "result"}


def test_dual_era_on_one_process_and_initialize_stays_legacy() -> None:
    """basic/versioning#backward-compatibility: initialize selects legacy semantics."""
    legacy = _rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "_meta": _meta()})
    assert legacy["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert "resultType" not in legacy["result"]
    assert "resultType" not in _rpc("tools/list")["result"]  # no _meta → legacy bytes
    assert _rpc("ping")["result"] == {}  # legacy ping still answered
    assert _modern("tools/list")["result"]["resultType"] == "complete"


def test_modern_output_is_deterministic() -> None:
    """Determinism: identical request bytes → identical response bytes."""
    msg = (
        json.dumps(
            {"jsonrpc": "2.0", "id": 7, "method": "server/discover", "params": {"_meta": _meta()}}
        )
        + "\n"
    ).encode()
    assert handle_line(msg) == handle_line(msg)
