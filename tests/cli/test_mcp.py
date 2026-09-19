"""Conformance tests for the MCP stdio server (integrations/T-01).

Recorded MCP message sequences replayed through ``handle_line``/``serve``
deterministically — no live client, no network, no threads.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from sesslint.mcp_server import PROTOCOL_VERSION, TOOLS, handle_line, serve

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = REPO_ROOT / "fixtures" / "adapters" / "codex" / "dangling_call.jsonl"


def _line(msg: dict) -> bytes:
    return (json.dumps(msg) + "\n").encode("utf-8")


def _call(raw: bytes) -> dict | None:
    out = handle_line(raw)
    return json.loads(out) if out is not None else None


def test_initialize_handshake() -> None:
    resp = _call(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            }
        )
    )
    assert resp is not None
    assert resp["id"] == 1
    result = resp["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == "sesslint"
    assert "tools" in result["capabilities"]
    # Only the tools capability is advertised in v1.
    assert set(result["capabilities"]) == {"tools"}


def test_initialized_notification_is_dropped() -> None:
    assert handle_line(_line({"jsonrpc": "2.0", "method": "notifications/initialized"})) is None


def test_tools_list_returns_three_readonly_tools() -> None:
    resp = _call(_line({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    assert resp is not None
    tools = {t["name"]: t for t in resp["result"]["tools"]}
    assert set(tools) == {"sesslint_check", "sesslint_precheck", "sesslint_scan"}
    for t in tools.values():
        assert t["inputSchema"]["type"] == "object"
        assert "path" in t["inputSchema"]["required"]


def test_tools_list_is_static() -> None:
    assert [t["name"] for t in TOOLS] == [
        "sesslint_check",
        "sesslint_precheck",
        "sesslint_scan",
    ]


def test_tools_call_check_reports_findings_as_result() -> None:
    """A corrupted file is a successful call whose content reports findings."""
    resp = _call(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "sesslint_check",
                    "arguments": {"path": str(FIXTURE)},
                },
            }
        )
    )
    assert resp is not None
    result = resp["result"]
    assert result["isError"] is False
    sc = result["structuredContent"]
    assert sc["schema_version"] == "sesslint.report/v1"
    assert sc["counts"]["by_code"]  # the fixture is corrupted on purpose
    assert result["content"][0]["type"] == "text"


def test_tools_call_precheck_gate() -> None:
    resp = _call(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "sesslint_precheck",
                    "arguments": {"path": str(FIXTURE)},
                },
            }
        )
    )
    sc = resp["result"]["structuredContent"]
    assert set(sc) >= {"ok", "reason", "exit_code"}
    assert sc["ok"] is False and sc["exit_code"] == 1


def test_tools_call_scan_directory() -> None:
    resp = _call(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "sesslint_scan",
                    "arguments": {"path": str(FIXTURE.parent)},
                },
            }
        )
    )
    sc = resp["result"]["structuredContent"]
    assert "totals" in sc and "files" in sc


def test_missing_path_is_iserror_result_not_protocol_error() -> None:
    resp = _call(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "sesslint_check", "arguments": {"path": "nope.jsonl"}},
            }
        )
    )
    assert "error" not in resp
    assert resp["result"]["isError"] is True
    assert "io-error" in resp["result"]["content"][0]["text"]


def test_invalid_params_produce_error_objects() -> None:
    cases = [
        # unknown tool
        {"name": "sesslint_bogus", "arguments": {"path": "x"}},
        # missing path
        {"name": "sesslint_check", "arguments": {}},
        # unknown argument
        {"name": "sesslint_check", "arguments": {"path": "x", "bogus": 1}},
        # bad profile
        {"name": "sesslint_check", "arguments": {"path": "x", "profile": "nope"}},
    ]
    for i, params in enumerate(cases):
        resp = _call(
            _line(
                {
                    "jsonrpc": "2.0",
                    "id": 100 + i,
                    "method": "tools/call",
                    "params": params,
                }
            )
        )
        assert resp["error"]["code"] == -32602, params


def test_unknown_method_and_malformed_json() -> None:
    resp = _call(_line({"jsonrpc": "2.0", "id": 7, "method": "bogus/method"}))
    assert resp["error"]["code"] == -32601
    resp = _call(b"this is not json\n")
    assert resp["id"] is None
    assert resp["error"]["code"] == -32700


def test_ping_responds_empty_result() -> None:
    resp = _call(_line({"jsonrpc": "2.0", "id": 8, "method": "ping"}))
    assert resp["result"] == {}


def test_full_recorded_sequence_through_serve() -> None:
    """End-to-end stdio loop: initialize → initialized → list → call → EOF."""
    script = b"".join(
        [
            _line(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
                }
            ),
            _line({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            _line({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            _line(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "sesslint_precheck", "arguments": {"path": str(FIXTURE)}},
                }
            ),
        ]
    )
    stdin, stdout = io.BytesIO(script), io.BytesIO()
    assert serve(stdin, stdout) == 0
    replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3]  # notification produced none


def test_deterministic_responses() -> None:
    """Identical request bytes produce identical response bytes."""
    req = _line({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
    assert handle_line(req) == handle_line(req)


def test_no_values_leak_in_tool_results() -> None:
    """Structured content is the standard content-free report shape."""
    resp = _call(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "sesslint_check", "arguments": {"path": str(FIXTURE)}},
            }
        )
    )
    blob = json.dumps(resp)
    # Report shapes carry names/codes/counts — never payload text.
    assert "structuredContent" in blob
    sc = resp["result"]["structuredContent"]
    for finding in sc["findings"]:
        assert "payload" not in json.dumps(finding.get("evidence", {}))
