"""Conformance tests for the MCP ``sesslint_triage`` tool (read-only, content-free)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.cli import main
from sesslint.mcp_server import TOOLS, handle_line
from tests.utils.schema import assert_schema

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "fixtures"
CASES = [
    "claude_code/basic.jsonl",
    "adapters/codex/dangling_call.jsonl",
    "checks/secret_seed/sl009_clean.jsonl",
    "checks/secret_seed/sl009_seeded.jsonl",
    "checks/sl303_critical_dup.jsonl",
    "adapters/codex/unknown_version.jsonl",
]
MARKER = "ZZ-UNIQUE-TRIAGE-MARKER-7f3a91"


def _request(arguments: Any, name: str = "sesslint_triage") -> bytes:
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    return (json.dumps(msg) + "\n").encode("utf-8")


def _call(arguments: Any, name: str = "sesslint_triage") -> dict[str, Any]:
    out = handle_line(_request(arguments, name))
    assert out is not None
    resp: dict[str, Any] = json.loads(out)
    return resp


def _canon(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def test_tools_list_includes_triage_with_valid_schema() -> None:
    out = handle_line(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    assert out is not None
    tools = {t["name"]: t for t in json.loads(out)["result"]["tools"]}
    assert "sesslint_triage" in tools
    assert [t["name"] for t in TOOLS] == sorted(t["name"] for t in TOOLS)
    schema = tools["sesslint_triage"]["inputSchema"]
    assert schema["type"] == "object"
    assert schema["required"] == ["path"]
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"path", "profile", "format"}
    assert tools["sesslint_triage"]["inputSchema"] == tools["sesslint_check"]["inputSchema"]


@pytest.mark.parametrize("fixture", CASES)
def test_triage_matches_cli_json_and_schema(
    fixture: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = FIXTURES / fixture
    result = _call({"path": str(path)})["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert json.loads(result["content"][0]["text"]) == structured
    assert_schema(structured, "sesslint.triage.v1.json")

    main(["triage", str(path), "-f", "json"])
    cli_doc = json.loads(capsys.readouterr().out)
    assert _canon(structured) == _canon(cli_doc)


def test_triage_parity_with_format_and_profile(capsys: pytest.CaptureFixture[str]) -> None:
    path = FIXTURES / "adapters/codex/dangling_call.jsonl"
    structured = _call({"path": str(path), "format": "codex-rollout", "profile": "neutral"})[
        "result"
    ]["structuredContent"]
    main(["triage", str(path), "--adapter", "codex-rollout", "--profile", "neutral", "-f", "json"])
    assert _canon(structured) == _canon(json.loads(capsys.readouterr().out))
    auto = _call({"path": str(path), "format": "auto"})["result"]["structuredContent"]
    assert _canon(auto) == _canon(_call({"path": str(path)})["result"]["structuredContent"])


def test_triage_previews_are_never_applied() -> None:
    sc = _call({"path": str(FIXTURES / "adapters/codex/dangling_call.jsonl")})["result"][
        "structuredContent"
    ]
    assert all(preview["applied"] is False for preview in sc["previews"])


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        None,
        [],
        "x",
        {"path": 1},
        {"path": ""},
        {"path": ["a"]},
        {"path": "x", "bogus": 1},
        {"path": "x", "profile": "nope"},
        {"path": "x", "profile": 3},
        {"path": "x", "format": "nope"},
        {"path": "x", "format": 3},
        {"path": "x", "recursive": True},
        {"path": "x", "policy": "salvage"},
        {"path": "x", "state_copy": "y"},
    ],
)
def test_bad_arguments_match_existing_tools(arguments: Any) -> None:
    triage = _call(arguments)
    check = _call(arguments, "sesslint_check")
    assert triage["error"]["code"] == -32602
    assert triage["error"] == check["error"]


def test_nonexistent_path_is_iserror_result() -> None:
    resp = _call({"path": "definitely-missing.jsonl"})
    assert "error" not in resp
    assert resp["result"]["isError"] is True
    assert resp["result"]["content"][0]["text"] == "io-error: path does not exist"
    assert resp["result"] == _call({"path": "definitely-missing.jsonl"}, "sesslint_check")["result"]


def test_directory_is_usage_error_like_check() -> None:
    resp = _call({"path": str(FIXTURES / "adapters" / "codex")})
    assert resp["result"]["isError"] is True
    assert resp["result"]["content"][0]["text"] == "usage-error: path is not a file"
    assert (
        resp["result"]
        == _call({"path": str(FIXTURES / "adapters" / "codex")}, "sesslint_check")["result"]
    )


def test_triage_responses_are_deterministic() -> None:
    req = _request({"path": str(FIXTURES / "adapters/codex/dangling_call.jsonl")})
    first = handle_line(req)
    assert first is not None and first == handle_line(req)


def test_triage_output_is_content_free(tmp_path: Path) -> None:
    session = tmp_path / "private-triage-dir-name.jsonl"
    rows = (FIXTURES / "adapters/codex/dangling_call.jsonl").read_text().splitlines()
    session.write_text("\n".join([*rows, json.dumps({"payload": {"text": MARKER}})]) + "\n")
    out = handle_line(_request({"path": str(session)}))
    assert out is not None
    assert b'"isError": false' in out
    assert MARKER.encode() not in out
    assert session.name.encode() not in out


def test_triage_does_not_modify_the_input(tmp_path: Path) -> None:
    session = tmp_path / "s.jsonl"
    session.write_bytes((FIXTURES / "adapters/codex/dangling_call.jsonl").read_bytes())
    before = session.read_bytes()
    _call({"path": str(session)})
    assert session.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["s.jsonl"]


def test_unreadable_file_matches_check_without_echoing_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "private-unreadable.jsonl"
    session.write_bytes((FIXTURES / "adapters/codex/healthy_min.jsonl").read_bytes())
    original_open = Path.open

    def denied_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == session:
            raise PermissionError(MARKER)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied_open)
    triage_result = _call({"path": str(session)})["result"]
    check_result = _call({"path": str(session)}, "sesslint_check")["result"]
    assert triage_result == check_result
    assert triage_result == {"content": [{"type": "text", "text": "io-error"}], "isError": True}
    assert MARKER not in json.dumps(triage_result)
    assert session.name not in json.dumps(triage_result)
