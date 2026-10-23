"""FR-081: an object or array in an id field never reaches a report (CL-05 fuzz).

Adapters used ``str()`` on raw id values, so a JSON object id put its nested
keys and values (as a Python repr) into finding ids, messages and evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint import api

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
MARKER = "planted marker 7731"
CONTAINERS = [{MARKER: 1}, [MARKER]]


def _claude_variants() -> list[Any]:
    records = [
        json.loads(line)
        for line in (FIXTURES / "claude_code" / "basic.jsonl").read_text().splitlines()
    ]
    out = []
    for index, record in enumerate(records):
        for field in ("id", "parentId", "toolUseId"):
            if field not in record:
                continue
            for value in CONTAINERS:
                mutated = [dict(r) for r in records]
                mutated[index][field] = value
                text = "\n".join(json.dumps(r) for r in mutated) + "\n"
                out.append(
                    pytest.param("claude-code-jsonl", text.encode(), id=f"claude-{index}-{field}")
                )
    return out


def _openai_variants() -> list[Any]:
    doc = json.loads((FIXTURES / "openai_agents" / "items_basic.json").read_text())
    out = []
    for index, item in enumerate(doc["items"]):
        for field in ("id", "prev_id", "call_id"):
            if field not in item:
                continue
            for value in CONTAINERS:
                mutated = json.loads(json.dumps(doc))
                mutated["items"][index][field] = value
                out.append(
                    pytest.param(
                        "openai-agents", json.dumps(mutated).encode(), id=f"openai-{index}-{field}"
                    )
                )
    return out


@pytest.mark.parametrize(("adapter", "data"), _claude_variants() + _openai_variants())
def test_container_id_values_stay_out_of_reports(adapter: str, data: bytes) -> None:
    for fmt in (adapter, None):
        report = json.dumps(api.check_bytes(data, format=fmt).to_dict(), ensure_ascii=False)
        assert MARKER not in report


@pytest.mark.parametrize("marker", ["pvt", MARKER])
@pytest.mark.parametrize("as_list", [False, True])
@pytest.mark.parametrize("field", ["id", "call_id", "tool_call_id"])
def test_codex_container_identifiers_are_content_free(
    marker: str, as_list: bool, field: str, tmp_path: Path
) -> None:
    value = [marker] if as_list else {"x": marker}
    payloads = (
        [{"type": "message", "role": "user", field: value}] * 2
        if field == "id"
        else [
            {"type": "function_call", "id": "call", "name": "read", field: value},
            {"type": "function_call_output", "id": "result", field: value},
        ]
    )
    rows = [{"type": "session_meta", "payload": {}}] + [
        {"type": "response_item", "ordinal": i + 1, "payload": payload}
        for i, payload in enumerate(payloads)
    ]
    data = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
    source = tmp_path / "rollout.jsonl"
    source.write_bytes(data)
    for fmt in ("codex-rollout", None):
        first = api.check_file(source, format=fmt)
        second = api.check_file(source, format=fmt)
        assert first.to_dict() == second.to_dict()
        assert marker not in json.dumps(first.to_dict())
        assert marker not in repr(first.findings)
    assert source.read_bytes() == data
