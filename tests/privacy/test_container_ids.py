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
