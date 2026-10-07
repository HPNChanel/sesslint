"""B37: a torn final line never targets the complete event sharing its id.

The reader salvages a record id from the torn bytes, but the torn record never
decoded into an event. A complete event carrying the same id (a writer
re-appending the record it was writing) is a different record: the
conservative SL002 discard drops the torn line and keeps that event.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint import api

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
HEADER = (
    '{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1",'
    '"session_id":"torn-id"}\n'
)


def _msg(i: int, parent: str | None, text: str) -> str:
    event = {
        "actor": "user" if i % 2 == 0 else "assistant",
        "id": f"msg-{i}",
        "kind": "message",
        "parent_id": parent,
        "payload": {"text": text},
        "seq": i,
        "ts": f"2026-09-05T12:00:0{i}Z",
    }
    return json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n"


def test_canonical_torn_tail_keeps_event_with_same_id(tmp_path: Path) -> None:
    src = tmp_path / "session.jsonl"
    complete = HEADER + _msg(0, None, "a") + _msg(1, "msg-0", "b") + _msg(2, "msg-1", "c")
    src.write_bytes((complete + '{"actor":"user","id":"msg-2","kind":"message","pay').encode())
    plan = api.plan_repair(src)
    assert [(s.recipe, s.target_index) for s in plan.steps] == [
        ("torn-terminal-record-discard", None),
        ("seq-renumber", None),
    ]
    out = tmp_path / "out.jsonl"
    _plan, manifest = api.repair(src, out)
    assert manifest is not None
    assert manifest.declared_loss == ()
    assert out.read_bytes() == complete.encode()


def test_vendor_torn_tail_keeps_line_with_same_id(tmp_path: Path) -> None:
    complete = (FIXTURES / "claude_code" / "basic.jsonl").read_bytes().replace(b"\r\n", b"\n")
    last = json.loads(complete.splitlines()[-1])
    src = tmp_path / "session.jsonl"
    src.write_bytes(complete + b'{"id":"' + last["id"].encode() + b'","type":"assistant_mess')
    out = tmp_path / "out.jsonl"
    _plan, manifest = api.repair(src, out)
    assert manifest is not None
    assert out.read_bytes() == complete
