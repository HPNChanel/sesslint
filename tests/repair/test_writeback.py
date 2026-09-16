"""Vendor write-back projection tests (drop-only, line-verbatim).

Covers emit_vendor_bytes refusal conditions R1-R6, verbatim keep/drop
semantics for event-bearing vs event-less lines, and the api.repair/executor
vendor emit path end to end.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sesslint import api
from sesslint.adapters.claude_code import load_claude_code
from sesslint.canonical import SessionEvent, canonical_bytes
from sesslint.repair.errors import VendorProjectionRefused
from sesslint.repair.writeback import emit_vendor_bytes

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "fixtures"
CLAUDE_BASIC = FIXTURES / "claude_code" / "basic.jsonl"


def _record_hash(obj: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_bytes(obj)).hexdigest()}"


def _load(path: Path) -> tuple[bytes, list[SessionEvent]]:
    src = path.read_bytes()
    events, _ = load_claude_code(path)
    return src, list(events)


def _mk_event(
    eid: str,
    seq: int,
    *,
    source_line: int | None = None,
    parent_id: str | None = None,
) -> SessionEvent:
    return SessionEvent(
        id=eid,
        parent_id=parent_id,
        seq=seq,
        ts="2026-09-15T00:00:00Z",
        actor="assistant",
        kind="message",
        source_line=source_line,
    )


# -----------------------------------------------------------------------------
# Unit: emit_vendor_bytes semantics
# -----------------------------------------------------------------------------


def test_writeback_identity_passthrough(tmp_path: Path) -> None:
    """No drops -> emitted bytes are byte-identical to source."""
    src, events = _load(CLAUDE_BASIC)
    out, summary = emit_vendor_bytes(src, events, events, "claude-code-jsonl")
    assert out == src
    assert summary.dropped_lines == 0
    assert summary.retained_lines == len(src.splitlines())
    assert summary.emitted_sha256 == hashlib.sha256(src).hexdigest()


def test_writeback_drops_line_when_all_events_dropped(tmp_path: Path) -> None:
    """A line whose every derived event was removed is dropped verbatim."""
    src, events = _load(CLAUDE_BASIC)
    last_line = events[-1].source_line
    survivors = events[:-1]
    out, summary = emit_vendor_bytes(src, events, survivors, "claude-code-jsonl")
    kept = [raw for idx, raw in enumerate(src.splitlines(keepends=True)) if idx + 1 != last_line]
    assert out == b"".join(kept)
    assert summary.dropped_lines == 1
    assert summary.retained_lines == len(src.splitlines()) - 1


def test_writeback_refuses_synthesized_event_r1(tmp_path: Path) -> None:
    """R1: an output event with no source_line cannot be written back."""
    src, events = _load(CLAUDE_BASIC)
    synth = _mk_event("evt_synth", seq=99, source_line=None)
    with pytest.raises(VendorProjectionRefused) as exc:
        emit_vendor_bytes(src, events, [*events, synth], "claude-code-jsonl")
    assert exc.value.reason == "R1"


def test_writeback_refuses_partial_line_r2(tmp_path: Path) -> None:
    """R2: partial survival of a multi-event line requires intra-line edit."""
    line1 = {"id": "m1", "type": "user_message", "message": "hi"}
    line2 = {
        "id": "m2",
        "parentId": "m1",
        "type": "assistant_message",
        "message": "yo",
        "content": [
            {"type": "tool_use", "id": "call_9", "name": "x", "input": {}},
            {"type": "tool_use", "id": "call_8", "name": "y", "input": {}},
        ],
    }
    src_path = tmp_path / "multi.jsonl"
    src_path.write_text(json.dumps(line1) + "\n" + json.dumps(line2) + "\n")
    src, events = _load(src_path)

    line2_events = [e for e in events if e.source_line == 2]
    if len(line2_events) < 2:
        pytest.skip("adapter produced a single event for the multi-block line")

    survivors = [e for e in events if e.source_line == 1] + line2_events[:1]
    with pytest.raises(VendorProjectionRefused) as exc:
        emit_vendor_bytes(src, events, survivors, "claude-code-jsonl")
    assert exc.value.reason == "R2"


def test_writeback_refuses_rewritten_event_r3(tmp_path: Path) -> None:
    """R3: a recipe-rewritten field changes content identity -> refuse."""
    src, events = _load(CLAUDE_BASIC)
    target = events[-1]
    rewritten = SessionEvent(
        id=target.id,
        parent_id="rewritten_parent",
        seq=target.seq,
        ts=target.ts,
        actor=target.actor,
        kind=target.kind,
        payload=target.payload,
        content_hash=target.content_hash,
        correlation_id=target.correlation_id,
        source_line=target.source_line,
        source_record_hash=target.source_record_hash,
        original_id=target.original_id,
        source_adapter=target.source_adapter,
        source_location=target.source_location,
    )
    out_events = [*events[:-1], rewritten]
    with pytest.raises(VendorProjectionRefused) as exc:
        emit_vendor_bytes(src, events, out_events, "claude-code-jsonl")
    assert exc.value.reason == "R3"


def test_writeback_refuses_source_drift_r4(tmp_path: Path) -> None:
    """R4: a source line that changed since planning refuses the write."""
    src, events = _load(CLAUDE_BASIC)
    # Mutate the source bytes AFTER events were loaded (drift).
    drifted = src.replace(b'"id":"msg_01"', b'"id":"msg_XX"', 1)
    assert drifted != src
    with pytest.raises(VendorProjectionRefused) as exc:
        emit_vendor_bytes(drifted, events, events, "claude-code-jsonl")
    assert exc.value.reason == "R4"


def test_writeback_refuses_reorder_r5(tmp_path: Path) -> None:
    """R5: non-monotonic output order cannot be expressed verbatim."""
    src, events = _load(CLAUDE_BASIC)
    if len(events) < 2:
        pytest.skip("fixture needs >=2 events")
    reordered = [events[-1], *events[:-1]]
    with pytest.raises(VendorProjectionRefused) as exc:
        emit_vendor_bytes(src, events, reordered, "claude-code-jsonl")
    assert exc.value.reason == "R5"


def test_writeback_refuses_single_doc_json_r6(tmp_path: Path) -> None:
    """R6: a single-document JSON export has no per-line record boundaries."""
    doc = tmp_path / "single_doc.json"
    doc.write_text(json.dumps({"export_version": "1.0.0", "items": [{"id": "i1"}]}, indent=2))
    src = doc.read_bytes()
    ev = _mk_event("i1", seq=0, source_line=4)
    with pytest.raises(VendorProjectionRefused) as exc:
        emit_vendor_bytes(src, [ev], [ev], "openai-agents")
    assert exc.value.reason == "R6"


def test_writeback_refuses_unsupported_format_r6() -> None:
    """R6: unknown emit format refuses."""
    ev = _mk_event("e1", seq=0, source_line=1)
    with pytest.raises(VendorProjectionRefused) as exc:
        emit_vendor_bytes(b"{}\n", [ev], [ev], "bogus-format")
    assert exc.value.reason == "R6"


def test_writeback_drop_lines_discards_torn_record(tmp_path: Path) -> None:
    """Torn terminal line produces no events; drop_lines discards it."""
    torn = tmp_path / "torn.jsonl"
    healthy = CLAUDE_BASIC.read_bytes()
    torn.write_bytes(healthy + b'{"id":"msg_03","type":"assistant_messa')
    src = torn.read_bytes()
    events, findings = load_claude_code(torn)
    assert any(f.code == "SL002" for f in findings)
    torn_line = max(f.source.line for f in findings if f.code == "SL002" and f.source.line)
    out, summary = emit_vendor_bytes(
        src, events, events, "claude-code-jsonl", drop_lines=frozenset({torn_line})
    )
    assert out == healthy
    assert summary.dropped_lines == 1


def test_writeback_keeps_uninterpreted_lines(tmp_path: Path) -> None:
    """No-event lines not covered by a plan step are kept verbatim."""
    healthy = CLAUDE_BASIC.read_bytes()
    padded = tmp_path / "padded.jsonl"
    padded.write_bytes(healthy + b"\n")
    src = padded.read_bytes()
    events, _ = load_claude_code(padded)
    out, summary = emit_vendor_bytes(src, events, events, "claude-code-jsonl")
    # trailing blank line kept verbatim
    assert out == src


# -----------------------------------------------------------------------------
# Integration: api.repair vendor emit
# -----------------------------------------------------------------------------


def test_api_repair_vendor_torn_writeback(tmp_path: Path) -> None:
    """api.repair on a torn vendor file emits a byte-verbatim vendor artifact."""
    torn = tmp_path / "torn.jsonl"
    healthy_bytes = CLAUDE_BASIC.read_bytes()
    torn.write_bytes(healthy_bytes + b'{"id":"msg_03","type":"assistant_messa')
    out = tmp_path / "repaired.jsonl"

    plan_obj, manifest = api.repair(torn, out)
    assert out.exists()
    assert manifest is not None
    assert manifest.adapter_id == "claude-code-jsonl"
    # The torn line was the only change: output is byte-identical to healthy.
    assert out.read_bytes() == healthy_bytes
    assert manifest.record_counts.get("dropped_lines") == 1


def test_api_repair_vendor_emit_canonical(tmp_path: Path) -> None:
    """emit='canonical' on vendor input produces a canonical repaired stream."""
    torn = tmp_path / "torn.jsonl"
    torn.write_bytes(CLAUDE_BASIC.read_bytes() + b'{"id":"m3","type":"assis')
    out = tmp_path / "repaired_canon.jsonl"

    _, manifest = api.repair(torn, out, emit="canonical")
    assert manifest is not None
    assert manifest.adapter_id == "canonical"
    first_line = out.read_bytes().splitlines()[0]
    header = json.loads(first_line)
    assert header.get("schema_version") == "sesslint.session/v1"


def test_api_verify_vendor_pair(tmp_path: Path) -> None:
    """verify() passes on a vendor write-back pair (replay == emitted events)."""
    torn = tmp_path / "torn.jsonl"
    torn.write_bytes(CLAUDE_BASIC.read_bytes() + b'{"id":"m3","type":"assis')
    out = tmp_path / "repaired.jsonl"
    _, manifest = api.repair(torn, out)
    assert manifest is not None

    verdict = api.verify(
        source_path=torn,
        output_path=out,
        manifest_path=tmp_path / "repaired.jsonl.manifest.json",
    )
    assert verdict.ok is True
