"""SL001 vendor-invisible-tail evidence — detector-depth T-01.

Vendor loaders commonly stop reading at the first malformed line; SessLint
parses past it. The first SL001 per file gains ``following_complete_records``
and ``following_bytes`` integer evidence keys quantifying that hidden tail.

Pinned contracts:
- first SL001 only (no double-counting across multiple malformed lines);
- keys omitted when the tail is empty (nothing follows but a torn terminal);
- ``following_bytes`` excludes a torn terminal region already claimed by SL002;
- integers are byte-exact across LF and multibyte content;
- stream order and finding fingerprints are unchanged.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from sesslint.adapters.claude_code import load_claude_code
from sesslint.adapters.codex_rollout import load_codex_rollout
from sesslint.adapters.openai_agents import load_openai_agents
from sesslint.canonical import SessionEvent
from sesslint.finding import Finding
from sesslint.io import MalformedTailTracker, iter_events

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
CANONICAL_MALFORMED = FIXTURES_DIR / "sessions" / "malformed-line.jsonl"
CLAUDE_MALFORMED = FIXTURES_DIR / "claude_code" / "malformed-mid.jsonl"

CLAUDE_LINE = (
    '{"id":"msg_X","type":"user_message","message":"hi","timestamp":"2025-01-01T12:00:00Z"}'
)


def _sl001s(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.code == "SL001"]


def _first_sl001(items: list[object]) -> Finding:
    for it in items:
        if isinstance(it, Finding) and it.code == "SL001":
            return it
    raise AssertionError("no SL001 produced")


class TestCanonicalStream:
    def test_mid_file_malformed_counts_tail(self) -> None:
        items = list(iter_events(CANONICAL_MALFORMED))
        f = _first_sl001(items)
        ev = f.evidence
        assert ev is not None
        assert ev["following_complete_records"] == 3
        # byte_end (line 2 end) to EOF — exact integer.
        assert ev["following_bytes"] == CANONICAL_MALFORMED.stat().st_size - ev["byte_end"]

    def test_stream_order_unchanged(self) -> None:
        items = list(iter_events(CANONICAL_MALFORMED))
        assert isinstance(items[0], SessionEvent)
        assert isinstance(items[1], Finding) and items[1].code == "SL001"
        assert isinstance(items[2], SessionEvent)

    def test_clean_file_no_keys(self) -> None:
        items = list(iter_events(FIXTURES_DIR / "sessions" / "minimal-valid.jsonl"))
        findings = [it for it in items if isinstance(it, Finding)]
        assert not findings
        for it in items:
            if isinstance(it, Finding):
                assert "following_bytes" not in (it.evidence or {})

    def test_malformed_then_only_torn_tail_omits_keys(self, tmp_path: Path) -> None:
        p = tmp_path / "tail_only_torn.jsonl"
        p.write_bytes(
            b'{"actor":"user","id":"e1","kind":"message","parent_id":null,'
            b'"payload":{},"seq":0,"ts":"2026-01-01T00:00:00Z"}\n'
            b"BROKEN LINE\n"
            b'{"id":"e2", torn'
        )
        findings = [it for it in list(iter_events(p)) if isinstance(it, Finding)]
        sl001 = _sl001s(findings)
        assert len(sl001) == 1
        assert "following_complete_records" not in (sl001[0].evidence or {})
        assert "following_bytes" not in (sl001[0].evidence or {})
        assert any(f.code == "SL002" for f in findings)

    def test_multiple_malformed_only_first_enriched(self, tmp_path: Path) -> None:
        p = tmp_path / "multi.jsonl"
        p.write_bytes(
            b"FIRST BROKEN\n"
            b"SECOND BROKEN\n"
            b'{"actor":"user","id":"e1","kind":"message","parent_id":null,'
            b'"payload":{},"seq":0,"ts":"2026-01-01T00:00:00Z"}\n'
        )
        sl001 = _sl001s([it for it in list(iter_events(p)) if isinstance(it, Finding)])
        assert len(sl001) == 2
        first, second = sl001[0], sl001[1]
        assert (first.evidence or {})["following_complete_records"] == 1
        assert "following_bytes" in (first.evidence or {})
        assert "following_complete_records" not in (second.evidence or {})
        assert "following_bytes" not in (second.evidence or {})

    def test_torn_terminal_excluded_from_tail_bytes(self, tmp_path: Path) -> None:
        good = (
            b'{"actor":"user","id":"e1","kind":"message","parent_id":null,'
            b'"payload":{},"seq":0,"ts":"2026-01-01T00:00:00Z"}\n'
        )
        p = tmp_path / "mid_plus_torn.jsonl"
        p.write_bytes(good + b"BROKEN\n" + good + b'{"id":"e9", torn')
        items = list(iter_events(p))
        f = _first_sl001(items)
        ev = f.evidence or {}
        # tail = the second `good` line only; torn final line claimed by SL002.
        assert ev["following_complete_records"] == 1
        assert ev["following_bytes"] == len(good)

    def test_multibyte_and_crlf_byte_exactness(self, tmp_path: Path) -> None:
        payload = "é☃".encode()
        rec = (
            b'{"actor":"user","id":"e1","kind":"message","parent_id":null,'
            b'"payload":{"text":"' + payload + b'"},"seq":0,"ts":"2026-01-01T00:00:00Z"}'
        )
        lf = tmp_path / "lf.jsonl"
        lf.write_bytes(rec + b"\n" + b"BROKEN\n" + rec + b"\n")
        f_lf = _first_sl001(list(iter_events(lf)))
        tail_lf = (f_lf.evidence or {})["following_bytes"]
        assert tail_lf == len(rec) + 1

        crlf = tmp_path / "crlf.jsonl"
        crlf.write_bytes(rec + b"\r\n" + b"BROKEN\r\n" + rec + b"\r\n")
        f_crlf = _first_sl001(list(iter_events(crlf)))
        assert (f_crlf.evidence or {})["following_bytes"] == len(rec) + 2


class TestClaudeAdapter:
    def test_golden_fixture_pinned_counts(self) -> None:
        events, findings = load_claude_code(CLAUDE_MALFORMED)
        assert len(events) == 4
        sl001 = _sl001s(findings)
        assert len(sl001) == 1
        ev = sl001[0].evidence or {}
        assert ev["following_complete_records"] == 3
        assert ev["following_bytes"] == CLAUDE_MALFORMED.stat().st_size - ev["byte_end"]

    def test_synthetic_mid_malformed(self) -> None:
        data = (
            CLAUDE_LINE.replace("msg_X", "m1")
            + "\nBROKEN\n"
            + CLAUDE_LINE.replace("msg_X", "m2")
            + "\n"
        ).encode()
        events, findings = load_claude_code(io.BytesIO(data))
        assert len(events) == 2
        sl001 = _sl001s(findings)
        assert len(sl001) == 1
        assert (sl001[0].evidence or {})["following_complete_records"] == 1


class TestOtherVendorAdapters:
    """Same shared machinery — smoke the wiring on Codex and OpenAI streams."""

    def test_codex_rollout_enriched(self) -> None:
        meta = (
            '{"ordinal": 0, "payload": {"cli_version": "0.42.0", "id": "s1",'
            ' "model_provider": "openai", "originator": "codex_cli",'
            ' "session_id": "s1", "timestamp": "2026-09-17T10:00:00Z"},'
            ' "timestamp": "2026-09-17T10:00:00Z", "type": "session_meta"}'
        )
        msg = (
            '{{"ordinal": {o}, "payload": {{"content": [{{"text": "hi",'
            ' "type": "input_text"}}], "id": "{i}", "role": "user",'
            ' "type": "message"}}, "timestamp": "2026-09-17T10:01:00Z",'
            ' "type": "response_item"}}'
        )
        data = (
            meta
            + "\nBROKEN LINE\n"
            + msg.format(o=1, i="m1")
            + "\n"
            + msg.format(o=2, i="m2")
            + "\n"
        ).encode()
        events, findings = load_codex_rollout(io.BytesIO(data))
        sl001 = _sl001s(findings)
        assert len(sl001) == 1
        ev = sl001[0].evidence or {}
        assert ev["following_complete_records"] == 2
        assert isinstance(ev["following_bytes"], int) and ev["following_bytes"] > 0

    def test_openai_agents_enriched(self) -> None:
        doc = json.loads((FIXTURES_DIR / "openai_agents" / "items_basic.json").read_text())
        line = json.dumps(doc["items"][0], separators=(",", ":"))
        data = (line + "\nBROKEN LINE\n" + line + "\n" + line + "\n").encode()
        events, findings = load_openai_agents(io.BytesIO(data))
        sl001 = _sl001s(findings)
        assert len(sl001) == 1
        ev = sl001[0].evidence or {}
        assert ev["following_complete_records"] == 2
        assert ev["following_bytes"] == 2 * (len(line) + 1)


class TestTrackerUnit:
    def test_no_enrichment_without_sl001(self) -> None:
        t = MalformedTailTracker()
        t.finalize(total_bytes=100)
        # nothing raised, nothing recorded
        assert t.following_records == 0

    def test_finding_without_dict_evidence_ignored(self) -> None:
        t = MalformedTailTracker()
        # A finding lacking byte_end coordinates can never anchor a tail.
        t.finalize(total_bytes=50, torn_tail_offset=10)
        assert t.following_records == 0


class TestRenderAndDeterminism:
    def test_human_render_suffix(self) -> None:
        from sesslint.report import _human_bytes

        assert _human_bytes(410) == "410 B"
        assert _human_bytes(2048) == "2.0 KiB"
        assert _human_bytes(11 * 1024 * 1024) == "11.0 MiB"

    def test_check_report_contains_suffix(self, tmp_path: Path) -> None:
        from sesslint.api import check_file
        from sesslint.report import render_human

        rep = check_file(CLAUDE_MALFORMED, format="claude-code-jsonl")
        out = render_human(rep)
        assert "may be invisible to vendor loaders" in out
        assert "3 further record(s)" in out

    def test_determinism_replay(self) -> None:
        a = [f.evidence for f in load_claude_code(CLAUDE_MALFORMED)[1]]
        b = [f.evidence for f in load_claude_code(CLAUDE_MALFORMED)[1]]
        assert a == b
