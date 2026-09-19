"""Drift guard for contrib/editors/problem-matcher.json (integrations/T-04).

The matcher regexes must extract code/message/severity from finding header
lines and file/line from ``Span:`` lines for every location line the human
renderer actually emits. If the renderer format changes, this test fails
before the shipped matcher silently rots.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sesslint.api import check_file
from sesslint.report import render_human

REPO_ROOT = Path(__file__).resolve().parent.parent
MATCHER_FILE = REPO_ROOT / "contrib" / "editors" / "problem-matcher.json"
FIXTURES = [
    REPO_ROOT / "fixtures" / "adapters" / "codex" / "dangling_call.jsonl",
    REPO_ROOT / "fixtures" / "claude_code" / "mixed_unknown_noncritical.jsonl",
    REPO_ROOT / "fixtures" / "checks" / "sl003_identical.json",
]


def _patterns() -> tuple[re.Pattern[str], re.Pattern[str]]:
    doc = json.loads(MATCHER_FILE.read_text(encoding="utf-8"))
    pats = doc["problemMatcher"]["pattern"]
    assert len(pats) == 2, "matcher must be a two-line multiline matcher"
    header = re.compile(pats[0]["regexp"])
    span = re.compile(pats[1]["regexp"])
    # Slot assignments pin the capture groups.
    assert pats[0]["code"] == 1 and pats[0]["message"] == 2 and pats[0]["severity"] == 3
    assert pats[1]["file"] == 1 and pats[1]["line"] == 2
    return header, span


def _human_lines(path: Path) -> list[str]:
    report = check_file(path)
    text = render_human(report, color=False)
    return text.splitlines()


@pytest.mark.parametrize("fixture", FIXTURES)
def test_matcher_matches_live_location_lines(fixture: Path) -> None:
    """Every ``Span:`` line carrying ``path:line`` must match; line-less
    spans are legal (no navigation target) and skipped."""
    _, span_re = _patterns()
    lines = _human_lines(fixture)
    for line in [ln for ln in lines if "Span:" in ln and re.search(r":\d+", ln)]:
        m = span_re.match(line)
        assert m is not None, f"Span line not matched: {line!r}"
        path, lineno = m.group(1), m.group(2)
        assert path and int(lineno) >= 1


@pytest.mark.parametrize("fixture", FIXTURES)
def test_matcher_matches_live_header_lines(fixture: Path) -> None:
    header_re, _ = _patterns()
    lines = _human_lines(fixture)
    for line in [ln for ln in lines if re.match(r"^\s*\[SL", ln)]:
        m = header_re.match(line)
        assert m is not None, f"header line not matched: {line!r}"
        code, message, severity = m.group(1), m.group(2), m.group(3)
        assert code.startswith("SL") and message
        assert severity in {"ERROR", "FATAL", "WARNING", "INFO"}


def test_corpus_produces_matchable_lines() -> None:
    """The fixture corpus must exercise both patterns at least once."""
    header_re, span_re = _patterns()
    all_lines = [ln for f in FIXTURES for ln in _human_lines(f)]
    assert any(header_re.match(ln) for ln in all_lines), "no header matched in corpus"
    assert any(span_re.match(ln) for ln in all_lines), "no span matched in corpus"


def test_every_finding_pair_matches() -> None:
    """Header+Span pairing: each emitted pair resolves code/severity/path/line."""
    header_re, span_re = _patterns()
    lines = _human_lines(FIXTURES[0])
    headers = [(i, ln) for i, ln in enumerate(lines) if re.match(r"^\s*\[SL", ln)]
    for idx, hline in headers:
        hm = header_re.match(hline)
        assert hm is not None
        span_line = next(
            (lines[j] for j in range(idx + 1, min(idx + 6, len(lines))) if "Span:" in lines[j]),
            None,
        )
        if span_line is None:
            continue  # findings without a location are legal
        sm = span_re.match(span_line)
        assert sm is not None, f"unmatched span after {hline!r}: {span_line!r}"


def test_byte_suffix_span_variant_matches() -> None:
    _, span_re = _patterns()
    line = "    Span:        ../x/session.jsonl:12 (bytes 40-77)"
    m = span_re.match(line)
    assert m is not None and m.group(2) == "12"


def test_matcher_json_is_valid_and_complete() -> None:
    doc = json.loads(MATCHER_FILE.read_text(encoding="utf-8"))
    pm = doc["problemMatcher"]
    assert pm["owner"] == "sesslint"
    assert "fileLocation" in pm
