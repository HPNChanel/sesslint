"""Mutation-driven unit tests for adapters/claude_code.py (CL-20).

Pins version normalisation / support checks and the session-envelope
defaults that the broader adapter tests never exercised.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from sesslint.adapters import claude_code as cc
from sesslint.errors import MaxRecordsExceededError
from sesslint.io import ReaderLimits

# ------------------------------------------------- is_supported_claude_version


def test_exact_supported_versions_accepted_even_as_schema_marker() -> None:
    assert cc.is_supported_claude_version("1.0.0", is_schema_marker=True) is True
    assert cc.is_supported_claude_version("claude-code-v1", is_schema_marker=True) is True


def test_schema_marker_default_is_app_version_semantics() -> None:
    # Default is_schema_marker=False: a semver with a supported major passes.
    assert cc.is_supported_claude_version("2.5.1") is True
    # Explicit marker outside the exact set fails closed.
    assert cc.is_supported_claude_version("2.5.1", is_schema_marker=True) is False


def test_semver_regex_must_match_and_major_must_be_supported() -> None:
    assert cc.is_supported_claude_version("1.9") is True
    assert cc.is_supported_claude_version("3.0.0") is False
    assert cc.is_supported_claude_version("not-a-version") is False
    assert cc.is_supported_claude_version("") is False


# ------------------------------------------------------------ normalize_version


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("v1.0.0", "1.0.0"),
        ("  V0.1.0  ", "0.1.0"),
        ("v", "v"),  # len == 1: must not index cleaned[1]
        ("vx", "vx"),  # 'v' but next char not a digit
        ("v1", "1"),  # len == 2 boundary
        ("abc", "abc"),  # no leading v, must not index/strip
        ("a1", "a1"),  # not 'v' prefix but cleaned[1] is a digit
    ],
)
def test_normalize_version(raw: str, expected: str) -> None:
    assert cc.normalize_version(raw) == expected


# ------------------------------------------------------------ _safe_type_value


def test_safe_type_value_delegates() -> None:
    assert cc._safe_type_value("abc") == "<str:len=3>"
    assert cc._safe_type_value(7) == "<int>"


# ------------------------------------------------- load_claude_code_session


def _line(ts: str | None = "2026-01-02T03:04:05Z", sid: str | None = "s-1") -> bytes:
    parts = ['"type":"user"', '"uuid":"u1"', '"message":{"role":"user","content":"hi"}']
    if ts is not None:
        parts.append(f'"timestamp":"{ts}"')
    if sid is not None:
        parts.append(f'"sessionId":"{sid}"')
    return ("{" + ",".join(parts) + "}\n").encode()


def test_session_header_uses_first_event_ts_and_session_id() -> None:
    session, _ = cc.load_claude_code_session(io.BytesIO(_line()))
    assert session.header.created_at == session.events[0].ts
    assert session.header.created_at.startswith("2026-01-02")
    assert session.header.session_id == "s-1"
    assert session.header.schema_version == "sesslint.session/v1"
    assert session.header.source == {"format": "claude-code-jsonl"}


def test_session_header_uses_first_not_second_event() -> None:
    data = _line("2026-01-02T00:00:00Z") + _line("2027-05-05T00:00:00Z")
    session, _ = cc.load_claude_code_session(io.BytesIO(data))
    assert len(session.events) >= 2
    assert session.header.created_at == session.events[0].ts
    assert session.header.created_at != session.events[1].ts


def test_session_header_defaults_when_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_bytes(b"")
    session, _ = cc.load_claude_code_session(p)
    assert session.events == ()
    assert session.header.created_at == "1970-01-01T00:00:00Z"
    assert session.header.session_id == "claude-session"


def test_session_forwards_reader_limits() -> None:
    data = _line() + _line()
    with pytest.raises(MaxRecordsExceededError):
        cc.load_claude_code_session(io.BytesIO(data), limits=ReaderLimits(max_records=1))
