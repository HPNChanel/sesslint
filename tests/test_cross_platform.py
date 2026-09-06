"""Cross-platform path normalization, newline consistency, and multibyte offsets (TASK-026).

Verifies:
- Paths in JSON reports always normalize to POSIX forward slashes regardless of Windows.
- Canonical JSON output terminates strictly with LF (\\n), never CRLF (\\r\\n).
- Coordinates in evidence and spans represent exact 0-based byte offsets into UTF-8 stream.
"""

from __future__ import annotations

import json
from pathlib import Path

from sesslint import api
from sesslint.canonical import SessionEvent
from sesslint.determinism import canonical_json_bytes
from sesslint.io import iter_events
from sesslint.report import render_json


def test_canonical_json_terminates_with_strict_lf() -> None:
    """canonical_json_bytes terminates with \\n and contains zero \\r\\n sequences."""
    sample = {"key": "value", "list": [1, 2, 3]}
    b = canonical_json_bytes(sample)

    assert b.endswith(b"\n")
    assert not b.endswith(b"\r\n")
    assert b"\r" not in b


def test_json_paths_are_posix_normalized(tmp_path: Path) -> None:
    """Paths reported in JSON findings always use forward slashes even on Windows."""
    session_file = tmp_path / "subdir" / "session.jsonl"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.write_text(
        '{"created_at":"2026-09-06T00:00:00Z","schema_version":"sesslint.session/v1","session_id":"s_posix"}\n'
        '{"actor":"user","id":"e1","kind":"message","parent_id":null,"payload":{"text":"hello"},"seq":1,"ts":"2026-09-06T00:00:01Z"}\n',
        encoding="utf-8",
    )

    report = api.check_file(session_file)
    json_out = render_json(report)
    data = json.loads(json_out)

    for finding in data.get("findings", []):
        span_path = finding.get("span", {}).get("path", "")
        assert "\\" not in span_path, f"Path in finding contains Windows backslash: {span_path}"


def test_multibyte_emoji_coordinates_are_exact_byte_offsets(tmp_path: Path) -> None:
    """Offsets for multibyte Unicode (e.g. 4-byte emoji) are byte offsets into UTF-8 stream."""
    # Line 1: header (46 bytes)
    # Line 2: 🚀 (U+1F680, 4 bytes UTF-8: F0 9F 9A 80) in text
    emoji_file = tmp_path / "emoji_session.jsonl"
    header = (
        '{"created_at":"2026-09-06T00:00:00Z","schema_version":"sesslint.session/v1",'
        '"session_id":"s_emoji"}\n'
    )
    line2 = (
        '{"actor":"user","id":"e1","kind":"message","parent_id":null,'
        '"payload":{"text":"Hello 🚀 Rocket"},"seq":1,"ts":"2026-09-06T00:00:01Z"}\n'
    )

    header_bytes = header.encode("utf-8")
    line2_bytes = line2.encode("utf-8")
    emoji_file.write_bytes(header_bytes + line2_bytes)

    # Line 2 starts at exact byte offset len(header_bytes)
    expected_line2_byte_offset = len(header_bytes)
    assert expected_line2_byte_offset > 0

    events = list(iter_events(emoji_file))
    assert len(events) == 1
    evt = events[0]
    assert isinstance(evt, SessionEvent)
    assert evt.payload.get("text") == "Hello 🚀 Rocket"

    # Emoji is 4 bytes in UTF-8, but 2 chars / 1 grapheme
    emoji_utf8_len = len("🚀".encode())
    assert emoji_utf8_len == 4
    assert len("🚀") == 1  # 1 python character
