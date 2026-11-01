"""Mutation-driven tests for the SL009 gate helpers and tracker (CL-15).

All secret-shaped strings are synthetic and assembled from fragments.
"""

from __future__ import annotations

import pytest

from sesslint.checks import hygiene as hy

# --------------------------------------------------------- _short_prefix_present


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"npm_", True),
        (b"hf_", True),
        (b" npm_", True),
        (b"anpm_", False),
        (b"-hf_", False),
        (b"_hf_", False),
        (b"9npm_", False),
        (b"hello world", False),
        (b"", False),
        # escaped-whitespace boundary (JSON \n \r \t \b \f before the prefix)
        (b"\\nhf_", True),
        (b"\\rhf_", True),
        (b"\\thf_", True),
        (b"\\bhf_", True),
        (b"\\fhf_", True),
        (b"\\ahf_", False),
        (b"\\Xhf_", False),
        (b"\\Nhf_", False),
        # xox needs [a-z] at +3 and '-' at +4
        (b"xoxb-", True),
        (b"xoxa-", True),
        (b"xoxz-", True),
        (b"xox`-", False),
        (b"xox{-", False),
        (b"xoxB-", False),
        (b"xoxb_", False),
        (b"xoxbx", False),
        (b"xoxb", False),
        (b"xox", False),
        (b"xoxb-tail", True),
        (b"axoxb-", False),
        # first candidate rejected, later one accepted (and vice versa)
        (b"anpm_ npm_", True),
        (b"npm_ anpm_", True),
        (b"anpm_ bnpm_", False),
        (b"xoxB- xoxb-", True),
        (b"xoxb- xoxB-", True),
    ],
)
def test_short_prefix_present(raw: bytes, expected: bool) -> None:
    assert hy._short_prefix_present(raw) is expected


# -------------------------------------------------------- _kw_assignment_present


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"password: x", True),
        (b"passwd=x", True),
        (b"api_key = v", True),
        (b"secret:v", True),
        (b"token=v", True),
        (b'"key"  :v', True),
        (b"key  \t\r\n: v", True),
        (b"key\\\".-' =v", True),
        (b"key", False),
        (b"key  ", False),
        (b"key;", False),
        (b"nothing here", False),
        (b"", False),
        (b"keyboard key=1", True),
        (b"key=1 keyboard", True),
        (b"keyboard key=1 keyboard", True),
        (b"keyboard keyboard", False),
        (b"tokenizer password: x", True),
    ],
)
def test_kw_assignment_present(raw: bytes, expected: bool) -> None:
    assert hy._kw_assignment_present(raw) is expected


# ---------------------------------------------------------- gates


@pytest.mark.parametrize(
    "gate", [hy._gate_maybe_contains_secret, hy._line_gate_maybe_contains_secret]
)
def test_gates_truth_table(gate: object) -> None:
    g = gate  # type: ignore[assignment]
    assert g(b"nothing to see") is False
    assert g(b"") is False
    assert g(b"prefix sk-abc") is True
    assert g(b"ghp_xyz") is True
    assert g(b"Authorization: BEARER abc") is True
    assert g(b"npm_abc") is True
    assert g(b"id 123456789:" + b"A" * 35) is True
    assert g(b":" + b"A" * 34) is False
    assert g(b"PASSWORD = x") is True


# ---------------------------------------------------- _json_escape_boundary_shadow


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"no escapes", b"no escapes"),
        (b"a\\nb", b"a  b"),
        (b"a\\rb", b"a  b"),
        (b"a\\tb", b"a  b"),
        (b"a\\bb", b"a  b"),
        (b"a\\fb", b"a  b"),
        (b"a\\Xb", b"a\\Xb"),
        (b"a\\ub", b"a\\ub"),
        (b"a\\\\nb", b"a\\\\nb"),
        (b"a\\\\\\nb", b"a\\\\  b"),
        (b"trailing\\", b"trailing\\"),
        (b"\\n\\t", b"    "),
    ],
)
def test_json_escape_shadow(raw: bytes, expected: bytes) -> None:
    out = hy._json_escape_boundary_shadow(raw)
    assert out == expected
    assert len(out) == len(raw)
    assert isinstance(out, bytes)


# ------------------------------------------------------ _looks_like_placeholder


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"abc", True),
        (b"abcdefg", True),
        (b"abcdefgh", False),
        (b"abababab", True),
        (b"aaaaaaaa", True),
        (b"abcabcab", False),
        (b"'${VARIABLE}'", True),
        (b'"<variable>"', True),
        (b"{variable}", True),
        (b"[variable]", True),
        (b"${variable}", True),
        (b"your-api-key-here", True),
        (b"YOUR-API-KEY-HERE", True),
        (b"your_api_key_here", True),
        (b"your.api.key.here", True),
        (b"YOUR.API.KEY.HERE", True),
        (b"changeme", True),
        (b"REDACTED", True),
        (b"placeholder", True),
        (b"'`RealValue9876`'", False),
        (b"Zk3fQ9xLm2Pq7Rt5", False),
        (b"  Zk3fQ9xLm2Pq7Rt5", False),
    ],
)
def test_looks_like_placeholder(value: bytes, expected: bool) -> None:
    assert hy._looks_like_placeholder(value) is expected


def test_placeholder_strips_quote_characters_only_at_edges() -> None:
    assert hy._looks_like_placeholder(b"`'\"Zk3fQ9xLm2Pq7Rt5\"'`") is False
    assert hy._looks_like_placeholder(b"\"'${VARIABLE}'\"") is True


# ------------------------------------------------------------ SecretScanTracker

PAT = b"ghp_" + b"A1b2C3d4E5" * 3 + b"A1b2C3"


def _feed(t: hy.SecretScanTracker, raw: bytes, line: int = 1, off: int = 0) -> None:
    t.feed(raw, line_number=line, byte_offset=off, byte_end=off + len(raw), record_ordinal=line - 1)


def test_pending_window_flushes_at_threshold() -> None:
    t = hy.SecretScanTracker()
    _feed(t, b"x" * (hy._GATE_WINDOW_BYTES - 1))
    assert len(t._pending) == 1
    assert t._pending_bytes == hy._GATE_WINDOW_BYTES - 1
    t.feed(b"y", line_number=2, byte_offset=0, byte_end=1, record_ordinal=1)
    assert t._pending == []
    assert t._pending_bytes == 0
    # counter restarts from zero after a flush
    _feed(t, b"x" * (hy._GATE_WINDOW_BYTES - 1))
    assert len(t._pending) == 1


def test_feed_ignores_empty_records() -> None:
    t = hy.SecretScanTracker()
    _feed(t, b"")
    assert t._pending == []
    assert t._pending_bytes == 0


def test_feed_blob_line_numbers_offsets_and_last_line_without_newline() -> None:
    blob = b"first line\n" + PAT + b"\nplain\n" + PAT
    t = hy.SecretScanTracker()
    t.feed_blob(blob)
    findings = t.into_findings(path_str="p.json")
    assert [f.source.line for f in findings] == [2, 4]
    ev0 = dict(findings[0].evidence or {})
    ev1 = dict(findings[1].evidence or {})
    assert ev0["byte_offset"] == 11
    assert ev0["byte_end"] == 11 + len(PAT) + 1
    assert ev1["byte_offset"] == len(blob) - len(PAT)
    assert ev1["byte_end"] == len(blob)
    assert "record_ordinal" not in ev0
    assert ev0["secret_family"] == "github-pat-classic"
    assert ev0["occurrence_count"] == 1
    assert ev0["match_len"] == len(PAT)


def test_feed_blob_single_line_and_empty() -> None:
    t = hy.SecretScanTracker()
    t.feed_blob(b"")
    assert t.into_findings(path_str="p") == []
    t.feed_blob(PAT)
    (f,) = t.into_findings(path_str="p")
    assert f.source.line == 1
    assert dict(f.evidence or {})["byte_end"] == len(PAT)


def test_feed_blob_lines_with_only_newlines() -> None:
    t = hy.SecretScanTracker()
    t.feed_blob(b"\n\n" + PAT + b"\n")
    (f,) = t.into_findings(path_str="p")
    assert f.source.line == 3
    assert dict(f.evidence or {})["byte_offset"] == 2


def test_uppercase_generic_keyword_is_detected() -> None:
    t = hy.SecretScanTracker()
    _feed(t, b'API_KEY = "Zk3fQ9xLm2Pq7Rt5"')
    (f,) = t.into_findings(path_str="p")
    assert dict(f.evidence or {})["secret_family"] == "generic-credential-assignment"
    assert dict(f.evidence or {})["match_len"] == len(b"Zk3fQ9xLm2Pq7Rt5")


def test_placeholder_does_not_hide_later_real_value_in_same_record() -> None:
    raw = b'{"password": "your-password-here", "api_key": "Zk3fQ9xLm2Pq7Rt5"}'
    t = hy.SecretScanTracker()
    _feed(t, raw)
    (f,) = t.into_findings(path_str="p")
    ev = dict(f.evidence or {})
    assert ev["occurrence_count"] == 1
    assert ev["match_len"] == len(b"Zk3fQ9xLm2Pq7Rt5")


def test_no_truncation_markers_without_overflow() -> None:
    t = hy.SecretScanTracker()
    _feed(t, PAT)
    (f,) = t.into_findings(path_str="p")
    ev = dict(f.evidence or {})
    assert "truncated" not in ev
    assert "overflow" not in ev
    assert f.severity.value == "warning"
    assert f.repairability.value == "manual"


def test_overflow_marks_last_finding_with_suppressed_count() -> None:
    t = hy.SecretScanTracker()
    extra = 3
    for i in range(hy.MAX_SECRET_FINDINGS_PER_FILE + extra):
        _feed(t, PAT, line=i + 1, off=i * 100)
    out = t.into_findings(path_str="p")
    assert len(out) == hy.MAX_SECRET_FINDINGS_PER_FILE
    last = dict(out[-1].evidence or {})
    assert last["truncated"] is True
    assert last["overflow"] == extra
    assert "overflow" not in dict(out[-2].evidence or {})
    # exactly at the cap: no overflow marker
    t2 = hy.SecretScanTracker()
    for i in range(hy.MAX_SECRET_FINDINGS_PER_FILE):
        _feed(t2, PAT, line=i + 1, off=i * 100)
    out2 = t2.into_findings(path_str="p")
    assert "overflow" not in dict(out2[-1].evidence or {})
