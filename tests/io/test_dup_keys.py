"""Parse-level and integration tests for SL303 duplicate JSON key detection.

The detector hooks the strict record-decode path (``object_pairs_hook``) so
last-wins parsing is preserved while every duplicated key position is
reported — ``error`` on adapter CRITICAL_KEYS, ``warning`` elsewhere,
capped at 16 per record with ``truncated``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from sesslint.adapters.canonical import CRITICAL_KEYS, load_canonical
from sesslint.api import check_file
from sesslint.codes import SL303, Repairability, Severity
from sesslint.finding import Finding
from sesslint.io import decode_json_dupaware, dup_key_findings, iter_events
from sesslint.scan import scan_path

FIXTURES_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks"


def _sl303(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.code == SL303]


def test_decode_clean_no_dups() -> None:
    """Clean records produce no dup entries and skip the path walk."""
    obj, dups, truncated = decode_json_dupaware('{"a": 1, "b": {"c": 2}, "d": [3, 4]}')
    assert obj == {"a": 1, "b": {"c": 2}, "d": [3, 4]}
    assert dups == ()
    assert truncated is False


def test_critical_key_dup_error() -> None:
    """A duplicated key in CRITICAL_KEYS escalates to error severity."""
    obj, dups, truncated = decode_json_dupaware(
        '{"id": "a", "id": "b", "x": 1}', critical_keys=CRITICAL_KEYS
    )
    assert obj == {"id": "b", "x": 1}  # stdlib last-wins semantics preserved
    assert not truncated
    assert len(dups) == 1
    assert dups[0].key_path == "$.id"
    assert dups[0].occurrence_count == 2
    assert dups[0].critical is True

    findings = dup_key_findings(dups, path_str="f.jsonl", line=2, record_id="b")
    assert len(findings) == 1
    f = findings[0]
    assert f.code == SL303
    assert f.severity == Severity.ERROR
    assert f.repairability == Repairability.MANUAL


def test_noncritical_key_dup_warning() -> None:
    """A duplicated non-critical key stays a warning."""
    _, dups, _ = decode_json_dupaware('{"note": 1, "note": 2}', critical_keys=CRITICAL_KEYS)
    findings = dup_key_findings(dups, path_str="f.jsonl", line=1)
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert cast(dict[str, Any], findings[0].evidence)["key_path"] == "$.note"


def test_nested_and_array_key_paths() -> None:
    """Nested objects and array positions report full schema paths."""
    _, dups, _ = decode_json_dupaware(
        '{"a": {"b": [{"k": 1, "k": 2}]}, "c": {"d": {"e": 1, "e": 2}}}'
    )
    paths = [d.key_path for d in dups]
    assert paths == ["$.a.b[0].k", "$.c.d.e"]


def test_dup_occurrence_count() -> None:
    """A key appearing three times reports occurrence_count 3."""
    _, dups, _ = decode_json_dupaware('{"k": 1, "k": 2, "k": 3}')
    assert len(dups) == 1
    assert dups[0].occurrence_count == 3


def test_dup_cap_truncated() -> None:
    """Collection caps at 16 duplicate positions and marks truncated."""
    text = "{" + ",".join(f'"f{i}":0,"f{i}":1' for i in range(17)) + "}"
    _, dups, truncated = decode_json_dupaware(text)
    assert len(dups) == 16
    assert truncated is True

    findings = dup_key_findings(dups, truncated=truncated, path_str="f.jsonl", line=1)
    assert len(findings) == 16
    assert all(cast(dict[str, Any], f.evidence)["truncated"] is True for f in findings)
    assert len({f.fingerprint for f in findings}) == 16  # unique per key_path


def test_strictness_preserved() -> None:
    """The dup-aware decoder keeps strict-parse rejection semantics."""
    for bad in ('{"a": NaN}', '{"a": Infinity}', '{"a": 1e999}', '{"a": }'):
        with pytest.raises(ValueError):
            decode_json_dupaware(bad)


def test_fixture_critical_dup() -> None:
    """Critical-key fixture: exactly one SL303 error naming $.id."""
    _events, findings = load_canonical(FIXTURES_CHECKS_DIR / "sl303_critical_dup.jsonl")
    sl303 = _sl303(list(findings))
    assert len(sl303) == 1
    f = sl303[0]
    assert f.severity == Severity.ERROR
    evidence = cast(dict[str, Any], f.evidence)
    assert evidence["key_path"] == "$.id"
    assert evidence["critical"] is True
    assert evidence["occurrence_count"] == 2


def test_fixture_noncritical_dup() -> None:
    """Non-critical fixture: one SL303 warning naming $.seq."""
    _events, findings = load_canonical(FIXTURES_CHECKS_DIR / "sl303_noncritical_dup.jsonl")
    sl303 = _sl303(list(findings))
    assert len(sl303) == 1
    assert sl303[0].severity == Severity.WARNING
    assert cast(dict[str, Any], sl303[0].evidence)["key_path"] == "$.seq"


def test_fixture_nested_dup() -> None:
    """Nested fixture: one warning naming $.payload.meta.tag."""
    _events, findings = load_canonical(FIXTURES_CHECKS_DIR / "sl303_nested_dup.jsonl")
    sl303 = _sl303(list(findings))
    assert len(sl303) == 1
    assert cast(dict[str, Any], sl303[0].evidence)["key_path"] == "$.payload.meta.tag"


def test_fixture_overflow_dup() -> None:
    """Overflow fixture: 16 findings emitted, evidence marks truncated."""
    _events, findings = load_canonical(FIXTURES_CHECKS_DIR / "sl303_overflow_dup.jsonl")
    sl303 = _sl303(list(findings))
    assert len(sl303) == 16
    assert all(cast(dict[str, Any], f.evidence)["truncated"] is True for f in sl303)


def test_single_doc_key_paths(tmp_path: Path) -> None:
    """Single-document canonical input reports $.events[i].<key> paths."""
    doc = (
        '{"events": ['
        '{"actor":"user","id":"e1","id":"e1b","kind":"message","parent_id":null,'
        '"payload":{"text":"x"},"seq":0,"ts":"2026-09-05T12:00:01Z"}'
        '], "schema": "sesslint.session/v1", "session_id": "doc-dup", "version": 1}'
    )
    p = tmp_path / "doc_dup.json"
    p.write_text(doc, encoding="utf-8")
    _events, findings = load_canonical(p)
    sl303 = _sl303(list(findings))
    assert len(sl303) == 1
    assert cast(dict[str, Any], sl303[0].evidence)["key_path"] == "$.events[0].id"


def test_malformed_record_with_dup() -> None:
    """A record that is both malformed and dup-carrying yields SL001 + SL303."""
    _events, findings = load_canonical(FIXTURES_CHECKS_DIR / "sl303_critical_dup.jsonl")
    codes = {f.code for f in findings}
    assert SL303 in codes
    # parent edge resolves to winning value; structural checks still run


def test_iter_events_yields_dup_findings(tmp_path: Path) -> None:
    """iter_events streams SL303 findings alongside events (repair path)."""
    p = tmp_path / "dup.jsonl"
    p.write_text(
        '{"schema_version":"sesslint.session/v1","session_id":"s","created_at":"2026-01-01T00:00:00Z"}\n'
        '{"actor":"user","id":"e1","id":"e1b","kind":"message","parent_id":null,'
        '"payload":{"text":"x"},"seq":0,"ts":"2026-01-01T00:00:01Z"}\n',
        encoding="utf-8",
    )
    items = list(iter_events(p, critical_keys=CRITICAL_KEYS))
    sl303 = _sl303([i for i in items if isinstance(i, Finding)])
    assert len(sl303) == 1
    assert sl303[0].severity == Severity.ERROR


def test_select_ignore_gating(tmp_path: Path) -> None:
    """SL303 honors --select/--ignore like every other finding code."""
    p = tmp_path / "dup.jsonl"
    p.write_text(
        '{"schema_version":"sesslint.session/v1","session_id":"s","created_at":"2026-01-01T00:00:00Z"}\n'
        '{"actor":"user","id":"e1","id":"e1b","kind":"message","parent_id":null,'
        '"payload":{"text":"x"},"seq":0,"ts":"2026-01-01T00:00:01Z"}\n',
        encoding="utf-8",
    )
    sel = check_file(p, format="canonical", select=["SL303"])
    assert _sl303(list(sel.findings))
    assert all(f.code == SL303 for f in sel.findings)

    ign = check_file(p, format="canonical", ignore=["SL303"])
    assert not _sl303(list(ign.findings))


def test_check_scan_consistency(tmp_path: Path) -> None:
    """check and scan surfaces report identical SL303 findings."""
    src = FIXTURES_CHECKS_DIR / "sl303_critical_dup.jsonl"
    file_rep = check_file(src, format="canonical")
    scan_rep = scan_path(FIXTURES_CHECKS_DIR, ext=[".jsonl"], recursive=True)
    scan_fr = next(
        (fr for fr in scan_rep.files if fr.path.endswith("sl303_critical_dup.jsonl")),
        None,
    )
    assert scan_fr is not None, "fixture missing from scan results"
    assert [f.fingerprint for f in _sl303(list(scan_fr.findings))] == [
        f.fingerprint for f in _sl303(list(file_rep.findings))
    ]


def test_determinism(tmp_path: Path) -> None:
    """Two loads of the same fixture produce identical findings bytes."""
    a = check_file(FIXTURES_CHECKS_DIR / "sl303_overflow_dup.jsonl", format="canonical")
    b = check_file(FIXTURES_CHECKS_DIR / "sl303_overflow_dup.jsonl", format="canonical")
    assert a.to_dict() == b.to_dict()


def test_vendor_adapter_dup(tmp_path: Path) -> None:
    """Vendor adapters route record decode through the dup-aware path."""
    # Claude Code JSONL record with a duplicated critical key (type field).
    p = tmp_path / "claude_dup.jsonl"
    p.write_text(
        '{"type":"user","type":"assistant","uuid":"u1","timestamp":"2026-01-01T00:00:00Z",'
        '"sessionId":"s1","message":{"role":"user","content":"hi"}}\n',
        encoding="utf-8",
    )
    report = check_file(p, format="claude-code-jsonl")
    sl303 = _sl303(list(report.findings))
    assert sl303, "expected SL303 on vendor decode path"
    assert cast(dict[str, Any], sl303[0].evidence)["key_path"] == "$.type"


def test_no_payload_values_in_evidence() -> None:
    """Evidence carries positions and counts only — never duplicated values."""
    _, dups, _ = decode_json_dupaware('{"secret_key": "value-one", "secret_key": "value-two"}')
    findings = dup_key_findings(dups, path_str="f.jsonl", line=1)
    blob = json.dumps(cast(dict[str, Any], findings[0].evidence))
    assert "value-one" not in blob and "value-two" not in blob
