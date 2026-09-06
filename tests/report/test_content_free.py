"""Tests for content-free reporting defaults and --include-content gate (TASK-025)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.codes import SL001, Repairability, Severity
from sesslint.errors import OperationalError
from sesslint.finding import SourceRef, make_finding
from sesslint.report import (
    REPORT_DEFAULT_FINDING_KEYS,
    REPORT_FORBIDDEN_FINDING_KEYS,
    REPORT_ROOT_KEYS,
    build_report,
    render_json,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "report" / "secret_seed"
TOKEN_FILE = FIXTURES_DIR / "token.txt"


def _get_token() -> str:
    return TOKEN_FILE.read_text(encoding="utf-8").strip()


def test_default_mode_never_leaks_seeded_secret(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that default human and JSON check reports contain zero occurrences of secret token."""
    token = _get_token()
    claude_fixture = FIXTURES_DIR / "claude_secret.jsonl"

    # 1. Human check mode
    code = main(["check", str(claude_fixture), "--format", "claude-code-jsonl"])
    assert code == 0
    captured = capsys.readouterr()
    assert token not in captured.out
    assert token not in captured.err

    # 2. JSON check mode
    code_json = main(["check", str(claude_fixture), "--format", "claude-code-jsonl", "--json"])
    assert code_json == 0
    captured_json = capsys.readouterr()
    assert token not in captured_json.out
    assert token not in captured_json.err


def test_json_keys_subset_of_allowlist() -> None:
    """Verify JSON report keys strictly conform to approved allowlists and forbid content keys."""
    f = make_finding(
        code=SL001,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Malformed syntax at line {line}",
        template_args={"line": "5"},
        source=SourceRef(path="session.jsonl", line=5),
    )
    rep = build_report(
        session_id="sess_allowlist",
        source_fingerprint="fp_1234567890abcdef",
        tool_version="0.1.0",
        findings=[f],
        assurance="A0",
        limitation="No structural conclusion.",
    )

    rendered_str = render_json(rep, include_content=False)
    data = json.loads(rendered_str)

    # Root keys ⊆ allowlist
    assert set(data.keys()).issubset(REPORT_ROOT_KEYS)
    assert "content_warning" not in data
    assert "included_content" not in data

    # Findings keys ⊆ allowlist
    findings = data["findings"]
    assert len(findings) == 1
    finding_keys = set(findings[0].keys())
    assert finding_keys.issubset(REPORT_DEFAULT_FINDING_KEYS)

    # Strictly no forbidden keys in default mode
    for forbidden_key in REPORT_FORBIDDEN_FINDING_KEYS:
        msg = f"Forbidden key {forbidden_key!r} found in finding"
        assert forbidden_key not in finding_keys, msg


def test_fail_closed_on_crafted_content_key() -> None:
    """Verify that a crafted dictionary with unapproved key raises OperationalError."""
    crafted_finding = {
        "code": "SL001",
        "severity": "error",
        "repairability": "manual",
        "fingerprint": "1234567890abcdef",
        "span": {"path": "session.jsonl", "line": 1, "byte": None},
        "evidence": None,
        "remediation": "manual fix",
        "content": "UNAUTHORIZED_PAYLOAD_LEAK",
    }
    crafted_report = {
        "schema_version": "sesslint.report/v1",
        "session_id": "sess-test",
        "source_fingerprint": "0" * 64,
        "tool_version": "0.1.0",
        "assurance": "A0",
        "limitation": "Test limitation",
        "counts": {
            "by_severity": {"fatal": 0, "error": 1, "warning": 0, "info": 0},
            "by_code": {"SL001": 1},
            "total": 1,
        },
        "findings": [crafted_finding],
    }

    with pytest.raises(OperationalError, match="forbidden content key violation"):
        render_json(crafted_report, include_content=False)

    # Also test extra rogue root key
    rogue_root_report = dict(crafted_report)
    rogue_root_report["findings"] = []
    rogue_root_report["rogue_key"] = "leak"
    with pytest.raises(OperationalError, match="root key allowlist violation"):
        render_json(rogue_root_report, include_content=False)


def test_include_content_embeds_token_and_adds_warnings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --include-content adds warning keys to JSON and emits stderr warning banner."""
    claude_fixture = FIXTURES_DIR / "claude_secret.jsonl"

    code = main(
        [
            "check",
            str(claude_fixture),
            "--format",
            "claude-code-jsonl",
            "--json",
            "--include-content",
        ]
    )
    assert code == 0
    captured = capsys.readouterr()

    # Stderr must contain warning banner
    warn_banner = "WARNING: --include-content embeds raw transcript content; do not share output"
    assert warn_banner in captured.err

    # JSON output must have warning keys
    data = json.loads(captured.out)
    assert data.get("content_warning") is True
    assert data.get("included_content") is True


def test_shorthand_flag_c_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify shorthand -c is rejected with exit code 2 (spelled-out only requirement)."""
    claude_fixture = FIXTURES_DIR / "claude_secret.jsonl"
    with pytest.raises(SystemExit) as exc_info:
        main(["check", str(claude_fixture), "-c"])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "unrecognized arguments" in captured.err or "-c" in captured.err
