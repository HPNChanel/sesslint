"""AC-02 exit-code contract (FR-098).

An internal tool error exits 2, a session with findings exits 1, a clean
session exits 0. User-facing docs must state that sentence verbatim, and the
observed ``check`` codes must match it. ``NO_COLOR`` changes styling only.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from sesslint.cli import CHECK_EXIT_CONTRACT, main

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "fixtures" / "cli"
HEALTHY = FIXTURES_DIR / "check_basic" / "healthy.jsonl"

# Verbatim AC-02 sentence. Docs, ``--help``, and man pages must contain it.
AC02_CONTRACT = (
    "an internal tool error exits 2, a session with findings exits 1, a clean session exits 0"
)

DOC_PATHS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "CI_TEMPLATES.md",
    REPO_ROOT / "docs" / "REPORTING_CORRUPTION.md",
)

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _findings_session(tmp_path: Path) -> Path:
    """Synthetic session with one orphan tool result (SL101)."""
    path = tmp_path / "findings.jsonl"
    path.write_text(
        '{"id":"msg_01","type":"user_message","message":"hi"}\n'
        '{"id":"msg_02","parentId":"msg_01","type":"tool_result",'
        '"toolUseId":"call_missing","content":"res"}\n',
        encoding="utf-8",
    )
    return path


def _run(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0


def test_contract_constant_is_the_ac02_sentence() -> None:
    """The CLI constant is the sentence the docs are required to state."""
    assert CHECK_EXIT_CONTRACT == AC02_CONTRACT


def test_clean_session_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    """A clean session exits 0."""
    code = _run(["check", str(HEALTHY)])
    assert code == 0
    captured = capsys.readouterr()
    assert "Session is healthy" in captured.out
    assert "Integrity check failed" not in captured.out
    assert "Operational error" not in captured.err


def test_session_with_findings_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A session with findings exits 1."""
    session = _findings_session(tmp_path)
    code = _run(["check", str(session), "--format", "claude-code-jsonl"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Integrity check failed" in captured.out
    assert "SL101" in captured.out
    assert "Operational error" not in captured.err


def test_internal_tool_error_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    """An internal tool error exits 2 and is not reported as a healthy session."""
    with patch(
        "sesslint.api.check_file",
        side_effect=RuntimeError("simulated internal tool error"),
    ):
        code = _run(["check", str(HEALTHY)])
    assert code == 2
    captured = capsys.readouterr()
    assert "Operational error [ERR-" in captured.err
    assert "simulated internal tool error" in captured.err
    assert "Traceback (most recent call last):" not in captured.out
    assert "Traceback (most recent call last):" not in captured.err
    assert "Session is healthy" not in captured.out
    assert "Valid " not in captured.out


def test_no_color_keeps_exit_codes_and_strips_ansi(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NO_COLOR=1 does not change 0/1/2 and suppresses ANSI even with --color always."""
    monkeypatch.setenv("NO_COLOR", "1")
    session = _findings_session(tmp_path)

    clean = _run(["check", str(HEALTHY), "--color", "always"])
    clean_out = capsys.readouterr()
    assert clean == 0
    assert ANSI_ESCAPE.search(clean_out.out) is None
    assert "Session is healthy" in clean_out.out

    findings = _run(["check", str(session), "--format", "claude-code-jsonl", "--color", "always"])
    findings_out = capsys.readouterr()
    assert findings == 1
    assert ANSI_ESCAPE.search(findings_out.out) is None
    assert "SL101" in findings_out.out

    with patch(
        "sesslint.api.check_file",
        side_effect=RuntimeError("simulated internal tool error"),
    ):
        internal = _run(["check", str(HEALTHY), "--color", "always"])
    internal_out = capsys.readouterr()
    assert internal == 2
    assert "Operational error [ERR-" in internal_out.err
    assert ANSI_ESCAPE.search(internal_out.err) is None


def test_docs_state_ac02_contract_exactly() -> None:
    """README, CI docs, the corruption guide, and every man page state AC-02."""
    for path in DOC_PATHS:
        text = path.read_text(encoding="utf-8")
        assert AC02_CONTRACT in text, f"{path.relative_to(REPO_ROOT)} must state AC-02 exactly"

    man_pages = sorted((REPO_ROOT / "man").glob("*.1"))
    assert man_pages, "man/ pages missing"
    for page in man_pages:
        text = page.read_text(encoding="utf-8")
        assert AC02_CONTRACT in text, f"{page.name} must state AC-02 exactly"


def test_cli_help_states_ac02_contract(capsys: pytest.CaptureFixture[str]) -> None:
    """``sesslint --help`` and ``sesslint check --help`` state the contract."""
    with pytest.raises(SystemExit) as top:
        main(["--help"])
    assert top.value.code == 0
    top_out = capsys.readouterr().out
    assert AC02_CONTRACT in top_out
    assert "Exit codes:" in top_out

    with pytest.raises(SystemExit) as check_help:
        main(["check", "--help"])
    assert check_help.value.code == 0
    check_out = capsys.readouterr().out
    # Help wrapping may insert newlines; the words must still state the contract.
    assert AC02_CONTRACT in " ".join(check_out.split())


def test_documented_codes_match_observed_behavior(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The codes named in the documented sentence are the codes ``check`` returns."""
    session = _findings_session(tmp_path)
    clean = _run(["check", str(HEALTHY), "--color", "never"])
    capsys.readouterr()
    findings = _run(["check", str(session), "--format", "claude-code-jsonl", "--color", "never"])
    capsys.readouterr()
    with patch(
        "sesslint.api.check_file",
        side_effect=RuntimeError("simulated internal tool error"),
    ):
        internal = _run(["check", str(HEALTHY), "--color", "never"])
    capsys.readouterr()

    observed = {
        "a clean session exits": clean,
        "a session with findings exits": findings,
        "an internal tool error exits": internal,
    }
    assert observed == {
        "a clean session exits": 0,
        "a session with findings exits": 1,
        "an internal tool error exits": 2,
    }
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for phrase, code in observed.items():
        assert f"{phrase} {code}" in readme
        assert f"{phrase} {code}" in AC02_CONTRACT
