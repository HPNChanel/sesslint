"""Tests for per-rule ``--select`` / ``--ignore`` selection.

Selection filters the profile's ``enabled_rules`` before the check runner
executes, so deselected rules are honestly absent from coverage rather than
post-filtered from output. Unknown codes fail closed with a usage error.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.api import check_file
from sesslint.cli import main
from sesslint.profiles import apply_rule_selection, get_profile

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CORRUPT = FIXTURES / "adapters" / "codex" / "orphan_output.jsonl"  # SL101


def test_apply_rule_selection_select() -> None:
    prof = apply_rule_selection("neutral", select=["SL101"])
    assert prof.enabled_rules == ("SL101",)
    assert prof.name == "neutral"


def test_apply_rule_selection_ignore() -> None:
    prof = apply_rule_selection("neutral", ignore=["sl101", "SL102"])
    assert "SL101" not in prof.enabled_rules
    assert "SL102" not in prof.enabled_rules
    assert len(prof.enabled_rules) == len(get_profile("neutral").enabled_rules) - 2


def test_apply_rule_selection_noop() -> None:
    prof = apply_rule_selection("neutral")
    assert prof.enabled_rules == get_profile("neutral").enabled_rules


def test_apply_rule_selection_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        apply_rule_selection("neutral", select=["SL101"], ignore=["SL102"])


def test_apply_rule_selection_unknown_code() -> None:
    with pytest.raises(ValueError, match="Unknown rule code"):
        apply_rule_selection("neutral", select=["SL999"])


def test_check_file_select_only_runs_selected() -> None:
    report = check_file(CORRUPT, select=["SL101"])
    assert report.counts.by_code == {"SL101": 1}
    assert report.coverage.performed[0].startswith("SL101")


def test_check_file_ignore_suppresses_finding() -> None:
    report = check_file(CORRUPT, ignore=["SL101"])
    assert report.counts.by_code.get("SL101", 0) == 0


def test_cli_select_reports_finding(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", str(CORRUPT), "--select", "SL101", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"] == {"SL101": 1}
    assert code == 1


def test_cli_ignore_suppresses_finding(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", str(CORRUPT), "--ignore", "SL101", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["by_code"].get("SL101", 0) == 0
    assert code == 0


def test_cli_select_ignore_mutually_exclusive() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["check", str(CORRUPT), "--select", "SL101", "--ignore", "SL102"])
    assert exc.value.code == 2


def test_cli_unknown_code_fails(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["check", str(CORRUPT), "--ignore", "SL999"])
    assert exc.value.code == 2
    assert "Unknown rule code" in capsys.readouterr().err


def test_scan_ignore_parity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import shutil

    shutil.copy(CORRUPT, tmp_path / "rollout.jsonl")
    code = main(["scan", str(tmp_path), "--ignore", "SL101", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["invalid"] == 0
    assert data["totals"]["healthy"] == 1
    assert code == 0


def test_scan_select_parity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import shutil

    shutil.copy(CORRUPT, tmp_path / "rollout.jsonl")
    code = main(["scan", str(tmp_path), "--select", "SL101", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["invalid"] == 1
    assert code == 1
