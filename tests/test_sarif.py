"""Tests for SARIF 2.1.0 output (``--output-format sarif``).

SARIF documents are deterministic and content-free: rule metadata comes from
the code registry, results carry codes/severities/paths/lines/fingerprints
only — never session payload content.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from sesslint.sarif import SARIF_VERSION, build_sarif

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CORRUPT = FIXTURES / "adapters" / "codex" / "orphan_output.jsonl"  # SL101
HEALTHY = FIXTURES / "canonical" / "minimal.json"


def _load_sarif(capsys: pytest.CaptureFixture[str]) -> dict:
    return json.loads(capsys.readouterr().out)


def test_check_sarif_structure(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", str(CORRUPT), "--output-format", "sarif"])
    doc = _load_sarif(capsys)
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 27
    assert [r["id"] for r in rules] == sorted(r["id"] for r in rules)
    results = run["results"]
    assert len(results) == 1
    result = results[0]
    assert result["ruleId"] == "SL101"
    assert result["level"] == "error"
    assert result["partialFingerprints"]["sesslint/finding-fingerprint"]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri  # forward-slash normalized
    assert code == 1


def test_check_sarif_clean_file_empty_results(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", str(HEALTHY), "--output-format", "sarif"])
    doc = _load_sarif(capsys)
    assert doc["runs"][0]["results"] == []
    assert code == 0


def test_scan_sarif_aggregates_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import shutil

    shutil.copy(CORRUPT, tmp_path / "rollout.jsonl")
    code = main(["scan", str(tmp_path), "--output-format", "sarif"])
    doc = _load_sarif(capsys)
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "SL101"
    assert code == 1


def test_json_and_output_format_mutually_exclusive() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["check", str(CORRUPT), "--json", "--output-format", "sarif"])
    assert exc.value.code == 2


def test_sarif_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    main(["check", str(CORRUPT), "--output-format", "sarif"])
    first = capsys.readouterr().out
    main(["check", str(CORRUPT), "--output-format", "sarif"])
    second = capsys.readouterr().out
    assert first == second


def test_sarif_content_free(capsys: pytest.CaptureFixture[str]) -> None:
    """SARIF output must not carry session payload fields."""
    main(["check", str(CORRUPT), "--output-format", "sarif"])
    doc = _load_sarif(capsys)
    blob = json.dumps(doc)
    for forbidden in ("payload", "tool_calls", "arguments"):
        assert forbidden not in blob


def test_build_sarif_level_mapping() -> None:
    doc = build_sarif([], tool_version="0.0.0-test")
    levels = {
        r["id"]: r["defaultConfiguration"]["level"]
        for r in doc["runs"][0]["tool"]["driver"]["rules"]
    }
    assert levels["SL003"] == "warning"
    assert levels["SL101"] == "error"
    assert set(levels.values()) <= {"error", "warning", "note"}
