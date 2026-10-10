"""Tests for sesslint doctor (adapter info) and version commands (TASK-023)."""

from __future__ import annotations

import json

import pytest

from sesslint._version import CLI_VERSION, get_version_info
from sesslint.cli import main


def test_doctor_human_lists_adapters(capsys: pytest.CaptureFixture[str]) -> None:
    """doctor in human mode prints an adapters section with all 4 adapters."""
    code = main(["doctor"])
    assert code == 0
    captured = capsys.readouterr()
    assert "adapters:" in captured.out
    assert "canonical" in captured.out
    assert "claude-code-jsonl" in captured.out
    assert "codex-rollout" in captured.out
    assert "openai-agents" in captured.out
    assert captured.err == ""


def test_doctor_json_adapter_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    """doctor --json returns adapter metadata objects."""
    code = main(["doctor", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""

    data = json.loads(captured.out)
    items = data["adapters"]
    assert isinstance(items, list)
    assert len(items) == 4

    names = {item["name"] for item in items}
    assert names == {"canonical", "claude-code-jsonl", "codex-rollout", "openai-agents"}

    for item in items:
        assert "default_profile" in item
        assert "description" in item
        assert "versions_supported" in item
        assert isinstance(item["versions_supported"], list)


def test_version_human(capsys: pytest.CaptureFixture[str]) -> None:
    """version command prints human summary with CLI, schema, adapter, and profile info."""
    code = main(["version"])
    assert code == 0
    captured = capsys.readouterr()
    assert f"SessLint CLI: {CLI_VERSION}" in captured.out
    assert "session:" in captured.out
    assert "report:" in captured.out
    assert "manifest:" in captured.out
    assert "canonical:" in captured.out
    assert "neutral:" in captured.out
    assert captured.err == ""


def test_version_json(capsys: pytest.CaptureFixture[str]) -> None:
    """version --json returns structured version object matching get_version_info()."""
    code = main(["version", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""

    data = json.loads(captured.out)
    expected = get_version_info()
    assert data == expected
    assert data["cli"] == CLI_VERSION
    assert "schema_session" in data
    assert "schema_report" in data
    assert "schema_manifest" in data
    assert "adapters" in data
    assert "profiles" in data


def test_doctor_adapters_subset_of_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Adapter names from doctor --json are a subset of version adapters keys."""
    main(["doctor", "--json"])
    doctor_data = json.loads(capsys.readouterr().out)
    format_names = {item["name"] for item in doctor_data["adapters"]}

    main(["version", "--json"])
    version_data = json.loads(capsys.readouterr().out)
    version_adapter_keys = set(version_data["adapters"].keys())

    assert format_names.issubset(version_adapter_keys)
