"""Tests for sesslint formats and version commands (TASK-023)."""

from __future__ import annotations

import json

import pytest

from sesslint._version import CLI_VERSION, get_version_info
from sesslint.cli import main


def test_formats_human(capsys: pytest.CaptureFixture[str]) -> None:
    """formats command in human mode prints table with header and all 3 adapters."""
    code = main(["formats"])
    assert code == 0
    captured = capsys.readouterr()
    assert "NAME" in captured.out
    assert "DEFAULT PROFILE" in captured.out
    assert "canonical" in captured.out
    assert "claude-code-jsonl" in captured.out
    assert "openai-agents" in captured.out
    assert captured.err == ""


def test_formats_json(capsys: pytest.CaptureFixture[str]) -> None:
    """formats --json returns JSON array of adapter metadata."""
    code = main(["formats", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""

    items = json.loads(captured.out)
    assert isinstance(items, list)
    assert len(items) == 3

    names = {item["name"] for item in items}
    assert names == {"canonical", "claude-code-jsonl", "openai-agents"}

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


def test_formats_adapters_subset_of_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Adapter names from formats --json are a subset of version adapters keys."""
    main(["formats", "--json"])
    formats_items = json.loads(capsys.readouterr().out)
    format_names = {item["name"] for item in formats_items}

    main(["version", "--json"])
    version_data = json.loads(capsys.readouterr().out)
    version_adapter_keys = set(version_data["adapters"].keys())

    assert format_names.issubset(version_adapter_keys)
