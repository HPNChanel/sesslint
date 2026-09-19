"""Tests for scripts/shape_inventory.py (adapters T-01)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "shape_inventory.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("shape_inventory", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def script_mod():
    return _load_script()


def test_script_imports_live_adapter_tables(script_mod) -> None:
    """The tool's known-sets come from the adapters, not copies (drift guard)."""
    from sesslint.adapters.claude_code import TYPE_MAP
    from sesslint.adapters.codex_rollout import (
        ENVELOPE_OPAQUE_TYPES,
        RESPONSE_ITEM_TYPE_MAP,
    )

    assert set(TYPE_MAP) <= script_mod._KNOWN["claude-code-jsonl"]["types"]
    assert ENVELOPE_OPAQUE_TYPES <= script_mod._KNOWN["codex-rollout"]["types"]
    assert set(RESPONSE_ITEM_TYPE_MAP) <= script_mod._KNOWN["codex-rollout"]["payload_types"]


def test_inventory_fixtures_tree_content_free(script_mod, tmp_path: Path) -> None:
    """Doc shape: schema, histograms, unknown diff — names+counts only."""
    src = tmp_path / "s.jsonl"
    src.write_text(
        '{"timestamp":"2026-01-01T00:00:00Z","type":"session_meta","ordinal":0,"payload":{"session_id":"x"}}\n'
        '{"timestamp":"2026-01-01T00:00:01Z","type":"response_item","ordinal":1,"payload":{"type":"message","role":"user","content":[{"text":"hi"}]}}\n'
        '{"timestamp":"2026-01-01T00:00:02Z","type":"mystery_env","ordinal":2,"payload":{"weird":true}}\n',
        encoding="utf-8",
    )
    doc = script_mod.inventory([tmp_path])
    assert doc["schema"] == "sesslint.shape-inventory/v1"
    assert doc["files"]["scanned"] == 1
    types = doc["types"]["codex-rollout"]
    assert types["session_meta"] == 1
    assert types["response_item"] == 1
    assert types["mystery_env"] == 1
    assert doc["payload_types"]["codex-rollout"]["message"] == 1
    # Drift diff: the foreign envelope type surfaces, payload value never does.
    assert doc["unknown"]["codex-rollout"]["unknown_types"] == ["mystery_env"]
    blob = json.dumps(doc)
    assert '"hi"' not in blob
    assert "true" not in blob or '"weird": true' not in blob


def test_deterministic_output(script_mod, tmp_path: Path) -> None:
    """Identical trees produce byte-identical JSON."""
    (tmp_path / "a.jsonl").write_text('{"type":"summary"}\n', encoding="utf-8")
    a = json.dumps(script_mod.inventory([tmp_path]), sort_keys=True)
    b = json.dumps(script_mod.inventory([tmp_path]), sort_keys=True)
    assert a == b


def test_unknown_only_and_known_only_modes(script_mod, capsys, tmp_path: Path) -> None:
    """CLI flags filter the emitted surface."""
    (tmp_path / "a.jsonl").write_text('{"type":"summary"}\n', encoding="utf-8")
    rc = script_mod.main([str(tmp_path), "--json", "--unknown-only"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) <= {"schema", "unknown", "truncated"}
    rc = script_mod.main([str(tmp_path), "--json", "--known-only"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "unknown" not in out


def test_no_values_in_output(script_mod, tmp_path: Path) -> None:
    """Payload strings never leak into the document."""
    secret = "SUPER_SECRET_CANARY_VALUE_9f4e"
    (tmp_path / "a.jsonl").write_text(
        json.dumps(
            {
                "type": "session_meta",
                "timestamp": "2026-01-01T00:00:00Z",
                "ordinal": 0,
                "payload": {"session_id": secret, "cli_version": "1.0"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    doc_json = json.dumps(script_mod.inventory([tmp_path]))
    assert secret not in doc_json
    assert "session_id" in doc_json  # key names are emitted; values are not
