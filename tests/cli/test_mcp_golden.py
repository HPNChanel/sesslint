"""Byte-identity golden for the MCP ``2025-06-18`` stdio server (CL-07).

``fixtures/mcp/2025-06-18`` holds request lines and the exact response bytes
recorded from the server over stdio *before* ``2026-07-28`` support landed.
A client that negotiates ``2025-06-18`` must keep getting those bytes.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from sesslint._version import CLI_VERSION
from sesslint.mcp_server import serve

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GOLDEN = REPO_ROOT / "fixtures" / "mcp" / "2025-06-18"


def _expected() -> bytes:
    recorded = json.loads((GOLDEN / "PROVENANCE.json").read_text(encoding="utf-8"))[
        "recorded_cli_version"
    ]
    raw = (GOLDEN / "responses.jsonl").read_bytes()
    # serverInfo.version tracks the release; every other byte is pinned.
    return raw.replace(f'"version": "{recorded}"'.encode(), f'"version": "{CLI_VERSION}"'.encode())


def test_golden_provenance_is_synthetic() -> None:
    prov = json.loads((GOLDEN / "PROVENANCE.json").read_text(encoding="utf-8"))
    assert prov["contains_real_data"] is False


def test_2025_06_18_responses_are_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    """Basic/Lifecycle 2025-06-18: legacy handshake output must not change."""
    monkeypatch.chdir(REPO_ROOT)  # request paths are repo-relative
    out = io.BytesIO()
    rc = serve(io.BytesIO((GOLDEN / "requests.jsonl").read_bytes()), out)
    assert rc == 0
    assert out.getvalue() == _expected()
