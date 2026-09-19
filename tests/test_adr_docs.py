"""Drift checks for docs/adr/ (docs-spec/T-02).

ADRs cite pinning tests/files; if those move, the citation goes stale.
This suite keeps citations resolvable and the index honest.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ADR_DIR = REPO_ROOT / "docs" / "adr"
ADR_FILES = sorted(ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md"))

_STATUS_RE = re.compile(r"^- Status: (accepted|superseded-by-\d{4})$", re.M)
_PATH_CITE_RE = re.compile(
    r"`((?:src|tests|docs|fixtures|AGENTS\.md|README\.md|"
    r"pyproject\.toml|FIXTURES\.md)[^`\s:]*)"
)


def _adr_text(name: str) -> str:
    return (ADR_DIR / name).read_text(encoding="utf-8")


def test_eight_seed_adrs_exist() -> None:
    assert len(ADR_FILES) >= 8
    numbers = {f.name[:4] for f in ADR_FILES}
    assert numbers >= {f"000{i}" for i in range(1, 9)}


def test_every_adr_has_status_and_sections() -> None:
    for f in ADR_FILES:
        text = f.read_text(encoding="utf-8")
        assert _STATUS_RE.search(text), f"{f.name}: missing/invalid status"
        for section in (
            "## Context",
            "## Decision",
            "## Consequences",
            "## Alternatives rejected",
            "## Evidence",
        ):
            assert section in text, f"{f.name}: missing {section}"


def test_no_proposed_status_parking() -> None:
    for f in ADR_FILES:
        assert "Status: proposed" not in f.read_text(encoding="utf-8")


def test_adr_path_citations_resolve() -> None:
    for f in ADR_FILES:
        text = f.read_text(encoding="utf-8")
        cites = [m for m in _PATH_CITE_RE.findall(text) if not m.endswith("*") and "NNNN" not in m]
        assert cites, f"{f.name}: no file citations"
        for cite in cites:
            target = REPO_ROOT / cite.rstrip("/")
            assert target.exists() or cite.endswith("/"), f"{f.name}: unresolved citation {cite}"


def test_index_lists_every_adr() -> None:
    index = _adr_text("README.md")
    for f in ADR_FILES:
        assert f.name in index, f"index missing {f.name}"


def test_index_status_vocabulary_documented() -> None:
    index = _adr_text("README.md")
    assert "accepted" in index and "superseded-by-" in index
    assert "proposed" in index  # explicitly banned, documented


def test_template_exists() -> None:
    assert (ADR_DIR / "TEMPLATE.md").is_file()
