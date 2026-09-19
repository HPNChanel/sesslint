"""Drift checks for docs/THREAT_MODEL.md (docs-spec/T-03).

Every mitigation must cite an enforcing bound that exists; every hostile
fixture family must map to a threat entry.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "docs" / "THREAT_MODEL.md"
TEXT = DOC.read_text(encoding="utf-8")

_PATH_CITE_RE = re.compile(
    r"`((?:src|tests|docs|fixtures|bench|contrib|AGENTS\.md|"
    r"SECURITY\.md|FIXTURES\.md|RELEASING\.md|README\.md)"
    r"[^`\s:]*)"
)
_SYMBOL_CITE_RE = re.compile(r"`([a-zA-Z_][\w./]*):(\w+)`")
_THREAT_RE = re.compile(r"### (T-\d\d) ")
_RISK_RE = re.compile(r"\| (R-\d\d) \|")


def test_doc_exists_and_has_required_sections() -> None:
    assert DOC.is_file()
    for section in (
        "## 1. Assets",
        "## 2. Adversaries",
        "## 3. Trust boundaries",
        "## 4. Threat catalog",
        "## 6. Declared out-of-scope",
        "## 7. Residual-risk register",
    ):
        assert section in TEXT


def test_threat_and_risk_ids_unique_and_numbered() -> None:
    threats = _THREAT_RE.findall(TEXT)
    risks = _RISK_RE.findall(TEXT)
    assert len(threats) == len(set(threats)) >= 10
    assert len(risks) == len(set(risks)) >= 5


def test_path_citations_resolve() -> None:
    cites = [m for m in _PATH_CITE_RE.findall(TEXT) if "NNNN" not in m]
    assert len(cites) >= 15
    for cite in cites:
        cleaned = cite.rstrip("/").split("{")[0].split(",")[0]
        if cleaned.endswith("/") or not cleaned:
            continue
        assert (REPO_ROOT / cleaned).exists(), f"unresolved citation: {cite}"


def test_symbol_citations_resolve() -> None:
    import ast

    for mod_path, symbol in _SYMBOL_CITE_RE.findall(TEXT):
        if "/" in mod_path or "{" in mod_path or mod_path == "file":
            continue
        mod_name = mod_path[:-3] if mod_path.endswith(".py") else mod_path
        candidates = list(REPO_ROOT.glob(f"src/sesslint/{mod_name}.py"))
        candidates += list(REPO_ROOT.glob(f"src/sesslint/**/{mod_name}.py"))
        assert candidates, f"module not found for citation {mod_path}:{symbol}"
        tree = ast.parse(candidates[0].read_text(encoding="utf-8"))
        names = {
            n.name
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        names |= {
            t.id
            for n in ast.walk(tree)
            if isinstance(n, ast.Assign)
            for t in n.targets
            if isinstance(t, ast.Name)
        }
        names |= {
            n.target.id
            for n in ast.walk(tree)
            if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
        }
        assert symbol in names, f"{mod_path}:{symbol} not found"


def test_hostile_fixture_families_mapped() -> None:
    hostile = REPO_ROOT / "fixtures" / "hostile"
    section = TEXT.split("## 5. Hostile-fixture")[1].split("## 6.")[0]
    for entry in sorted(hostile.iterdir()):
        if entry.name in {"PROVENANCE.json", "EXPECTATIONS.json"}:
            continue
        assert entry.name in section, f"hostile fixture {entry.name} unmapped"


def test_out_of_scope_names_banned_apis() -> None:
    section = TEXT.split("## 6. Declared out-of-scope")[1]
    for token in ("eval", "exec", "pickle", "subprocess"):
        assert token in section


def test_residual_risks_have_rationale() -> None:
    section = TEXT.split("## 7. Residual-risk register")[1].split("## 8.")[0]
    rows = [r for r in section.splitlines() if r.startswith("| R-")]
    assert len(rows) >= 5
    for row in rows:
        cells = [c.strip() for c in row.split("|")]
        assert len(cells) >= 4 and len(cells[3]) > 20, f"thin rationale: {row}"
