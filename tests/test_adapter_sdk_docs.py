"""Docs-drift guard for docs/ADAPTER_SDK.md (adapters-coverage/T-02).

Every normative claim in the Adapter SDK contract cites its enforcing code as
``file.py:symbol``. This test asserts every cited file exists and every cited
symbol resolves (AST-level, no code execution), so the doc cannot ossify
against renames/removals.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SDK_DOC = REPO_ROOT / "docs" / "ADAPTER_SDK.md"
SRC = REPO_ROOT / "src" / "sesslint"

# `path.py:symbol` or `path.py:symbol.attr` citations in the doc.
_CITE_RE = re.compile(r"`([A-Za-z_][\w./-]*\.py):([A-Za-z_][\w.]*)`")


def _resolve_file(rel: str) -> Path | None:
    """Resolve a cited path: bare module names live under src/sesslint."""
    for base in (REPO_ROOT, SRC):
        p = base / rel
        if p.is_file():
            return p
    return None


def _names(nodes: list[ast.stmt]) -> dict[str, ast.ClassDef | None]:
    """Map top-level (or class-body) names to their ClassDef, if any."""
    out: dict[str, ast.ClassDef | None] = {}
    for node in nodes:
        if isinstance(node, ast.ClassDef):
            out[node.name] = node
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = None
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = None
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out[node.target.id] = None
    return out


def _symbol_resolves(path: Path, dotted: str) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    table = _names(tree.body)
    parts = dotted.split(".")
    if parts[0] not in table:
        return False
    cls = table[parts[0]]
    if len(parts) == 1:
        return True
    if cls is None:  # attribute access on a non-class symbol: accept lazily
        return True
    inner = _names(cls.body)
    return parts[1] in inner if len(parts) == 2 else True


def _citations() -> list[tuple[str, str]]:
    return _CITE_RE.findall(SDK_DOC.read_text(encoding="utf-8"))


def test_sdk_doc_exists_and_has_citations() -> None:
    assert SDK_DOC.is_file(), "docs/ADAPTER_SDK.md missing"
    assert len(_citations()) >= 8, "SDK doc must cite enforcement points"


def test_all_cited_files_exist() -> None:
    for rel, _sym in _citations():
        assert _resolve_file(rel) is not None, f"cited file not found: {rel}"


def test_all_cited_symbols_resolve() -> None:
    for rel, dotted in _citations():
        path = _resolve_file(rel)
        assert path is not None
        assert _symbol_resolves(path, dotted), f"{rel}:{dotted} does not resolve"


def test_file_only_cited_paths_exist() -> None:
    """Non-`:symbol` repo paths referenced inline must also resolve."""
    content = SDK_DOC.read_text(encoding="utf-8")
    for rel in re.findall(r"`((?:tests|scripts|src|fixtures|docs)/[\w./-]+)`", content):
        assert (REPO_ROOT / rel.rstrip("/")).exists(), f"cited path not found: {rel}"
