"""Docs-drift guard for docs/SPEC.md (docs-spec/T-01).

Two layers:

1. Citation integrity — every ``file.py:symbol`` enforcement cite in the spec
   resolves against the live source (AST-level, no execution), reusing the
   ADAPTER_SDK drift-guard pattern.
2. Vocabulary drift — the normative sets the spec pins (SessionEvent fields,
   kind/actor/execution-state vocabularies, required-field sets, provenance
   exclusions, assurance grades, synthetic-id prefix, schema version) are
   re-derived from the live code and asserted to appear in the document, so
   the spec cannot silently diverge from the registry.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "docs" / "SPEC.md"
SRC = REPO_ROOT / "src" / "sesslint"

_CITE_RE = re.compile(r"`([A-Za-z_][\w./-]*\.py):([A-Za-z_][\w.]*)`")


def _resolve_file(rel: str) -> Path | None:
    for base in (REPO_ROOT, SRC):
        p = base / rel
        if p.is_file():
            return p
    return None


def _names(nodes: list[ast.stmt]) -> dict[str, ast.ClassDef | None]:
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
    if cls is None:
        return True
    inner = _names(cls.body)
    return parts[1] in inner if len(parts) == 2 else True


def _doc() -> str:
    assert SPEC.is_file(), "docs/SPEC.md missing"
    return SPEC.read_text(encoding="utf-8")


def test_spec_exists_versioned_and_cited() -> None:
    content = _doc()
    assert re.search(r"Spec v0\.\d+", content), "spec must carry a v0.x version header"
    assert len(_CITE_RE.findall(content)) >= 10, "spec must cite enforcement points"


def test_all_cited_symbols_resolve() -> None:
    for rel, dotted in _CITE_RE.findall(_doc()):
        path = _resolve_file(rel)
        assert path is not None, f"cited file not found: {rel}"
        assert _symbol_resolves(path, dotted), f"{rel}:{dotted} does not resolve"


def test_every_session_event_field_documented() -> None:
    from sesslint.canonical import SessionEvent

    content = _doc()
    for f in dataclasses.fields(SessionEvent):
        assert re.search(rf"`{re.escape(f.name)}`", content), (
            f"SessionEvent field '{f.name}' not documented in SPEC.md"
        )


def test_vocabularies_match_live_registry() -> None:
    from sesslint.canonical import (
        KNOWN_EVENT_FIELDS,
        REQUIRED_EVENT_FIELDS,
        SCHEMA_VERSION,
        VALID_ACTORS,
        VALID_EXECUTION_STATES,
        VALID_KINDS,
    )

    content = _doc()
    for token in sorted(VALID_KINDS | VALID_ACTORS | VALID_EXECUTION_STATES):
        assert token in content, f"vocabulary '{token}' missing from SPEC.md"
    for field_name in sorted(KNOWN_EVENT_FIELDS | REQUIRED_EVENT_FIELDS):
        assert re.search(rf"`{re.escape(field_name)}`", content), (
            f"event field '{field_name}' missing from SPEC.md"
        )
    assert SCHEMA_VERSION in content


def test_provenance_exclusion_set_matches() -> None:
    from sesslint._canonical_codec import _PROVENANCE_FIELD_NAMES

    content = _doc()
    for name in sorted(_PROVENANCE_FIELD_NAMES):
        assert f"`{name}`" in content, f"provenance exclusion '{name}' undocumented"


def test_adapter_level_guarantees_documented() -> None:
    from sesslint.adapters.canonical import REQUIRED_EVENT_KEYS
    from sesslint.adapters.synthetic import SYNTHETIC_ID_PREFIX

    content = _doc()
    for key in REQUIRED_EVENT_KEYS:
        assert f"`{key}`" in content
    assert SYNTHETIC_ID_PREFIX in content
    assert "<adapter>:<ordinal>:<8-hex" in content


def test_assurance_grades_documented() -> None:
    content = _doc()
    for grade in ("A0", "A1", "A2", "A3", "A4"):
        assert f"`{grade}`" in content, f"assurance grade {grade} undocumented"
