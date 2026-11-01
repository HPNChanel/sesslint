"""Guard explicit canonical serialization domains without changing defaults (CX-06)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC_PATH = Path(__file__).resolve().parent.parent / "src" / "sesslint"


def _missing_newline_calls(source: str) -> list[int]:
    tree = ast.parse(source)
    names = {"canonical_json_bytes"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "canonical_json_bytes"
            )

    violations: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_canonical = (isinstance(func, ast.Name) and func.id in names) or (
            isinstance(func, ast.Attribute) and func.attr == "canonical_json_bytes"
        )
        if is_canonical and not any(keyword.arg == "newline" for keyword in node.keywords):
            violations.append(node.lineno)
    return sorted(violations)


def test_runtime_canonical_calls_pass_newline_explicitly() -> None:
    violations = [
        f"{path.relative_to(SRC_PATH)}:{line}"
        for path in sorted(SRC_PATH.rglob("*.py"))
        for line in _missing_newline_calls(path.read_text(encoding="utf-8"))
    ]
    assert not violations, f"canonical_json_bytes calls must pass newline=: {violations}"


@pytest.mark.parametrize(
    "callee",
    ["canonical_json_bytes", "codec.canonical_json_bytes", "_seam_cjb"],
)
@pytest.mark.parametrize("explicit", [False, True])
def test_guard_detects_function_method_and_import_alias(callee: str, explicit: bool) -> None:
    source = "from sesslint._canonical_codec import canonical_json_bytes as _seam_cjb\n"
    source += f"{callee}({{}}, newline=False)" if explicit else f"{callee}({{}})"
    assert _missing_newline_calls(source) == ([] if explicit else [2])
