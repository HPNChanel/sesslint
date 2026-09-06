"""Static audit verifying zero dynamic code evaluation in src/sesslint (TASK-027).

Guarantees (FR-012, FR-090):
- Zero use of eval(), exec(), __import__, importlib, pickle, marshal, subprocess.
- Zero runtime imports of development-only test dependencies (hypothesis, pytest).
"""

from __future__ import annotations

import re
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "sesslint"

FORBIDDEN_CALL_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\b__import__\b"),
    re.compile(r"\bimportlib\b"),
    re.compile(r"\bpickle\b"),
    re.compile(r"\bmarshal\b"),
    re.compile(r"\byaml\.load\b"),
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bos\.system\b"),
]

FORBIDDEN_DEV_IMPORTS = [
    re.compile(r"\bimport\s+hypothesis\b"),
    re.compile(r"\bfrom\s+hypothesis\b"),
    re.compile(r"\bimport\s+pytest\b"),
    re.compile(r"\bfrom\s+pytest\b"),
]


def test_zero_dynamic_eval_or_exec() -> None:
    """Audit all source files in src/sesslint for forbidden execution constructs."""
    violations: list[str] = []

    for py_file in SRC_DIR.rglob("*.py"):
        lines = py_file.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            # Ignore comments
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern in FORBIDDEN_CALL_PATTERNS:
                if pattern.search(line):
                    rel = py_file.relative_to(SRC_DIR)
                    violations.append(
                        f"{rel}:{idx} matches forbidden pattern {pattern.pattern}: {line.strip()}"
                    )

    assert not violations, "Forbidden dynamic code evaluation calls found:\n" + "\n".join(
        violations
    )


def test_zero_dev_dependencies_in_runtime_source() -> None:
    """Audit that development-only libraries are never imported in production code."""
    violations: list[str] = []

    for py_file in SRC_DIR.rglob("*.py"):
        lines = py_file.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern in FORBIDDEN_DEV_IMPORTS:
                if pattern.search(line):
                    rel = py_file.relative_to(SRC_DIR)
                    violations.append(f"{rel}:{idx} imports dev-only dependency: {line.strip()}")

    assert not violations, "Dev-only imports detected in runtime source:\n" + "\n".join(violations)
