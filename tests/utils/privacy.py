"""Privacy and PII scanning test utilities protecting against data and credential leaks."""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

KNOWN_PII_SAMPLES: tuple[str, ...] = (
    "alice@example.com",
    "bob.smith@company.org",
    "+1-555-0100",
    "555-0199",
    "sk-proj-testkey1234567890",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_1234567890abcdefghijklmnopqrstuvwx",
)

# Regex markers for leaked email addresses, credentials, and tokens
_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
_CREDENTIAL_PREFIXES = ("sk-", "ghp_", "gho_", "glpat-", "AKIA", "bearer ")


def assert_no_pii(
    obj: Any,
    *,
    samples: Collection[str] = KNOWN_PII_SAMPLES,
    path: str = "root",
) -> None:
    """Recursively scan an object (string, mapping, sequence, dataclass) for PII and secrets.

    Args:
        obj: The data structure to inspect.
        samples: Explicit known forbidden PII / credential samples.
        path: Path identifier indicating current object traversal location.

    Raises:
        AssertionError: If any PII pattern, credential marker, or sample is detected.
    """
    if isinstance(obj, str):
        # 1. Exact sample matches
        for sample in samples:
            if sample in obj:
                raise AssertionError(f"PII sample detected at {path}: found {sample!r} in {obj!r}")

        # 2. Email pattern check
        email_match = _EMAIL_REGEX.search(obj)
        if email_match:
            raise AssertionError(
                f"Email address pattern detected at {path}: {email_match.group(0)!r}"
            )

        # 3. Credential marker check
        lower_obj = obj.lower()
        for prefix in _CREDENTIAL_PREFIXES:
            if prefix.lower() in lower_obj:
                raise AssertionError(
                    f"Credential marker detected at {path}: found prefix {prefix!r} in {obj!r}"
                )
        return

    if isinstance(obj, Mapping):
        for k, v in obj.items():
            assert_no_pii(str(k), samples=samples, path=f"{path}.<key:{k}>")
            assert_no_pii(v, samples=samples, path=f"{path}.{k}")
        return

    if isinstance(obj, (list, tuple, set)):
        for idx, item in enumerate(obj):
            assert_no_pii(item, samples=samples, path=f"{path}[{idx}]")
        return

    if is_dataclass(obj) and not isinstance(obj, type):
        assert_no_pii(asdict(obj), samples=samples, path=f"{path}<dataclass>")
        return


def assert_fixtures_pii_free(root: Path = Path("fixtures")) -> None:
    """Scan all text and data files in root directory to ensure zero PII or credential leaks.

    Args:
        root: Root directory of fixtures.

    Raises:
        AssertionError: If any fixture file contains forbidden PII or credential markers.
    """
    if not root.exists():
        raise FileNotFoundError(f"Fixtures directory not found: {root}")

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        # Only inspect session and data files
        if file_path.suffix in (".json", ".jsonl", ".txt"):
            content = file_path.read_text(encoding="utf-8", errors="replace")
            assert_no_pii(
                content,
                samples=KNOWN_PII_SAMPLES,
                path=str(file_path).replace("\\", "/"),
            )
