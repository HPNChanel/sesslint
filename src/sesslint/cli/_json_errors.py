"""AC-03: bounded diagnostics and fallback JSON for otherwise silent failures."""

from __future__ import annotations

import argparse
import io
import json
import os
from collections.abc import Sequence
from typing import Any, TextIO


class TrackedStream(io.TextIOBase):
    """Forward writes, tracking presence and at most a bounded diagnostic prefix."""

    def __init__(self, raw: TextIO, *, diagnostic_limit: int = 0) -> None:
        super().__init__()
        self.raw = raw
        self.nonempty = False
        self._limit = diagnostic_limit
        self._diagnostic = ""

    def write(self, s: str) -> int:
        self.nonempty = self.nonempty or bool(s.strip())
        remaining = self._limit - len(self._diagnostic)
        if remaining > 0:
            self._diagnostic += s[:remaining]
        written = self.raw.write(s)
        return len(s) if not isinstance(written, int) else written

    def flush(self) -> None:
        self.raw.flush()

    def isatty(self) -> bool:
        return self.raw.isatty()

    def fileno(self) -> int:
        return self.raw.fileno()

    def writable(self) -> bool:
        return True

    def diagnostic(self) -> str:
        return self._diagnostic.strip()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw, name)


def wants_json(argv: Sequence[str], args: argparse.Namespace | None = None) -> bool:
    """Resolve JSON intent for failures, including pre-parse and context errors."""
    if args is not None:
        if getattr(args, "json", False):
            return True
        output = getattr(args, "output_format", None)
        if output is not None:
            return bool(output == "json")
        if not hasattr(args, "json") and not hasattr(args, "output_format"):
            return False  # Commands without a JSON surface ignore SESSLINT_FORMAT.
    selected: str | None = None
    for index, token in enumerate(argv):
        if token == "--":
            break
        if token == "--json":
            return True
        if token in ("--format", "-f") and index + 1 < len(argv):
            selected = argv[index + 1]
        elif token.startswith("--format="):
            selected = token.partition("=")[2]
        elif token.startswith("-f") and len(token) > 2:
            selected = token[2:]
    return (selected if selected is not None else os.environ.get("SESSLINT_FORMAT")) == "json"


def error_document(message: str) -> str:
    """One ASCII object; surrogate diagnostics cannot break redirected UTF-8 output."""
    safe = message.encode("utf-8", errors="backslashreplace").decode("utf-8")
    return json.dumps({"code": "ERROR", "message": safe, "verdict": "error"}, sort_keys=True)
