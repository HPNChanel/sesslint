"""Shared CLI helpers: config folding, output plumbing, error handling."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Final

from sesslint import __version__
from sesslint.api import build_internal_error_envelope
from sesslint.cli._errors import CliError
from sesslint.finding import Finding

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

FORMAT_DISPLAY_NAMES: Final[dict[str, str]] = {
    "canonical": "canonical",
    "claude-code-jsonl": "Claude Code",
    "codex-rollout": "Codex rollout",
    "openai-agents": "OpenAI Agents",
}


def _handle_internal_error(err: Exception, args: argparse.Namespace | None = None) -> int:
    """Handle unexpected internal operational errors per FR-097, FR-098, FR-099.

    Guarantees:
    - Generates a unique, content-free diagnostic ID matching ^ERR-[0-9a-f]{8}$.
    - In JSON mode: outputs a JSON envelope to stdout with verdict='error', code='INTERNAL_ERROR',
      error_id, and message.
    - In human mode: outputs actionable error information to stderr.
    - Never prints raw Python tracebacks to stdout.
    - Never verdicts healthy.
    - Exits with return code 2.
    """
    # CliError is a user-facing usage failure, not an internal fault — let
    # it propagate to the dispatcher's dedicated handler (exit 2).
    if isinstance(err, CliError):
        raise err
    error_id = f"ERR-{secrets.token_hex(4)}"
    is_json = getattr(args, "json", False) if args is not None else False
    if is_json:
        envelope = build_internal_error_envelope(err, error_id=error_id)
        print(json.dumps(envelope, sort_keys=True))
    else:
        print(f"Operational error [{error_id}]: {err}", file=sys.stderr)
    return 2


def should_color(args: argparse.Namespace, stream: Any = sys.stdout) -> bool:
    """Determine whether color output should be enabled."""
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "json", False):
        return False
    if "NO_COLOR" in os.environ and os.environ["NO_COLOR"]:
        return False
    color_opt = getattr(args, "color", "auto")
    if color_opt == "never":
        return False
    if color_opt == "always":
        return True
    return hasattr(stream, "isatty") and bool(stream.isatty())


def _rule_codes_arg(args: argparse.Namespace, name: str) -> list[str] | None:
    """Split a comma-separated --select/--ignore value into a code list, or None."""
    raw = getattr(args, name, None)
    if raw is None:
        return None
    codes = [c.strip() for c in str(raw).split(",") if c.strip()]
    return codes or None


def _load_baseline_arg(args: argparse.Namespace) -> frozenset[str] | None:
    """Load the ``--baseline`` file into a fingerprint set, or None when unset.

    Raises ``BaselineError`` (a ``ValueError``) on missing/malformed files.
    """
    path = getattr(args, "baseline", None)
    if path is None:
        return None
    from sesslint.baseline import load_baseline

    return load_baseline(path)


def _write_baseline_arg(
    ctx: CliContext, args: argparse.Namespace, findings: Iterable[Finding]
) -> None:
    """Write a baseline file for ``--write-baseline`` and note it on stderr."""
    path = getattr(args, "write_baseline", None)
    if path is None:
        return
    from sesslint.baseline import write_baseline

    count = write_baseline(path, findings, created_by=f"sesslint {__version__}")
    ctx.info(f"wrote baseline: {count} fingerprint(s) -> {path}")


def _output_format(args: argparse.Namespace) -> str:
    """Resolve the effective output format: --json wins, else --format."""
    if getattr(args, "json", False):
        return "json"
    return getattr(args, "output_format", None) or "human"


def _read_stdin_bytes(max_file_bytes: int | None = None) -> bytes:
    """Slurp stdin once into a bounded buffer (ux T-06).

    Reads at most ``DEFAULT_MAX_FILE_BYTES + 1`` bytes so callers detect
    oversize exactly (``len(data) > cap``). Binary-mode read avoids Windows
    text-mode newline translation.
    """
    from sesslint.io import DEFAULT_MAX_FILE_BYTES

    limit = DEFAULT_MAX_FILE_BYTES if max_file_bytes is None else max_file_bytes
    if limit <= 0:
        raise ValueError("max_file_bytes must be positive")
    return sys.stdin.buffer.read(limit + 1)
