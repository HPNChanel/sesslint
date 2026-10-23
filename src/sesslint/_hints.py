"""Copy-paste runnable command hints for operator-facing output (AC-04).

A hint printed by ``check``, ``export`` or a refusal must run exactly as
printed. ``sesslint repair`` writes only with ``--output`` (the planning
modes aside), a stdin source is spelled ``-``, and an argument that a shell
would split is double-quoted only when its characters are literal in bash,
zsh, PowerShell and cmd. Other arguments produce no command: shell-specific
escaping cannot be guessed safely. The suggested output name is relative to
the working directory and never sits next to the source, so a hint never proposes a
write into an agent-owned session directory; ``repair`` refuses to overwrite
an existing output either way.
"""

from __future__ import annotations

import re
from typing import Final

STDIN_LABEL: Final[str] = "<stdin>"
"""Source label the readers record for ``-`` (stdin) input."""

DEFAULT_OUTPUT_NAME: Final[str] = "repaired.jsonl"
"""Suggested ``--output`` when the source has no usable file name."""

# Characters no supported shell (bash, zsh, PowerShell, cmd) splits on or
# expands inside an unquoted word. ',' and '@' are absent on purpose:
# PowerShell reads them as array and splat syntax.
_SHELL_SAFE: Final[re.Pattern[str]] = re.compile(r"[\w+=:./~-]+")
_QUOTABLE: Final[re.Pattern[str]] = re.compile(r"[\w +=:./~,@;()\[\]{}-]+")
MANUAL_HINT: Final[str] = (
    "No command suggested: the path or option needs shell-specific quoting. "
    "Consult sesslint --help and supply the arguments manually."
)


def _quote(value: str) -> str | None:
    if _SHELL_SAFE.fullmatch(value):
        return value
    if _QUOTABLE.fullmatch(value):
        return f'"{value}"'
    return None


def hint_arg(value: str) -> str | None:
    """Return ``value`` as one shell word, double-quoted only when needed.

    A word starting with ``-`` (other than ``-`` itself) gains a ``./``
    prefix so the CLI never parses a file name as an option. Return None
    when a portable literal argument cannot be represented safely.
    """
    if value.startswith("-") and value != "-":
        value = f"./{value}"
    return _quote(value)


def hint_options(
    adapter: str | None = None, profile: str | None = None
) -> tuple[str | None, ...]:
    """Return the ``--adapter``/``--profile`` words a follow-up command repeats.

    A suggested command must read the session the way the command that
    printed it did, so an explicit adapter or profile carries over; the
    defaults (``auto``, ``neutral``) are left out.
    """
    words: list[str | None] = []
    if adapter and adapter != "auto":
        words += ["--adapter", _quote(adapter)]
    if profile and profile != "neutral":
        words += ["--profile", _quote(profile)]
    return tuple(words)


def hint_source(path: str) -> str | None:
    """Spell a source path for a command hint (``-`` for stdin)."""
    return "-" if path == STDIN_LABEL else hint_arg(path)


def repaired_output_name(path: str) -> str:
    """Return the suggested ``--output`` for a repair hint on ``path``.

    ``<stem>.repaired<suffix>`` built from the source's base name and
    relative to the working directory. Stdin and nameless sources get
    ``repaired.jsonl``.
    """
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if name in ("", "-", "~", ".", "..", STDIN_LABEL):
        return DEFAULT_OUTPUT_NAME
    stem, dot, suffix = name.rpartition(".")
    if not dot or not stem:
        return f"{name}.repaired"
    return f"{stem}.repaired.{suffix}"


def command_hint(*words: str | None) -> str | None:
    """Join shell-ready words, refusing the entire command if any is unsafe."""
    if any(word is None for word in words):
        return None
    return " ".join(word for word in words if word is not None)


def hint_instruction(command: str | None, *, verb: str = "Run") -> str:
    """Render a command or content-free manual guidance when none is safe."""
    return MANUAL_HINT if command is None else f"{verb} '{command}'"


def repair_hint(path: str, *options: str | None) -> str | None:
    """Return a ``sesslint repair`` command for ``path`` that runs as printed.

    ``options`` are shell-ready words (see ``hint_options``).
    """
    words = [
        "sesslint",
        "repair",
        hint_source(path),
        "--output",
        hint_arg(repaired_output_name(path)),
        *options,
    ]
    return command_hint(*words)


def check_hint(path: str, *options: str | None) -> str | None:
    """Return a read-only ``sesslint check`` command for ``path``."""
    return command_hint("sesslint", "check", hint_source(path), *options)


def repair_plan_hint(path: str) -> str | None:
    """Return a read-only ``sesslint repair --dry-run`` command for ``path``."""
    return command_hint("sesslint", "repair", hint_source(path), "--dry-run")
