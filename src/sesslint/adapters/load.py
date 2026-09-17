"""Format-dispatch loaders for vendor session artifacts.

Vendor-specific imports live here so the repair engine (``sesslint.repair``)
stays vendor-neutral: repair modules dispatch through these helpers by format
id instead of importing vendor adapters directly.
"""

from __future__ import annotations

import io
from pathlib import Path

from sesslint.adapters.detect import (
    FORMAT_CLAUDE_CODE,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_OPENAI_AGENTS,
)
from sesslint.canonical import SessionEvent
from sesslint.finding import Finding


def is_vendor_format(format: str | None) -> bool:
    """Return True when ``format`` names a vendor (non-canonical) adapter."""
    return format in (FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS, FORMAT_CODEX_ROLLOUT)


def load_vendor_events(
    path: str | Path | io.BytesIO,
    format: str | None,
) -> tuple[list[SessionEvent], list[Finding]]:
    """Load canonical events and adapter findings for a vendor format id.

    Raises:
        ValueError: If ``format`` is not a supported vendor format.
    """
    if format == FORMAT_CLAUDE_CODE:
        from sesslint.adapters.claude_code import load_claude_code

        events, findings = load_claude_code(path)
        return list(events), list(findings)
    if format == FORMAT_OPENAI_AGENTS:
        from sesslint.adapters.openai_agents import load_openai_agents

        events, findings = load_openai_agents(path)
        return list(events), list(findings)
    if format == FORMAT_CODEX_ROLLOUT:
        from sesslint.adapters.codex_rollout import load_codex_rollout

        events, findings = load_codex_rollout(path)
        return list(events), list(findings)
    raise ValueError(f"Not a vendor format: {format!r}")


def reload_vendor_bytes(
    format: str,
    data: bytes,
) -> tuple[list[SessionEvent], list[Finding]]:
    """Re-load an emitted vendor artifact through its adapter (honesty gate)."""
    return load_vendor_events(io.BytesIO(data), format)


__all__ = [
    "is_vendor_format",
    "load_vendor_events",
    "reload_vendor_bytes",
]
