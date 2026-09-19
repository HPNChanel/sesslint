"""Format-dispatch loaders for vendor session artifacts.

Vendor-specific imports live here so the repair engine (``sesslint.repair``)
stays vendor-neutral: repair modules dispatch through these helpers by format
id instead of importing vendor adapters directly.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Final

from sesslint.adapters.detect import (
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_CODEX_ROLLOUT,
    FORMAT_OPENAI_AGENTS,
)
from sesslint.canonical import SessionEvent
from sesslint.finding import Finding

# Single authority mapping resolved format ids to the short keys used inside
# profile ``allowed_adapters`` tuples. Both ``api.check_file`` and the
# directory scanner consume this map so adapter support cannot drift between
# call sites (DW-T-12 regression fix).
FORMAT_PROFILE_KEYS: Final[dict[str, str]] = {
    FORMAT_CLAUDE_CODE: "claude",
    FORMAT_OPENAI_AGENTS: "openai",
    FORMAT_CODEX_ROLLOUT: "codex",
    FORMAT_CANONICAL: "canonical",
}


def profile_key_for_format(format: str | None) -> str | None:
    """Return the profile ``allowed_adapters`` key for a resolved format id.

    Unknown format ids pass through unchanged so the caller's membership check
    still fails closed.
    """
    if format is None:
        return None
    return FORMAT_PROFILE_KEYS.get(format, format)


def is_vendor_format(format: str | None) -> bool:
    """Return True when ``format`` names a vendor (non-canonical) adapter."""
    return format in (FORMAT_CLAUDE_CODE, FORMAT_OPENAI_AGENTS, FORMAT_CODEX_ROLLOUT)


def load_vendor_events(
    path: str | Path | io.BytesIO,
    format: str | None,
) -> tuple[list[SessionEvent], list[Finding]]:
    """Load canonical events and adapter findings for a vendor format id.

    The returned event list is the adapter's own object: adapters that attach
    ``.source`` metadata (``EventList``) keep it — it is never re-wrapped in a
    plain ``list`` that would strip the metadata.

    Raises:
        ValueError: If ``format`` is not a supported vendor format.
    """
    events: list[SessionEvent]
    if format == FORMAT_CLAUDE_CODE:
        from sesslint.adapters.claude_code import load_claude_code

        events, findings = load_claude_code(path)
        return events, list(findings)
    if format == FORMAT_OPENAI_AGENTS:
        from sesslint.adapters.openai_agents import load_openai_agents

        events, findings = load_openai_agents(path)
        return events, list(findings)
    if format == FORMAT_CODEX_ROLLOUT:
        from sesslint.adapters.codex_rollout import load_codex_rollout

        events, findings = load_codex_rollout(path)
        return events, list(findings)
    raise ValueError(f"Not a vendor format: {format!r}")


def load_events_for_format(
    path: str | Path | io.BytesIO,
    format: str | None,
) -> tuple[list[SessionEvent], list[Finding]]:
    """Load canonical events and adapter findings for any supported format id.

    Single authoritative loader shared by check/scan/export/verify/bundle so a
    new adapter only needs registering here — not in per-call-site dispatch
    chains. Preserves adapter ``.source`` metadata like ``load_vendor_events``.

    Raises:
        ValueError: If ``format`` is not a supported format.
    """
    if format == FORMAT_CANONICAL:
        from sesslint.adapters.canonical import load_canonical

        events, findings = load_canonical(path)
        return events, list(findings)
    if is_vendor_format(format):
        return load_vendor_events(path, format)
    raise ValueError(f"Unsupported format: {format!r}")


def reload_vendor_bytes(
    format: str,
    data: bytes,
) -> tuple[list[SessionEvent], list[Finding]]:
    """Re-load an emitted vendor artifact through its adapter (honesty gate)."""
    return load_vendor_events(io.BytesIO(data), format)


__all__ = [
    "FORMAT_PROFILE_KEYS",
    "is_vendor_format",
    "load_events_for_format",
    "load_vendor_events",
    "profile_key_for_format",
    "reload_vendor_bytes",
]
