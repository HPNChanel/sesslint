"""SessLint format adapters package.

Provides input adapters converting vendor-specific session logs (Claude Code JSONL,
OpenAI Agents SDK export, etc.) into the canonical session event graph (sesslint.session/v1).
"""

from __future__ import annotations

from sesslint.adapters.canonical import (
    detect_canonical,
    dump_canonical,
    load_canonical,
    load_canonical_session,
)
from sesslint.adapters.claude_code import (
    CanonicalEvent,
    detect_claude_code,
    load_claude_code,
    load_claude_code_session,
)
from sesslint.adapters.detect import (
    CONFIDENCE_MIN,
    FORMAT_AUTO,
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    MARGIN_MIN,
    SNIFF_BYTES,
    SUPPORTED_FORMATS,
    VALID_FORMAT_OPTIONS,
    DetectionResult,
    detect_format,
    resolve_format,
    to_source_block,
)
from sesslint.adapters.openai_agents import (
    EventList,
    SourceMetadata,
    detect_openai_agents,
    load_openai_agents,
    load_openai_agents_session,
)

__all__ = [
    "CONFIDENCE_MIN",
    "CanonicalEvent",
    "DetectionResult",
    "EventList",
    "FORMAT_AUTO",
    "FORMAT_CANONICAL",
    "FORMAT_CLAUDE_CODE",
    "FORMAT_OPENAI_AGENTS",
    "MARGIN_MIN",
    "SNIFF_BYTES",
    "SUPPORTED_FORMATS",
    "SourceMetadata",
    "VALID_FORMAT_OPTIONS",
    "detect_canonical",
    "detect_claude_code",
    "detect_format",
    "detect_openai_agents",
    "dump_canonical",
    "load_canonical",
    "load_canonical_session",
    "load_claude_code",
    "load_claude_code_session",
    "load_openai_agents",
    "load_openai_agents_session",
    "resolve_format",
    "to_source_block",
]
