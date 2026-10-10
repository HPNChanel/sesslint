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
from sesslint.adapters.codex_rollout import (
    detect_codex_rollout,
    load_codex_rollout,
    load_codex_rollout_session,
)
from sesslint.adapters.detect import (
    CONFIDENCE_MIN,
    FORMAT_AUTO,
    FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE,
    FORMAT_CODEX_ROLLOUT,
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
    MAX_PROJECTED_CHECKPOINTS,
    MAX_PROJECTED_RUN_STATE_KEYS,
    EventList,
    SourceMetadata,
    detect_openai_agents,
    load_openai_agents,
    load_openai_agents_session,
    project_run_state,
)
from sesslint.adapters.safe_value import (
    safe_discriminator,
    safe_type_value,
)
from sesslint.adapters.synthetic import (
    SYNTHETIC_ID_PREFIX,
    SyntheticIdCollisionGuard,
    is_synthetic_id,
    synthetic_event_id,
)


def supported_adapters() -> list[dict[str, object]]:
    """Return supported-adapter metadata rows (name, profile, description, versions)."""
    from sesslint.adapters.canonical import SUPPORTED_CANONICAL_VERSIONS
    from sesslint.adapters.claude_code import SUPPORTED_CLAUDE_VERSIONS
    from sesslint.adapters.codex_rollout import SUPPORTED_CODEX_ROLLOUT_VERSIONS
    from sesslint.adapters.openai_agents import SUPPORTED_OPENAI_AGENTS_VERSIONS

    return [
        {
            "name": "canonical",
            "default_profile": "neutral",
            "description": (
                "sesslint.session/v1 canonical JSONL (SessLint's own interchange format)"
            ),
            "versions_supported": sorted(SUPPORTED_CANONICAL_VERSIONS),
        },
        {
            "name": "claude-code-jsonl",
            "default_profile": "claude-strict",
            "description": "Claude Code JSONL (per-turn records incl. snapshots/hooks)",
            "versions_supported": sorted(SUPPORTED_CLAUDE_VERSIONS),
        },
        {
            "name": "codex-rollout",
            "default_profile": "openai-strict",
            "description": "Codex rollout/session_meta + response_item records",
            "versions_supported": sorted(SUPPORTED_CODEX_ROLLOUT_VERSIONS),
        },
        {
            "name": "openai-agents",
            "default_profile": "openai-strict",
            "description": "OpenAI Agents SDK session export (session + item arrays)",
            "versions_supported": sorted(SUPPORTED_OPENAI_AGENTS_VERSIONS),
        },
    ]


__all__ = [
    "CONFIDENCE_MIN",
    "CanonicalEvent",
    "DetectionResult",
    "EventList",
    "FORMAT_AUTO",
    "FORMAT_CANONICAL",
    "FORMAT_CLAUDE_CODE",
    "FORMAT_CODEX_ROLLOUT",
    "FORMAT_OPENAI_AGENTS",
    "MARGIN_MIN",
    "MAX_PROJECTED_CHECKPOINTS",
    "MAX_PROJECTED_RUN_STATE_KEYS",
    "SNIFF_BYTES",
    "SUPPORTED_FORMATS",
    "SYNTHETIC_ID_PREFIX",
    "SourceMetadata",
    "SyntheticIdCollisionGuard",
    "VALID_FORMAT_OPTIONS",
    "detect_canonical",
    "detect_claude_code",
    "detect_codex_rollout",
    "detect_format",
    "detect_openai_agents",
    "dump_canonical",
    "is_synthetic_id",
    "load_canonical",
    "load_canonical_session",
    "load_claude_code",
    "load_claude_code_session",
    "load_codex_rollout",
    "load_codex_rollout_session",
    "load_openai_agents",
    "load_openai_agents_session",
    "project_run_state",
    "resolve_format",
    "safe_discriminator",
    "supported_adapters",
    "safe_type_value",
    "synthetic_event_id",
    "to_source_block",
]
