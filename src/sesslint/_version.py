"""Version declarations for SessLint CLI, schemas, adapters, and profiles."""

from __future__ import annotations

from typing import Any, Final

__version__ = "0.1.0"
CLI_VERSION: Final[str] = __version__
SESSION_SCHEMA_VERSION: Final[str] = "sesslint.session/v1"
REPORT_SCHEMA_VERSION: Final[str] = "sesslint.report/v1"
MANIFEST_SCHEMA_VERSION: Final[str] = "sesslint.repair-manifest/v1"

ADAPTER_VERSIONS: Final[dict[str, str]] = {
    "canonical": "1.0.0",
    "claude-code-jsonl": "1.0.0",
    "openai-agents": "1.0.0",
}

PROFILE_VERSIONS: Final[dict[str, str]] = {
    "neutral": "1.0.0",
    "claude-strict": "1.0.0",
    "openai-strict": "1.0.0",
}


def get_version_info() -> dict[str, Any]:
    """Return structured version dictionary for CLI version command."""
    return {
        "cli": CLI_VERSION,
        "schema_session": SESSION_SCHEMA_VERSION,
        "schema_report": REPORT_SCHEMA_VERSION,
        "schema_manifest": MANIFEST_SCHEMA_VERSION,
        "adapters": dict(ADAPTER_VERSIONS),
        "profiles": dict(PROFILE_VERSIONS),
    }
