"""Agent hook snippet builders (integrations T-02).

Print-only generators: ``sesslint init-hooks`` emits ready-to-merge JSON
blocks for the documented hook recipes. The command **never writes agent
configuration** — that is a permanent design invariant, not a deferral.
There is no ``--install``/``--write`` flag and there never will be.

Snippets are content-free by construction: hook commands reference
``sesslint check``/``sesslint precheck`` with ``--json`` and take no
transcript arguments. Output is deterministic modulo the optional binary
path interpolation (bare ``sesslint`` by default — PATH requirement is
documented).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "sesslint.init-hooks/v1"

_CLAUDE_TARGET = "~/.claude/settings.json (hooks section)"

_CLAUDE_SESSIONSTART_BLOCK: dict[str, Any] = {
    "hooks": {
        "SessionStart": [
            {
                "matcher": "startup|resume|clear",
                "hooks": [
                    {
                        "type": "command",
                        "command": (
                            'sesslint check "$CLAUDE_PROJECT_DIR"/*.jsonl '
                            "--json --skip-undetected || true"
                        ),
                    }
                ],
            }
        ]
    }
}

_CLAUDE_PRECOMPACT_BLOCK: dict[str, Any] = {
    "hooks": {
        "PreCompact": [
            {
                "matcher": "auto|manual",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sesslint check /path/to/session.jsonl --json",
                    }
                ],
            }
        ]
    }
}

_CLAUDE_NOTE = (
    "Merge each block into ~/.claude/settings.json (user) or "
    ".claude/settings.json (project). || true keeps SessionStart "
    "non-blocking; drop it to hard-block. Replace "
    "/path/to/session.jsonl in the PreCompact recipe with the session "
    "file you actually resume. See docs/INTEGRATIONS.md."
)

_CODEX_NOTE = (
    "Codex CLI has no documented user-facing hook surface as of this "
    "writing — no snippet is emitted (SessLint never invents agent "
    "configuration). Coverage for Codex session roots: "
    "`sesslint scan --agent codex`; gate behavior via wrapper scripts."
)

VALID_AGENTS: tuple[str, ...] = ("claude", "codex", "all")


@dataclass(frozen=True)
class HookFile:
    """One mergeable snippet targeting a config file section."""

    target_path_hint: str
    recipe: str
    merge_block: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"target_path_hint": self.target_path_hint, "recipe": self.recipe}
        if self.merge_block is not None:
            d["merge_block"] = self.merge_block
        return d


@dataclass(frozen=True)
class InitHooksDoc:
    """Emitted init-hooks document — ``sesslint.init-hooks/v1``."""

    agent: str
    files: tuple[HookFile, ...] = ()
    note: str = ""
    schema_version: str = field(default=SCHEMA_VERSION, init=False)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "schema": self.schema_version,
            "agent": self.agent,
            "files": [f.to_dict() for f in self.files],
        }
        if self.note:
            d["note"] = self.note
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def render_human(self) -> str:
        lines: list[str] = []
        if self.note:
            lines.append(f"# {self.agent}: {self.note}")
        for f in self.files:
            lines.append(f"# {f.recipe} - merge into {f.target_path_hint}")
            if f.merge_block is not None:
                lines.append(json.dumps(f.merge_block, indent=2, sort_keys=True))
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def _claude_doc() -> InitHooksDoc:
    return InitHooksDoc(
        agent="claude",
        files=(
            HookFile(
                target_path_hint=_CLAUDE_TARGET,
                recipe="SessionStart corruption warning (non-blocking)",
                merge_block=dict(_CLAUDE_SESSIONSTART_BLOCK),
            ),
            HookFile(
                target_path_hint=_CLAUDE_TARGET,
                recipe="PreCompact gate",
                merge_block=dict(_CLAUDE_PRECOMPACT_BLOCK),
            ),
        ),
        note=_CLAUDE_NOTE,
    )


def _codex_doc() -> InitHooksDoc:
    return InitHooksDoc(agent="codex", files=(), note=_CODEX_NOTE)


def init_hooks_doc(agent: str) -> InitHooksDoc:
    """Build the init-hooks document for one agent (or ``all``)."""
    if agent == "claude":
        return _claude_doc()
    if agent == "codex":
        return _codex_doc()
    if agent == "all":
        # Combined doc: claude files + codex note, per-agent sections kept.
        return InitHooksDoc(
            agent="all",
            files=_claude_doc().files,
            note=_CLAUDE_NOTE + " | codex: " + _CODEX_NOTE,
        )
    raise ValueError(f"unknown agent: {agent!r}")


__all__ = [
    "SCHEMA_VERSION",
    "VALID_AGENTS",
    "HookFile",
    "InitHooksDoc",
    "init_hooks_doc",
]
