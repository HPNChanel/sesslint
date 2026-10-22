"""Agent hook snippet builders (integrations T-02).

Print-only generators: ``sesslint hook --init`` emits ready-to-merge JSON
blocks for the documented hook recipes (Claude Code ``settings.json``,
Codex ``hooks.json``). The command **never writes agent
configuration** — that is a permanent design invariant, not a deferral.
There is no ``--install``/``--write`` flag and there never will be.

Snippets are content-free by construction: hook commands reference
``sesslint hook --event <name>``, which reads the hook payload (including
``transcript_path``) from stdin — no paths to substitute, no globs, no
shell plumbing. Output is deterministic modulo the optional binary
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
                "matcher": "resume|compact|fork",
                "hooks": [
                    {
                        "type": "command",
                        "command": (
                            "sesslint hook --event SessionStart --format claude-json || true"
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
                        "command": "sesslint hook --event PreCompact || true",
                    }
                ],
            }
        ]
    }
}

_CLAUDE_POSTCOMPACT_BLOCK: dict[str, Any] = {
    "hooks": {
        "PostCompact": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "sesslint hook --event PostCompact || true",
                        "timeout": 5,
                    }
                ],
            }
        ]
    }
}

_CLAUDE_SESSIONEND_BLOCK: dict[str, Any] = {
    "hooks": {
        "SessionEnd": [
            {
                "matcher": "clear|logout|prompt_input_exit|other",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sesslint hook --event SessionEnd || true",
                        "timeout": 5,
                    }
                ],
            }
        ]
    }
}

_CLAUDE_NOTE = (
    "Merge each block into ~/.claude/settings.json (user) or "
    ".claude/settings.json (project). Every command reads the hook "
    "payload from stdin (transcript_path, session_id) - no paths to "
    "substitute. '|| true' keeps each recipe advisory; 'sesslint hook' "
    "never exits 2, so nothing can block the agent. To gate on findings, "
    "pass '--fail-on warning' (exits 1; drop '|| true' to surface it). "
    "Requires a SessLint release carrying 'sesslint hook' - check "
    "'sesslint version'. See docs/INTEGRATIONS.md."
)

_CODEX_TARGET = "~/.codex/hooks.json (hooks section)"

# Codex adds plain SessionStart stdout to model context and ignores plain
# PreCompact/PostCompact stdout, so those recipes print the content-free
# systemMessage envelope, which Codex surfaces to the user as a warning.
# SessionStart skips "compact": PostCompact already checks that transcript.
# Codex runs hooks through the session shell (PowerShell or cmd on Windows),
# so commandWindows drops the POSIX '|| true'. A non-zero exit is reported
# as a failed hook and never stops Codex; only JSON "continue": false does.
_CODEX_SESSIONSTART_BLOCK: dict[str, Any] = {
    "hooks": {
        "SessionStart": [
            {
                "matcher": "resume|fork",
                "hooks": [
                    {
                        "type": "command",
                        "command": (
                            "sesslint hook --event SessionStart --format claude-json || true"
                        ),
                        "commandWindows": (
                            "sesslint hook --event SessionStart --format claude-json"
                        ),
                    }
                ],
            }
        ]
    }
}

_CODEX_PRECOMPACT_BLOCK: dict[str, Any] = {
    "hooks": {
        "PreCompact": [
            {
                "matcher": "auto|manual",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sesslint hook --event PreCompact --format claude-json || true",
                        "commandWindows": "sesslint hook --event PreCompact --format claude-json",
                    }
                ],
            }
        ]
    }
}

_CODEX_POSTCOMPACT_BLOCK: dict[str, Any] = {
    "hooks": {
        "PostCompact": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "sesslint hook --event PostCompact --format claude-json || true",
                        "commandWindows": "sesslint hook --event PostCompact --format claude-json",
                        "timeout": 5,
                    }
                ],
            }
        ]
    }
}

# Codex reports only the "other" end reason, so the recipe has no matcher;
# SessionEnd hooks default to a 1s timeout with a 3s maximum.
_CODEX_SESSIONEND_BLOCK: dict[str, Any] = {
    "hooks": {
        "SessionEnd": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "sesslint hook --event SessionEnd || true",
                        "commandWindows": "sesslint hook --event SessionEnd",
                        "timeout": 3,
                    }
                ],
            }
        ]
    }
}

_CODEX_NOTE = (
    "Merge each block into ~/.codex/hooks.json (user) or "
    ".codex/hooks.json (project; loads only when that .codex/ layer is "
    "trusted). Codex skips new or changed hooks until you review and "
    "trust them in /hooks. Every command reads the hook payload from "
    "stdin (transcript_path, session_id) - no paths to substitute. "
    "SessionStart, PreCompact and PostCompact print a content-free "
    "systemMessage, which Codex shows as a warning (a clean pass too) "
    "instead of adding plain output to model context. SessionStart "
    "skips 'compact' because PostCompact checks the same transcript. "
    "SessionEnd uses the 3s maximum Codex allows. commandWindows omits "
    "'|| true' because Windows hooks may run in PowerShell or cmd; a "
    "missing or older sesslint then shows a hook error, and no exit code "
    "stops Codex. Requires SessLint 0.5.0 or later on PATH. See "
    "docs/INTEGRATIONS.md."
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
                recipe="PreCompact integrity check (non-blocking)",
                merge_block=dict(_CLAUDE_PRECOMPACT_BLOCK),
            ),
            HookFile(
                target_path_hint=_CLAUDE_TARGET,
                recipe="PostCompact boundary check (non-blocking)",
                merge_block=dict(_CLAUDE_POSTCOMPACT_BLOCK),
            ),
            HookFile(
                target_path_hint=_CLAUDE_TARGET,
                recipe="SessionEnd secret check (non-blocking)",
                merge_block=dict(_CLAUDE_SESSIONEND_BLOCK),
            ),
        ),
        note=_CLAUDE_NOTE,
    )


def _codex_doc() -> InitHooksDoc:
    return InitHooksDoc(
        agent="codex",
        files=(
            HookFile(
                target_path_hint=_CODEX_TARGET,
                recipe="SessionStart corruption warning (non-blocking)",
                merge_block=dict(_CODEX_SESSIONSTART_BLOCK),
            ),
            HookFile(
                target_path_hint=_CODEX_TARGET,
                recipe="PreCompact integrity check (non-blocking)",
                merge_block=dict(_CODEX_PRECOMPACT_BLOCK),
            ),
            HookFile(
                target_path_hint=_CODEX_TARGET,
                recipe="PostCompact boundary check (non-blocking)",
                merge_block=dict(_CODEX_POSTCOMPACT_BLOCK),
            ),
            HookFile(
                target_path_hint=_CODEX_TARGET,
                recipe="SessionEnd secret check (non-blocking)",
                merge_block=dict(_CODEX_SESSIONEND_BLOCK),
            ),
        ),
        note=_CODEX_NOTE,
    )


def init_hooks_doc(agent: str) -> InitHooksDoc:
    """Build the init-hooks document for one agent (or ``all``)."""
    if agent == "claude":
        return _claude_doc()
    if agent == "codex":
        return _codex_doc()
    if agent == "all":
        # Combined doc: claude files then codex files; target_path_hint
        # tells them apart, and the note labels one section per agent.
        return InitHooksDoc(
            agent="all",
            files=_claude_doc().files + _codex_doc().files,
            note="claude: " + _CLAUDE_NOTE + " | codex: " + _CODEX_NOTE,
        )
    raise ValueError(f"unknown agent: {agent!r}")


__all__ = [
    "SCHEMA_VERSION",
    "VALID_AGENTS",
    "HookFile",
    "InitHooksDoc",
    "init_hooks_doc",
]
