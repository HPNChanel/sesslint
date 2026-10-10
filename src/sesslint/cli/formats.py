"""The ``sesslint formats`` subcommand."""

from __future__ import annotations

import argparse
import json
from typing import Final

from sesslint.adapters.canonical import SUPPORTED_CANONICAL_VERSIONS
from sesslint.adapters.claude_code import SUPPORTED_CLAUDE_VERSIONS
from sesslint.adapters.codex_rollout import SUPPORTED_CODEX_ROLLOUT_VERSIONS
from sesslint.adapters.openai_agents import SUPPORTED_OPENAI_AGENTS_VERSIONS

NAME: Final[str] = "formats"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "formats",
        help="[read-only] List supported session format adapters.",
        description=(
            "[read-only] List supported session format adapters and their supported version specs."
        ),
    )
    sub.add_argument(
        "--json",
        action="store_true",
        help="Output supported formats as JSON array",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    adapter_data = [
        {
            "default_profile": "neutral",
            "description": "SessLint Canonical Session Format v1 (JSON/JSONL)",
            "name": "canonical",
            "versions_supported": sorted(SUPPORTED_CANONICAL_VERSIONS),
        },
        {
            "default_profile": "neutral",
            "description": "Claude Code JSONL session logs adapter",
            "name": "claude-code-jsonl",
            "versions_supported": sorted(SUPPORTED_CLAUDE_VERSIONS),
        },
        {
            "default_profile": "neutral",
            "description": "OpenAI Agents SDK item-export adapter",
            "name": "openai-agents",
            "versions_supported": sorted(SUPPORTED_OPENAI_AGENTS_VERSIONS),
        },
        {
            "default_profile": "neutral",
            "description": "Codex CLI/Desktop rollout-*.jsonl adapter",
            "name": "codex-rollout",
            "versions_supported": sorted(SUPPORTED_CODEX_ROLLOUT_VERSIONS),
        },
    ]
    if getattr(args, "json", False):
        print(json.dumps(adapter_data, indent=2, sort_keys=True))
    else:
        print(f"{'NAME':<20} {'DEFAULT PROFILE':<18} {'SUPPORTED VERSIONS':<24} DESCRIPTION")
        print("-" * 80)
        for item in adapter_data:
            vers_str = ", ".join(item["versions_supported"])
            print(
                f"{item['name']:<20} {item['default_profile']:<18} "
                f"{vers_str:<24} {item['description']}"
            )
    return 0
