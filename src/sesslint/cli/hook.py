"""The ``sesslint hook`` subcommand."""

from __future__ import annotations

import argparse
import sys
from typing import Final

from sesslint.adapters.detect import VALID_FORMAT_OPTIONS

NAME: Final[str] = "hook"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "hook",
        help=(
            "[read-only] Agent hook entrypoint: reads one hook payload "
            "from stdin and checks the transcript."
        ),
        description=(
            "[read-only] Reads one JSON hook payload from stdin (Claude Code "
            "contract: session_id, transcript_path, cwd, hook_event_name), "
            "resolves the transcript file, and runs the event-appropriate "
            "integrity check. Prints one content-free line and exits 0 "
            "(advisory) — or 1 when --fail-on gates on findings. Exit 2 is "
            "never emitted: hook checks never block the agent."
        ),
    )
    sub.add_argument(
        "--event",
        required=True,
        metavar="NAME",
        help=(
            "Hook event name (e.g. SessionStart, PreCompact, PostCompact, "
            "SessionEnd). Unknown names run the generic integrity check."
        ),
    )
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.hook-result/v1 JSON instead of the one-line form",
    )
    sub.add_argument(
        "--output",
        choices=["text", "claude-json"],
        default="text",
        help="Output format; claude-json emits a content-free systemMessage envelope",
    )
    sub.add_argument(
        "--fail-on",
        choices=["never", "error", "warning"],
        default=None,
        help=(
            "Minimum finding severity that exits 1 (default: never — hook "
            "checks are advisory; 'warning' fails on any finding)"
        ),
    )
    sub.add_argument(
        "--profile",
        default=None,
        help="Validation profile (default: neutral)",
    )
    sub.add_argument(
        "--format",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default=None,
        help="Session format adapter (default: auto-detect)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.hook_event import MAX_HOOK_PAYLOAD_BYTES, run_hook

    # Bounded stdin read: the payload is a small JSON control message,
    # not session bytes — cap at 1 MiB so oversize is detectable.
    payload = sys.stdin.buffer.read(MAX_HOOK_PAYLOAD_BYTES + 1)
    fmt = getattr(args, "format", None)
    hook_result = run_hook(
        args.event,
        payload,
        profile=getattr(args, "profile", None),
        format=None if fmt in (None, "auto") else fmt,
        fail_on=getattr(args, "fail_on", None),
    )
    if getattr(args, "output", None) == "claude-json":
        print(hook_result.to_claude_json())
    elif getattr(args, "json", False):
        print(hook_result.to_json())
    else:
        print(hook_result.line())
    return hook_result.exit_code
