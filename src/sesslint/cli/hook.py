"""The ``sesslint hook`` subcommand (absorbs the old ``init-hooks`` command)."""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Final

from sesslint.adapters.detect import VALID_FORMAT_OPTIONS

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

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
            "never emitted: hook checks never block the agent. "
            "--init prints ready-to-merge hook snippets (never writes config)."
        ),
    )
    event_group = sub.add_mutually_exclusive_group(required=True)
    event_group.add_argument(
        "--event",
        metavar="NAME",
        help=(
            "Hook event name (e.g. SessionStart, PreCompact, PostCompact, "
            "SessionEnd). Unknown names run the generic integrity check."
        ),
    )
    event_group.add_argument(
        "--init",
        action="store_true",
        default=False,
        help="Print ready-to-merge agent hook snippets (never writes config)",
    )
    sub.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default="all",
        help="Agent to generate snippets for with --init (default: all)",
    )
    out_group = sub.add_mutually_exclusive_group()
    out_group.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=["text", "json", "claude-json"],
        default=None,
        help="Output format (default: text; claude-json emits a content-free "
        "systemMessage envelope)",
    )
    out_group.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit JSON (shortcut for --format json)",
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
        "--adapter",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default=None,
        help="Session format adapter (default: auto-detect)",
    )
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    out_fmt = "json" if getattr(args, "json", False) else getattr(args, "output_format", None)

    if getattr(args, "init", False):
        from sesslint.hooks import init_hooks_doc

        hooks_doc = init_hooks_doc(getattr(args, "agent", "all"))
        if out_fmt == "json":
            print(hooks_doc.to_json())
        else:
            sys.stdout.write(hooks_doc.render_human())
        return 0

    from sesslint.hook_event import MAX_HOOK_PAYLOAD_BYTES, run_hook

    # Bounded stdin read: the payload is a small JSON control message,
    # not session bytes — cap at 1 MiB so oversize is detectable.
    payload = sys.stdin.buffer.read(MAX_HOOK_PAYLOAD_BYTES + 1)
    fmt = getattr(args, "adapter", None)
    hook_result = run_hook(
        args.event,
        payload,
        profile=getattr(args, "profile", None),
        format=None if fmt in (None, "auto") else fmt,
        fail_on=getattr(args, "fail_on", None),
    )
    if out_fmt == "claude-json":
        print(hook_result.to_claude_json())
    elif out_fmt == "json":
        print(hook_result.to_json())
    else:
        print(hook_result.line())
    return hook_result.exit_code
