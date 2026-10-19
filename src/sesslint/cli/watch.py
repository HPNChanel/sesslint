"""The ``sesslint watch`` subcommand."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from sesslint.adapters.detect import VALID_FORMAT_OPTIONS

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

NAME: Final[str] = "watch"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "watch",
        help="[read-only] Poll session directories and flag newly corrupted files.",
        description=(
            "[read-only] Poll-based observer: debounced mtime+size snapshots, "
            "emits one line per verdict transition. Pure observer — never "
            "writes, never installs hooks. Ctrl+C exits cleanly."
        ),
    )
    sub.add_argument(
        "path",
        type=Path,
        nargs="*",
        help="Path(s) to session file(s) or directories to watch",
    )
    sub.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default=None,
        help="Watch a well-known agent session root instead of paths",
    )
    sub.add_argument(
        "--interval",
        type=float,
        default=2.0,
        metavar="SEC",
        help="Poll interval in seconds (default: 2.0, min: 0.05)",
    )
    sub.add_argument(
        "--adapter",
        choices=sorted(VALID_FORMAT_OPTIONS),
        default="auto",
        help="Session format adapter for all inputs (default: auto)",
    )
    sub.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit sesslint.watch-event/v1 NDJSON transition events",
    )
    return sub


def run(ctx: CliContext, args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    import json as _json

    from sesslint.api import discover_session_roots
    from sesslint.progress import OperationCancelled
    from sesslint.watch import watch

    agent = getattr(args, "agent", None)
    watch_paths: list[Path] = list(getattr(args, "path", []) or [])
    if agent is not None:
        if watch_paths:
            ctx.error("Error: --agent cannot be combined with explicit paths.")
            return 2
        agents = None if agent == "all" else [agent]
        watch_paths = [Path(r.path) for r in discover_session_roots(agents) if r.exists]
        if not watch_paths:
            ctx.error(f"Error: no existing session roots found for agent '{agent}'.")
            return 2
    if not watch_paths:
        ctx.error("Error: watch requires at least one path or --agent.")
        return 2
    for wp in watch_paths:
        if not wp.exists():
            ctx.error(f"Error: Path not found: {wp}")
            return 2

    use_json = getattr(args, "json", False)

    def _emit(t: Any) -> None:
        if use_json:
            print(_json.dumps(t.to_dict(), sort_keys=True), flush=True)
        else:
            from sesslint.watch import format_transition

            print(format_transition(t), flush=True)

    shared_fmt = getattr(args, "adapter", "auto")
    try:
        watch(
            watch_paths,
            interval=getattr(args, "interval", 2.0),
            on_transition=_emit,
            format=None if shared_fmt in (None, "auto") else shared_fmt,
        )
    except OperationCancelled:
        return 0
    except ValueError as err:
        ctx.error(f"Error: {err}")
        return 2
    except KeyboardInterrupt:
        return 0
    return 0
