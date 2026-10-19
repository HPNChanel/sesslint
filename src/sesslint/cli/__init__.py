"""SessLint command-line interface — parser construction and dispatch."""

from __future__ import annotations

import argparse
import io
import sys
import time
from collections.abc import Sequence
from typing import Final

from sesslint import __version__, api
from sesslint.cli._common import (
    FORMAT_DISPLAY_NAMES,
    _handle_internal_error,
    should_color,
)
from sesslint.cli._context import CliContext, build_context
from sesslint.cli._errors import CliError
from sesslint.cli._options import add_color_options, add_verbosity_options
from sesslint.cli._registry import COMMANDS, REMOVED_COMMANDS, REMOVED_FLAGS, build_dispatch
from sesslint.cli._render import format_scan_report_human
from sesslint.progress import OperationCancelled

__all__: Final = [
    "FORMAT_DISPLAY_NAMES",
    "_handle_internal_error",
    "create_parser",
    "format_scan_report_human",
    "load_session_file",
    "main",
    "should_color",
]

# Test-facing monkeypatch alias for the canonical session reader (v0.4.x name).
load_session_file = api.validate_session


def create_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser."""
    parser = argparse.ArgumentParser(
        prog="sesslint",
        description=(
            "Offline, vendor-neutral session integrity checker and conservative repair tool."
        ),
        epilog=(
            "Exit codes:\n"
            "  0  Healthy session / verification passed / dry-run plan generated\n"
            "  1  Integrity findings detected / verification failed / repair refused\n"
            "  2  Usage error / invalid flag combination / I/O failure\n\n"
            "Important Notes:\n"
            "  - redaction is best-effort minimization, not a completeness guarantee\n"
            "  - sesslint makes no semantic or side-effect safety claims"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sesslint {__version__}",
    )
    add_color_options(parser, root=True)
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for command in COMMANDS:
        command.configure(subparsers)
    # Prefix matching would resurrect removed flags (e.g. --out -> --output).
    # -q/-v land on every subparser: the commands that call
    # add_color_options already have them via add_verbosity_options.
    seen: set[int] = set()
    for sub in subparsers.choices.values():
        if id(sub) in seen:
            continue
        seen.add(id(sub))
        sub.allow_abbrev = False
        if not any("-q" in action.option_strings for action in sub._actions):
            add_verbosity_options(sub)
    return parser


def _removed_command_hint(argv: Sequence[str]) -> str | None:
    """Return a removal hint for the first non-dash token, if it names a removed command."""
    for token in argv:
        if token.startswith("-"):
            continue
        replacement = REMOVED_COMMANDS.get(token)
        if replacement is None:
            return None
        return f"Error: '{token}' was removed in 0.5.0; use: {replacement}"
    return None


def _removed_flag_hint(argv: Sequence[str]) -> str | None:
    """Return a hint line for the first removed flag in argv, else None."""
    from sesslint.adapters import VALID_FORMAT_OPTIONS

    for index, token in enumerate(argv):
        flag, sep, _value = token.partition("=")
        if (
            flag == "--format"
            and not sep
            and index + 1 < len(argv)
            and argv[index + 1] in VALID_FORMAT_OPTIONS
        ):
            return "hint: '--format' now selects the output format; use '--adapter <name>'"
        if flag in REMOVED_FLAGS:
            return f"hint: '{flag}' was removed in 0.5.0; use {REMOVED_FLAGS[flag]}"
    return None


def _verbose_settings(ctx: CliContext) -> None:
    """Emit ``debug:`` provenance lines for non-default settings (-v)."""
    ctx.debug(f"config file: {ctx.config_path if ctx.config_path is not None else 'none'}")
    for name, setting in ctx.settings.items():
        if setting.source != "default":
            ctx.debug(f"{name} = {setting.value}  ({setting.source})")


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Dispatch parsed CLI command and return exit code."""
    if args.command is None:
        parser.print_help(sys.stdout)
        return 2

    ctx: CliContext | None = None
    try:
        ctx = build_context(args, parser)

        if getattr(args, "include_content", False):
            ctx.warn(
                "WARNING: --include-content embeds raw transcript content; do not share output"
            )

        dispatch = build_dispatch()
        command = dispatch.get(str(args.command))
        if command is None:
            return 0
        start = time.monotonic()
        _verbose_settings(ctx)
        try:
            return command.run(ctx, args, parser)
        finally:
            ctx.debug(f"elapsed {time.monotonic() - start:.2f}s")
    except CliError as err:
        if ctx is not None:
            ctx.error(err.message)
        else:
            print(err.message, file=sys.stderr)
        return err.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning exit code with top-level safety guarantees."""
    # T-12: redirected Windows streams otherwise use the legacy ANSI code page.
    # Reports and diagnostics must accept Unicode filenames even in a frozen
    # executable, where PYTHONUTF8 may be ignored. Leave caller-owned StringIO
    # and other custom streams untouched; importing the API has no side effects.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")

    argv_tokens: Sequence[str] = list(argv) if argv is not None else sys.argv[1:]

    # Removed-surface compatibility hints (pre-parse, pure). Command hints
    # replace argparse output entirely; flag hints precede argparse's own
    # usage error (exit 2 either way).
    cmd_hint = _removed_command_hint(argv_tokens)
    if cmd_hint is not None:
        print(cmd_hint, file=sys.stderr)
        return 2
    flag_hint = _removed_flag_hint(argv_tokens)
    if flag_hint is not None:
        print(flag_hint, file=sys.stderr)

    parser = create_parser()
    args = parser.parse_args(argv_tokens)

    try:
        return _dispatch(args, parser)
    except KeyboardInterrupt:
        print("Operation cancelled by user", file=sys.stderr)
        return 130
    except OperationCancelled:
        # Cooperative cancellation keeps the same CLI exit semantics as
        # Ctrl+C (DW-T-13): cleanup already ran inside the callee.
        print("Operation cancelled", file=sys.stderr)
        return 130
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    except CliError as err:
        print(err.message, file=sys.stderr)
        return err.exit_code
    except Exception as err:
        return _handle_internal_error(err, args)
