"""SessLint command-line interface — parser construction and dispatch."""

from __future__ import annotations

import argparse
import io
import sys
import time
from collections.abc import Sequence
from typing import Final, TextIO, cast

from sesslint import __version__, api
from sesslint.cli._common import (
    FORMAT_DISPLAY_NAMES,
    _handle_internal_error,
    should_color,
)
from sesslint.cli._context import CliContext, build_context
from sesslint.cli._errors import CliError
from sesslint.cli._json_errors import TrackedStream, error_document, wants_json
from sesslint.cli._options import add_color_options, add_verbosity_options
from sesslint.cli._registry import COMMANDS, REMOVED_COMMANDS, REMOVED_FLAGS, build_dispatch
from sesslint.cli._render import format_scan_report_human
from sesslint.progress import OperationCancelled

__all__: Final = [
    "CHECK_EXIT_LINES",
    "CHECK_EXIT_NOTES",
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

# AC-02 / FR-098: shared exact exit-code wording, in order 0, 1, 2.
CHECK_EXIT_LINES: Final[tuple[str, ...]] = (
    "0  a clean session exits 0",
    "1  a session with findings exits 1",
    "2  an internal tool error exits 2",
)
CHECK_EXIT_NOTES: Final[tuple[str, ...]] = (
    "(also verification passed / dry-run plan generated)",
    "(also verification failed / repair refused)",
    "(also usage error / invalid flags / I/O failure)",
)


def create_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser."""
    parser = argparse.ArgumentParser(
        prog="sesslint",
        description=(
            "Offline, vendor-neutral session integrity checker and conservative repair tool."
        ),
        epilog=(
            "Exit codes:\n"
            + "".join(
                f"  {line}\n     {note}\n"
                for line, note in zip(CHECK_EXIT_LINES, CHECK_EXIT_NOTES, strict=True)
            )
            + "\n"
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
        from sesslint.cli._output import preflight_report_outputs

        preflight_report_outputs(ctx, args)

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
    previous_out, previous_err = sys.stdout, sys.stderr
    output = TrackedStream(previous_out)
    diagnostics = TrackedStream(previous_err, diagnostic_limit=8192)
    args: argparse.Namespace | None = None
    code = 2
    try:
        # Track stdout presence only; reports can be arbitrarily large. Stderr
        # retains a bounded prefix for failures that otherwise have no document.
        sys.stdout = cast(TextIO, output)
        sys.stderr = cast(TextIO, diagnostics)
        cmd_hint = _removed_command_hint(argv_tokens)
        if cmd_hint is not None:
            print(cmd_hint, file=sys.stderr)
            return code
        flag_hint = _removed_flag_hint(argv_tokens)
        if flag_hint is not None:
            print(flag_hint, file=sys.stderr)
        parser = create_parser()
        args = parser.parse_args(argv_tokens)
        code = _dispatch(args, parser)
        return code
    except SystemExit as err:
        code = err.code if isinstance(err.code, int) else (0 if err.code is None else 1)
        raise
    except KeyboardInterrupt:
        print("Operation cancelled by user", file=sys.stderr)
        code = 130
        return code
    except OperationCancelled:
        print("Operation cancelled", file=sys.stderr)
        code = 130
        return code
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return code
    except CliError as err:
        print(err.message, file=sys.stderr)
        code = err.exit_code
        return code
    except Exception as err:
        # Never append a second document after a report was already emitted.
        # Effective --format/env JSON must also select the internal envelope.
        error_args = None if output.nonempty else args
        if error_args is not None and wants_json(argv_tokens, args):
            error_args.json = True
        code = _handle_internal_error(err, error_args)
        return code
    finally:
        sys.stdout, sys.stderr = previous_out, previous_err
        if code not in (0, 130) and wants_json(argv_tokens, args) and not output.nonempty:
            print(error_document(diagnostics.diagnostic() or "Command failed"), file=previous_out)
