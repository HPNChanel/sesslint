"""The ``sesslint validate-session`` subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final

from sesslint.errors import SesslintError

NAME: Final[str] = "validate-session"


def configure(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse.ArgumentParser:
    sub = subparsers.add_parser(
        "validate-session",
        help="[read-only] Validate a canonical session file against schema.",
        description="[read-only] Validate a canonical session file against schema.",
    )
    sub.add_argument(
        "path",
        type=Path,
        help="Path to session file (.json or .jsonl)",
    )
    return sub


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from sesslint.cli import load_session_file

    try:
        session = load_session_file(args.path)
        print(f"Valid session: {session.header.session_id} ({len(session.events)} events)")
        return 0
    except SesslintError as err:
        print(f"Validation error [{err.code}]: {err}", file=sys.stderr)
        return 1
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2
    except Exception as err:
        print(f"Unexpected error: {err}", file=sys.stderr)
        return 2
