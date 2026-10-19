"""Subcommand registry: (name, configure, run) triples in registration order."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

from sesslint.cli import (
    bundle,
    check,
    completion,
    diff,
    doctor,
    export,
    hook,
    mcp,
    repair,
    seal,
    stats,
    triage,
    verify,
    version,
    watch,
)


@dataclass(frozen=True, slots=True)
class Command:
    name: str
    configure: Callable[
        [argparse._SubParsersAction[argparse.ArgumentParser]], argparse.ArgumentParser
    ]
    run: Callable[[CliContext, argparse.Namespace, argparse.ArgumentParser], int]
    aliases: tuple[str, ...] = ()


REMOVED_COMMANDS: Final[dict[str, str]] = {
    "validate-session": "sesslint check --adapter canonical PATH",
    "baseline": (
        "v1 baselines still load via 'sesslint check --baseline OLD.json'; "
        "regenerate v2 with 'sesslint check PATH --write-baseline NEW.json'"
    ),
    "formats": "sesslint doctor  (or: sesslint version --json)",
    "init-hooks": "sesslint hook --init [--agent claude|codex|all]",
}

REMOVED_FLAGS: Final[dict[str, str]] = {
    "--output-format": "--format",
    "--recursive": "(directories are always recursive now; drop the flag)",
    "-r": "(directories are always recursive now; drop the flag)",
    "--batch": "pass the directory as a positional path and add --output-dir DIR",
    "--files": "pass the files as positional paths and add --output-dir DIR",
    "--salvage-unsupported": "--policy salvage",
    "--show-limits": "sesslint doctor",
    "--format-a": "--adapter-a",
    "--format-b": "--adapter-b",
    "--out": "-o/--output",
}


# Registration order is help/manpage order — keep stable.
COMMANDS: Final[tuple[Command, ...]] = (
    Command("check", check.configure, check.run, aliases=("scan",)),
    Command("version", version.configure, version.run),
    Command("repair", repair.configure, repair.run),
    Command("verify", verify.configure, verify.run),
    Command("seal", seal.configure, seal.run),
    Command("bundle", bundle.configure, bundle.run),
    Command("export", export.configure, export.run),
    Command("completion", completion.configure, completion.run),
    Command("diff", diff.configure, diff.run),
    Command("stats", stats.configure, stats.run),
    Command("triage", triage.configure, triage.run),
    Command("doctor", doctor.configure, doctor.run),
    Command("watch", watch.configure, watch.run),
    Command("hook", hook.configure, hook.run),
    Command("mcp", mcp.configure, mcp.run),
)


def build_dispatch() -> dict[str, Command]:
    """Map canonical names and aliases to their Command."""
    out: dict[str, Command] = {}
    for command in COMMANDS:
        out[command.name] = command
        for alias in command.aliases:
            out[alias] = command
    return out
