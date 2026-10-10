"""Subcommand registry: ordered command specs for parser build and dispatch."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from sesslint.cli import (
    baseline,
    bundle,
    check,
    completion,
    diff,
    doctor,
    export,
    formats,
    hook,
    hooks,
    mcp,
    repair,
    scan,
    seal,
    stats,
    triage,
    validate_session,
    verify,
    version,
    watch,
)

@dataclass(frozen=True)
class Command:
    """One CLI subcommand: parser registration plus dispatch."""

    name: str
    configure: Callable[
        [argparse._SubParsersAction[argparse.ArgumentParser]], argparse.ArgumentParser
    ]
    run: Callable[[argparse.Namespace, argparse.ArgumentParser], int]


COMMANDS: Final[tuple[Command, ...]] = (
    Command(validate_session.NAME, validate_session.configure, validate_session.run),
    Command(check.NAME, check.configure, check.run),
    Command(formats.NAME, formats.configure, formats.run),
    Command(version.NAME, version.configure, version.run),
    Command(scan.NAME, scan.configure, scan.run),
    Command(repair.NAME, repair.configure, repair.run),
    Command(verify.NAME, verify.configure, verify.run),
    Command(seal.NAME, seal.configure, seal.run),
    Command(bundle.NAME, bundle.configure, bundle.run),
    Command(export.NAME, export.configure, export.run),
    Command(completion.NAME, completion.configure, completion.run),
    Command(baseline.NAME, baseline.configure, baseline.run),
    Command(diff.NAME, diff.configure, diff.run),
    Command(stats.NAME, stats.configure, stats.run),
    Command(triage.NAME, triage.configure, triage.run),
    Command(doctor.NAME, doctor.configure, doctor.run),
    Command(watch.NAME, watch.configure, watch.run),
    Command(hooks.NAME, hooks.configure, hooks.run),
    Command(hook.NAME, hook.configure, hook.run),
    Command(mcp.NAME, mcp.configure, mcp.run),
)
