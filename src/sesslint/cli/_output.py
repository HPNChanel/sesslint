"""``-o/--output`` report-file plumbing shared by report-producing commands.

When ``args.output`` is set the report bytes stdout would have received are
written atomically instead, and a one-line ``wrote ...`` confirmation goes to
stdout (suppressed by ``--quiet``). Refuses to overwrite any input path —
an output that would clobber its own source is a usage error.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from sesslint.cli._errors import CliError

if TYPE_CHECKING:
    from sesslint.cli._context import CliContext

_REPORT_COMMANDS = frozenset({"check", "scan", "triage", "stats", "diff", "doctor", "verify"})


def _boundaries(
    ctx: CliContext, args: argparse.Namespace, inputs: Sequence[Path] = ()
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Collect physical inputs, including auxiliary files omitted from reports."""
    files = list(inputs)
    for name in (
        "path",
        "a",
        "b",
        "source",
        "source_flag",
        "repaired",
        "repaired_flag",
        "manifest",
        "plan",
        "state_copy",
        "baseline",
        "seal",
    ):
        value = getattr(args, name, None)
        values = value if isinstance(value, (tuple, list)) else (value,)
        files.extend(Path(p) for p in values if isinstance(p, (str, Path)) and str(p) != "-")
    if ctx.config_path is not None:
        files.append(ctx.config_path)
    roots = [p for p in files if p.is_dir()]
    agent = getattr(args, "agent", None)
    if args.command == "doctor" or (agent is not None and not getattr(args, "path", None)):
        from sesslint.api import discover_session_roots

        agents = None if agent in (None, "all") else (agent,)
        # Scans also read registry/index sidecars beside the session roots.
        roots.extend(
            root.path.parent
            for root in discover_session_roots(
                agents, include_archived=bool(getattr(args, "include_archived", False))
            )
        )
    return tuple(files), tuple(roots)


def _guard_destination(path: Path, files: Sequence[Path], roots: Sequence[Path]) -> None:
    """Refuse aliases and existing artifacts beneath an inspected directory."""
    resolved = path.resolve()
    if path.is_symlink() or (path.exists() and path.stat().st_nlink > 1):
        raise CliError(2, "Error: --output/--write-baseline must not be a link alias")
    for source in files:
        if source.resolve() == resolved or (
            path.exists() and source.exists() and path.samefile(source)
        ):
            raise CliError(2, "Error: --output/--write-baseline must not be an input path")
    if path.exists() and any(resolved.is_relative_to(root.resolve()) for root in roots):
        raise CliError(2, "Error: --output must not replace an artifact inside an input directory")


def preflight_report_outputs(ctx: CliContext, args: argparse.Namespace) -> None:
    """Validate report/baseline destinations before commands perform any writes."""
    if args.command not in _REPORT_COMMANDS:
        return
    destinations = [
        Path(value)
        for name in ("output", "write_baseline")
        if (value := getattr(args, name, None)) is not None
    ]
    if not destinations:
        return
    try:
        files, roots = _boundaries(ctx, args)
        for index, path in enumerate(destinations):
            other_outputs = destinations[:index] + destinations[index + 1 :]
            _guard_destination(path, (*files, *other_outputs), roots)
    except (OSError, RuntimeError) as err:
        raise CliError(2, "Error: output safety could not be established") from err


def emit_text(
    ctx: CliContext,
    args: argparse.Namespace,
    text: str,
    *,
    inputs: Sequence[Path] = (),
    summary: str,
) -> None:
    """Emit ``text`` to stdout, or atomically to ``--output`` when set.

    ``text`` is exactly what ``print`` would receive — the file gets the
    same bytes plus the trailing newline ``print`` would have appended.
    ``inputs`` are the command's source paths; the output must not resolve
    to any of them.
    """
    output = getattr(args, "output", None)
    if output is None:
        print(text)
        return
    out_path = Path(output)
    from sesslint.atomic import atomic_write_bytes

    try:
        files, roots = _boundaries(ctx, args, inputs)
        baseline_output = getattr(args, "write_baseline", None)
        if baseline_output is not None:
            files = (*files, Path(baseline_output))
        _guard_destination(out_path, files, roots)
        inside_root = any(out_path.resolve().is_relative_to(p.resolve()) for p in roots)
        atomic_write_bytes(
            out_path,
            text.encode("utf-8") + b"\n",
            refuse_paths=files,
            overwrite=not inside_root,
            pre_rename_hook=lambda _temp: _guard_destination(out_path, files, roots),
        )
    except OSError as err:
        raise CliError(2, f"Error: cannot write report to {output}: {err}") from err
    if not ctx.quiet:
        print(f"wrote {output} ({summary})")
