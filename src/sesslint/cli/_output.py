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
    out_path = Path(output).resolve()
    for src in inputs:
        if Path(src).resolve() == out_path:
            raise CliError(2, "Error: --output must not be an input path")
    from sesslint.atomic import atomic_write_bytes

    try:
        atomic_write_bytes(out_path, text.encode("utf-8") + b"\n")
    except OSError as err:
        raise CliError(2, f"Error: cannot write report to {output}: {err}") from err
    if not ctx.quiet:
        print(f"wrote {output} ({summary})")
