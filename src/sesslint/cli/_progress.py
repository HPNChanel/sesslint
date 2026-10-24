"""Progress callback plumbing: NDJSON (machine) and TTY (human) renderers.

stdout remains the result channel (FR-091); every progress byte goes to
stderr and carries counters only — never record content or full paths.
"""

from __future__ import annotations

import json
import sys
import time
from typing import TextIO

from sesslint.progress import ProgressCallback, ProgressEvent


def ndjson_progress_cb(stream: TextIO | None = None) -> ProgressCallback:
    """Return an NDJSON progress callback writing to stderr (DW-T-13).

    Events are flushed per line so a supervising process can consume them
    incrementally.
    """
    out = stream if stream is not None else sys.stderr

    def _cb(event: ProgressEvent) -> None:
        print(json.dumps(event.to_dict(), sort_keys=True), file=out, flush=True)

    return _cb


class TtyProgress:
    """Single-line TTY progress renderer matching ``ProgressCallback``.

    Rewrites one stderr line at most every 100 ms (and always on the event
    that completes a phase). Emits counts only — ``item`` is never rendered
    (content-free). ``finish()`` clears the line; call it in a ``finally``.
    """

    _MIN_INTERVAL = 0.1

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._last = 0.0
        self._width = 0

    def __call__(self, event: ProgressEvent) -> None:
        done = event.total is not None and event.completed >= event.total
        now = time.monotonic()
        if not done and now - self._last < self._MIN_INTERVAL:
            return
        self._last = now
        if event.total is not None:
            line = f"{event.phase} {event.completed}/{event.total}"
        else:
            line = f"{event.phase} {event.completed}"
        pad = " " * max(0, self._width - len(line))
        self._width = len(line)
        self._stream.write("\r" + line + pad)
        self._stream.flush()

    def finish(self) -> None:
        """Clear the progress line if anything was rendered."""
        if self._width:
            self._stream.write("\r" + " " * self._width + "\r")
            self._stream.flush()
            self._width = 0
