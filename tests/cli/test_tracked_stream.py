"""AC-03: TrackedStream finalization must not raise on a closed underlying stream."""

from __future__ import annotations

import gc
import io

import pytest

from sesslint.cli._json_errors import TrackedStream


def test_flush_after_underlying_close_is_ignored() -> None:
    raw = io.StringIO()
    stream = TrackedStream(raw)
    raw.close()
    stream.flush()


def test_flush_on_open_stream_still_raises_write_errors() -> None:
    class Broken(io.StringIO):
        failing = True

        def flush(self) -> None:
            if self.failing:
                raise OSError("disk full")

    raw = Broken()
    stream = TrackedStream(raw)
    with pytest.raises(OSError, match="disk full"):
        stream.flush()
    raw.failing = False


@pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning")
def test_finalizing_wrapper_after_underlying_close_is_silent() -> None:
    raw = io.StringIO()
    stream = TrackedStream(raw)
    raw.close()
    del stream
    gc.collect()
