"""Determinism assertion utilities ensuring repeatable, byte-identical outputs."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def assert_deterministic(fn: Callable[[], T], *, runs: int = 3) -> T:
    """Execute fn repeatedly and assert that all outputs are strictly identical.

    Args:
        fn: A zero-argument callable producing an output (e.g. bytes, str, or object).
        runs: Number of consecutive runs to execute (minimum 2, defaults to 3).

    Returns:
        The deterministic result returned by all runs.

    Raises:
        ValueError: If runs is less than 2.
        AssertionError: If any execution yields an output different from the first run.
    """
    if runs < 2:
        raise ValueError(f"runs must be at least 2, got {runs}")

    first_result = fn()
    for run_idx in range(2, runs + 1):
        subsequent = fn()
        if subsequent != first_result:
            raise AssertionError(
                f"Determinism violation detected on run {run_idx}/{runs}:\n"
                f"First run output:  {first_result!r}\n"
                f"Run {run_idx} output: {subsequent!r}"
            )
    return first_result
