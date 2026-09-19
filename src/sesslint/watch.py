"""Poll-based session directory monitor (ux-reporting T-05).

``sesslint watch --agent all`` polls session directories and flags newly
corrupted files as they are written — prevention posture (flag a poisoned
ledger before resume), portable by construction: stdlib ``scandir``
snapshots only, no OS-event dependency, no runtime deps.

Semantics:

- Snapshot poll on ``(mtime_ns, size)`` of every file under the resolved
  roots (same built-in exclusions as scan).
- Debounce: a file must be stable for one full interval before it is
  checked — agents append in bursts, mid-append reads would tear.
- One transition line per verdict *change* (``healthy→invalid``, codes
  included); quiet by default — repeated states are not re-printed.
- Pure observer: never writes, never installs hooks, never holds files
  open. Ctrl+C / cancellation exits cleanly.
- Bounded memory: per-file state table is an LRU capped at
  ``MAX_TRACKED_FILES``.

Determinism caveat (documented per plan): watch is inherently real-time —
each transition *payload* is deterministic for a given file state;
ordering follows event order.
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from sesslint.progress import CancellationToken, OperationCancelled

WATCH_EVENT_SCHEMA: Final[str] = "sesslint.watch-event/v1"

DEFAULT_INTERVAL: Final[float] = 2.0
MIN_INTERVAL: Final[float] = 0.05
MAX_TRACKED_FILES: Final[int] = 4096

_EXCLUDED_DIRS: Final[frozenset[str]] = frozenset({".git", ".hg", ".svn"})
_EXCLUDED_NAMES: Final[frozenset[str]] = frozenset({"sesslint.toml", ".sesslint.toml"})


class CheckFn(Protocol):
    """Signature of the per-file check callable (``api.check_file`` shape)."""

    def __call__(self, path: Path) -> Any: ...


@dataclass(frozen=True, slots=True)
class WatchTransition:
    """One verdict transition on a watched file (content-free)."""

    path: str
    from_state: str
    to_state: str
    codes: tuple[str, ...]

    def to_dict(self, *, home: Path | None = None) -> dict[str, Any]:
        from sesslint.report import minimize_path

        return {
            "schema_version": WATCH_EVENT_SCHEMA,
            "path": minimize_path(self.path, home=home),
            "from": self.from_state,
            "to": self.to_state,
            "codes": list(self.codes),
        }


@dataclass(slots=True)
class _FileState:
    mtime_ns: int
    size: int
    stable_polls: int
    verdict: str | None


def _snapshot_file(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _walk_files(root: Path) -> list[Path]:
    """Iterative sorted walk with the scan built-in exclusions."""
    out: list[Path] = []
    stack: list[Path] = [root]
    while stack:
        curr = stack.pop()
        try:
            entries = sorted(os.scandir(curr), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in _EXCLUDED_DIRS:
                        stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    if entry.name not in _EXCLUDED_NAMES:
                        out.append(Path(entry.path))
            except OSError:
                continue
    return out


def _verdict_of(report: Any) -> tuple[str, tuple[str, ...]]:
    """Map a check Report to a watch verdict + bounded code list."""
    sev = report.counts.by_severity
    codes = tuple(sorted({f.code for f in report.findings}))
    if sev.get("error", 0) + sev.get("fatal", 0) > 0:
        return "invalid", codes
    if sev.get("warning", 0) > 0:
        return "warnings", codes
    if report.findings:
        return "warnings", codes
    return "healthy", codes


def watch(
    roots: Sequence[Path | str],
    *,
    interval: float = DEFAULT_INTERVAL,
    check_fn: CheckFn | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_transition: Callable[[WatchTransition], None] | None = None,
    cancel_token: CancellationToken | None = None,
    max_polls: int | None = None,
    format: str | None = None,
) -> int:
    """Poll ``roots`` until cancelled, emitting verdict transitions.

    Returns the number of transitions emitted. ``check_fn`` defaults to
    ``api.check_file`` (lazy import keeps this module light); tests inject
    fakes for check/sleep. ``max_polls`` bounds the loop for harness runs.
    Raises ``OperationCancelled`` on cancellation — the CLI maps it to a
    clean exit.
    """
    if interval < MIN_INTERVAL:
        raise ValueError(f"interval must be >= {MIN_INTERVAL}s, got {interval}")

    if check_fn is None:
        from sesslint.api import check_file

        def _default_check(path: Path) -> Any:
            return check_file(path, format=format)

        check_impl: CheckFn = _default_check
    else:
        check_impl = check_fn

    emit = on_transition if on_transition is not None else (lambda t: None)
    root_paths = [Path(r) for r in roots]

    states: OrderedDict[Path, _FileState] = OrderedDict()
    pending: set[Path] = set()
    emitted = 0
    polls = 0

    while True:
        if cancel_token is not None:
            cancel_token.throw_if_cancelled()
        if max_polls is not None and polls >= max_polls:
            return emitted
        polls += 1

        seen: set[Path] = set()
        for root in root_paths:
            files = [root] if (root.is_symlink() or not root.is_dir()) else _walk_files(root)
            for f in files:
                seen.add(f)
                snap = _snapshot_file(f)
                if snap is None:
                    continue
                mtime_ns, size = snap
                state = states.get(f)
                if state is None:
                    state = _FileState(mtime_ns, size, 0, None)
                    states[f] = state
                    pending.add(f)
                elif (state.mtime_ns, state.size) != (mtime_ns, size):
                    state.mtime_ns, state.size = mtime_ns, size
                    state.stable_polls = 0
                    pending.add(f)
                else:
                    state.stable_polls += 1
                states.move_to_end(f)

        # Files that disappeared drop out of pending (a vanished file mid-
        # debounce must not emit "unreadable"); their last verdict is kept so
        # reappearance re-evaluates as a change.
        pending.intersection_update(seen)

        # Debounced dispatch: stable for one full interval.
        for f in sorted(pending, key=str):
            state = states[f]
            if state.stable_polls < 1:
                continue
            pending.discard(f)
            try:
                report = check_impl(f)
                verdict, codes = _verdict_of(report)
            except OperationCancelled:
                raise
            except Exception:
                verdict, codes = "unreadable", ()
            previous = state.verdict
            state.verdict = verdict
            if verdict == "healthy" and previous is None:
                continue
            if verdict != previous:
                emit(
                    WatchTransition(
                        path=str(f),
                        from_state=previous or "new",
                        to_state=verdict,
                        codes=codes,
                    )
                )
                emitted += 1

        # LRU bound.
        while len(states) > MAX_TRACKED_FILES:
            evicted, _st = states.popitem(last=False)
            pending.discard(evicted)

        if max_polls is not None and polls >= max_polls:
            return emitted
        sleep_fn(interval)


def format_transition(t: WatchTransition, *, home: Path | None = None) -> str:
    """One-line human rendering of a transition event."""
    from sesslint.report import minimize_path

    codes = ",".join(t.codes) if t.codes else "-"
    return f"{t.from_state}->{t.to_state}  {minimize_path(t.path, home=home)}  [{codes}]"


__all__ = [
    "DEFAULT_INTERVAL",
    "MAX_TRACKED_FILES",
    "MIN_INTERVAL",
    "WATCH_EVENT_SCHEMA",
    "CheckFn",
    "WatchTransition",
    "format_transition",
    "watch",
]
