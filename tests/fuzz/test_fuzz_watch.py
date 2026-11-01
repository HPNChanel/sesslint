"""CL-17: ``watch`` through the library with ``max_polls``.

A scripted sequence of filesystem steps (hostile rewrites, deletes, replacing a
file with a directory or a symlink, touching mtime) runs between polls with the
real checker. Properties: the returned count equals the transitions emitted,
each path's transitions chain (``from_state`` is the previous ``to_state``), a
fresh healthy file never emits, replaying the same script
gives the same transitions, and no payload marker reaches an emitted line.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint.progress import CancellationToken, OperationCancelled
from sesslint.watch import WatchTransition, format_transition, watch
from tests.fuzz.test_fuzz_cli_surfaces import _ADAPTERS
from tests.fuzz.test_fuzz_hostile_inputs import MARKER, OPS, _mutated

_STEP = st.one_of(
    st.tuples(st.just("write"), st.integers(0, 1), _ADAPTERS, OPS),
    st.tuples(st.just("delete"), st.integers(0, 1)),
    st.tuples(st.just("dir"), st.integers(0, 1)),
    st.tuples(st.just("symlink"), st.integers(0, 1)),
    st.tuples(st.just("touch"), st.integers(0, 1)),
    st.tuples(st.just("idle")),
)


def _apply(work: Path, step: tuple[object, ...]) -> None:
    kind = step[0]
    if kind == "idle":
        return
    target = work / f"t{step[1]}.jsonl"
    if kind == "write":
        adapter, ops = step[2], step[3]
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        elif target.is_symlink():
            target.unlink()
        target.write_bytes(_mutated(adapter, ops))  # type: ignore[arg-type]
    elif kind == "delete":
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink(missing_ok=True)
    elif kind == "dir":
        if target.is_symlink() or target.is_file():
            target.unlink()
        target.mkdir(exist_ok=True)
    elif kind == "symlink":
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)
        target.symlink_to(work / "nowhere")
    elif kind == "touch" and target.is_file() and not target.is_symlink():
        stat = target.stat()
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))


def _run(
    steps: list[tuple[object, ...]], initial: bytes
) -> tuple[int, list[WatchTransition], list[str]]:
    work = Path(tempfile.mkdtemp(prefix="sl-cl17-w-"))
    try:
        (work / "t0.jsonl").write_bytes(initial)
        queue = iter(steps)
        seen: list[WatchTransition] = []

        def sleep(_s: float) -> None:
            step = next(queue, None)
            if step is not None:
                _apply(work, step)

        count = watch(
            [work],
            interval=0.05,
            sleep_fn=sleep,
            on_transition=seen.append,
            max_polls=len(steps) + 3,
        )
        lines = [format_transition(t, home=work) for t in seen]
        lines += [str(t.to_dict(home=work)) for t in seen]
        # Normalise the per-run temp root so replays compare equal.
        norm = [line.replace(str(work), "<w>") for line in lines]
        return count, seen, norm
    finally:
        shutil.rmtree(work, ignore_errors=True)


@given(
    steps=st.lists(_STEP, max_size=7),
    adapter=_ADAPTERS,
    ops=OPS,
)
@settings(deadline=None, max_examples=40, suppress_health_check=[HealthCheck.too_slow])
def test_watch_scripted_changes(
    steps: list[tuple[object, ...]], adapter: str, ops: list[tuple[str, int]]
) -> None:
    initial = _mutated(adapter, ops)
    count, seen, lines = _run(steps, initial)
    assert count == len(seen)
    last: dict[str, str] = {}
    for t in seen:
        name = Path(t.path).name
        if name in last:
            assert t.from_state == last[name], (name, t)
        else:  # a first healthy verdict is silent, so the chain may start there
            assert t.from_state in ("new", "healthy"), (name, t)
            assert not (t.from_state == "new" and t.to_state == "healthy")
        assert t.from_state != t.to_state
        last[name] = t.to_state
    assert not any(MARKER in line for line in lines)
    again = _run(steps, initial)
    assert again[0] == count
    assert again[2] == lines


def test_watch_cancel_and_bad_interval() -> None:
    token = CancellationToken()
    token.cancel()
    with pytest.raises(OperationCancelled):
        watch([Path("/nonexistent-sl")], interval=0.05, cancel_token=token, max_polls=3)
    for bad in (0.0, -1.0, float("nan"), float("inf"), 1e9):
        with pytest.raises(ValueError):
            watch([Path("/nonexistent-sl")], interval=bad, max_polls=1)
    assert (
        watch([Path("/nonexistent-sl")], interval=0.05, sleep_fn=lambda _s: None, max_polls=0) == 0
    )
