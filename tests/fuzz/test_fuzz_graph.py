"""Hypothesis fuzz tests for parent graph integrity and cycle detection (TASK-027, FR-011..017).

Guarantees:
- Graph verification terminates bounded in time (< 1s) regardless of graph complexity.
- Total function: handles arbitrary cycle structures, self-loops, disconnected components,
  and deep causal chains without RecursionError or uncaught exceptions.
- Deterministic: identical graph topologies yield identical Finding fingerprints.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import cast

from hypothesis import given, settings
from hypothesis import strategies as st

from sesslint.canonical import SessionEvent
from sesslint.checks.graph import check_cycles, check_graph
from sesslint.finding import Finding


def _make_events(parent_map: Mapping[str, str | None]) -> list[SessionEvent]:
    """Helper to construct minimal SessionEvent list from parent map."""
    events: list[SessionEvent] = []
    for idx, (node_id, parent_id) in enumerate(parent_map.items()):
        events.append(
            SessionEvent(
                id=node_id,
                seq=idx,
                kind="message",
                actor="assistant",
                ts="2026-09-06T12:00:00Z",
                parent_id=parent_id,
                payload={},
            )
        )
    return events


@given(
    st.integers(min_value=5, max_value=60).flatmap(
        lambda n: st.fixed_dictionaries(
            {
                "node_count": st.just(n),
                "parents": st.lists(
                    st.integers(min_value=-2, max_value=n + 5),
                    min_size=n,
                    max_size=n,
                ),
            }
        )
    )
)
@settings(max_examples=50, deadline=None)
def test_fuzz_arbitrary_parent_topologies(spec: dict[str, object]) -> None:
    """Arbitrary parent topologies terminate cleanly and produce valid findings."""
    n = int(str(spec["node_count"]))
    raw_parents = cast(list[int], spec["parents"])

    node_ids = [f"n_{i}" for i in range(n)]
    parent_map: dict[str, str | None] = {}

    for i, p_idx in enumerate(raw_parents):
        if p_idx == -2:
            parent_map[node_ids[i]] = None
        elif p_idx == -1:
            parent_map[node_ids[i]] = "ghost_missing_parent"
        elif 0 <= p_idx < n:
            parent_map[node_ids[i]] = node_ids[p_idx]
        else:
            parent_map[node_ids[i]] = f"external_{p_idx}"

    events = _make_events(parent_map)

    start = time.perf_counter()
    findings = check_graph(events)
    elapsed = time.perf_counter() - start

    # Termination guarantee
    assert elapsed < 1.0, f"Graph check took too long: {elapsed:.3f}s"
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.code in ("SL004", "SL005", "SL006", "SL007")

    # Determinism check
    findings2 = check_graph(events)
    assert len(findings) == len(findings2)
    for f1, f2 in zip(findings, findings2, strict=True):
        assert f1.fingerprint == f2.fingerprint
        assert f1.code == f2.code


def test_deep_parent_chain_recursion_resistance() -> None:
    """A linear parent chain of 500 nodes executes without RecursionError."""
    chain_len = 500
    parent_map: dict[str, str | None] = {"node_0": None}
    for i in range(1, chain_len):
        parent_map[f"node_{i}"] = f"node_{i - 1}"

    events = _make_events(parent_map)
    start = time.perf_counter()
    findings = check_graph(events)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0
    # Clean linear chain has 0 errors (0 missing parents, 0 cycles, 1 component, 1 head)
    sl004_or_sl005 = [f for f in findings if f.code in ("SL004", "SL005")]
    assert len(sl004_or_sl005) == 0


def test_tight_and_extended_cycles() -> None:
    """Cycles of length 1 (self-loop), 2, and 10 are detected with SL005."""
    # Self-loop
    self_loop = _make_events({"n0": "n0"})
    f_self = check_cycles(self_loop)
    assert any(f.code == "SL005" for f in f_self)

    # 2-cycle
    cycle2 = _make_events({"n0": "n1", "n1": "n0"})
    f_cycle2 = check_cycles(cycle2)
    assert any(f.code == "SL005" for f in f_cycle2)

    # 10-cycle
    cycle10_map = {f"n{i}": f"n{(i + 1) % 10}" for i in range(10)}
    f_cycle10 = check_cycles(_make_events(cycle10_map))
    assert any(f.code == "SL005" for f in f_cycle10)
