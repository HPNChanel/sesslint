"""Hypothesis fuzz tests for canonical adapter (TASK-027, FR-011..017, AC-003..006).

Guarantees:
- Total function: load_canonical handles arbitrary bytes/objects without uncaught exceptions.
- Determinism: identical input bytes produce identical outputs.
- Schema integrity: malformed or malicious structures fail closed into typed Finding objects.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from hypothesis import given, settings
from hypothesis import strategies as st

from sesslint.adapters.canonical import dump_canonical, load_canonical
from sesslint.canonical import SessionEvent
from sesslint.errors import SesslintError
from sesslint.finding import Finding


@given(st.binary(max_size=32768))
@settings(max_examples=50, deadline=None)
def test_fuzz_load_canonical_arbitrary_bytes(data: bytes) -> None:
    """load_canonical never raises uncaught exceptions on arbitrary bytes."""
    try:
        events1, findings1 = load_canonical(data)
    except SesslintError:
        return

    # Must return valid types
    assert isinstance(events1, list)
    assert isinstance(findings1, list)
    for f in findings1:
        assert isinstance(f, Finding)
    for e in events1:
        assert isinstance(e, SessionEvent)

    # Determinism check
    events2, findings2 = load_canonical(data)
    assert len(events1) == len(events2)
    assert len(findings1) == len(findings2)
    for f1, f2 in zip(findings1, findings2, strict=True):
        assert f1.fingerprint == f2.fingerprint
        assert f1.code == f2.code


# Recursive strategy for arbitrary JSON objects
json_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=50),
)

json_values = st.recursive(
    json_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=10),
        st.dictionaries(st.text(max_size=20), children, max_size=10),
    ),
    max_leaves=25,
)


@given(st.dictionaries(st.text(max_size=20), json_values, max_size=10))
@settings(max_examples=50, deadline=None)
def test_fuzz_load_canonical_arbitrary_json_document(doc: dict[str, object]) -> None:
    """load_canonical safely processes arbitrary JSON documents."""
    data = json.dumps(doc).encode("utf-8")
    try:
        events, findings = load_canonical(data)
        assert isinstance(events, list)
        assert isinstance(findings, list)
    except SesslintError:
        # Limits errors are acceptable fail-closed behavior
        pass


@given(
    st.fixed_dictionaries(
        {
            "id": st.from_regex(r"[a-zA-Z0-9_\-\.]{1,20}", fullmatch=True),
            "seq": st.integers(min_value=0, max_value=1000),
            "kind": st.sampled_from(["message", "tool_call", "tool_result", "checkpoint"]),
            "actor": st.sampled_from(["user", "assistant", "system", "tool"]),
            "ts": st.just("2026-09-06T12:00:00Z"),
            "parent_id": st.one_of(
                st.none(), st.from_regex(r"[a-zA-Z0-9_\-\.]{1,20}", fullmatch=True)
            ),
            "payload": st.dictionaries(st.text(max_size=10), st.text(max_size=20), max_size=3),
        }
    )
)
@settings(max_examples=30, deadline=None)
def test_fuzz_canonical_valid_event_round_trip(event_dict: dict[str, object]) -> None:
    """Valid canonical event structures survive dump and reload deterministically."""
    raw_payload = event_dict["payload"]
    payload_dict = (
        dict(cast(Mapping[str, Any], raw_payload)) if isinstance(raw_payload, Mapping) else {}
    )
    ev = SessionEvent(
        id=str(event_dict["id"]),
        seq=int(str(event_dict["seq"])),
        kind=cast(Any, event_dict["kind"]),
        actor=cast(Any, event_dict["actor"]),
        ts=str(event_dict["ts"]),
        parent_id=str(event_dict["parent_id"]) if event_dict["parent_id"] is not None else None,
        payload=payload_dict,
    )

    dumped = dump_canonical([ev])
    events, findings = load_canonical(dumped)

    # Clean round-trip without structural errors
    assert len(events) == 1
    reloaded = events[0]
    assert reloaded.id == ev.id
    assert reloaded.seq == ev.seq
    assert reloaded.kind == ev.kind
    assert reloaded.actor == ev.actor
    assert reloaded.ts == ev.ts
    assert reloaded.parent_id == ev.parent_id
