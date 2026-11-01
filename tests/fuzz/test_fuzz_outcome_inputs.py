"""CL-17: OutcomeGuard beyond file-read errors.

Structurally hostile contracts (wrong types, unknown keys, odd operators,
deep values) and hostile snapshots (CSV/JSON/JSONL bytes) go through
``sesslint outcome``. Each run must exit 0/1/2 without the internal-error
handler, give the same bytes twice, and never print the planted marker.
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.fuzz.test_fuzz_cli_surfaces import _assert_clean
from tests.fuzz.test_fuzz_hostile_inputs import FIXTURES, MARKER

ORDERS = FIXTURES / "outcome" / "orders"
_BASE: dict[str, Any] = json.loads((ORDERS / "contract.json").read_text(encoding="utf-8"))
_SOURCE = (ORDERS / "source.csv").read_bytes()
_TARGET = (ORDERS / "target.jsonl").read_bytes()

_LEAF = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(2**70), 2**70),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=12),
    st.lists(st.text(max_size=4), max_size=3),
    st.dictionaries(st.text(max_size=4), st.integers(), max_size=2),
)
_OPS = st.sampled_from(["eq", "ne", "in", "gt", "lt", "re", "contains", ""])
_TYPES = st.sampled_from(
    ["exists", "count", "required", "one_of", "equals", "route", "on_time", "range", "bogus"]
)


def _paths(node: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out: list[tuple[Any, ...]] = [prefix] if prefix else []
    if isinstance(node, dict):
        for k, v in node.items():
            out += _paths(v, (*prefix, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _paths(v, (*prefix, i))
    return out


_ALL_PATHS = _paths(_BASE)


@st.composite
def _contracts(draw: st.DrawFn) -> bytes:
    doc = copy.deepcopy(_BASE)
    for _ in range(draw(st.integers(0, 3))):
        path = draw(st.sampled_from(_ALL_PATHS))
        parent: Any = doc
        try:
            for step in path[:-1]:
                parent = parent[step]
            action = draw(st.sampled_from(["set", "delete", "type", "op", "addkey"]))
            leaf = path[-1]
            if action == "set":
                parent[leaf] = draw(_LEAF)
            elif action == "delete":
                del parent[leaf]
            elif action == "type":
                parent[leaf] = draw(_TYPES)
            elif action == "op":
                parent[leaf] = draw(_OPS)
            elif isinstance(parent, dict):
                parent[draw(st.text(max_size=6))] = draw(_LEAF)
        except (KeyError, IndexError, TypeError):
            continue
    try:
        return json.dumps(doc).encode()
    except ValueError:
        return b"{}"


_RAW = st.one_of(
    st.binary(max_size=300),
    st.sampled_from(
        [
            b"",
            b"\xef\xbb\xbf",
            b"[]",
            b'{"a":1}\n{"a":',
            b"a,b\n1\n",
            b'a,b\n"1,2\n',
            b"a,a\n1,2\n",
            b"\x00\x00",
            b"[" * 3000 + b"]" * 3000,
            ("k,v\n" + MARKER + ",1\n").encode(),
        ]
    ),
)


def _run_outcome(work: Path, extra: list[str]) -> None:
    base = ["outcome", str(work / "contract.json"), "--source", str(work / "source.csv")]
    base += ["--target", str(work / "target.jsonl"), "--as-of", "2026-10-20T12:00:00Z"]
    for fmt in ([], ["--json"], ["--json", "--hash-keys", "--all-conditions"]):
        _assert_clean([*base, *fmt, *extra])


@given(contract=_contracts())
@settings(deadline=None, max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_hostile_contract_structure(contract: bytes) -> None:
    work = Path(tempfile.mkdtemp(prefix="sl-cl17-oc-"))
    try:
        (work / "contract.json").write_bytes(contract)
        (work / "source.csv").write_bytes(_SOURCE)
        (work / "target.jsonl").write_bytes(_TARGET)
        _run_outcome(work, [])
        _assert_clean(["outcome", str(work / "contract.json"), "--explain"])
    finally:
        shutil.rmtree(work, ignore_errors=True)


@given(source=_RAW, target=_RAW, tgt_ext=st.sampled_from([".jsonl", ".json", ".csv"]))
@settings(deadline=None, max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_hostile_snapshots(source: bytes, target: bytes, tgt_ext: str) -> None:
    work = Path(tempfile.mkdtemp(prefix="sl-cl17-os-"))
    try:
        (work / "contract.json").write_bytes((ORDERS / "contract.json").read_bytes())
        (work / "source.csv").write_bytes(source)
        tgt = work / f"target{tgt_ext}"
        tgt.write_bytes(target)
        base = ["outcome", str(work / "contract.json"), "--source", str(work / "source.csv")]
        base += ["--target", str(tgt), "--as-of", "2026-10-20T12:00:00Z"]
        for fmt in ([], ["--json"]):
            _assert_clean([*base, *fmt])
            _assert_clean([*base, *fmt, "--target-completeness", "complete"])
            _assert_clean([*base, *fmt, "--max-file-bytes", "50"])
    finally:
        shutil.rmtree(work, ignore_errors=True)
