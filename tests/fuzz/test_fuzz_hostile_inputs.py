"""CL-05: hostile-input properties across adapters, codec, repair and OutcomeGuard.

Each property asserts the three campaign invariants: no unhandled exception
(only the published error types), the same input gives the same bytes, and a
planted payload marker never reaches a report or finding. The marker carries
spaces so it can never pass the bounded discriminator echo (DEV-008).
"""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint import api
from sesslint._canonical_codec import PurePythonCanonicalCodec
from sesslint.errors import SchemaError, SesslintError
from sesslint.outcome import verify_outcome
from sesslint.outcome.contract import ContractError
from sesslint.outcome.snapshot import SnapshotError

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
MARKER = "planted payload 9b1e"
SEEDS = {
    "canonical": "cli/check_basic/healthy.jsonl",
    "claude-code-jsonl": "claude_code/basic.jsonl",
    "codex-rollout": "adapters/codex/healthy_min.jsonl",
    "openai-agents": "openai_agents/items_basic.json",
}
_MARKER_RECORD = json.dumps({"type": "message", "text": MARKER, "content": MARKER}).encode()


def _apply(op: str, data: bytes, at: int) -> bytes:
    lines = data.split(b"\n")
    k = at % len(lines)
    if op == "truncate":
        return data[: at % (len(data) + 1)]
    if op == "invalid-utf8":
        return data[:at] + b"\xff\xfe\xc3" + data[at:]
    if op == "bom":
        return b"\xef\xbb\xbf" + data
    if op == "crlf":
        return data.replace(b"\n", b"\r\n")
    if op == "nul":
        return data[:at] + b"\x00" + data[at:]
    if op == "duplicate-line":
        return b"\n".join([*lines[: k + 1], lines[k], *lines[k + 1 :]])
    if op == "reverse-lines":
        return b"\n".join(reversed(lines))
    if op == "deep-nesting":
        return data[:at] + b"[" * 400 + b"]" * 400 + data[at:]
    if op == "duplicate-key":
        return data.replace(b'"type":', b'"type": "x", "type":', 1)
    if op == "marker-value":
        return data.replace(b'"text"', b'"text": "%s", "text"' % MARKER.encode(), 1)
    if op == "marker-record":
        return b"\n".join([*lines[:k], _MARKER_RECORD, *lines[k:]])
    # huge-line
    return data[:at] + b'"' + b"x" * 200_000 + b'"' + data[at:]


OPS = st.lists(
    st.tuples(
        st.sampled_from(
            [
                "truncate",
                "invalid-utf8",
                "bom",
                "crlf",
                "nul",
                "duplicate-line",
                "reverse-lines",
                "deep-nesting",
                "duplicate-key",
                "marker-value",
                "marker-record",
                "huge-line",
            ]
        ),
        st.integers(min_value=0, max_value=2_000),
    ),
    min_size=1,
    max_size=3,
)


def _mutated(adapter: str, ops: list[tuple[str, int]]) -> bytes:
    data = (FIXTURES / SEEDS[adapter]).read_bytes()
    for op, at in ops:
        data = _apply(op, data, at)
    return data


def _report_text(report: Any) -> str:
    return json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=False)


@pytest.mark.parametrize("adapter", SEEDS)
@given(ops=OPS, auto=st.booleans())
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_adapter_hostile_bytes_are_typed_deterministic_and_content_free(
    adapter: str, ops: list[tuple[str, int]], auto: bool
) -> None:
    data = _mutated(adapter, ops)
    fmt = None if auto else adapter
    try:
        first = api.check_bytes(data, format=fmt)
    except SesslintError as error:
        assert MARKER not in str(error)
        with pytest.raises(type(error)):
            api.check_bytes(data, format=fmt)
        return
    text = _report_text(first)
    assert text == _report_text(api.check_bytes(data, format=fmt))
    assert MARKER not in text


@pytest.mark.parametrize("adapter", SEEDS)
@given(ops=OPS, policy=st.sampled_from(["conservative", "salvage"]))
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_repair_on_hostile_input_refuses_or_verifies(
    adapter: str, ops: list[tuple[str, int]], policy: Literal["conservative", "salvage"]
) -> None:
    ext = ".json" if adapter == "openai-agents" else ".jsonl"
    work = Path(tempfile.mkdtemp(prefix="sl-cl05-"))
    try:
        src = work / f"session{ext}"
        src.write_bytes(_mutated(adapter, ops))
        out = work / f"out{ext}"
        try:
            _plan, manifest = api.repair(src, out, policy=policy, acknowledge_side_effects=True)
        except SesslintError as error:
            assert MARKER not in str(error)
            assert not out.exists()
            return
        assert manifest is not None
        verdict = api.verify(
            src, out, work / f"out{ext}.manifest.json", acknowledge_side_effects=True
        )
        assert verdict.ok, [c for c in verdict.checks if not c.ok]
        assert MARKER not in json.dumps(manifest.to_dict(), ensure_ascii=False)
    finally:
        shutil.rmtree(work, ignore_errors=True)


CODEC_LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.integers(min_value=10**4300, max_value=10**4400),
    st.floats(),
    st.sampled_from([-0.0, 0.0, 1e308, -1e-320]),
    st.text(),
    st.sampled_from(["\ud800", "x\udfffy", "\U0001f600", "\x00", " "]),
)
CODEC_VALUES = st.recursive(
    CODEC_LEAVES,
    lambda child: st.one_of(
        st.lists(child, max_size=4), st.dictionaries(st.text(max_size=8), child, max_size=4)
    ),
    max_leaves=12,
)


def _reversed_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _reversed_keys(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [_reversed_keys(v) for v in value]
    return value


@given(value=CODEC_VALUES)
@settings(deadline=None)
def test_codec_is_typed_and_key_order_independent(value: Any) -> None:
    codec = PurePythonCanonicalCodec()
    try:
        encoded = codec.canonical_json_bytes({"v": value})
    except SchemaError:
        with pytest.raises(SchemaError):
            codec.canonical_json_bytes({"v": _reversed_keys(value)})
        return
    assert encoded == codec.canonical_json_bytes({"v": _reversed_keys(value)})
    assert json.loads(encoded) == json.loads(encoded.decode("utf-8"))


CSV_NUMBERS = st.one_of(
    st.sampled_from(
        [
            "0",
            "-0",
            "+0",
            "-0.0",
            "1e400",
            "1E-400",
            "1e9999999",
            "NaN",
            "Infinity",
            " 1",
            "1 ",
            "+1",
            "--1",
            "1,5",
            "2.50",
            "１２",
            "1" + "0" * 4400,
            "9" * 101,
            "",
        ]
    ),
    st.text(alphabet="0123456789.-+eE ", max_size=12),
)
JSON_NUMBERS = st.sampled_from(
    ["0", "-0", "-0.0", "1e400", "1e-400", "1e999999", "1e9999999", "2.500", "1" + "0" * 5000]
)
OUTCOME = FIXTURES / "outcome" / "orders"


@given(
    weight=CSV_NUMBERS,
    sku=CSV_NUMBERS,
    target_weight=JSON_NUMBERS,
    range_max=JSON_NUMBERS,
    hash_keys=st.booleans(),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_outcome_odd_numbers_are_typed_and_deterministic(
    weight: str, sku: str, target_weight: str, range_max: str, hash_keys: bool
) -> None:
    work = Path(tempfile.mkdtemp(prefix="sl-cl05-og-"))
    try:
        contract = (OUTCOME / "contract.json").read_text()
        contract = contract.replace('"max": 50', f'"max": {range_max}')
        (work / "contract.json").write_text(contract)

        def cell(text: str) -> str:
            return '"' + text.replace('"', '""') + '"'

        (work / "source.csv").write_text(
            "order_id,placed_at,state,region,sku,weight_kg\n"
            f"0001,2026-10-20T08:00:00Z,open,EU,{cell(sku)},{cell(weight)}\n"
            f"0002,2026-10-20T08:00:00Z,open,US,{cell(MARKER)},1\n"
        )
        (work / "target.jsonl").write_text(
            '{"order_ref": "0001", "status": "shipped", "sku": "SKU-A", "warehouse": "EU-1", '
            f'"shipped_at": "2026-10-20T08:40:00Z", "weight_kg": {target_weight}}}\n'
            f'{{"order_ref": "0002", "status": "{MARKER}", "weight_kg": 1}}\n'
        )
        as_of = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)

        def run() -> str:
            report = verify_outcome(
                work / "contract.json",
                work / "source.csv",
                work / "target.jsonl",
                as_of=as_of,
                hash_keys=hash_keys,
            )
            return json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=False)

        try:
            first = run()
        except (ContractError, SnapshotError) as error:
            assert MARKER not in str(error)
            return
        assert first == run()
        assert MARKER not in first
    finally:
        shutil.rmtree(work, ignore_errors=True)
