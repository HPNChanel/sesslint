"""CL-16: MCP stdio dispatcher under arbitrary JSON-RPC traffic (integrations T-01).

Both protocol revisions are exercised in one stream: legacy ``initialize``
traffic interleaved with stateless 2026-07-28 requests, batches, scalars,
wrong types, hostile ids and tool arguments. Invariants: the server never
dies, every response is one strict-JSON line that is a well-formed JSON-RPC
2.0 response, every addressable request gets exactly one answer with its id,
and the stream answer equals the per-line answers (stateless, deterministic).
"""

from __future__ import annotations

import io
import json
import math
from pathlib import Path
from typing import Any

from hypothesis import example, given
from hypothesis import strategies as st

from sesslint.mcp_server import MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION, handle_line, serve

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "cli" / "check_basic" / "healthy.jsonl"
V = "io.modelcontextprotocol/protocolVersion"
C = "io.modelcontextprotocol/clientCapabilities"
_CODES = {-32700, -32600, -32601, -32602, -32603, -32022}

_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**70), max_value=2**70),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=20),
)
_json = st.recursive(
    _scalars,
    lambda kids: st.one_of(
        st.lists(kids, max_size=4), st.dictionaries(st.text(max_size=8), kids, max_size=4)
    ),
    max_leaves=12,
)
_ids = st.one_of(_json, st.integers(-5, 5), st.text(max_size=5))
_methods = st.one_of(
    st.sampled_from(
        [
            "initialize",
            "ping",
            "tools/list",
            "tools/call",
            "server/discover",
            "notifications/initialized",
            "logging/setLevel",
            "bogus",
        ]
    ),
    _json,
)
_paths = st.one_of(
    st.just(str(FIXTURE)),
    st.just(str(FIXTURE.parent)),
    st.just("a" * 5000),
    st.just("/nonexistent/x\x00y"),
    st.just("\ud800"),
    st.text(max_size=12),
    _json,
)
_args = st.one_of(
    _json,
    st.fixed_dictionaries(
        {"path": _paths},
        optional={
            "profile": st.one_of(st.sampled_from(["neutral", "nope"]), _json),
            "format": st.one_of(st.sampled_from(["auto", "canonical", "x"]), _json),
            "recursive": _json,
            "extra": _json,
        },
    ),
)
_meta = st.one_of(
    _json,
    st.fixed_dictionaries(
        {},
        optional={
            V: st.one_of(
                st.sampled_from([MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION, "1999"]), _json
            ),
            C: st.one_of(st.just({}), _json),
        },
    ),
)
_params = st.one_of(
    _json,
    st.fixed_dictionaries(
        {},
        optional={
            "name": st.one_of(
                st.sampled_from(
                    ["sesslint_check", "sesslint_scan", "sesslint_precheck", "sesslint_triage"]
                ),
                _json,
            ),
            "arguments": _args,
            "_meta": _meta,
            "cursor": _json,
            "requestState": _json,
        },
    ),
)
_message = st.one_of(
    _json,
    st.fixed_dictionaries(
        {"jsonrpc": st.one_of(st.just("2.0"), _json)},
        optional={"id": _ids, "method": _methods, "params": _params},
    ),
)


def _encode(msg: Any) -> bytes:
    return json.dumps(msg, ensure_ascii=False).encode("utf-8", "surrogatepass")


_line = st.one_of(
    _message.map(_encode),
    st.lists(_message, max_size=3).map(_encode),  # batches
    st.binary(max_size=40),
)


def _reject_constant(token: str) -> Any:
    raise AssertionError(f"non-standard JSON constant {token}")


def _addressable(raw: bytes) -> tuple[bool, Any]:
    """(must-answer, id) for a well-formed request line."""
    try:
        msg = json.loads(raw.strip().decode("utf-8"))
    except (ValueError, RecursionError):
        return False, None
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "id" not in msg:
        return False, None
    rid, method = msg["id"], msg.get("method")
    ok_id = (
        rid is None
        or isinstance(rid, str)
        or (isinstance(rid, int | float) and not isinstance(rid, bool) and math.isfinite(rid))
    )
    if not ok_id or not isinstance(method, str) or method.startswith("notifications/"):
        return False, None
    return True, rid


def _check_response(out: bytes) -> dict[str, Any]:
    assert out.endswith(b"\n") and out.count(b"\n") == 1
    resp = json.loads(out, parse_constant=_reject_constant)
    assert isinstance(resp, dict) and resp["jsonrpc"] == "2.0"
    assert ("result" in resp) != ("error" in resp)
    rid = resp["id"]
    assert rid is None or isinstance(rid, str | int | float) and not isinstance(rid, bool)
    if "error" in resp:
        assert resp["error"]["code"] in _CODES
        assert isinstance(resp["error"]["message"], str)
    return resp


@given(lines=st.lists(_line, min_size=1, max_size=6))
@example(lines=[b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}'])
@example(lines=[b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]', b"[]", b"7"])
@example(lines=[b'{"jsonrpc":"1.0","id":3,"method":"ping"}'])
@example(
    lines=[
        _encode(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "sesslint_check", "arguments": {"path": "a" * 5000}},
            }
        )
    ]
)
def test_mcp_always_answers_within_protocol(lines: list[bytes]) -> None:
    per_line: list[bytes] = []
    for raw in lines:
        out = handle_line(raw)
        must, rid = _addressable(raw)
        if out is None:
            assert not must
            continue
        resp = _check_response(out)
        if must:
            nan_id = isinstance(rid, float) and math.isnan(rid)
            assert resp["id"] == rid or (nan_id and resp["id"] is None)
        per_line.append(out)

    stdout = io.BytesIO()
    stream = b"".join(raw.replace(b"\n", b" ") + b"\n" for raw in lines)
    assert serve(io.BytesIO(stream), stdout) == 0
    flat = [handle_line(raw.replace(b"\n", b" ") + b"\n") for raw in lines]
    assert stdout.getvalue() == b"".join(o for o in flat if o is not None)
