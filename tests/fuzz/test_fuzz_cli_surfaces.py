"""CL-16: hostile inputs through the CLI surfaces added since CL-05.

``triage``, ``bundle``, ``seal --verify``, baselines, ``diff``, ``stats``,
``export``, ``hook`` and ``watch`` plus every ``check`` report format. Each
run must exit with a published code (0/1/2) without the internal-error
handler, give the same bytes on a second run, and never print the planted
payload marker.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint.cli import main
from sesslint.seal import append_seal
from sesslint.watch import format_transition, watch
from tests.fuzz.test_fuzz_hostile_inputs import MARKER, OPS, SEEDS, _mutated

_ADAPTERS = st.sampled_from(sorted(SEEDS))
_CRASH = ("Operational error [ERR-", "INTERNAL_ERROR", "Traceback")


@contextmanager
def _workdir() -> Iterator[Path]:
    work = Path(tempfile.mkdtemp(prefix="sl-cl16-"))
    try:
        yield work
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _ext(adapter: str) -> str:
    return ".json" if adapter == "openai-agents" else ".jsonl"


def _run(argv: list[str], stdin: bytes = b"") -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    old_in = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main(argv)
            except SystemExit as exc:  # argparse usage errors
                code = exc.code if isinstance(exc.code, int) else 2
    finally:
        sys.stdin = old_in
    text = out.getvalue() + "\x00" + err.getvalue()
    return code, text


def _assert_clean(
    argv: list[str],
    stdin: bytes = b"",
    *,
    files: tuple[Path, ...] = (),
    cleanup: tuple[Path, ...] = (),
) -> int:
    code, text = _run(argv, stdin)
    assert code in (0, 1, 2), (argv, code, text[-500:])
    assert not any(c in text for c in _CRASH), (argv, text[-800:])
    assert MARKER not in text, argv
    for f in files:
        if f.exists():
            assert MARKER.encode() not in f.read_bytes(), (argv, f.name)
    for f in cleanup:  # output-writing commands refuse to overwrite (fail closed)
        f.unlink(missing_ok=True)
    again, text2 = _run(argv, stdin)
    assert (again, text2) == (code, text), argv
    return code


@given(adapter=_ADAPTERS, ops=OPS)
# ~20 CLI runs per example: capped to stay inside the dev budget; the CL-16
# campaign ran it at 2000 examples via an external profile.
@settings(deadline=None, max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_single_file_surfaces_on_hostile_input(adapter: str, ops: list[tuple[str, int]]) -> None:
    with _workdir() as work:
        src = work / f"s{_ext(adapter)}"
        src.write_bytes(_mutated(adapter, ops))
        p = str(src)
        _assert_clean(["triage", p, "-f", "json"])
        _assert_clean(["triage", p])
        _assert_clean(["bundle", p, "--json"])
        _assert_clean(["stats", p, "--json"])
        _assert_clean(["stats", p])
        for fmt in ("human", "json", "sarif", "html"):
            _assert_clean(["check", p, "-f", fmt])
        _assert_clean(
            ["export", p, "-o", str(work / "e.jsonl"), "--json"], cleanup=(work / "e.jsonl",)
        )
        bl = work / "bl.json"
        _assert_clean(["check", p, "--write-baseline", str(bl), "-f", "json"], files=(bl,))
        if bl.exists():
            _assert_clean(["check", p, "--baseline", str(bl), "-f", "json"])
        payload = json.dumps(
            {"session_id": MARKER, "transcript_path": p, "cwd": MARKER, "hook_event_name": "Stop"}
        ).encode()
        for event in ("Stop", "SessionStart", "PreCompact", "SessionEnd"):
            for fmt in ("text", "json", "claude-json"):
                _assert_clean(["hook", "--event", event, "-f", fmt], payload)


@given(a=_ADAPTERS, b=_ADAPTERS, ops_a=OPS, ops_b=OPS)
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_diff_on_hostile_pairs(
    a: str, b: str, ops_a: list[tuple[str, int]], ops_b: list[tuple[str, int]]
) -> None:
    with _workdir() as work:
        pa, pb = work / f"a{_ext(a)}", work / f"b{_ext(b)}"
        pa.write_bytes(_mutated(a, ops_a))
        pb.write_bytes(_mutated(b, ops_b))
        _assert_clean(["diff", str(pa), str(pb), "--json"])
        _assert_clean(["diff", str(pa), str(pb)])
        _assert_clean(["diff", str(pa), str(pa), "--json"])


_HOSTILE_BYTES = st.one_of(
    st.binary(max_size=200),
    st.sampled_from(
        [
            b"",
            b"\xef\xbb\xbf{}",
            b"[]",
            b"null",
            b'{"version": 2, "entries": "x"}',
            b'{"version": 2, "entries": [{"fingerprint": 1}]}',
            b'{"version": 1, "fingerprints": [null, 1, {"a": []}]}',
            b'{"version": 99}',
            b"[" * 5000 + b"]" * 5000,
            b'{"version": NaN}',
            b'{"version": 1e400}',
            json.dumps({"x": MARKER}).encode(),
        ]
    ),
)


@given(adapter=_ADAPTERS, baseline=_HOSTILE_BYTES)
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_hostile_baseline_file(adapter: str, baseline: bytes) -> None:
    with _workdir() as work:
        src = work / f"s{_ext(adapter)}"
        src.write_bytes(
            (Path(__file__).resolve().parents[2] / "fixtures" / SEEDS[adapter]).read_bytes()
        )
        bl = work / "bl.json"
        bl.write_bytes(baseline)
        _assert_clean(["check", str(src), "--baseline", str(bl), "-f", "json"])
        _assert_clean(["check", str(src), "--baseline", str(bl)])


@given(payload=_HOSTILE_BYTES, event=st.sampled_from(["Stop", "SessionStart", "x" * 300, ""]))
@settings(deadline=None)
def test_hook_hostile_payload(payload: bytes, event: str) -> None:
    for fmt in ("text", "json", "claude-json"):
        code = _assert_clean(["hook", "--event", event, "-f", fmt], payload)
        assert code in (0, 2)


def _ledger(work: Path, n: int) -> bytes:
    ledger = work / "ledger.jsonl"
    for i in range(n):
        append_seal(
            ledger,
            tool="verify",
            file_sha256=f"{i:064x}",
            path=None,
            verdict="healthy",
            codes={},
            report_sha256=f"{i + 7:064x}",
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
    return ledger.read_bytes() if ledger.exists() else b""


@given(
    n=st.integers(0, 4),
    ops=st.lists(
        st.tuples(st.sampled_from(["flip", "cut", "insert", "dup", "swap"]), st.integers(0, 4000)),
        max_size=3,
    ),
    junk=_HOSTILE_BYTES,
)
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_seal_verify_on_hostile_ledger(n: int, ops: list[tuple[str, int]], junk: bytes) -> None:
    with _workdir() as work:
        data = _ledger(work, n)
        for op, at in ops:
            lines = data.split(b"\n")
            k = at % max(len(lines), 1)
            if op == "flip" and data:
                i = at % len(data)
                data = data[:i] + bytes([data[i] ^ 0x01]) + data[i + 1 :]
            elif op == "cut":
                data = data[: at % (len(data) + 1)]
            elif op == "insert":
                data = b"\n".join([*lines[:k], junk, *lines[k:]])
            elif op == "dup":
                data = b"\n".join([*lines[: k + 1], lines[k], *lines[k + 1 :]])
            else:
                data = b"\n".join(reversed(lines))
        ledger = work / "hostile.jsonl"
        ledger.write_bytes(data)
        _assert_clean(["seal", "--verify", str(ledger), "--json"])
        _assert_clean(["seal", "--verify", str(ledger)])


@given(adapter=_ADAPTERS, ops=OPS, later=OPS)
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_watch_transitions_on_hostile_rewrites(
    adapter: str, ops: list[tuple[str, int]], later: list[tuple[str, int]]
) -> None:
    with _workdir() as work:
        src = work / f"s{_ext(adapter)}"
        src.write_bytes(_mutated(adapter, ops))
        lines: list[str] = []
        steps = iter([lambda: src.write_bytes(_mutated(adapter, later)), lambda: src.unlink()])

        def sleep(_s: float) -> None:
            step = next(steps, None)
            if step is not None:
                step()

        def emit(t: object) -> None:
            lines.append(format_transition(t, home=work))  # type: ignore[arg-type]
            lines.append(json.dumps(t.to_dict(home=work), sort_keys=True))  # type: ignore[attr-defined]

        watch([work], interval=0.05, sleep_fn=sleep, on_transition=emit, max_polls=8)
        text = "\n".join(lines)
        assert MARKER not in text


_HOSTILE_IDS = (
    "zq@planted.example",
    "Bearer QWERTYUIOPASDFGHJKLZXCVBNM123456",
    "id\x1b[31m",
    "id\nFORGED",
    "id‮RLO",
)
_LEAKS = ("planted.example", "QWERTYUIOP", "\x1b", "\nFORGED", "‮")
_ID_FIELDS = ("id", "parentId", "toolUseId", "sessionId")
_TYPES = ("user_message", "assistant_message", "tool_use", "tool_result")


@st.composite
def _hostile_id_session(draw: st.DrawFn) -> bytes:
    n = draw(st.integers(1, 6))
    lines = []
    for i in range(n):
        rec: dict[str, object] = {
            "id": f"m{i}",
            "type": draw(st.sampled_from(_TYPES)),
            "message": "hi",
            "timestamp": f"2025-01-01T12:00:0{i}Z",
        }
        if i:
            rec["parentId"] = f"m{i - 1}"
        for fld in draw(st.lists(st.sampled_from(_ID_FIELDS), max_size=3, unique=True)):
            rec[fld] = draw(st.sampled_from(_HOSTILE_IDS))
        lines.append(json.dumps(rec))
    return ("\n".join(lines) + "\n").encode()


@given(a=_hostile_id_session(), b=_hostile_id_session())
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_hostile_ids_never_reach_any_output(a: bytes, b: bytes) -> None:
    with _workdir() as work:
        pa, pb = work / "a.jsonl", work / "b.jsonl"
        pa.write_bytes(a)
        pb.write_bytes(b)
        runs = [
            ["diff", str(pa), str(pb)],
            ["diff", str(pa), str(pb), "--json"],
            ["triage", str(pa)],
            ["triage", str(pa), "-f", "json"],
            ["bundle", str(pa), "--json"],
            ["stats", str(pa), "--json"],
            ["repair", str(pa), "--dry-run", "--json"],
            *(["check", str(pa), "-f", fmt] for fmt in ("human", "json", "sarif", "html")),
        ]
        for argv in runs:
            _code, text = _run(argv)
            assert not any(c in text for c in _CRASH), (argv, text[-800:])
            leaked = [t for t in _LEAKS if t in text]
            assert not leaked, (argv, leaked)
