"""Tests for `sesslint watch` directory monitor (ux-reporting T-05)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sesslint.cli import main
from sesslint.progress import CancellationToken, OperationCancelled
from sesslint.watch import (
    MAX_TRACKED_FILES,
    MIN_INTERVAL,
    WatchTransition,
    format_transition,
    watch,
)


class _FakeFinding:
    def __init__(self, code: str) -> None:
        self.code = code


class _FakeReport:
    def __init__(self, codes: tuple[str, ...] = (), errors: int = 0, warnings: int = 0) -> None:
        self.findings = [_FakeFinding(c) for c in codes]
        self.counts = type(
            "C", (), {"by_severity": {"error": errors, "fatal": 0, "warning": warnings}}
        )()


def _healthy(path: Path) -> Any:
    return _FakeReport()


def _write(path: Path, recs: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")


_CLAUDE = [
    {"id": "m1", "type": "user_message", "message": "x", "timestamp": "2025-01-01T00:00:01Z"},
    {
        "id": "m2",
        "parentId": "m1",
        "type": "assistant_message",
        "message": "y",
        "timestamp": "2025-01-01T00:00:02Z",
    },
]


def test_watch_first_seen_healthy_quiet(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    _write(f, _CLAUDE)
    transitions: list[WatchTransition] = []
    emitted = watch(
        [tmp_path],
        interval=MIN_INTERVAL,
        check_fn=_healthy,
        sleep_fn=lambda s: None,
        on_transition=transitions.append,
        max_polls=4,
    )
    assert emitted == 0
    assert transitions == []


def test_watch_healthy_to_invalid_one_transition(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    _write(f, _CLAUDE)
    corrupt = {"armed": False}

    def check(path: Path) -> Any:
        if corrupt["armed"]:
            return _FakeReport(("SL004", "SL101"), errors=2)
        return _FakeReport()

    polls = {"n": 0}

    def sleep(_s: float) -> None:
        polls["n"] += 1
        if polls["n"] == 3:
            f.write_text(f.read_text(encoding="utf-8") + '{"id":"m3","type":"bogus"}\n')
            corrupt["armed"] = True

    transitions: list[WatchTransition] = []
    emitted = watch(
        [tmp_path],
        interval=MIN_INTERVAL,
        check_fn=check,
        sleep_fn=sleep,
        on_transition=transitions.append,
        max_polls=8,
    )
    assert emitted == 1
    t = transitions[0]
    assert t.from_state == "healthy"
    assert t.to_state == "invalid"
    assert t.codes == ("SL004", "SL101")


def test_watch_debounce_skips_mid_append(tmp_path: Path) -> None:
    """A file still changing between polls is never checked (stable<1)."""
    f = tmp_path / "s.jsonl"
    _write(f, _CLAUDE)
    checks: list[Path] = []
    polls = {"n": 0}

    def check(path: Path) -> Any:
        checks.append(path)
        return _FakeReport()

    def sleep(_s: float) -> None:
        polls["n"] += 1
        # Keep appending every poll — file never stabilizes.
        f.write_text(
            f.read_text(encoding="utf-8")
            + json.dumps(
                {
                    "id": f"x{polls['n']}",
                    "type": "user_message",
                    "message": "z",
                    "timestamp": "2025-01-01T00:00:03Z",
                }
            )
            + "\n"
        )

    watch(
        [tmp_path],
        interval=MIN_INTERVAL,
        check_fn=check,
        sleep_fn=sleep,
        max_polls=5,
    )
    assert checks == []


def test_watch_unreadable_transition(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    _write(f, _CLAUDE)

    def bad_check(path: Path) -> Any:
        raise OSError("gone")

    transitions: list[WatchTransition] = []
    watch(
        [tmp_path],
        interval=MIN_INTERVAL,
        check_fn=bad_check,
        sleep_fn=lambda s: None,
        on_transition=transitions.append,
        max_polls=4,
    )
    assert len(transitions) == 1
    assert transitions[0].to_state == "unreadable"


def test_watch_cancellation(tmp_path: Path) -> None:
    f = tmp_path / "s.jsonl"
    _write(f, _CLAUDE)
    token = CancellationToken()

    polls = {"n": 0}

    def sleep(_s: float) -> None:
        polls["n"] += 1
        if polls["n"] == 2:
            token.cancel()

    with pytest.raises(OperationCancelled):
        watch(
            [tmp_path],
            interval=MIN_INTERVAL,
            check_fn=_healthy,
            sleep_fn=sleep,
            cancel_token=token,
        )


def test_watch_interval_floor(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="interval"):
        watch([tmp_path], interval=0.001, check_fn=_healthy, sleep_fn=lambda s: None)


def test_watch_lru_bound_constant() -> None:
    assert MAX_TRACKED_FILES == 4096


def test_watch_format_transition_line(tmp_path: Path) -> None:
    t = WatchTransition(
        path=str(tmp_path / "s.jsonl"), from_state="healthy", to_state="invalid", codes=("SL004",)
    )
    line = format_transition(t)
    assert "healthy->invalid" in line
    assert "SL004" in line
    assert str(tmp_path) not in line  # minimized path only


def test_watch_transition_to_dict(tmp_path: Path) -> None:
    t = WatchTransition(
        path=str(tmp_path / "s.jsonl"),
        from_state="new",
        to_state="invalid",
        codes=("SL004", "SL101"),
    )
    d = t.to_dict()
    assert d["schema_version"] == "sesslint.watch-event/v1"
    assert d["from"] == "new"
    assert d["to"] == "invalid"
    assert d["codes"] == ["SL004", "SL101"]
    assert str(tmp_path) not in json.dumps(d)


def test_watch_cli_usage_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["watch"]) == 2
    assert main(["watch", str(tmp_path / "nope.jsonl")]) == 2
    f = tmp_path / "s.jsonl"
    _write(f, _CLAUDE)
    assert main(["watch", str(f), "--agent", "claude"]) == 2
    capsys.readouterr()


def test_watch_clean_to_secret_transition(tmp_path: Path) -> None:
    """A file gaining a persisted-secret shape emits a transition with SL009.

    Uses the real ``check_file`` path (transcript-hygiene T-02 acceptance):
    clean -> warnings with codes containing SL009.
    """
    import shutil

    fixture_dir = (
        Path(__file__).resolve().parent.parent.parent / "fixtures" / "checks" / "secret_seed"
    )
    f = tmp_path / "s.jsonl"
    shutil.copyfile(fixture_dir / "sl009_clean.jsonl", f)
    armed = {"n": 0}

    def sleep(_s: float) -> None:
        armed["n"] += 1
        if armed["n"] == 3:
            with f.open("ab") as fh:
                fh.write(
                    b'{"actor":"user","id":"evt_900","kind":"message",'
                    b'"parent_id":"evt_002","payload":{"text":"rotation"},'
                    b'"seq":900,"ts":"2026-09-21T00:00:09Z"}\n'
                )
                fh.write(
                    b'{"actor":"assistant","id":"evt_901","kind":"message",'
                    b'"parent_id":"evt_900","payload":{"text":"'
                    b"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"
                    b'"},"seq":901,"ts":"2026-09-21T00:00:10Z"}\n'
                )

    transitions: list[WatchTransition] = []
    emitted = watch(
        [tmp_path],
        interval=MIN_INTERVAL,
        sleep_fn=sleep,
        on_transition=transitions.append,
        max_polls=8,
        format="canonical",
    )
    assert emitted == 1
    t = transitions[0]
    assert t.from_state == "healthy"
    assert t.to_state == "warnings"
    assert "SL009" in t.codes
    line = format_transition(t)
    assert "SL009" in line
    assert "ghp_" not in line
