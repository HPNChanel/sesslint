"""Hypothesis stateful session-mutation machine (qa-infra T-01).

A ``RuleBasedStateMachine`` that mutates a synthetic canonical session through
the operations real corruption produces — duplicate records, reordered
records, truncated tails, NUL/invalid-UTF-8 injection, dangling parents,
spliced blobs, corrupted ids — asserting the invariants that matter after
every step:

- ``check_file`` never escapes with an unexpected exception (``SesslintError``
  subclasses are legal fail-closed outcomes; anything else is a crash);
- identical bytes produce byte-identical reports (determinism);
- ``check_file`` findings equal ``check_dir`` per-file findings on the same
  bytes — the metamorphic invariant that hunts the field-test bug class
  (check vs scan diverging on identical input);
- every finding code is a registered code (``ALL_CODES``).

Seeded-repro protocol: any failure found is minimized by hypothesis, then the
minimized input bytes are frozen into ``fixtures/`` as a named regression —
never the whole generated session. Sessions stay synthetic-only; generated
payloads carry placeholder text, never real data.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from sesslint import api
from sesslint.codes import ALL_CODES
from sesslint.errors import SesslintError

_MAX_EVENTS = 200
_BASE_TS = "2026-01-01T00:00:{sec:02d}Z"


def _event(idx: int, parent: str | None) -> dict[str, object]:
    """Build one well-formed canonical event dict."""
    return {
        "actor": "user" if idx % 2 == 0 else "assistant",
        "id": f"evt_{idx:04d}",
        "kind": "message",
        "parent_id": parent,
        "payload": {"text": f"synthetic-{idx}"},
        "seq": idx,
        "ts": _BASE_TS.format(sec=idx % 60),
    }


def _doc(records: list[dict[str, object]]) -> bytes:
    """Serialize record dicts into a sesslint.session/v1 document."""
    doc = {
        "schema": "sesslint.session/v1",
        "version": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "events": records,
    }
    return (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8")


class SessionMutationMachine(RuleBasedStateMachine):
    """Mutate a canonical session; assert check/scan consistency every step."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[dict[str, object]] = []
        self.next_idx = 0
        self._dir = Path(tempfile.mkdtemp(prefix="sesslint-stateful-"))

    def teardown(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    def _verify(self, data: bytes) -> None:
        """Write ``data`` and assert all invariants on it."""
        path = self._dir / "session.json"
        path.write_bytes(data)

        try:
            report = api.check_file(path)
        except SesslintError:
            report = None

        # Determinism: identical bytes -> byte-identical report.
        try:
            again = api.check_file(path)
        except SesslintError:
            again = None
        assert (report is None) == (again is None), "check_file outcome unstable"
        if report is not None and again is not None:
            assert json.dumps(report.to_dict(), sort_keys=True) == json.dumps(
                again.to_dict(), sort_keys=True
            )

        # Metamorphic: check_file and scan must agree on the same bytes.
        scan = api.check_dir(self._dir, ext=(".json",))
        assert len(scan.files) == 1, f"expected 1 file, got {len(scan.files)}"
        file_result = scan.files[0]
        if report is None:
            assert file_result.verdict in ("invalid", "unreadable", "skipped"), (
                f"check refused but scan verdict is {file_result.verdict}"
            )
            return
        check_side = sorted((f.code, str(f.severity)) for f in report.findings)
        scan_side = sorted((f.code, str(f.severity)) for f in file_result.findings)
        assert check_side == scan_side, (
            f"check/scan divergence: only-in-check={set(check_side) - set(scan_side)} "
            f"only-in-scan={set(scan_side) - set(check_side)}"
        )
        for finding in report.findings:
            assert finding.code in ALL_CODES, f"unregistered code {finding.code}"

    def _verify_records(self) -> None:
        self._verify(_doc(self.records))

    # -- rules (structural mutations) ---------------------------------------

    @rule()
    def add_event(self) -> None:
        """Append a well-formed event; the base state generator."""
        if len(self.records) >= _MAX_EVENTS:
            return
        parent = self.records[-1]["id"] if self.records else None
        self.records.append(_event(self.next_idx, str(parent) if parent else None))
        self.next_idx += 1
        self._verify_records()

    @rule(pos=st.integers(min_value=0, max_value=_MAX_EVENTS - 1))
    def duplicate_event(self, pos: int) -> None:
        """Insert a verbatim copy of an existing record (duplicate id)."""
        if not self.records or len(self.records) >= _MAX_EVENTS:
            return
        pos %= len(self.records)
        self.records.insert(pos, dict(self.records[pos]))
        self._verify_records()

    @rule(
        a=st.integers(min_value=0, max_value=_MAX_EVENTS - 1),
        b=st.integers(min_value=0, max_value=_MAX_EVENTS - 1),
    )
    def swap_events(self, a: int, b: int) -> None:
        """Swap two records (order/monotonicity corruption)."""
        if len(self.records) < 2:
            return
        a %= len(self.records)
        b %= len(self.records)
        self.records[a], self.records[b] = self.records[b], self.records[a]
        self._verify_records()

    @rule(drop=st.integers(min_value=1, max_value=10))
    def truncate_tail(self, drop: int) -> None:
        """Drop the last N records (torn tail / dangling parents upstream)."""
        if len(self.records) < 2:
            return
        del self.records[-drop:]
        self._verify_records()

    @rule(pos=st.integers(min_value=0, max_value=_MAX_EVENTS - 1))
    def remove_parent_link(self, pos: int) -> None:
        """Null or dangle a record's parent_id."""
        if not self.records:
            return
        pos %= len(self.records)
        self.records[pos] = dict(self.records[pos])
        self.records[pos]["parent_id"] = "evt_missing_9999" if pos else None
        self._verify_records()

    @rule(pos=st.integers(min_value=0, max_value=_MAX_EVENTS - 1))
    def corrupt_id(self, pos: int) -> None:
        """Corrupt a record id: empty, non-string, or colliding."""
        if not self.records:
            return
        pos %= len(self.records)
        self.records[pos] = dict(self.records[pos])
        choice = pos % 3
        if choice == 0:
            self.records[pos]["id"] = ""
        elif choice == 1:
            self.records[pos]["id"] = 42
        else:
            other = (pos + 1) % len(self.records)
            self.records[pos]["id"] = self.records[other]["id"]
        self._verify_records()

    @rule(pos=st.integers(min_value=0, max_value=_MAX_EVENTS - 1))
    def corrupt_field(self, pos: int) -> None:
        """Break a record's kind or drop a required key."""
        if not self.records:
            return
        pos %= len(self.records)
        self.records[pos] = dict(self.records[pos])
        if pos % 2 == 0:
            self.records[pos]["kind"] = "bogus_kind_xyz"
        else:
            self.records[pos].pop("ts", None)
        self._verify_records()

    # -- rules (byte-level mutations, one-shot) ------------------------------

    @rule(off=st.integers(min_value=0, max_value=64))
    def inject_bytes(self, off: int) -> None:
        """Insert NUL/0xFF into the serialized document; records unchanged."""
        if not self.records:
            return
        data = bytearray(_doc(self.records))
        off = min(off, len(data) - 1)
        data[off:off] = b"\x00\xff"
        self._verify(bytes(data))

    @rule()
    def splice_blob(self) -> None:
        """Splice a non-JSON line into the document middle."""
        if not self.records:
            return
        data = _doc(self.records)
        mid = data.find(b"\n", len(data) // 2)
        if mid == -1:
            return
        corrupted = data[:mid] + b"\n{{{not json\n" + data[mid:]
        self._verify(corrupted)

    @rule(cut=st.integers(min_value=1, max_value=64))
    def truncate_bytes(self, cut: int) -> None:
        """Cut the document tail mid-token (torn file)."""
        if not self.records:
            return
        data = _doc(self.records)
        self._verify(data[: max(1, len(data) - cut)])

    # -- global invariants ----------------------------------------------------

    @invariant()
    def session_bounded(self) -> None:
        assert len(self.records) <= _MAX_EVENTS


StatefulSessionTest = SessionMutationMachine.TestCase
StatefulSessionTest.settings = settings(max_examples=25, stateful_step_count=20, deadline=None)
