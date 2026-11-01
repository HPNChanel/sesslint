"""CL-17: ``--jobs`` parallel scans give the same findings and bytes as ``--jobs 1``.

A small tree of hostile-mutated session files (plus a non-session file and an
empty one) is scanned through the library and the CLI at ``jobs`` 1 and 2.
Workers are ``spawn`` processes, so the example count stays low.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint.scan import scan_path
from tests.fuzz.test_fuzz_cli_surfaces import _ADAPTERS, _ext, _run
from tests.fuzz.test_fuzz_hostile_inputs import MARKER, OPS, _mutated

_FILE = st.tuples(_ADAPTERS, OPS)


@given(files=st.lists(_FILE, min_size=2, max_size=4), junk=st.binary(max_size=60))
@settings(deadline=None, max_examples=6, suppress_health_check=[HealthCheck.too_slow])
def test_jobs_matches_sequential_scan(
    files: list[tuple[str, list[tuple[str, int]]]], junk: bytes
) -> None:
    work = Path(tempfile.mkdtemp(prefix="sl-cl17-jobs-"))
    try:
        for i, (adapter, ops) in enumerate(files):
            (work / f"s{i}{_ext(adapter)}").write_bytes(_mutated(adapter, ops))
        (work / "junk.jsonl").write_bytes(junk)
        (work / "empty.jsonl").write_bytes(b"")
        (work / "notes.txt").write_bytes(b"plain text")
        seq = scan_path(work, recursive=True, jobs=1).to_json()
        par = scan_path(work, recursive=True, jobs=2).to_json()
        assert par == seq
        assert MARKER not in par
        for fmt in ("json", "sarif"):
            one = _run(["check", str(work), "-f", fmt, "--jobs", "1"])
            two = _run(["check", str(work), "-f", fmt, "--jobs", "2"])
            assert one == two, fmt
    finally:
        shutil.rmtree(work, ignore_errors=True)
