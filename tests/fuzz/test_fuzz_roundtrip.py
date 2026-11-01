"""CL-16: repair → verify → check round trip on hostile inputs (FR-repair).

A repair that succeeds must verify, must not leave more error/fatal findings
than the source had, and a second repair of its output must be a no-op
(no steps, byte-identical output) — repair is idempotent.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Literal

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint import api
from sesslint.errors import SesslintError
from tests.fuzz.test_fuzz_hostile_inputs import MARKER, OPS, SEEDS, _mutated

_BAD = ("error", "fatal")


def _errors(path: Path, fmt: str | None) -> int:
    report = api.check_file(path, format=fmt)
    return sum(1 for f in report.findings if f.severity.value in _BAD)


@given(
    adapter=st.sampled_from(sorted(SEEDS)),
    ops=OPS,
    policy=st.sampled_from(["conservative", "salvage"]),
    emit=st.sampled_from(["auto", "canonical", "vendor"]),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_repair_verify_check_never_worse_and_idempotent(
    adapter: str,
    ops: list[tuple[str, int]],
    policy: Literal["conservative", "salvage"],
    emit: Literal["auto", "canonical", "vendor"],
) -> None:
    ext = ".json" if adapter == "openai-agents" else ".jsonl"
    work = Path(tempfile.mkdtemp(prefix="sl-cl16-rt-"))
    try:
        src = work / f"session{ext}"
        src.write_bytes(_mutated(adapter, ops))
        out1, out2 = work / f"one{ext}", work / f"two{ext}"
        try:
            _plan, manifest = api.repair(
                src, out1, policy=policy, emit=emit, acknowledge_side_effects=True
            )
        except SesslintError as error:
            assert MARKER not in str(error)
            assert not out1.exists()
            return
        assert manifest is not None
        verdict = api.verify(
            src, out1, work / f"one{ext}.manifest.json", acknowledge_side_effects=True
        )
        assert verdict.ok, [c for c in verdict.checks if not c.ok]

        try:
            before = _errors(src, None)
        except SesslintError:
            before = None
        after = _errors(out1, None)
        if before is not None:
            assert after <= before, (before, after)

        plan2, manifest2 = api.repair(
            out1, out2, policy=policy, emit=emit, acknowledge_side_effects=True
        )
        assert manifest2 is not None
        assert plan2.steps == (), [s for s in plan2.steps]
        assert out2.read_bytes() == out1.read_bytes()
    finally:
        shutil.rmtree(work, ignore_errors=True)


@given(adapter=st.sampled_from(sorted(SEEDS)), ops=OPS)
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_export_never_adds_errors_and_reexport_is_identity(
    adapter: str, ops: list[tuple[str, int]]
) -> None:
    from sesslint.exporter import export_to_canonical

    ext = ".json" if adapter == "openai-agents" else ".jsonl"
    work = Path(tempfile.mkdtemp(prefix="sl-cl16-ex-"))
    try:
        src = work / f"session{ext}"
        src.write_bytes(_mutated(adapter, ops))
        one, two = work / "one.jsonl", work / "two.jsonl"
        try:
            export_to_canonical(src, one)
        except (SesslintError, OSError) as error:
            assert MARKER not in str(error)
            assert not one.exists()
            return
        # Export is a faithful projection: check findings survive, none appear.
        assert _errors(one, "canonical") <= _errors(src, None)
        export_to_canonical(one, two, format="canonical")
        assert two.read_bytes() == one.read_bytes()
    finally:
        shutil.rmtree(work, ignore_errors=True)
