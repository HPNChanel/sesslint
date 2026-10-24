"""N4 repair-safety invariants over synthetic session artifacts.

These tests exercise public repair boundaries with generated, content-free
records.  They deliberately cover both the high-level API and the exported
executor because a resealed plan digest is not an authorization decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sesslint import api
from sesslint.adapters.detect import FORMAT_CLAUDE_CODE
from sesslint.errors import SesslintError
from sesslint.repair.errors import RepairRefused
from sesslint.repair.executor import execute, load_source_for_format
from sesslint.repair.fingerprint import compute_plan_fingerprint
from sesslint.repair.planner import RepairPlan

VENDOR_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "claude_code" / "basic.jsonl"
TEXTS = st.lists(st.text(alphabet="abcXYZ012-_ ", max_size=32), min_size=1, max_size=12)


def _line(value: MappingLike) -> bytes:
    """Encode one deterministic synthetic JSONL record."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


MappingLike = dict[str, Any]


def _header() -> MappingLike:
    return {
        "created_at": "2026-10-08T00:00:00Z",
        "schema_version": "sesslint.session/v1",
        "session_id": "n4-synthetic",
    }


def _event(index: int, text: str) -> MappingLike:
    return {
        "actor": "user" if index % 2 == 0 else "assistant",
        "id": f"event-{index}",
        "kind": "message",
        "parent_id": None if index == 0 else f"event-{index - 1}",
        "payload": {"text": text},
        "seq": index,
        "ts": f"2026-10-08T00:00:{index:02d}Z",
    }


def _canonical_bytes(events: list[MappingLike], *, tail: bytes = b"") -> bytes:
    return _line(_header()) + b"".join(_line(event) for event in events) + tail


def _event_records(path: Path) -> list[MappingLike]:
    return [json.loads(line) for line in path.read_bytes().splitlines()[1:]]


def _resealed_torn_record_plan(source: Path, target_index: int) -> RepairPlan:
    """Make a fingerprint-valid but planner-unauthorized conservative plan."""
    source_bytes = source.read_bytes()
    document: dict[str, Any] = {
        "blocked": [],
        "loss_accounting": {"preview": {"none": 0}},
        "policy": "conservative",
        "profile": "neutral",
        "source_hash": hashlib.sha256(source_bytes).hexdigest(),
        "steps": [
            {
                "min_policy": "conservative",
                "params": {"cut_index": target_index},
                "recipe": "torn-terminal-record-discard",
                "recipe_version": "1.0.0",
                "seq": 0,
                "target_finding_fp": "resealed-forgery",
                "target_index": target_index,
            }
        ],
        "version": "sesslint.plan/v1",
    }
    provisional = RepairPlan.from_dict(document)
    sealed = provisional.to_dict()
    sealed.pop("fingerprint", None)
    sealed["fingerprint"] = compute_plan_fingerprint(sealed)
    return RepairPlan.from_dict(sealed)


@given(texts=TEXTS)
@settings(
    max_examples=20,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_conservative_torn_tail_preserves_every_unique_decodable_record(
    tmp_path: Path, texts: list[str]
) -> None:
    """A conservative terminal-tail repair may remove no decoded source event."""
    events = [_event(index, text) for index, text in enumerate(texts)]
    # Proper JSON-object prefix without a newline: it is provably an SL002 tail,
    # while every generated event above remains complete and uniquely identified.
    torn_tail = b'{"id":"incomplete","payload":{"text":"cut'
    with tempfile.TemporaryDirectory(dir=tmp_path) as directory:
        root = Path(directory)
        source = root / "source.jsonl"
        output = root / "output.jsonl"
        source_bytes = _canonical_bytes(events, tail=torn_tail)
        source.write_bytes(source_bytes)

        _plan, manifest = api.repair(source, output)

        assert source.read_bytes() == source_bytes
        assert manifest is not None
        assert manifest.declared_loss == ()
        assert _event_records(output) == events
        assert {event["id"] for event in events} == {
            event["id"] for event in _event_records(output)
        }


def test_untargeted_malformed_line_refuses_or_salvage_loss_matches_physical_difference(
    tmp_path: Path,
) -> None:
    """Every malformed physical line is refused or explicitly counted as loss."""
    events = [_event(0, "left"), _event(1, "right")]
    malformed = b'{"id":"undecoded","payload":\n'
    source_bytes = _line(_header()) + _line(events[0]) + malformed + _line(events[1])
    source = tmp_path / "source.jsonl"
    source.write_bytes(source_bytes)

    conservative_output = tmp_path / "conservative.jsonl"
    with pytest.raises(SesslintError):
        api.repair(source, conservative_output)
    assert source.read_bytes() == source_bytes
    assert not conservative_output.exists()

    salvage_output = tmp_path / "salvage.jsonl"
    _plan, manifest = api.repair(
        source,
        salvage_output,
        policy="salvage",
        acknowledge_side_effects=True,
    )

    assert manifest is not None
    assert manifest.declared_loss == ("torn-record:1",)
    assert len(source_bytes.splitlines()) - len(salvage_output.read_bytes().splitlines()) == 1
    assert _event_records(salvage_output) == events
    assert source.read_bytes() == source_bytes


@pytest.mark.parametrize("surface", ["api", "executor"])
@pytest.mark.parametrize("input_kind", ["canonical", "vendor"])
def test_resealed_tampered_plan_is_refused_at_every_public_execution_boundary(
    tmp_path: Path,
    surface: str,
    input_kind: str,
) -> None:
    """A valid digest cannot authorize a made-up torn-record deletion."""
    if input_kind == "canonical":
        events = [_event(0, "one"), _event(1, "two"), _event(2, "three")]
        source_bytes = _canonical_bytes(events)
        fmt: str | None = None
        target_index = len(events) - 1
    else:
        source_bytes = VENDOR_FIXTURE.read_bytes()
        staged_vendor = tmp_path / "vendor-source.jsonl"
        staged_vendor.write_bytes(source_bytes)
        _header_value, vendor_events, _findings = load_source_for_format(
            staged_vendor, FORMAT_CLAUDE_CODE, data=source_bytes
        )
        fmt = FORMAT_CLAUDE_CODE
        target_index = len(vendor_events) - 1

    source = tmp_path / "source.jsonl"
    source.write_bytes(source_bytes)
    forged = _resealed_torn_record_plan(source, target_index)
    output = tmp_path / "output.jsonl"

    with pytest.raises(RepairRefused):
        if surface == "api":
            api.apply_plan(source, forged, output_path=output, format=fmt)
        else:
            execute(
                source_path=source,
                plan=forged,
                output_path=output,
                format=fmt,
                emit_format=fmt,
            )

    assert source.read_bytes() == source_bytes
    assert not output.exists()
    assert not Path(f"{output}.manifest.json").exists()


def test_repair_keeps_source_plan_bundle_and_existing_artifact_aliases_immutable(
    tmp_path: Path,
) -> None:
    """Repair never mutates source evidence, plan/bundle artifacts, or alias targets."""
    first = _event(0, "first")
    duplicate = _event(1, "duplicate")
    final = _event(2, "final")
    source_bytes = _canonical_bytes([first, duplicate, duplicate, final])
    source = tmp_path / "source.jsonl"
    source.write_bytes(source_bytes)

    plan = api.plan_repair(source)
    plan_snapshot = plan.to_dict()
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan_snapshot, sort_keys=True), encoding="utf-8")
    plan_bytes = plan_path.read_bytes()

    bundle = api.build_bundle(source)
    bundle_snapshot = bundle.to_json()
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(bundle_snapshot, encoding="utf-8")
    bundle_bytes = bundle_path.read_bytes()

    output = tmp_path / "output.jsonl"
    api.apply_plan(source, plan, output_path=output)
    output_bytes = output.read_bytes()

    source_alias = tmp_path / "source-alias.jsonl"
    try:
        os.link(source, source_alias)
    except OSError:
        source_alias = source

    for existing_artifact in (source, source_alias, output, plan_path, bundle_path):
        with pytest.raises(RepairRefused):
            api.apply_plan(source, plan, output_path=existing_artifact)

    assert source.read_bytes() == source_bytes
    assert plan.to_dict() == plan_snapshot
    assert bundle.to_json() == bundle_snapshot
    assert plan_path.read_bytes() == plan_bytes
    assert bundle_path.read_bytes() == bundle_bytes
    assert output.read_bytes() == output_bytes
