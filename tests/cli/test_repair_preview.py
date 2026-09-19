"""Tests for structural repair preview (repair-engine T-03)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sesslint import api
from sesslint.cli import main
from sesslint.preview import PreviewDoc, repair_preview

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "repair_cli"
BASIC_SRC = FIXTURES_DIR / "basic" / "source.jsonl"


def _stage(tmp_path: Path) -> Path:
    src = tmp_path / "src.jsonl"
    shutil.copyfile(BASIC_SRC, src)
    return src


def test_preview_lists_delta_rows(tmp_path: Path) -> None:
    """Preview maps plan steps to content-free delta rows."""
    src = _stage(tmp_path)
    doc = repair_preview(src)
    assert isinstance(doc, PreviewDoc)
    assert len(doc.steps) == 2
    d = doc.steps[0]
    assert d.action == "dedupe"
    assert d.reason_code == "SL003"
    assert d.event_id is not None
    assert d.kind == "message"
    ren = doc.steps[1]
    assert ren.action == "normalize"
    assert ren.recipe == "seq-renumber"
    assert doc.blocked == ()


def test_preview_cli_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--preview prints deltas and exits 0 with zero writes."""
    src = _stage(tmp_path)
    code = main(["repair", str(src), "--preview"])
    assert code == 0
    out = capsys.readouterr().out
    assert "dedupe" in out
    assert "SL003" in out
    # No output/manifest/plan artifacts anywhere in tmp.
    assert list(tmp_path.glob("*.manifest.json")) == []
    assert list(tmp_path.glob("*.repaired.jsonl")) == []


def test_preview_json_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--preview --json emits sesslint.preview/v1 with steps+blocked."""
    src = _stage(tmp_path)
    code = main(["repair", str(src), "--preview", "--json"])
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == "sesslint.preview/v1"
    assert doc["counts"]["dedupe"] == 1
    assert doc["counts"]["normalize"] == 1
    assert doc["steps"][0]["action"] == "dedupe"
    assert doc["blocked"] == []
    assert "payload" not in json.dumps(doc)


def test_preview_refused_lists_blocked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Refused input renders blocked codes+reasons, exits non-zero, no writes."""
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(b'{"type":"summary"}\n{"type":"turn_context","payload":{}}\nnot json\n')
    code = main(["repair", str(bad), "--preview"])
    assert code == 1
    out = capsys.readouterr().out
    assert "blocked" in out
    assert list(tmp_path.glob("*.manifest.json")) == []


def test_preview_deterministic(tmp_path: Path) -> None:
    """Identical input yields byte-identical JSON docs."""
    src = _stage(tmp_path)
    assert repair_preview(src).to_json() == repair_preview(src).to_json()


@pytest.mark.parametrize(
    "extra",
    [
        ["--output", "o.jsonl"],
        ["--plan-out", "p.json"],
        ["--emit", "canonical"],
        ["--files", "x"],
    ],
)
def test_preview_conflicts_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], extra: list[str]
) -> None:
    """Preview refuses write-implying/foreign-plan flags."""
    src = _stage(tmp_path)
    code = main(["repair", str(src), "--preview", *extra])
    assert code == 2
    assert "--preview writes nothing" in capsys.readouterr().err


def test_preview_privacy_no_payload(tmp_path: Path) -> None:
    """Delta docs contain no payload strings — ids/kinds/codes only."""
    src = _stage(tmp_path)
    doc_json = repair_preview(src).to_json()
    # Every long payload string from the source must be absent from the doc.
    for value in _walk_strings(BASIC_SRC.read_bytes()):
        if len(value) >= 20:
            assert value not in doc_json


def _walk_strings(data: bytes):
    for line in data.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        stack = [obj]
        while stack:
            cur = stack.pop()
            if isinstance(cur, str):
                yield cur
            elif isinstance(cur, dict):
                stack.extend(cur.values())
            elif isinstance(cur, list):
                stack.extend(cur)


def test_api_repair_preview_exported(tmp_path: Path) -> None:
    """api.repair_preview is the public preview entry point."""
    src = _stage(tmp_path)
    doc = api.repair_preview(src)
    assert isinstance(doc, PreviewDoc)
    assert "repair_preview" in api.__all__


def test_preview_unknown_recipe_fails_closed(tmp_path: Path) -> None:
    """Unmapped recipes default to the 'drop' action (conservative)."""
    from sesslint.preview import _deltas_for_plan
    from sesslint.repair.planner import PlanStep

    step = PlanStep(
        seq=0,
        recipe="brand-new-recipe",
        target_finding_fp="fp",
        target_index=None,
    )

    class _P:
        steps = (step,)
        blocked: tuple = ()

    deltas = _deltas_for_plan(_P(), [], [])
    assert deltas[0].action == "drop"
