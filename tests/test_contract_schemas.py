"""Contract schemas: every schema id the runtime names ships a JSON Schema (T-09).

Each ``sesslint.<name>/vN`` identifier under ``src/sesslint`` must have a
matching ``schemas/sesslint.<name>.vN.json`` whose ``$id`` names it, and the
README table must list every schema file. The schemas for ``watch --json``,
``hook --init --json``, ``version --json``, and the ``sesslint_precheck`` MCP
tool are also checked against live output.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from sesslint.hooks import VALID_AGENTS, init_hooks_doc
from sesslint.mcp_server import _call_tool
from sesslint.watch import WatchTransition, watch
from tests.utils.schema import assert_schema

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures"

SCHEMA_ID_RE = re.compile(r"sesslint\.([a-z0-9-]+)/(v[0-9]+)")
# Both $id spellings in use: .../sesslint.<name>/vN and .../sesslint.<name>.vN.json
SCHEMA_URL_RE = re.compile(
    r"https://sesslint\.dev/schemas/sesslint\.([a-z0-9-]+)(?:/(v[0-9]+)|\.(v[0-9]+)\.json)"
)
# Read (and upgraded to v2) but never written.
INPUT_ONLY_IDS = frozenset({"sesslint.baseline/v1"})
# Objects with no schema field of their own; the schema documents the shape.
SHAPE_ONLY_IDS = frozenset({"sesslint.precheck-result/v1", "sesslint.version/v1"})

CLEAN = FIXTURES / "checks/secret_seed/sl009_clean.jsonl"
PRECHECK_CASES = [
    ("checks/secret_seed/sl009_clean.jsonl", "clean"),
    ("checks/secret_seed/sl009_seeded.jsonl", "findings-warning"),
    ("checks/sl303_critical_dup.jsonl", "findings-error"),
    ("adapters/codex/unknown_version.jsonl", "detection-failed"),
]


def _runtime_ids() -> set[str]:
    """Every schema id named by a string literal under src/sesslint."""
    ids: set[str] = set()
    for path in sorted((ROOT / "src" / "sesslint").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                ids.update(f"sesslint.{n}/{v}" for n, v in SCHEMA_ID_RE.findall(node.value))
    return ids


def _schema_files() -> dict[str, Path]:
    """Map the schema id each versioned schema file describes to that file."""
    out: dict[str, Path] = {}
    for path in sorted(SCHEMAS.glob("sesslint.*.json")):
        url = json.loads(path.read_text(encoding="utf-8"))["$id"]
        match = SCHEMA_URL_RE.fullmatch(url)
        assert match is not None, (path.name, url)
        name, version = match.group(1), match.group(2) or match.group(3)
        assert path.name == f"sesslint.{name}.{version}.json", (path.name, url)
        out[f"sesslint.{name}/{version}"] = path
    return out


def _run_cli(*argv: str) -> str:
    res = subprocess.run(
        [sys.executable, "-m", "sesslint", *argv],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert res.returncode == 0, res.stderr
    return res.stdout


def _precheck(path: Path, **arguments: str) -> dict[str, Any]:
    result = _call_tool("sesslint_precheck", {"path": str(path), **arguments})
    assert result["isError"] is False
    payload: dict[str, Any] = result["structuredContent"]
    return payload


def test_every_runtime_schema_id_has_a_schema_file() -> None:
    missing = _runtime_ids() - INPUT_ONLY_IDS - set(_schema_files())
    assert not missing, sorted(missing)


def test_every_schema_file_describes_a_runtime_output() -> None:
    assert INPUT_ONLY_IDS <= _runtime_ids()
    assert SHAPE_ONLY_IDS <= set(_schema_files())
    stale = set(_schema_files()) - _runtime_ids() - SHAPE_ONLY_IDS
    assert not stale, sorted(stale)


def test_readme_schema_table_lists_every_schema() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    table = text.split("## JSON Schemas\n", 1)[1].split("\n---\n", 1)[0]
    listed = set(re.findall(r"`schemas/([^`]+\.json)`", table))
    assert listed == {path.name for path in SCHEMAS.glob("*.json")}


@pytest.mark.parametrize("agent", VALID_AGENTS)
def test_init_hooks_document_matches_schema(agent: str) -> None:
    assert_schema(init_hooks_doc(agent).to_dict(), "sesslint.init-hooks.v1.json")


def test_init_hooks_schema_rejects_a_foreign_command() -> None:
    # Deep copy: merge blocks share nested objects with the module's recipe constants.
    doc = deepcopy(init_hooks_doc("codex").to_dict())
    doc["files"][0]["merge_block"]["hooks"]["SessionStart"][0]["hooks"][0]["command"] = (
        "echo sesslint hook --event SessionStart"
    )
    with pytest.raises(AssertionError):
        assert_schema(doc, "sesslint.init-hooks.v1.json")


def test_cli_json_outputs_match_schemas() -> None:
    init = json.loads(_run_cli("hook", "--init", "--agent", "all", "--json"))
    assert_schema(init, "sesslint.init-hooks.v1.json")
    assert_schema(json.loads(_run_cli("version", "--json")), "sesslint.version.v1.json")


@pytest.mark.parametrize(("fixture", "reason"), PRECHECK_CASES)
def test_precheck_tool_result_matches_schema(fixture: str, reason: str) -> None:
    payload = _precheck(FIXTURES / fixture)
    assert payload["reason"] == reason
    assert_schema(payload, "sesslint.precheck-result.v1.json")
    assert_schema(payload["report"], "sesslint.report.v1.json")


def test_precheck_tool_usage_error_carries_no_report() -> None:
    payload = _precheck(CLEAN, format="bogus")
    assert (payload["reason"], payload["exit_code"], "report" in payload) == (
        "usage-error",
        2,
        False,
    )
    assert_schema(payload, "sesslint.precheck-result.v1.json")


_DELETE = object()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("exit_code", 1),
        ("ok", False),
        ("reason", "findings-error"),
        ("report", _DELETE),
        ("report", None),
        ("extra", 1),
    ],
)
def test_precheck_schema_rejects_inconsistent_results(key: str, value: object) -> None:
    payload = deepcopy(_precheck(CLEAN))
    if value is _DELETE:
        del payload[key]
    else:
        payload[key] = value
    with pytest.raises(AssertionError):
        assert_schema(payload, "sesslint.precheck-result.v1.json")


def test_precheck_schema_rejects_a_report_on_exit_2() -> None:
    payload: dict[str, Any] = {"ok": False, "reason": "io-error", "exit_code": 2}
    assert_schema(payload, "sesslint.precheck-result.v1.json")
    payload["report"] = {"schema_version": "sesslint.report/v1"}
    with pytest.raises(AssertionError):
        assert_schema(payload, "sesslint.precheck-result.v1.json")


def test_watch_transitions_match_schema(tmp_path: Path) -> None:
    for fixture, _ in PRECHECK_CASES:
        (tmp_path / Path(fixture).name).write_bytes((FIXTURES / fixture).read_bytes())
    events: list[WatchTransition] = []
    watch(
        [tmp_path],
        interval=0.05,
        sleep_fn=lambda _: None,
        on_transition=events.append,
        max_polls=2,
    )
    assert {event.to_state for event in events} >= {"warnings", "invalid"}
    for event in events:
        assert_schema(event.to_dict(), "sesslint.watch-event.v1.json")


def test_watch_unreadable_transition_matches_schema(tmp_path: Path) -> None:
    (tmp_path / "session.jsonl").write_bytes(b"{}\n")

    def unreadable(path: Path) -> object:
        raise OSError("unreadable")

    events: list[WatchTransition] = []
    watch(
        [tmp_path],
        interval=0.05,
        check_fn=unreadable,
        sleep_fn=lambda _: None,
        on_transition=events.append,
        max_polls=2,
    )
    assert [(e.from_state, e.to_state, e.codes) for e in events] == [("new", "unreadable", ())]
    assert_schema(events[0].to_dict(), "sesslint.watch-event.v1.json")


@pytest.mark.parametrize(
    ("to", "codes"),
    [("invalid", []), ("warnings", []), ("healthy", ["SL009"]), ("unreadable", ["SL009"])],
)
def test_watch_schema_ties_codes_to_the_new_verdict(to: str, codes: list[str]) -> None:
    event = {
        "schema_version": "sesslint.watch-event/v1",
        "path": "session.jsonl",
        "from": "new",
        "to": to,
        "codes": codes,
    }
    with pytest.raises(AssertionError):
        assert_schema(event, "sesslint.watch-event.v1.json")


def test_hook_result_reason_description_names_every_reason() -> None:
    source = (ROOT / "src" / "sesslint" / "hook_event.py").read_text(encoding="utf-8")
    reasons = {"clean", "findings-present", "detection-failed"}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "_skip":
                reason = node.args[1]
                assert isinstance(reason, ast.Constant)
                reasons.add(reason.value)
    schema = json.loads((SCHEMAS / "sesslint.hook-result.v1.json").read_text(encoding="utf-8"))
    description = schema["properties"]["reason"]["description"]
    missing = sorted(reason for reason in reasons if reason not in description)
    assert not missing, missing
