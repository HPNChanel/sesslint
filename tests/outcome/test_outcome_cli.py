"""``sesslint outcome`` CLI contract: exit codes, explain, output protection (ITF-02/04)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sesslint.cli import main
from tests.outcome.helpers import ORDERS, ROOT
from tests.utils.schema import assert_schema

CONTRACT = str(ORDERS / "contract.json")
SOURCE = str(ORDERS / "source.csv")
TARGET = str(ORDERS / "target_complete.json")
BASE = ["outcome", CONTRACT, "--source", SOURCE, "--target", TARGET]


def _copy(tmp_path: Path, *names: str) -> list[Path]:
    out = []
    for name in names:
        path = tmp_path / name
        path.write_bytes((ORDERS / name).read_bytes())
        out.append(path)
    return out


def test_json_report_validates_and_exits_one_on_violation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([*BASE, "--source-completeness", "complete", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert_schema(doc, "sesslint.outcome-report.v1.json")
    assert (doc["run_status"], doc["outcome"]) == ("completed", "VIOLATED")


def test_verified_outcome_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "s.csv"
    source.write_bytes(
        b"order_id,placed_at,state,region,sku\n0001,2026-10-20T08:00:00Z,open,EU,SKU-A\n"
    )
    argv = ["outcome", CONTRACT, "--source", str(source), "--target", TARGET]
    assert main([*argv, "--source-completeness", "complete", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "VERIFIED"
    # Without a completeness declaration the source cannot prove coverage (AT-21).
    assert main([*argv, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["outcome"] == "INCONCLUSIVE"


def test_human_output_is_the_default(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(BASE) == 1
    out = capsys.readouterr().out
    assert out.startswith("SessLint outcome: ")
    assert "session integrity:" in out and "outcome verification:" in out


def test_plain_target_needs_an_evaluation_instant(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["outcome", CONTRACT, "--source", SOURCE, "--target", str(ORDERS / "target.jsonl")]
    assert main(argv) == 2
    assert "wall clock is never used" in capsys.readouterr().err
    assert main([*argv, "--target-observed-at", "2026-10-20T12:00:00Z", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["observations"]["target"]["completeness"] == "unknown"
    assert doc["outcome"] in {"INCONCLUSIVE", "VIOLATED"}


@pytest.mark.parametrize(
    ("extra", "needle"),
    [
        (["--target-completeness", "partial"], "contradicts"),
        (["--as-of", "2026-10-20T10:00:00Z"], "precedes"),
    ],
)
def test_input_errors_exit_two(
    extra: list[str], needle: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*BASE, *extra]) == 2
    assert needle in capsys.readouterr().err


def test_naive_as_of_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main([*BASE, "--as-of", "2026-10-20T12:00:00"])
    assert info.value.code == 2
    assert "UTC offset" in capsys.readouterr().err


def test_invalid_contract_lists_problems(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "c.json"
    bad.write_text('{"schema_version": "sesslint.outcome-contract/v1", "conditions": []}', "utf-8")
    assert main(["outcome", str(bad), "--source", SOURCE, "--target", TARGET]) == 2
    err = capsys.readouterr().err
    assert "invalid outcome contract" in err
    assert err.count("  - ") >= 3


def test_missing_files_and_arguments_exit_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["outcome", str(tmp_path / "none.json"), "--explain"]) == 2
    assert main(["outcome", CONTRACT, "--source", SOURCE]) == 2
    assert main(["outcome", CONTRACT, "--source", str(tmp_path / "x.csv"), "--target", TARGET]) == 2
    err = capsys.readouterr().err
    assert "could not be read" in err and "needs --source and --target" in err


def test_explain_reads_only_the_contract(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["outcome", CONTRACT, "--explain"]) == 0
    assert "Conditions:" in capsys.readouterr().out
    assert main(["outcome", CONTRACT, "--explain", "--source", SOURCE]) == 2


@pytest.mark.parametrize("victim", ["contract.json", "source.csv", "target_complete.json"])
def test_output_never_overwrites_inputs(tmp_path: Path, victim: str) -> None:
    contract, source, target = _copy(
        tmp_path, "contract.json", "source.csv", "target_complete.json"
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    argv = ["outcome", str(contract), "--source", str(source), "--target", str(target)]
    assert main([*argv, "--json", "-o", str(tmp_path / victim)]) == 2
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_output_file_and_linked_session(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "report.json"
    session = ROOT / "fixtures" / "sessions" / "minimal-valid.jsonl"
    assert main([*BASE, "--session", str(session), "--json", "-o", str(out)]) == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["dimensions"]["session_integrity"]["link"] == "user_asserted"
    assert_schema(doc, "sesslint.outcome-report.v1.json")
    capsys.readouterr()


def test_hash_keys_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*BASE, "--hash-keys", "--json"]) == 1
    out = capsys.readouterr().out
    assert '"0002"' not in out
    assert json.loads(out)["key_display"] == "sha256"


def test_cli_output_is_byte_stable(capsys: pytest.CaptureFixture[str]) -> None:
    main([*BASE, "--json"])
    first = capsys.readouterr().out
    main([*BASE, "--json"])
    assert capsys.readouterr().out == first
