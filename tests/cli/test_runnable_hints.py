"""Every command a SessLint surface prints runs as printed (AC-04).

``check`` Next Action and Fix lines, refusal detail from ``repair`` and the
``export`` follow-up are executed exactly as printed (POSIX word splitting,
from the directory the operator ran the first command in). A printed command
may exit 0 or 1, never 2 (usage or input error), and it repeats the
operator's explicit ``--adapter``/``--profile``.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import tempfile
from pathlib import Path

import pytest

from sesslint.bundle import _sanitize_remediation
from sesslint.cli import main
from sesslint.cli._options import cli_path
from sesslint.codes import SL002, SL101, Repairability, Severity
from sesslint.finding import Finding, SourceRef, make_finding
from sesslint.report import EMPTY_INPUT_MESSAGE, get_finding_remediation, report_abstains

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"
CHECKS = FIXTURES / "checks"
REPAIR_BASIC = FIXTURES / "repair" / "exec_basic" / "source.jsonl"
CODEX_HEALTHY = FIXTURES / "adapters" / "codex" / "healthy_min.jsonl"
HINT = re.compile(r"'(sesslint (?:repair|check|bundle)\b[^']*)'")

# fixtures/report/** stays out of the corpus: its hand-written canonical
# headers omit created_at, which `check` derives from the first timestamp
# while the repair loader requires it (docs/SPEC.md), so repair exits 2 there
# for a reason unrelated to hint assembly.
CORPUS = sorted(
    p
    for family in ("adapters", "checks", "conformance", "repair", "sessions")
    for p in (FIXTURES / family).rglob("*")
    if p.suffix in (".json", ".jsonl")
    and p.name != "PROVENANCE.json"
    and not any(tag in p.name for tag in ("expected", "manifest", "plan"))
)
ADAPTERS = ("auto", "canonical", "claude-code-jsonl", "codex-rollout", "openai-agents")


def _run(capsys: pytest.CaptureFixture[str], argv: list[str]) -> tuple[int, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def _hints(text: str) -> list[str]:
    return [h for h in dict.fromkeys(HINT.findall(text)) if "<" not in h]


def _run_hint(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    hint: str,
    case: Path,
    runs: Path,
) -> tuple[int, str]:
    """Run one printed command in a fresh copy of the directory it was printed for.

    The command runs from its own new directory under ``runs`` (Windows cannot
    remove the working directory a previous command ran in).
    """
    runs.mkdir(exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(dir=runs))
    shutil.copytree(case, run_dir, dirs_exist_ok=True)
    monkeypatch.chdir(run_dir)
    argv = shlex.split(hint)
    assert argv[0] == "sesslint"
    return _run(capsys, argv[1:])


def _case(tmp_path: Path, name: str, data: bytes) -> Path:
    case = tmp_path / "case"
    case.mkdir(exist_ok=True)
    (case / name).write_bytes(data)
    return case


def _mid_record_session() -> bytes:
    """A valid header, then one malformed record between valid ones."""
    lines = REPAIR_BASIC.read_bytes().splitlines(keepends=True)
    return lines[0] + lines[1] + b'{"broken": \n' + b"".join(lines[2:])


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_corpus_hints_never_exit_2(
    adapter: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    failures: list[str] = []
    bundle_shapes: set[tuple[str, ...]] = set()
    ran = 0
    for src in CORPUS:
        case = Path(tempfile.mkdtemp(dir=tmp_path))
        shutil.copy2(src, case / src.name)
        monkeypatch.chdir(case)
        argv = ["check", src.name] + ([] if adapter == "auto" else ["--adapter", adapter])
        _code, text = _run(capsys, argv)
        for hint in _hints(text):
            if adapter != "auto":
                assert f"--adapter {adapter}" in hint, hint
            words = shlex.split(hint)[1:]
            if words == argv:
                continue  # the very check that printed it
            if words[0] == "bundle":
                # Only the source differs between bundle hints: one run per shape.
                shape = (words[0], *words[2:])
                if shape in bundle_shapes:
                    continue
                bundle_shapes.add(shape)
            ran += 1
            code, out = _run_hint(capsys, monkeypatch, hint, case, tmp_path / "runs")
            if code == 2:
                failures.append(f"{src.relative_to(FIXTURES)}: {hint} -> {out.strip()[:160]}")
    assert ran > 0
    assert failures == []


@pytest.mark.parametrize(
    "name", ["my session.jsonl", "-dash.jsonl", "a,b.jsonl", "semi;colon.jsonl"]
)
def test_awkward_file_names_are_quoted(
    name: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, name, _mid_record_session())
    monkeypatch.chdir(case)
    _code, text = _run(capsys, ["check", f"./{name}"])
    hints = _hints(text)
    assert hints
    for hint in hints:
        code, out = _run_hint(capsys, monkeypatch, hint, case, tmp_path / "runs")
        assert code != 2, (hint, out)


def test_mid_record_next_action_is_a_salvage_command_that_succeeds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, "mid.jsonl", _mid_record_session())
    monkeypatch.chdir(case)
    code, text = _run(capsys, ["check", "mid.jsonl"])
    assert code == 1
    expected = (
        "sesslint repair mid.jsonl --output mid.repaired.jsonl "
        "--policy salvage --acknowledge-side-effects"
    )
    next_action = next(line for line in text.splitlines() if line.startswith("Next Action:"))
    assert f"Possible path: run '{expected}'" in next_action
    hint_code, _ = _run_hint(capsys, monkeypatch, expected, case, tmp_path / "runs")
    assert hint_code == 0
    assert Path("mid.repaired.jsonl").is_file()


def test_header_level_malformed_record_suggests_no_salvage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A torn first record cannot be excised, so no salvage command is printed."""
    case = _case(tmp_path, "bad.jsonl", b'{not json\n{"id":"evt_ok"}\n')
    monkeypatch.chdir(case)
    code, text = _run(capsys, ["check", "bad.jsonl", "--adapter", "canonical"])
    assert code == 1
    assert "--policy salvage" not in text


def test_deterministic_error_next_action_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, "torn.jsonl", REPAIR_BASIC.read_bytes()[:-25])
    monkeypatch.chdir(case)
    code, text = _run(capsys, ["check", "torn.jsonl"])
    assert code == 1
    assert "Next Action: Run 'sesslint repair torn.jsonl --output torn.repaired.jsonl'" in text
    hint_code, _ = _run_hint(
        capsys,
        monkeypatch,
        "sesslint repair torn.jsonl --output torn.repaired.jsonl",
        case,
        tmp_path / "runs",
    )
    assert hint_code == 0


@pytest.mark.parametrize("fixture", ["sl108_compaction.json", "sl203_continuation.json"])
def test_sl203_report_suggests_no_repair_command(
    fixture: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SL203 blocks every recipe under every policy (FR-060): no repair hint anywhere."""
    case = _case(tmp_path, fixture, (CHECKS / fixture).read_bytes())
    monkeypatch.chdir(case)
    code, text = _run(capsys, ["check", fixture])
    assert code == 1
    assert "abstains under every policy (SL203)" in text
    assert f"re-run 'sesslint check {fixture}'" in text
    assert "sesslint repair" not in text

    json_code, payload = _run(capsys, ["check", fixture, "--json"])
    assert json_code == 1
    assert "sesslint repair" not in "".join(
        f["remediation"] for f in json.loads(payload)["findings"]
    )

    html_code, html = _run(capsys, ["check", fixture, "-f", "html"])
    assert html_code == 1
    assert "sesslint repair" not in html


def test_explicit_adapter_and_profile_carry_into_hints(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, "mid.jsonl", _mid_record_session())
    monkeypatch.chdir(case)
    _code, text = _run(
        capsys, ["check", "mid.jsonl", "--adapter", "canonical", "--profile", "openai-strict"]
    )
    hints = _hints(text)
    assert hints
    for hint in hints:
        assert "--adapter canonical --profile openai-strict" in hint
        code, out = _run_hint(capsys, monkeypatch, hint, case, tmp_path / "runs")
        assert code != 2, (hint, out)


def test_dry_run_lists_each_blocked_finding_with_its_salvage_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, "sl101_orphan.json", (CHECKS / "sl101_orphan.json").read_bytes())
    monkeypatch.chdir(case)
    code, text = _run(capsys, ["repair", "sl101_orphan.json", "--dry-run"])
    assert code == 1
    assert "dry-run" not in text  # the refusal no longer points back at itself
    salvage = (
        "sesslint repair sl101_orphan.json --output sl101_orphan.repaired.json "
        "--policy salvage --acknowledge-side-effects"
    )
    assert "[SL101] needs-salvage-policy: " in text
    assert f"salvage path: run '{salvage}'" in text
    hint_code, _ = _run_hint(capsys, monkeypatch, salvage, case, tmp_path / "runs")
    assert hint_code == 0


def test_dry_run_on_stdin_names_the_dash_source(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import sys

    class _FakeStdin:
        def __init__(self, data: bytes) -> None:
            self.buffer = io.BytesIO(data)

    monkeypatch.setattr(sys, "stdin", _FakeStdin((CHECKS / "sl101_orphan.json").read_bytes()))
    code, text = _run(capsys, ["repair", "-", "--dry-run", "--profile", "openai-strict"])
    assert code == 1
    assert (
        "salvage path: run 'sesslint repair - --output repaired.jsonl --profile openai-strict "
        "--policy salvage --acknowledge-side-effects'"
    ) in text
    assert "stdin.jsonl" not in text


def test_dry_run_under_sl203_prints_no_salvage_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = "sl203_continuation.json"
    case = _case(tmp_path, fixture, (CHECKS / fixture).read_bytes())
    monkeypatch.chdir(case)
    code, text = _run(
        capsys,
        ["repair", fixture, "--dry-run", "--policy", "salvage", "--acknowledge-side-effects"],
    )
    assert code == 1
    assert "SL203-refusal" in text
    assert "salvage path" not in text


def test_export_follow_up_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "out dir").mkdir()
    code, text = _run(capsys, ["export", str(CODEX_HEALTHY), "--output", "out dir/run.jsonl"])
    assert code == 0
    assert (
        "Next Action: Run 'sesslint repair \"out dir/run.jsonl\" --dry-run' to plan repair." in text
    )
    hint_code, _ = _run(capsys, ["repair", "out dir/run.jsonl", "--dry-run"])
    assert hint_code == 0


def test_unsupported_input_prints_no_valid_banner(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, "bad.jsonl", b'{not json\n{"id":"evt_ok"}\n')
    monkeypatch.chdir(case)
    code, text = _run(capsys, ["check", "bad.jsonl"])
    assert code == 0
    assert "Unsupported input" in text
    assert "Valid " not in text


def test_triage_empty_input_asks_for_the_session_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    _code, out = _run(capsys, ["triage", str(empty), "--json"])
    payload = json.loads(out)
    assert {item["detail"] for item in payload["missing_evidence"]} >= {f"{EMPTY_INPUT_MESSAGE}."}
    assert [a["id"] for a in payload["next_actions"]] == ["inspect-source"]
    assert "sesslint repair" not in out


def test_tilde_paths_expand_inside_the_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hints print ~/... paths; shells that keep '~' literal still work (AC-04)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert cli_path("~/run.jsonl") == tmp_path / "run.jsonl"
    assert cli_path("~") == tmp_path
    assert cli_path("-") == Path("-")
    assert cli_path("~other/run.jsonl") == Path("~other/run.jsonl")

    shutil.copy2(CHECKS / "sl101_orphan.json", tmp_path / "sl101_orphan.json")
    monkeypatch.chdir(tmp_path)
    code, text = _run(capsys, ["check", "~/sl101_orphan.json"])
    assert code == 1
    assert "sesslint repair ~/sl101_orphan.json --output sl101_orphan.repaired.json" in text


def test_bundle_sanitizer_reduces_every_quoted_hint_to_the_basename() -> None:
    remediation = (
        'run \'sesslint repair "/home/u/my dir/run.jsonl" --output "run.repaired.jsonl"\' '
        "or re-run 'sesslint check ~/a/b/run.jsonl --adapter canonical'"
    )
    sanitized = _sanitize_remediation(remediation, "run.jsonl")
    assert "/home/u" not in sanitized and "~/a/b" not in sanitized
    assert "'sesslint repair run.jsonl --output" in sanitized
    assert "'sesslint check run.jsonl --adapter canonical'" in sanitized
    spaced = _sanitize_remediation("run 'sesslint check /x/y/z.jsonl'", "my run.jsonl")
    assert spaced == "run 'sesslint check \"my run.jsonl\"'"


def _error(code: str, repairability: Repairability) -> Finding:
    return make_finding(
        code=code,
        severity=Severity.ERROR,
        repairability=repairability,
        message_template="Integrity finding on line {line}",
        template_args={"line": "2"},
        source=SourceRef(path="my run.jsonl", line=2),
    )


def test_operator_remediation_repeats_options() -> None:
    f = _error(SL002, Repairability.DETERMINISTIC)
    assert get_finding_remediation(f, for_operator=True, options=("--adapter", "canonical")) == (
        'deterministic recipe available: run \'sesslint repair "my run.jsonl" '
        '--output "my run.repaired.jsonl" --adapter canonical\''
    )


@pytest.mark.parametrize(
    "repairability", [Repairability.DETERMINISTIC, Repairability.LOSSY_EXPLICIT]
)
def test_remediation_names_no_command_while_sl203_is_present(
    repairability: Repairability,
) -> None:
    f = _error(SL002, repairability)
    remediation = get_finding_remediation(f, for_operator=True, abstain=True)
    assert remediation == (
        f"{repairability.value} recipe exists, but automated repair abstains under "
        "every policy while SL203 is present"
    )


def test_refusal_remediation_drops_the_salvage_path_while_sl203_is_present() -> None:
    f = _error(SL101, Repairability.MANUAL)
    assert "--policy salvage" in get_finding_remediation(f, for_operator=True)
    abstained = get_finding_remediation(f, for_operator=True, abstain=True)
    assert "salvage path" not in abstained
    assert "sesslint repair" not in abstained


def test_report_abstains_only_on_sl203() -> None:
    assert report_abstains([]) is False
    assert report_abstains([_error(SL101, Repairability.MANUAL)]) is False
    sl203 = make_finding(
        code="SL203",
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Unknown execution state",
        source=SourceRef(path="run.jsonl", line=4),
    )
    assert report_abstains([_error(SL101, Repairability.MANUAL), sl203]) is True
