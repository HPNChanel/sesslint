"""Copy-paste runnable command hints (AC-04): quoting and argument assembly."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from sesslint._hints import (
    DEFAULT_OUTPUT_NAME,
    MANUAL_HINT,
    STDIN_LABEL,
    check_hint,
    hint_arg,
    hint_instruction,
    hint_options,
    hint_source,
    repair_hint,
    repair_plan_hint,
    repaired_output_name,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("session.jsonl", "session.jsonl"),
        ("~/projects/a/run.jsonl", "~/projects/a/run.jsonl"),
        ("C:/work/run.jsonl", "C:/work/run.jsonl"),
        ("my session.json", '"my session.json"'),
        ("a,b.jsonl", '"a,b.jsonl"'),
        ("x@y.jsonl", '"x@y.jsonl"'),
        ("semi;colon.jsonl", '"semi;colon.jsonl"'),
        ("-dash.json", "./-dash.json"),
        ("-", "-"),
    ],
)
def test_hint_arg_quotes_only_when_needed(value: str, expected: str) -> None:
    assert hint_arg(value) == expected


def test_hint_arg_survives_posix_splitting() -> None:
    for value in ("my session.json", "a,b.jsonl", "x@y.jsonl", "plain.jsonl"):
        assert shlex.split(hint_arg(value)) == [value]


def test_hint_source_spells_stdin_as_dash() -> None:
    assert hint_source(STDIN_LABEL) == "-"
    assert hint_source("run.jsonl") == "run.jsonl"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("run.jsonl", "run.repaired.jsonl"),
        ("~/a/b/run.json", "run.repaired.json"),
        ("C:\\work\\run.jsonl", "run.repaired.jsonl"),
        ("archive.tar.jsonl", "archive.tar.repaired.jsonl"),
        ("noext", "noext.repaired"),
        (".hidden", ".hidden.repaired"),
        ("dir/", "dir.repaired"),
        ("-", DEFAULT_OUTPUT_NAME),
        ("~", DEFAULT_OUTPUT_NAME),
        (STDIN_LABEL, DEFAULT_OUTPUT_NAME),
    ],
)
def test_repaired_output_name_is_relative_and_never_the_source(path: str, expected: str) -> None:
    name = repaired_output_name(path)
    assert name == expected
    assert "/" not in name and "\\" not in name


def test_repair_hint_names_an_output() -> None:
    assert repair_hint("run.jsonl") == "sesslint repair run.jsonl --output run.repaired.jsonl"
    assert repair_hint("my run.jsonl", "--policy", "salvage") == (
        'sesslint repair "my run.jsonl" --output "my run.repaired.jsonl" --policy salvage'
    )
    assert repair_hint(STDIN_LABEL) == "sesslint repair - --output repaired.jsonl"


def test_check_and_plan_hints() -> None:
    assert check_hint("run.jsonl") == "sesslint check run.jsonl"
    assert check_hint(STDIN_LABEL, "--adapter", "canonical") == (
        "sesslint check - --adapter canonical"
    )
    assert repair_plan_hint("out dir/x.jsonl") == 'sesslint repair "out dir/x.jsonl" --dry-run'


def test_hint_options_repeat_only_explicit_choices() -> None:
    assert hint_options() == ()
    assert hint_options("auto", "neutral") == ()
    assert hint_options("codex-rollout", "neutral") == ("--adapter", "codex-rollout")
    assert hint_options("auto", "openai-strict") == ("--profile", "openai-strict")
    assert hint_options("canonical", "my profile") == (
        "--adapter",
        "canonical",
        "--profile",
        '"my profile"',
    )


def test_options_keep_flags_unprefixed() -> None:
    """Option flags are not file names: no './' prefix, no quoting."""
    command = repair_hint("run.jsonl", *hint_options("claude-code-jsonl", "claude-strict"))
    assert command == (
        "sesslint repair run.jsonl --output run.repaired.jsonl "
        "--adapter claude-code-jsonl --profile claude-strict"
    )
    assert "./--" not in command


@pytest.mark.parametrize(
    "value",
    [
        "$(echo sentinel).jsonl",
        "`echo sentinel`.jsonl",
        "%COMSPEC%.jsonl",
        "!SENTINEL!.jsonl",
        'quote".jsonl',
        "quote'.jsonl",
        "line\nbreak.jsonl",
        "line\rbreak.jsonl",
        "escape\x1b.jsonl",
        "back\\slash.jsonl",
        "pipe|name.jsonl",
        "redirect>name.jsonl",
    ],
)
def test_shell_sensitive_arguments_withhold_the_entire_command(value: str) -> None:
    assert hint_arg(value) is None
    assert repair_hint(value) is None
    assert check_hint(value) is None
    assert repair_plan_hint(value) is None
    assert hint_instruction(repair_hint(value)) == MANUAL_HINT
    assert value not in MANUAL_HINT


def test_unsafe_option_is_not_silently_dropped() -> None:
    options = hint_options("canonical", "$(echo sentinel)")
    assert repair_hint("run.jsonl", *options) is None
    assert check_hint("run.jsonl", *options) is None


@pytest.mark.parametrize(
    "value", ["my session.jsonl", "a,b.jsonl", "semi;colon.jsonl", "x@y.jsonl"]
)
def test_supported_arguments_round_trip_through_real_shells(value: str, tmp_path: Path) -> None:
    """Exercise shell evaluation, not only shlex tokenization (CX-05-P1-1)."""
    receiver = tmp_path / "argv_receiver.py"
    receiver.write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n", encoding="utf-8")
    argument = hint_arg(value)
    assert argument is not None
    if os.name == "nt":
        command = f'"{sys.executable}" "{receiver}" {argument}'
        result = subprocess.run(
            command, shell=True, capture_output=True, check=True, timeout=15
        )
        assert json.loads(result.stdout) == [value]
        executable = str(sys.executable).replace("'", "''")
        script = str(receiver).replace("'", "''")
        command = f"& '{executable}' '{script}' {argument}"
        argv = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ]
    else:
        command = f"{shlex.quote(sys.executable)} {shlex.quote(str(receiver))} {argument}"
        argv = ["/bin/sh", "-c", command]
    result = subprocess.run(argv, capture_output=True, check=True, timeout=15)
    assert json.loads(result.stdout) == [value]
