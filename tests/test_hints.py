"""Copy-paste runnable command hints (AC-04): quoting and argument assembly."""

from __future__ import annotations

import shlex

import pytest

from sesslint._hints import (
    DEFAULT_OUTPUT_NAME,
    STDIN_LABEL,
    check_hint,
    hint_arg,
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
