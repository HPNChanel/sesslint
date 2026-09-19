"""Drift checks for generated man pages (docs-spec/T-05).

Pages are generated from the live argparse tree by ``scripts/gen_man.py``;
these tests assert the generator covers every subcommand/flag/positional
present in the parser and emits structurally valid classic roff.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GEN_MAN = REPO_ROOT / "scripts" / "gen_man.py"

spec = importlib.util.spec_from_file_location("gen_man", GEN_MAN)
gen_man = importlib.util.module_from_spec(spec)
sys.modules.setdefault("gen_man", gen_man)
spec.loader.exec_module(gen_man)  # type: ignore[union-attr]


@pytest.fixture(scope="module")
def pages() -> dict[str, str]:
    return gen_man.generate_pages("0.0.0-test")


def _parser_commands() -> tuple[str, ...]:
    from sesslint.cli import create_parser

    parser = create_parser()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(action, argparse._SubParsersAction) and isinstance(choices, dict):
            return tuple(sorted(choices))
    raise AssertionError("no subparsers action in CLI parser")


def test_generator_exists_and_is_stdlib() -> None:
    assert GEN_MAN.is_file()
    text = GEN_MAN.read_text(encoding="utf-8")
    assert "import subprocess" not in text
    assert "import urllib" not in text and "import requests" not in text


def test_every_subcommand_gets_a_page(pages: dict[str, str]) -> None:
    expected = {f"sesslint-{name}.1" for name in _parser_commands()}
    expected.add("sesslint.1")
    assert set(pages) == expected


def test_master_page_lists_every_subcommand(pages: dict[str, str]) -> None:
    master = pages["sesslint.1"]
    assert master.startswith(".TH SESSLINT 1 ")
    commands = master.split(".SH COMMANDS")[1].split(".SH ")[0]
    for name in _parser_commands():
        assert f".B {name}" in commands or f".B {name.replace('-', chr(92) + '-')}" in commands


def test_required_sections_present(pages: dict[str, str]) -> None:
    for fname, page in pages.items():
        for section in (".TH ", ".SH NAME", ".SH SYNOPSIS", ".SH EXIT STATUS", ".SH SEE ALSO"):
            assert section in page, f"{fname}: missing {section}"
        assert ".SH NAME\n" in page


def test_every_flag_documented(pages: dict[str, str]) -> None:
    from sesslint.cli import create_parser

    parser = create_parser()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if not isinstance(action, argparse._SubParsersAction) or not isinstance(choices, dict):
            continue
        for name, sub in sorted(choices.items()):
            page = pages[f"sesslint-{name}.1"]
            for sub_action in sub._actions:
                if isinstance(
                    sub_action,
                    (argparse._HelpAction, argparse._SubParsersAction, argparse._VersionAction),
                ):
                    continue
                for opt in sub_action.option_strings:
                    escaped = opt.replace("-", "\\-")
                    assert opt in page or escaped in page, f"sesslint-{name}.1 missing flag {opt}"


def test_positional_metavars_in_synopsis(pages: dict[str, str]) -> None:
    from sesslint.cli import create_parser

    parser = create_parser()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if not isinstance(action, argparse._SubParsersAction) or not isinstance(choices, dict):
            continue
        for name, sub in choices.items():
            page = pages[f"sesslint-{name}.1"]
            synopsis = page.split(".SH SYNOPSIS")[1].split(".SH")[0]
            for sub_action in sub._actions:
                if sub_action.option_strings or isinstance(
                    sub_action, (argparse._HelpAction, argparse._SubParsersAction)
                ):
                    continue
                metavar = gen_man._metavar(sub_action)
                assert metavar in synopsis, (
                    f"sesslint-{name}.1 synopsis missing positional {metavar}"
                )


def test_deterministic_output() -> None:
    a = gen_man.generate_pages("0.0.0-test")
    b = gen_man.generate_pages("0.0.0-test")
    assert a == b


def test_roff_escaping_no_bare_leading_dots(pages: dict[str, str]) -> None:
    # A line starting with '.' that is not a macro must be escaped (\&.)
    # or it would be interpreted (and likely error) by man.
    macro = re.compile(r"^\.(TH|SH|TP|B|nf|fi|br|IP|PP|RS|RE|I|BI)\b")
    for fname, page in pages.items():
        for line in page.splitlines():
            if line.startswith("."):
                assert macro.match(line), f"{fname}: suspicious roff line {line!r}"


def test_no_content_or_secrets_in_pages(pages: dict[str, str]) -> None:
    # Pages document the CLI surface; payload/session content must never
    # appear. Spot-check that no page embeds fixture-style content.
    for fname, page in pages.items():
        assert "sesslint.session/v1" not in page.split(".SH SEE ALSO")[0] or fname == "sesslint.1"


def test_committed_goldens_match_live_parser() -> None:
    """man/ goldens are regenerated by ``python scripts/gen_man.py --out man``
    — run it (and commit) whenever the CLI surface or version changes."""
    from sesslint import __version__

    golden_dir = REPO_ROOT / "man"
    assert golden_dir.is_dir(), "man/ golden directory missing — run gen_man.py"
    live = gen_man.generate_pages(__version__)
    committed = {p.name: p.read_text(encoding="utf-8") for p in sorted(golden_dir.glob("*.1"))}
    assert committed == live, (
        "man/ pages are stale — regenerate: python scripts/gen_man.py --out man"
    )
