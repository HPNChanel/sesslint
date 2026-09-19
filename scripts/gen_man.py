#!/usr/bin/env python3
"""Generate classic-roff man pages from the live sesslint argparse tree.

Like ``sesslint.completion``, the pages cannot drift from the CLI surface
because they are built from the parser, not hand-maintained. Deterministic:
sorted subcommands, parser-order flags, fixed header fields, LF endings.

Usage::

    python scripts/gen_man.py --out dist/man

Emits ``sesslint.1`` (master) plus ``sesslint-<command>.1`` per subcommand.
Stdlib only; dev/build tooling — never shipped inside the wheel.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

PROG: Final[str] = "sesslint"

_EXIT_STATUS: Final[str] = """.SH EXIT STATUS
.TP
.B 0
Success — clean check, or repair executed, validated, and manifested.
.TP
.B 1
Finding / refusal — diagnostic errors found, repair plan blocked, or
execution refused (TOCTOU, SL203).
.TP
.B 2
Operational error — CLI syntax error, file not found, permission denied,
or live-DB path refusal.
.TP
.B 130
Cancelled — interrupted via Ctrl+C or a cooperative cancellation request;
partial outputs are cleaned up."""

_SEE_ALSO_TAIL: Final[str] = """Full documentation: the docs/ tree in the source repository
(docs/SPEC.md, docs/codes/, docs/recipes/, docs/adr/, docs/THREAT_MODEL.md),
or the project site."""


@dataclass(frozen=True, slots=True)
class _Positional:
    dest: str
    metavar: str
    nargs: str | None
    help: str


@dataclass(frozen=True, slots=True)
class _Option:
    option_strings: tuple[str, ...]
    metavar: str | None
    takes_value: bool
    required: bool
    choices: tuple[str, ...]
    default: object
    help: str


@dataclass(frozen=True, slots=True)
class _Command:
    name: str
    help: str
    description: str
    positionals: tuple[_Positional, ...]
    options: tuple[_Option, ...]


def _clean(raw: object) -> str:
    if raw is None or raw == argparse.SUPPRESS or not isinstance(raw, str):
        return ""
    return " ".join(raw.split())


def _metavar(action: argparse.Action) -> str:
    if action.metavar:
        return str(action.metavar)
    if isinstance(action.choices, (list, tuple)) and action.choices:
        return "{" + ",".join(str(c) for c in action.choices) + "}"
    return action.dest.upper()


def _harvest_command(name: str, sub: argparse.ArgumentParser) -> _Command:
    positionals: list[_Positional] = []
    options: list[_Option] = []
    for action in sub._actions:
        if isinstance(
            action, (argparse._HelpAction, argparse._SubParsersAction, argparse._VersionAction)
        ):
            continue
        if action.option_strings:
            takes_value = not isinstance(
                action,
                (
                    argparse._StoreTrueAction,
                    argparse._StoreFalseAction,
                    argparse._StoreConstAction,
                    argparse._AppendConstAction,
                    argparse._CountAction,
                ),
            )
            choices: tuple[str, ...] = ()
            if isinstance(action.choices, (list, tuple)) and all(
                isinstance(c, str) for c in action.choices
            ):
                choices = tuple(str(c) for c in action.choices)
            options.append(
                _Option(
                    option_strings=tuple(action.option_strings),
                    metavar=_metavar(action) if takes_value else None,
                    takes_value=takes_value,
                    required=bool(action.required),
                    choices=choices,
                    default=None if action.default in (argparse.SUPPRESS, None) else action.default,
                    help=_clean(action.help),
                )
            )
        else:
            positionals.append(
                _Positional(
                    dest=action.dest,
                    metavar=_metavar(action),
                    nargs=action.nargs,
                    help=_clean(action.help),
                )
            )
    return _Command(
        name=name,
        help=_clean(getattr(sub, "_help_string", "") or ""),
        description=_clean(sub.description) or _clean(getattr(sub, "_help_string", "") or ""),
        positionals=tuple(positionals),
        options=tuple(options),
    )


def harvest(parser: argparse.ArgumentParser) -> tuple[_Command, ...]:
    """Harvest every subcommand (sorted) with positionals and options."""
    commands: list[_Command] = []
    for action in parser._actions:
        choices_obj = getattr(action, "choices", None)
        if not isinstance(action, argparse._SubParsersAction) or not isinstance(choices_obj, dict):
            continue
        for name in sorted(choices_obj):
            sub = choices_obj[name]
            # argparse stores add_parser(help=...) on the action's choices
            # pseudo-actions; pull the per-subcommand help text from there.
            help_str = ""
            for pseudo in action._choices_actions:
                if pseudo.dest == name:
                    help_str = _clean(pseudo.help)
                    break
            cmd = _harvest_command(name, sub)
            commands.append(
                _Command(
                    name=cmd.name,
                    help=help_str or cmd.help,
                    description=cmd.description or help_str,
                    positionals=cmd.positionals,
                    options=cmd.options,
                )
            )
    return tuple(commands)


def _esc(text: str) -> str:
    """Escape text for roff: backslashes, hyphens, leading . and '."""
    out = text.replace("\\", "\\e").replace("-", "\\-")
    if out[:1] in (".", "'"):
        out = "\\&" + out
    return out


def _esc_line(line: str) -> str:
    return "\\&" + line if line[:1] in (".", "'") else line


def _literal_block(text: str) -> list[str]:
    """Render multi-line text as an .nf/.fi literal block."""
    lines = [".nf"]
    lines += [_esc_line(ln.rstrip()) for ln in text.splitlines()]
    lines.append(".fi")
    return lines


def _th(title: str, version: str) -> list[str]:
    # No date field — output must be byte-identical across build days.
    return [f'.TH {title} 1 "" "SessLint {version}" "SessLint Manual"']


def _synopsis_parts(cmd: _Command) -> list[str]:
    parts = [f"{PROG} {cmd.name}"]
    for opt in cmd.options:
        token = " | ".join(opt.option_strings)
        if opt.takes_value:
            token += f" {opt.metavar}"
        parts.append(token if opt.required else f"[{token}]")
    for pos in cmd.positionals:
        token = pos.metavar
        if pos.nargs in ("+", "*"):
            token += "..."
        elif pos.nargs == "?":
            token = f"[{token}]"
        parts.append(token)
    return parts


def _emit_command(cmd: _Command, version: str, all_names: tuple[str, ...]) -> str:
    title = f"{PROG}-{cmd.name}".upper()
    lines = _th(title, version)
    lines += [
        ".SH NAME",
        f"{PROG}-{cmd.name} \\- {_esc(cmd.help or 'sesslint subcommand')}",
        ".SH SYNOPSIS",
        ".B " + _esc(" ".join(_synopsis_parts(cmd))),
    ]
    if cmd.description:
        lines += [".SH DESCRIPTION", _esc(cmd.description)]
    if cmd.positionals:
        lines.append(".SH ARGUMENTS")
        for pos in cmd.positionals:
            lines.append(".TP")
            lines.append(".B " + _esc(pos.metavar))
            lines.append(_esc(pos.help) if pos.help else "Required argument.")
    if cmd.options:
        lines.append(".SH OPTIONS")
        for opt in cmd.options:
            head = ", ".join(
                f"{o} {opt.metavar}" if opt.takes_value else o for o in opt.option_strings
            )
            body_parts: list[str] = []
            if opt.help:
                body_parts.append(opt.help)
            if opt.choices:
                body_parts.append("Choices: " + ", ".join(opt.choices) + ".")
            if opt.takes_value and opt.default not in (None, ""):
                body_parts.append(f"Default: {opt.default}.")
            lines.append(".TP")
            lines.append(".B " + _esc(head))
            if body_parts:
                lines.append(_esc(" ".join(body_parts)))
    lines.append(_EXIT_STATUS)
    see_also = [f"{PROG}(1)"]
    see_also += [f"{PROG}-{n}(1)" for n in all_names if n != cmd.name][:3]
    lines.append(".SH SEE ALSO")
    lines.append(_esc(", ".join(see_also)) + ".")
    lines.append("")
    lines += _literal_block(_SEE_ALSO_TAIL)
    lines.append("")
    return "\n".join(lines) + "\n"


def _emit_master(commands: tuple[_Command, ...], version: str) -> str:
    lines = _th("SESSLINT", version)
    lines += [
        ".SH NAME",
        f"{PROG} \\- offline, vendor-neutral session integrity checker and "
        "conservative repair tool",
        ".SH SYNOPSIS",
        ".B sesslint",
        "[\\-\\-color auto|always|never] [\\-\\-profile PROFILE] <command> [<args>]",
        ".SH DESCRIPTION",
        "SessLint inspects AI agent session ledgers (Claude Code JSONL,",
        "OpenAI Agents exports, Codex rollout streams, and the canonical",
        "sesslint.session/v1 format) for structural and integrity defects,",
        "and can conservatively repair a bounded set of them. It runs fully",
        "offline with zero runtime dependencies, produces content-free",
        "findings by default, and fails closed whenever repair safety cannot",
        "be proven.",
        ".SH COMMANDS",
    ]
    for cmd in commands:
        lines.append(".TP")
        lines.append(".B " + _esc(cmd.name))
        lines.append(_esc(cmd.help or "See the subcommand man page."))
    lines += [
        ".SH GLOBAL OPTIONS",
        ".TP",
        ".B \\-\\-profile PROFILE",
        "Replay validation profile (default: neutral).",
        ".TP",
        ".B \\-\\-color auto|always|never",
        "Control colored terminal output (default: auto).",
        ".TP",
        ".B \\-\\-no\\-color",
        "Disable ANSI color styling (equivalent to NO_COLOR=1).",
        ".TP",
        ".B \\-\\-version",
        "Print version and exit.",
        ".SH FILES",
        ".TP",
        ".B .sesslint.toml / pyproject.toml [tool.sesslint]",
        "Optional configuration file and section.",
    ]
    lines.append(_EXIT_STATUS)
    lines.append(".SH SEE ALSO")
    see = ", ".join(f"{PROG}-{c.name}(1)" for c in commands[:8])
    lines.append(_esc(see) + ".")
    lines.append("")
    lines += _literal_block(_SEE_ALSO_TAIL)
    lines.append("")
    return "\n".join(lines) + "\n"


def generate_pages(version: str) -> dict[str, str]:
    """Return {filename: roff text} for the master page + every subcommand."""
    from sesslint.cli import create_parser

    commands = harvest(create_parser())
    names = tuple(c.name for c in commands)
    pages = {f"{PROG}.1": _emit_master(commands, version)}
    for cmd in commands:
        pages[f"{PROG}-{cmd.name}.1"] = _emit_command(cmd, version, names)
    return pages


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("dist") / "man",
        help="Output directory for generated pages (default: dist/man)",
    )
    args = ap.parse_args(argv)

    from sesslint import __version__

    pages = generate_pages(__version__)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(pages):
        (args.out / name).write_bytes(pages[name].encode("utf-8"))
    print(f"wrote {len(pages)} man pages to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
