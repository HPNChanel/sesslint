"""Shell completion script generation (T-13).

Generates bash/zsh/fish completion scripts at runtime from the live argparse
parser, so completion can never drift from the CLI surface: there are no
checked-in static scripts. Pure string building, deterministic output.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Final

COMPLETION_SHELLS: Final[tuple[str, ...]] = ("bash", "zsh", "fish")
PROG: Final[str] = "sesslint"


@dataclass(frozen=True, slots=True)
class _Flag:
    """A completable flag with optional fixed choices."""

    options: tuple[str, ...]
    choices: tuple[str, ...] = ()
    help: str = ""


@dataclass(frozen=True, slots=True)
class _Command:
    """A subcommand with its completable flags."""

    name: str
    flags: tuple[_Flag, ...] = ()


def _clean_help(raw: object) -> str:
    """Return single-line help text, or empty string when suppressed."""
    if raw is None or raw == argparse.SUPPRESS or not isinstance(raw, str):
        return ""
    return " ".join(raw.split())[:120]


def _harvest_parser(parser: argparse.ArgumentParser) -> tuple[_Command, ...]:
    """Harvest subcommands and flags from a live argparse parser."""
    commands: list[_Command] = []
    for action in parser._actions:
        choices_obj = getattr(action, "choices", None)
        if not isinstance(action, argparse._SubParsersAction) or not isinstance(choices_obj, dict):
            continue
        for name in sorted(choices_obj.keys()):
            sub = choices_obj[name]
            flags: list[_Flag] = []
            for sub_action in sub._actions:
                if isinstance(sub_action, (argparse._HelpAction, argparse._SubParsersAction)):
                    continue
                option_strings = [o for o in sub_action.option_strings if o.startswith("-")]
                if not option_strings:
                    continue
                raw_choices = getattr(sub_action, "choices", None)
                fixed: tuple[str, ...] = ()
                if isinstance(raw_choices, (list, tuple)) and all(
                    isinstance(c, str) for c in raw_choices
                ):
                    fixed = tuple(sorted(str(c) for c in raw_choices))
                flags.append(
                    _Flag(
                        options=tuple(sorted(option_strings)),
                        choices=fixed,
                        help=_clean_help(sub_action.help),
                    )
                )
            commands.append(_Command(name=name, flags=tuple(flags)))
    return tuple(commands)


def _bash_script(commands: tuple[_Command, ...]) -> str:
    """Render a bash completion script."""
    names = " ".join(c.name for c in commands)
    case_blocks: list[str] = []
    for cmd in commands:
        flag_words = " ".join(o for f in cmd.flags for o in f.options)
        choice_cases: list[str] = []
        for flag in cmd.flags:
            if not flag.choices:
                continue
            for opt in flag.options:
                values = " ".join(flag.choices)
                choice_cases.append(
                    f'                    {opt}) COMPREPLY=( $(compgen -W "{values}"'
                    f' -- "$cur") ); return 0 ;;'
                )
        block = f'            {cmd.name})\n                opts="{flag_words}"'
        if choice_cases:
            joined_cases = "\n".join(choice_cases)
            block += f'\n                case "$prev" in\n{joined_cases}\n                esac'
        block += " ;;"
        case_blocks.append(block)
    cases = "\n".join(case_blocks)
    return f"""# {PROG} completion (bash) - generated at runtime; do not edit.
_{PROG}_complete() {{
    local cur prev cmd opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    cmd=""
    for w in "${{COMP_WORDS[@]:1}}"; do
        case "$w" in
            -*) continue ;;
            *) cmd="$w"; break ;;
        esac
    done
    if [ -z "$cmd" ]; then
        COMPREPLY=( $(compgen -W "{names}" -- "$cur") )
        return 0
    fi
    case "$cmd" in
{cases}
        *) return 0 ;;
    esac
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    return 0
}}
complete -F _{PROG}_complete {PROG}
"""


def _zsh_script(commands: tuple[_Command, ...]) -> str:
    """Render a zsh completion script."""
    names = " ".join(f"'{c.name}:sesslint {c.name} command'" for c in commands)
    case_blocks: list[str] = []
    for cmd in commands:
        specs: list[str] = []
        for flag in cmd.flags:
            safe_help = (
                flag.help.replace(":", "\\:")
                .replace("'", "")
                .replace("[", "\\[")
                .replace("]", "\\]")
            )
            for opt in flag.options:
                if flag.choices:
                    choices_str = " ".join(flag.choices)
                    specs.append(f"'{opt}[{safe_help}]:value:({choices_str})'")
                else:
                    specs.append(f"'{opt}[{safe_help}]'")
        joined = " ".join(specs)
        case_blocks.append(f"      {cmd.name}) _arguments -s {joined} ;;")
    cases = "\n".join(case_blocks)
    return f"""#compdef {PROG}
# {PROG} completion (zsh) - generated at runtime; do not edit.
_{PROG}() {{
    local -a commands=({names})
    local curcontext="$curcontext" state ret=1
    _arguments -C '1:command:->cmd' '*:: :->args' && ret=0
    case $state in
        cmd) _describe 'command' commands && ret=0 ;;
        args) case $words[1] in
{cases}
            *) _arguments '*:file:_files' && ret=0 ;;
        esac ;;
    esac
    return ret
}}
_{PROG}
"""


def _fish_script(commands: tuple[_Command, ...]) -> str:
    """Render a fish completion script."""
    names = " ".join(c.name for c in commands)
    lines = [
        f"# {PROG} completion (fish) - generated at runtime; do not edit.",
        f'complete -c {PROG} -n "__fish_use_subcommand" -a "{names}"',
    ]
    for cmd in commands:
        for flag in cmd.flags:
            lines.append(f"# {cmd.name} {' '.join(flag.options)}")
            desc = flag.help.replace("'", "")
            for opt in sorted(flag.options):
                if opt.startswith("--"):
                    opt_part = f"-l {opt[2:]}"
                else:
                    opt_part = f"-s {opt[1:]}"
                parts = [
                    f"complete -c {PROG}",
                    f'-n "__fish_seen_subcommand_from {cmd.name}"',
                    opt_part,
                ]
                if flag.choices:
                    choices_str = " ".join(flag.choices)
                    parts.append(f'-a "{choices_str}"')
                if desc:
                    parts.append(f"-d '{desc}'")
                lines.append(" ".join(parts))
    return "\n".join(lines) + "\n"


_GENERATORS = {
    "bash": _bash_script,
    "zsh": _zsh_script,
    "fish": _fish_script,
}


def generate_completion(shell: str, *, parser: argparse.ArgumentParser | None = None) -> str:
    """Generate the completion script for a shell from the live parser.

    Args:
        shell: One of 'bash', 'zsh', 'fish'.
        parser: Parser to harvest (defaults to the real CLI parser).

    Raises:
        ValueError: If the shell is not supported.
    """
    if shell not in _GENERATORS:
        raise ValueError(f"Unsupported shell {shell!r}; expected one of {COMPLETION_SHELLS}")
    if parser is None:
        from sesslint.cli import create_parser

        parser = create_parser()
    commands = _harvest_parser(parser)
    return _GENERATORS[shell](commands)


__all__ = [
    "COMPLETION_SHELLS",
    "generate_completion",
]
