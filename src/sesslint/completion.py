"""Shell completion script generation (T-13).

Generates bash/zsh/fish/powershell completion scripts at runtime from the
live argparse parser, so completion can never drift from the CLI surface:
there are no checked-in static scripts. Pure string building, deterministic
output.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

COMPLETION_SHELLS: Final[tuple[str, ...]] = ("bash", "zsh", "fish", "powershell")
PROG: Final[str] = "sesslint"


def _profile_choices() -> tuple[str, ...]:
    """Live profile names from the registry (profiles are config-extensible,
    so argparse deliberately leaves ``--profile`` choice-free)."""
    from sesslint.profiles import list_profiles

    return tuple(sorted(list_profiles()))


_LIVE_CHOICES: Final[dict[str, Callable[[], tuple[str, ...]]]] = {
    "--profile": _profile_choices,
}


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
                if not fixed:
                    for opt in option_strings:
                        provider = _LIVE_CHOICES.get(opt)
                        if provider is not None:
                            fixed = provider()
                            break
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


def _ps_quote(value: str) -> str:
    """Single-quote a literal for PowerShell (embedded quotes doubled)."""
    return "'" + value.replace("'", "''") + "'"


def _powershell_script(commands: tuple[_Command, ...]) -> str:
    """Render a PowerShell completion script (Register-ArgumentCompleter -Native).

    Data tables (command names, per-command flags, per-flag fixed choices,
    tooltips) are emitted as literal hashtables; the scriptblock completes
    subcommand names, flags, and choice values. Compatible with Windows
    PowerShell 5.1 and pwsh 7 — the common ``-Native`` completer subset.
    """
    names = ", ".join(_ps_quote(c.name) for c in commands)
    flag_rows: list[str] = []
    choice_rows: list[str] = []
    help_rows: list[str] = []
    for cmd in commands:
        opts = [o for f in cmd.flags for o in f.options]
        flag_rows.append(f"    {_ps_quote(cmd.name)} = @({', '.join(_ps_quote(o) for o in opts)})")
        for flag in cmd.flags:
            for opt in flag.options:
                if flag.choices:
                    vals = ", ".join(_ps_quote(v) for v in flag.choices)
                    choice_rows.append(f"    {_ps_quote(cmd.name + ' ' + opt)} = @({vals})")
                if flag.help:
                    help_rows.append(
                        f"    {_ps_quote(cmd.name + ' ' + opt)} = {_ps_quote(flag.help)}"
                    )
    flags_table = "\n".join(flag_rows)
    choices_table = "\n".join(choice_rows)
    help_table = "\n".join(help_rows)
    return f"""# {PROG} completion (powershell) - generated at runtime; do not edit.
# Install: paste this script into your $PROFILE, or run:
#   sesslint completion powershell >> $PROFILE
${PROG}CommandNames = @({names})
${PROG}FlagMap = @{{
{flags_table}
}}
${PROG}ChoiceMap = @{{
{choices_table}
}}
${PROG}HelpMap = @{{
{help_table}
}}
${PROG}Core = {{
    param($wordToComplete, $commandAst)
    $elements = @($commandAst.CommandElements)
    $prevIndex = $elements.Count - 1
    if ($wordToComplete -ne '' -and $prevIndex -ge 1) {{ $prevIndex-- }}
    $prev = if ($prevIndex -ge 1) {{ $elements[$prevIndex].Extent.Text }} else {{ $null }}
    $cmd = $null
    for ($i = 1; $i -le $prevIndex; $i++) {{
        $t = $elements[$i].Extent.Text
        if (-not $t.StartsWith('-')) {{ $cmd = $t; break }}
    }}
    $candidates = @()
    if ($null -eq $cmd) {{
        $candidates = ${PROG}CommandNames
    }} elseif ($null -ne $prev -and ${PROG}ChoiceMap.ContainsKey("$cmd $prev")) {{
        $candidates = ${PROG}ChoiceMap["$cmd $prev"]
    }} elseif (${PROG}FlagMap.ContainsKey($cmd)) {{
        $candidates = ${PROG}FlagMap[$cmd]
    }}
    $candidates | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        $tip = ${PROG}HelpMap["$cmd $_"]
        if ($null -eq $tip) {{ $tip = $_ }}
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $tip)
    }}
}}
$_rac = Get-Command Register-ArgumentCompleter -ErrorAction SilentlyContinue
if ($null -ne $_rac -and $_rac.Parameters.ContainsKey('Native')) {{
    Register-ArgumentCompleter -Native -CommandName {PROG} -ScriptBlock {{
        param($wordToComplete, $commandAst, $cursorPosition)
        & ${PROG}Core $wordToComplete $commandAst
    }}.GetNewClosure()
}} else {{
    Register-ArgumentCompleter -CommandName {PROG} -ScriptBlock {{
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        & ${PROG}Core $wordToComplete $commandAst
    }}.GetNewClosure()
}}
"""


_GENERATORS = {
    "bash": _bash_script,
    "zsh": _zsh_script,
    "fish": _fish_script,
    "powershell": _powershell_script,
}


def generate_completion(shell: str, *, parser: argparse.ArgumentParser | None = None) -> str:
    """Generate the completion script for a shell from the live parser.

    Args:
        shell: One of 'bash', 'zsh', 'fish', 'powershell'.
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
