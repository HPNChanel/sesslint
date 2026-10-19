"""CLI execution context: settings resolution and leveled stderr channels.

One ``CliContext`` is built per invocation, right after argument parsing.
It resolves every overridable setting once — ``--config``/``SESSLINT_CONFIG``
picks the config file, then each setting falls back CLI > env > config file
> default — writes the resolved values back onto ``args``, and records
provenance in ``ctx.settings`` for ``--verbose`` provenance output.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TextIO

from sesslint.cli._errors import CliError
from sesslint.progress import ProgressCallback

_ENV_CONFIG: Final = "SESSLINT_CONFIG"
_ENV_PROFILE: Final = "SESSLINT_PROFILE"
_ENV_ADAPTER: Final = "SESSLINT_ADAPTER"
_ENV_FORMAT: Final = "SESSLINT_FORMAT"


@dataclass(frozen=True, slots=True)
class Setting:
    """One resolved setting value and where it came from."""

    value: object
    source: str  # "cli" | "env:SESSLINT_X" | "config:<path>" | "default"


@dataclass(slots=True)
class CliContext:
    """Per-invocation CLI context: resolved settings + stderr channels."""

    quiet: bool
    verbose: bool
    config_path: Path | None
    settings: dict[str, Setting]
    stderr: TextIO = sys.stderr

    def error(self, msg: str) -> None:
        """Always-printed stderr line (errors, usage failures)."""
        print(msg, file=self.stderr)

    def warn(self, msg: str) -> None:
        """Warnings and hints — suppressed by ``--quiet``."""
        if not self.quiet:
            print(msg, file=self.stderr)

    def info(self, msg: str) -> None:
        """Informational notes — suppressed by ``--quiet``."""
        if not self.quiet:
            print(msg, file=self.stderr)

    def debug(self, msg: str) -> None:
        """Verbose diagnostics — printed only with ``--verbose``."""
        if self.verbose:
            print(f"debug: {msg}", file=self.stderr)

    def progress_callback(self, args: argparse.Namespace) -> ProgressCallback | None:
        """Resolve the progress callback: NDJSON when ``--progress-json``,
        single-line TTY progress on an interactive stderr, else None."""
        if getattr(args, "progress_json", False):
            from sesslint.cli._progress import ndjson_progress_cb

            return ndjson_progress_cb(self.stderr)
        if self.quiet or getattr(args, "no_progress", False):
            return None
        if hasattr(self.stderr, "isatty") and self.stderr.isatty():
            from sesslint.cli._progress import TtyProgress

            return TtyProgress(self.stderr)
        return None


# (name, env_var, config_key, default)
# ``None`` env_var marks config-only settings (folded exactly as the old
# ``_apply_config`` did). ``output_format`` has no config key: its values are
# command-specific, so a shared config value could never be validated.
_SETTING_SPECS: Final[tuple[tuple[str, str | None, str | None, object], ...]] = (
    ("config", _ENV_CONFIG, None, None),
    ("profile", _ENV_PROFILE, "profile", "neutral"),
    ("adapter", _ENV_ADAPTER, "adapter", "auto"),
    ("output_format", _ENV_FORMAT, None, "human"),
    ("fail_on", None, "fail_on", "error"),
    ("policy", None, "policy", None),
    ("select", None, "select", None),
    ("ignore", None, "ignore", None),
    ("exclude", None, "exclude", None),
    ("ext", None, "ext", None),
    ("skip_undetected", None, "skip_undetected", False),
    ("fail_on_unsupported", None, "fail_on_unsupported", False),
    ("confidence_min", None, "confidence_min", None),
    ("margin_min", None, "margin_min", None),
    ("max_files", None, "max_files", 10000),
    ("max_bytes", None, "max_bytes", 1024 * 1024 * 1024),
    ("max_file_bytes", None, "max_file_bytes", 100 * 1024 * 1024),
    ("max_findings_per_code", None, "max_findings_per_code", 20),
    ("timestamp_skew_ms", None, "timestamp_skew_ms", 2000),
)

SETTING_SPECS: Final = _SETTING_SPECS

# Settings whose config fold (or built-in default) is meaningful only for
# specific commands. ``policy`` folds for repair/triage only — the old
# ``_apply_config`` refused to pretend-check other commands. ``fail_on`` is
# scoped to check: ``hook`` declares its own ``--fail-on`` vocabulary
# (never/error/warning) with an advisory ``None`` default that a written
# "error" would silently flip from never-block to block.
_SCOPED_TO_COMMANDS: Final[dict[str, frozenset[str]]] = {
    "policy": frozenset({"repair", "triage"}),
    "fail_on": frozenset({"check", "scan"}),
}


def _subparser_for(parser: argparse.ArgumentParser, command: str) -> argparse.ArgumentParser | None:
    """Return the subparser registered for ``command`` (aliases resolve)."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction) and isinstance(action.choices, dict):
            return action.choices.get(command)
    return None


def _format_choices(sub: argparse.ArgumentParser | None) -> tuple[str, ...] | None:
    """Output-format choices declared on a subparser, or None when absent.

    Commands with only ``--json`` (no ``-f/--format``) offer the implicit
    human/json pair so ``SESSLINT_FORMAT`` still validates against them.
    """
    if sub is None:
        return None
    for action in sub._actions:
        if action.dest == "output_format" and action.choices is not None:
            return tuple(str(c) for c in action.choices)
    for action in sub._actions:
        if "--json" in action.option_strings:
            return ("human", "json")
    return None


def _cli_supplied(args: argparse.Namespace, name: str) -> object | None:
    """Return the CLI-typed value for ``name``, or None when unset.

    Argparse leaves config-overridable options at ``None`` (or absent under
    ``SUPPRESS``); boolean toggles count as supplied only when True.
    """
    value: object = getattr(args, name, None)
    if value is None or value is False:
        return None
    return value


def _resolve_output_format(
    args: argparse.Namespace,
    env: Mapping[str, str],
    config_src: str | None,
    sub: argparse.ArgumentParser | None,
) -> Setting:
    """Resolve ``output_format``: ``--json`` > ``-f/--format`` > env > human."""
    del config_src
    if getattr(args, "json", False):
        return Setting("json", "cli")
    cli_fmt = getattr(args, "output_format", None)
    if cli_fmt is not None:
        return Setting(cli_fmt, "cli")
    env_val = env.get(_ENV_FORMAT)
    if env_val is not None:
        choices = _format_choices(sub)
        if choices is not None:
            if env_val not in choices:
                raise CliError(
                    2,
                    f"Invalid {_ENV_FORMAT}={env_val!r}: choose from {', '.join(choices)}",
                )
            return Setting(env_val, f"env:{_ENV_FORMAT}")
        # The command declares no output format — the variable has nothing
        # to apply to, so it is ignored rather than failing spuriously.
    return Setting("human", "default")


def build_context(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    environ: Mapping[str, str] | None = None,
) -> CliContext:
    """Resolve settings (CLI > env > config > default) and fold them onto ``args``.

    Loads the config file exactly once — explicit ``--config``/
    ``SESSLINT_CONFIG`` path or upward discovery — and raises ``CliError(2)``
    on config or env validation failures. ``policy`` only folds for the
    commands that accept it (repair, triage), matching the old
    ``_apply_config`` scoping.
    """
    env = os.environ if environ is None else environ

    from sesslint.config import ConfigError, find_config_file, load_config

    command = getattr(args, "command", None)
    sub = _subparser_for(parser, str(command)) if command is not None else None

    cli_config = getattr(args, "config", None)
    config_path: Path | None = None
    if cli_config is not None:
        config_path = Path(cli_config)
    elif env.get(_ENV_CONFIG):
        config_path = Path(env[_ENV_CONFIG])
    try:
        cfg = load_config(explicit=config_path)
    except ConfigError as err:
        raise CliError(2, f"Error: {err}") from err
    if config_path is None:
        config_path = find_config_file(Path.cwd())
    config_src = f"config:{config_path}" if config_path is not None else None

    settings: dict[str, Setting] = {}

    # select/ignore share one axis (mutually exclusive at the CLI and in
    # config): an explicit CLI choice wins outright; otherwise the config
    # axis applies — exactly the old _apply_config behaviour.
    cli_select = _cli_supplied(args, "select")
    cli_ignore = _cli_supplied(args, "ignore")

    for name, env_var, cfg_key, default in _SETTING_SPECS:
        if name == "output_format":
            settings[name] = _resolve_output_format(args, env, config_src, sub)
            continue
        if name == "config":
            value: object = cli_config if cli_config is not None else env.get(_ENV_CONFIG)
            source = (
                "cli"
                if cli_config is not None
                else (f"env:{_ENV_CONFIG}" if value is not None else "default")
            )
            settings[name] = Setting(Path(str(value)) if value is not None else None, source)
            continue

        cli_val = _cli_supplied(args, name)
        if name in ("select", "ignore"):
            # Jointly resolved below.
            continue
        scoped = _SCOPED_TO_COMMANDS.get(name)
        if scoped is not None and str(command) not in scoped and cli_val is None:
            # Setting does not apply to this command: record provenance as
            # unset so no value is folded onto args.
            settings[name] = Setting(None, "default")
            continue
        cfg_val: object = cfg.get(cfg_key) if cfg_key is not None else None

        if cli_val is not None:
            settings[name] = Setting(cli_val, "cli")
        elif env_var is not None and env.get(env_var) is not None:
            raw = env[env_var]
            if name == "adapter":
                from sesslint.adapters import VALID_FORMAT_OPTIONS

                if raw not in VALID_FORMAT_OPTIONS:
                    raise CliError(
                        2,
                        f"Invalid {env_var}={raw!r}: "
                        f"not a supported adapter (choose from "
                        f"{', '.join(sorted(VALID_FORMAT_OPTIONS))})",
                    )
            elif name == "profile":
                from sesslint.profiles.profile import list_profiles

                if raw not in list_profiles():
                    raise CliError(
                        2,
                        f"Invalid {env_var}={raw!r}: "
                        f"not a registered profile (choose from "
                        f"{', '.join(list_profiles())})",
                    )
            settings[name] = Setting(raw, f"env:{env_var}")
        elif cfg_val is not None:
            settings[name] = Setting(cfg_val, config_src or "config")
        else:
            settings[name] = Setting(default, "default")

    if cli_select is not None:
        settings["select"] = Setting(cli_select, "cli")
        settings["ignore"] = Setting(None, "cli")
    elif cli_ignore is not None:
        settings["ignore"] = Setting(cli_ignore, "cli")
        settings["select"] = Setting(None, "cli")
    elif cfg.get("select"):
        settings["select"] = Setting(",".join(cfg["select"]), config_src or "config")
        settings["ignore"] = Setting(None, config_src or "config")
    elif cfg.get("ignore"):
        settings["ignore"] = Setting(",".join(cfg["ignore"]), config_src or "config")
        settings["select"] = Setting(None, config_src or "config")
    else:
        settings["select"] = Setting(None, "default")
        settings["ignore"] = Setting(None, "default")

    for name, setting in settings.items():
        # Config-folded keys carry concrete built-in defaults that the old
        # ``_apply_config`` always wrote (commands read e.g. ``args.fail_on``
        # directly). Two exceptions keep absent semantics intact: a ``None``
        # default means "unset" and must stay absent/None so ``getattr``
        # fallbacks (e.g. triage's policy="conservative") fire; and
        # ``output_format`` has command-specific parser defaults (hook
        # defaults to "text"), so it is only written when a real source
        # supplied a value — ``_output_format`` maps None/absent itself.
        if setting.source == "default" and (setting.value is None or name == "output_format"):
            continue
        setattr(args, name, setting.value)

    return CliContext(
        quiet=bool(getattr(args, "quiet", False)),
        verbose=bool(getattr(args, "verbose", False)),
        config_path=config_path,
        settings=settings,
        stderr=sys.stderr,
    )
