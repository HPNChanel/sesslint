"""User configuration loading for the SessLint CLI (FR: lint-tool table stakes).

Resolution order for each supported option:

1. Explicit CLI argument (highest precedence).
2. ``[tool.sesslint]`` in ``pyproject.toml``, or a standalone
   ``sesslint.toml`` / ``.sesslint.toml`` file, discovered by walking upward
   from the current working directory (nearest wins). ``--config PATH``
   overrides discovery.
3. Built-in defaults.

Configuration is loaded with the stdlib ``tomllib`` only — no runtime
dependency. Unknown keys, wrong types, a file that sets both ``select`` and
``ignore``, and unreadable explicit config paths fail closed with a usage
error rather than being silently ignored. A ``pyproject.toml`` that contains
the literal marker ``[tool.sesslint`` but cannot be parsed also fails closed:
discovery must not substitute a parent config for a present-but-unparseable
sesslint section. A ``pyproject.toml`` without that marker is not a sesslint
config, so a parse or encoding failure there is skipped and the walk continues.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Final

from sesslint.profiles.profile import VALID_FORMATS

_CONFIG_FILENAMES: Final = ("sesslint.toml", ".sesslint.toml", "pyproject.toml")
_PYPROJECT_SECTION: Final = ("tool", "sesslint")
# Literal bytes, not a parsed table. Used only after a pyproject.toml fails
# to parse, so a broken ``[tool.sesslint]`` header cannot be skipped.
_PYPROJECT_SESSLINT_MARKER: Final = b"[tool.sesslint"

# Flat key set shared by check/scan/repair. Command-irrelevant keys are
# ignored per command; unknown keys are rejected outright.
_ALLOWED_KEYS: Final = frozenset(
    {
        "profile",
        "format",
        "policy",
        "fail_on",
        "select",
        "ignore",
        "skip_undetected",
        "confidence_min",
        "margin_min",
        "max_files",
        "max_bytes",
        "exclude",
        "ext",
    }
)

_STR_KEYS: Final = frozenset({"profile", "format", "policy", "fail_on"})
_BOOL_KEYS: Final = frozenset({"skip_undetected"})
_FLOAT_KEYS: Final = frozenset({"confidence_min", "margin_min"})
_INT_KEYS: Final = frozenset({"max_files", "max_bytes"})
_LIST_KEYS: Final = frozenset({"select", "ignore", "exclude", "ext"})

_ENUM_VALUES: Final = {
    "fail_on": ("error", "warning"),
    "policy": ("conservative", "salvage"),
    "format": tuple(sorted(VALID_FORMATS)),
}


def _allowed_profiles() -> tuple[str, ...]:
    """Return registered profile names (deferred import: profiles -> config cycle guard)."""
    from sesslint.profiles.profile import list_profiles

    return tuple(list_profiles())


class ConfigError(ValueError):
    """Raised when a sesslint config file is unreadable or invalid."""


def _extract_section(path: Path, raw: dict[str, Any]) -> dict[str, Any] | None:
    if path.name == "pyproject.toml":
        node: Any = raw
        for key in _PYPROJECT_SECTION:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return node if isinstance(node, dict) else None
    return raw


def _read_pyproject(candidate: Path) -> dict[str, Any] | None:
    """Parse a ``pyproject.toml`` candidate during discovery.

    Returns the document when it parses. Returns None when the file is
    unreadable, or when it is not valid UTF-8 / TOML and its bytes do not
    contain ``[tool.sesslint``. Those files are not sesslint configs, so the
    walk continues (an unrelated syntax error must not hide a parent
    ``sesslint.toml``).

    Raises:
        ConfigError: the file contains ``[tool.sesslint`` but cannot be
            parsed. The message names ``candidate`` and the parse error.
            Callers must not keep walking after this.
    """
    try:
        blob = candidate.read_bytes()
    except OSError:
        return None
    try:
        raw = tomllib.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        if _PYPROJECT_SESSLINT_MARKER in blob:
            raise ConfigError(f"Invalid TOML in {candidate}: {err}") from err
        return None
    return raw


def find_config_file(start: Path) -> Path | None:
    """Walk upward from ``start`` returning the nearest config file, or None.

    Within one directory the precedence is ``sesslint.toml`` >
    ``.sesslint.toml`` > ``pyproject.toml`` (the last only when it carries a
    ``[tool.sesslint]`` section).

    A ``pyproject.toml`` that contains the literal marker ``[tool.sesslint``
    but cannot be parsed raises ``ConfigError`` (the file and the parse error
    are named). Invalid TOML or invalid UTF-8 in a ``pyproject.toml`` without
    that marker is skipped. An unreadable candidate is skipped because the
    marker cannot be confirmed; an explicit ``--config`` path still fails
    closed in ``load_config``.

    Raises:
        ConfigError: a discovered ``pyproject.toml`` declares a sesslint
            section but is not valid TOML or UTF-8.
    """
    directory = start if start.is_dir() else start.parent
    for current in (directory, *directory.parents):
        for name in _CONFIG_FILENAMES:
            candidate = current / name
            if not candidate.is_file():
                continue
            if name == "pyproject.toml":
                raw = _read_pyproject(candidate)
                if raw is not None and _extract_section(candidate, raw) is not None:
                    return candidate
                continue
            return candidate
    return None


def _validate_keys(cfg: dict[str, Any], source: Path) -> dict[str, Any]:
    unknown = sorted(set(cfg) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError(
            f"Unknown sesslint config key(s) {unknown} in {source}. "
            f"Allowed keys: {sorted(_ALLOWED_KEYS)}"
        )
    # Presence, not truthiness: an empty list is still the key being set.
    # CLI apply uses if/elif and would otherwise drop ``ignore`` silently.
    if "select" in cfg and "ignore" in cfg:
        raise ConfigError(f"Config keys 'select' and 'ignore' are mutually exclusive in {source}")
    out: dict[str, Any] = {}
    for key, value in cfg.items():
        if key in _STR_KEYS:
            if not isinstance(value, str) or not value.strip():
                raise ConfigError(f"Config key {key!r} must be a non-empty string in {source}")
            value = value.strip()
            allowed = _ENUM_VALUES.get(key)
            if key == "profile":
                allowed = _allowed_profiles()
            if allowed is not None and value not in allowed:
                raise ConfigError(
                    f"Config key {key!r} must be one of {list(allowed)} in {source}, got {value!r}"
                )
        elif key in _BOOL_KEYS:
            if not isinstance(value, bool):
                raise ConfigError(f"Config key {key!r} must be a boolean in {source}")
        elif key in _FLOAT_KEYS:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigError(f"Config key {key!r} must be a number in {source}")
            value = float(value)
        elif key in _INT_KEYS:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigError(f"Config key {key!r} must be a positive integer in {source}")
        elif key in _LIST_KEYS:
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item.strip() for item in value
            ):
                raise ConfigError(
                    f"Config key {key!r} must be a list of non-empty strings in {source}"
                )
            value = [item.strip() for item in value]
        out[key] = value
    return out


def load_config(
    *,
    start: Path | None = None,
    explicit: Path | None = None,
) -> dict[str, Any]:
    """Load and validate sesslint configuration.

    Args:
        start: Directory (or file) the upward discovery walk starts from;
            defaults to the current working directory.
        explicit: ``--config`` path; disables discovery and must exist.

    Returns:
        Validated flat mapping of config keys. Empty when nothing is found.

    Raises:
        ConfigError: explicit path missing/unreadable, TOML parse failure,
            invalid keys/values, both ``select`` and ``ignore`` set, or a
            discovered ``pyproject.toml`` that contains ``[tool.sesslint``
            but cannot be parsed.
    """
    if explicit is not None:
        if explicit.is_dir():
            raise ConfigError(
                f"Config path is a directory, not a file: {explicit} "
                f"(pass a sesslint.toml / .sesslint.toml / pyproject.toml path)"
            )
        if not explicit.is_file():
            raise ConfigError(f"Config file not found: {explicit}")
        config_path = explicit
    else:
        base = start if start is not None else Path.cwd()
        discovered = find_config_file(base)
        if discovered is None:
            return {}
        config_path = discovered

    try:
        with config_path.open("rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as err:
        raise ConfigError(f"Invalid TOML in {config_path}: {err}") from err
    except OSError as err:
        raise ConfigError(f"Cannot read config file {config_path}: {err}") from err

    section = _extract_section(config_path, raw)
    if section is None:
        if explicit is not None:
            raise ConfigError(f"No [tool.sesslint] section found in {config_path}")
        return {}
    return _validate_keys(section, config_path)
