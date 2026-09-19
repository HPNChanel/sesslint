"""Conformance: ``schemas/sesslint-config.schema.json`` vs ``config.py`` truth.

The schema is generated-checked against ``config.py``'s own validation tables
so the two cannot silently drift: every case the runtime accepts must
validate, and every case the runtime rejects must fail — except documented
one-way gaps where draft-07 is expressively looser than TOML typing (the
schema is advisory; ``config.py`` stays the strict authority).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

from sesslint import config
from sesslint.config import ConfigError

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "sesslint-config.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft7Validator(SCHEMA)

_SOURCE = Path("matrix.toml")


def _config_accepts(cfg: dict[str, Any]) -> bool:
    try:
        config._validate_keys(dict(cfg), _SOURCE)
    except ConfigError:
        return False
    return True


def _schema_accepts(cfg: dict[str, Any]) -> bool:
    return VALIDATOR.is_valid(cfg)


def _valid_value_for(key: str) -> Any:
    if key == "profile":
        return config._allowed_profiles()[0]
    if key in config._ENUM_VALUES:
        return sorted(config._ENUM_VALUES[key])[0]
    if key in config._BOOL_KEYS:
        return True
    if key in config._FLOAT_KEYS:
        return 0.5
    if key in config._INT_KEYS:
        return 4
    if key in config._LIST_KEYS:
        return ["SL101"]
    raise AssertionError(f"untyped key {key!r} not covered by config tables")


def _invalid_values_for(key: str) -> list[Any]:
    """Wrong-type / wrong-value cases for ``key``; all must fail in both validators."""
    if key in config._STR_KEYS:
        return [3, "", "   ", "bogus-value", ["x"], True]
    if key in config._BOOL_KEYS:
        return ["true", 1, 0, ["x"]]
    if key in config._FLOAT_KEYS:
        return ["0.5", True, [0.5], {"v": 0.5}]
    if key in config._INT_KEYS:
        return ["4", 4.5, 4.0, 0, -3, True, [4]]
    if key in config._LIST_KEYS:
        return ["SL101", [""], ["  "], [1], {"a": 1}]
    raise AssertionError(f"untyped key {key!r} not covered by config tables")


# Documented schema-looser gaps (draft-07 "integer" accepts integral floats;
# config.py requires a TOML int). Schema must never be STRICTER than runtime.
KNOWN_GAPS = {"integer-valued float for int key"}


def test_schema_is_valid_draft07() -> None:
    Draft7Validator.check_schema(SCHEMA)


def test_schema_property_set_mirrors_allowed_keys() -> None:
    assert set(SCHEMA["properties"]) == set(config._ALLOWED_KEYS)
    assert SCHEMA["additionalProperties"] is False
    assert SCHEMA["type"] == "object"


def test_schema_enums_mirror_runtime_tables() -> None:
    for key, values in config._ENUM_VALUES.items():
        assert set(SCHEMA["properties"][key]["enum"]) == set(values), key
    assert set(SCHEMA["properties"]["profile"]["enum"]) == set(config._allowed_profiles())


def test_empty_config_validates() -> None:
    assert _config_accepts({}) and _schema_accepts({})


@pytest.mark.parametrize("key", sorted(config._ALLOWED_KEYS))
def test_each_key_valid_value(key: str) -> None:
    cfg = {key: _valid_value_for(key)}
    assert _config_accepts(cfg), f"runtime rejected canonical valid {key!r}"
    assert _schema_accepts(cfg), f"schema rejected runtime-valid {key!r}"


@pytest.mark.parametrize("key", sorted(config._LIST_KEYS))
def test_empty_list_is_valid(key: str) -> None:
    """config.py treats an empty list as valid (vacuous all()); schema must too."""
    cfg = {key: []}
    assert _config_accepts(cfg)
    assert _schema_accepts(cfg), f"schema stricter than runtime for {key!r} = []"


def test_full_config_all_keys() -> None:
    cfg = {key: _valid_value_for(key) for key in sorted(config._ALLOWED_KEYS)}
    assert _config_accepts(cfg)
    assert _schema_accepts(cfg)


def test_negative_float_is_valid_parity() -> None:
    """config.py accepts any float (no bounds); schema must not add one."""
    for key in sorted(config._FLOAT_KEYS):
        cfg = {key: -1.25}
        assert _config_accepts(cfg)
        assert _schema_accepts(cfg), f"schema added a bound config lacks: {key!r}"


@pytest.mark.parametrize("key", sorted(config._ALLOWED_KEYS))
def test_each_key_invalid_values(key: str) -> None:
    for bad in _invalid_values_for(key):
        cfg = {key: bad}
        assert not _config_accepts(cfg), f"runtime accepted {key!r}={bad!r}"
        name = f"{key}={bad!r}"
        if key in config._INT_KEYS and isinstance(bad, float) and bad.is_integer():
            name = "integer-valued float for int key"
        if name in KNOWN_GAPS:
            assert _schema_accepts(cfg), f"expected schema-looser gap for {name}"
        else:
            assert not _schema_accepts(cfg), f"schema accepted runtime-invalid {name}"


def test_unknown_keys_rejected() -> None:
    for cfg in ({"bogus": 1}, {"select": ["SL101"], "typo": "x"}, {"PROFILES": "x"}):
        assert not _config_accepts(cfg)
        assert not _schema_accepts(cfg), f"schema accepted unknown keys: {cfg}"


def test_schema_never_stricter_than_runtime() -> None:
    """Property check: for every matrix case, config-accept ⟹ schema-accept."""
    cases: list[dict[str, Any]] = [{}]
    for key in sorted(config._ALLOWED_KEYS):
        cases.append({key: _valid_value_for(key)})
        cases.extend({key: bad} for bad in _invalid_values_for(key))
    for cfg in cases:
        if _config_accepts(cfg):
            assert _schema_accepts(cfg), f"schema stricter than runtime: {cfg}"
