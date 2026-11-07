#!/usr/bin/env python3
"""Build and validate rx-receipt/v1 JSON from an rx_gates gate log."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_ID = "rx-receipt/v1"
ENVELOPE_BEGIN = "# rx-receipt-envelope/v1"
ENVELOPE_END = "# /rx-receipt-envelope/v1"

_GATE_CMD = re.compile(r"^rx-gates: (fmt|clippy|test): (.*)$")
_GATE_SUMMARY = re.compile(
    r"^rx-gates: summary scope=\S+ fmt=(\d+|skipped) "
    r"clippy=(\d+|skipped) test=(\d+|skipped)$"
)

_EXIT_INCONCLUSIVE = 1
_EXIT_USAGE = 2


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_schema_path() -> Path:
    return _repo_root() / "schemas" / "rx-receipt.v1.json"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def extract_envelope(text: str) -> dict[str, Any]:
    start = text.find(ENVELOPE_BEGIN)
    if start < 0:
        raise ValueError(f"gate log missing {ENVELOPE_BEGIN!r} marker")
    start = text.index("\n", start) + 1
    end = text.find(ENVELOPE_END, start)
    if end < 0:
        raise ValueError(f"gate log missing {ENVELOPE_END!r} marker")
    block = text[start:end].strip()
    if not block:
        raise ValueError("gate log envelope block is empty")
    payload = json.loads(block)
    if not isinstance(payload, dict):
        raise ValueError("gate log envelope must be a JSON object")
    return payload


def _summary_token(token: str) -> int | None:
    if token == "skipped":
        return None
    return int(token)


def parse_rx_gates_log(text: str) -> list[dict[str, Any]]:
    cmd_lines: dict[str, str] = {}
    summary: tuple[int | None, int | None, int | None] | None = None
    for line in text.splitlines():
        m = _GATE_CMD.match(line.strip())
        if m:
            cmd_lines[m.group(1)] = m.group(2).strip()
            continue
        sm = _GATE_SUMMARY.match(line.strip())
        if sm:
            summary = (
                _summary_token(sm.group(1)),
                _summary_token(sm.group(2)),
                _summary_token(sm.group(3)),
            )
    if summary is None:
        raise ValueError("gate log missing rx-gates summary line")

    order = ("fmt", "clippy", "test")
    commands: list[dict[str, Any]] = []
    for gate in order:
        cmd_text = cmd_lines.get(gate)
        exit_code = summary[order.index(gate)]
        if cmd_text is None and exit_code is None:
            continue
        if cmd_text is None:
            raise ValueError(f"gate log missing rx-gates {gate} command line")
        commands.append(
            {
                "cmd": cmd_text,
                "exit": exit_code if exit_code is not None else -1,
                "pass": None,
                "fail": None,
                "skip": None,
                "log": "",
            }
        )
    if not commands:
        raise ValueError("gate log produced no commands")
    return commands


def _missing_required_paths(schema: dict[str, Any], data: Any, prefix: str = "") -> list[str]:
    missing: list[str] = []
    if not isinstance(data, dict):
        return [prefix or "<root>"]

    required = schema.get("required", [])
    for key in required:
        path = f"{prefix}.{key}" if prefix else key
        if key not in data:
            missing.append(path)
            continue
        value = data[key]
        props = schema.get("properties", {})
        subschema = props.get(key)
        if subschema is None:
            continue
        if subschema.get("type") == "object":
            missing.extend(_missing_required_paths(subschema, value, path))
        elif subschema.get("type") == "array" and "items" in subschema:
            if not isinstance(value, list):
                missing.append(path)
                continue
            item_schema = subschema["items"]
            min_items = subschema.get("minItems", 0)
            if len(value) < min_items:
                missing.append(f"{path}[length<{min_items}]")
            for idx, item in enumerate(value):
                if item_schema.get("type") == "object":
                    missing.extend(
                        _missing_required_paths(item_schema, item, f"{path}[{idx}]")
                    )
    return missing


def _validate_with_jsonschema(schema: dict[str, Any], data: dict[str, Any]) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema is required for receipt validation; install dev extras"
        ) from exc
    jsonschema.validate(data, schema)


def compute_verdict(commands: list[dict[str, Any]]) -> str:
    for row in commands:
        exit_code = row.get("exit")
        if not isinstance(exit_code, int):
            return "INCONCLUSIVE"
        if exit_code != 0:
            return "FAIL"
        skip = row.get("skip")
        if isinstance(skip, int) and skip > 0:
            return "FAIL"
    return "PASS"


def build_receipt(gate_log_text: str, envelope: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    commands = parse_rx_gates_log(gate_log_text)
    receipt = _deep_merge({"schema": SCHEMA_ID}, envelope)
    receipt["commands"] = commands

    schema_path = default_schema_path()
    schema = _load_json(schema_path)
    missing = [
        path
        for path in _missing_required_paths(schema, receipt)
        if path != "verdict"
    ]
    if missing:
        receipt["verdict"] = "INCONCLUSIVE"
        note = receipt.get("notes", "")
        suffix = f"Missing required field(s): {', '.join(sorted(missing))}."
        receipt["notes"] = f"{note} {suffix}".strip() if note else suffix
        return receipt, missing

    receipt["verdict"] = compute_verdict(commands)
    return receipt, []


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def cmd_write(args: argparse.Namespace) -> int:
    gate_log = Path(args.gate_log)
    out = Path(args.output)
    schema_path = Path(args.schema) if args.schema else default_schema_path()
    text = gate_log.read_text(encoding="utf-8")
    envelope = extract_envelope(text)
    receipt, missing = build_receipt(text, envelope)
    write_receipt(out, receipt)

    if missing:
        return _EXIT_INCONCLUSIVE

    schema = _load_json(schema_path)
    _validate_with_jsonschema(schema, receipt)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt)
    schema_path = Path(args.schema) if args.schema else default_schema_path()
    receipt = _load_json(receipt_path)
    schema = _load_json(schema_path)
    missing = [
        path
        for path in _missing_required_paths(schema, receipt)
        if path != "verdict"
    ]
    if missing:
        return _EXIT_INCONCLUSIVE
    if receipt.get("verdict") == "INCONCLUSIVE":
        return _EXIT_INCONCLUSIVE
    _validate_with_jsonschema(schema, receipt)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write or validate rx-receipt/v1 JSON.")
    sub = parser.add_subparsers(dest="command", required=True)

    write_p = sub.add_parser("write", help="Build receipt JSON from a gate log")
    write_p.add_argument("--gate-log", required=True, help="Path to rx_gates gate log")
    write_p.add_argument("--output", required=True, help="Output receipt JSON path")
    write_p.add_argument("--schema", help="Override rx-receipt JSON Schema path")
    write_p.set_defaults(func=cmd_write)

    validate_p = sub.add_parser("validate", help="Validate an existing receipt JSON")
    validate_p.add_argument("--receipt", required=True, help="Receipt JSON path")
    validate_p.add_argument("--schema", help="Override rx-receipt JSON Schema path")
    validate_p.set_defaults(func=cmd_validate)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"rx_receipt: {exc}", file=sys.stderr)
        return _EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
