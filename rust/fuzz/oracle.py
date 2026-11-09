"""Batch oracle loaded from the exact exported Python pin, stdlib only."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any

from cases import MAX_CASES, MAX_LINE, encoded


def value(node: dict[str, Any], depth: int = 0) -> Any:
    if depth > 24:
        raise ValueError("input_depth")
    kind = node["kind"]
    if kind == "null":
        return None
    if kind in ("bool", "str"):
        return node["value"]
    if kind == "int":
        return int(node["value"])
    if kind == "float":
        return struct.unpack(">d", bytes.fromhex(node["bits"]))[0]
    if kind == "array":
        return [value(item, depth + 1) for item in node["items"]]
    if kind == "object":
        return {key: value(item, depth + 1) for key, item in node["items"]}
    if kind == "foreign":
        return object()
    if kind == "bad_key":
        return {42: None}
    if kind == "cycle_array":
        out: list[Any] = []
        out.append(out)
        return out
    if kind == "cycle_object":
        mapping: dict[str, Any] = {}
        mapping["self"] = mapping
        return mapping
    raise ValueError("unknown_kind")


def adapter_value(node: dict[str, Any]) -> Any:
    kind = node["kind"]
    if kind == "str":
        return node["value"]
    if kind == "int":
        return 1
    if kind == "float":
        return 0.5
    if kind == "bool":
        return True
    if kind == "null":
        return None
    if kind == "foreign":
        return object()
    length = node["length"]
    if type(length) is not int or not 0 <= length <= 512:
        raise ValueError("invalid_length")
    constructors = {
        "bytes": lambda: bytes(length),
        "array": lambda: [None] * length,
        "object": lambda: {str(i): None for i in range(length)},
        "tuple": lambda: (None,) * length,
        "set": lambda: set(range(length)),
    }
    return constructors[kind]()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source / "src"))
    from sesslint._canonical_codec import PurePythonCanonicalCodec
    from sesslint.adapters.canonical import detect_canonical
    from sesslint.adapters.safe_value import safe_discriminator, safe_type_value
    from sesslint.errors import SchemaError

    codec = PurePythonCanonicalCodec()
    index = 0
    while line := sys.stdin.buffer.readline(MAX_LINE + 1):
        if len(line) > MAX_LINE or index >= MAX_CASES:
            raise ValueError("input_budget")
        case = json.loads(line)
        if type(case["id"]) is not int or case["id"] != index:
            raise ValueError("case_order")
        op = case["op"]
        response: dict[str, Any] = {"id": index, "ok": True}
        if op == "codec":
            try:
                response["output_hex"] = codec.canonical_json_bytes(
                    value(case["input"]), newline=case["newline"]
                ).hex()
            except SchemaError as error:
                response = {"id": index, "ok": False, "error": str(error)}
        elif op == "adapter_discriminator":
            response["output"] = safe_discriminator(adapter_value(case["input"]))
        elif op == "adapter_type":
            response["output"] = safe_type_value(adapter_value(case["input"]))
        elif op == "adapter_detect":
            score = detect_canonical(bytes.fromhex(case["input"]["hex"]), "synthetic.jsonl")
            response["output"] = struct.pack(">d", score).hex()
        else:
            raise ValueError("unknown_operation")
        sys.stdout.buffer.write(encoded(response))
        index += 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Infrastructure errors are not model refusals and must fail the batch.
        sys.stderr.write("reason=oracle_failed\n")
        raise SystemExit(2) from None
