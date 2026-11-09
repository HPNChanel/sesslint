"""Seeded synthetic grammar for codec and adapter-helper differential smoke."""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from typing import Any

MAX_CASES = 100_000
MAX_LINE = 262_144
OPERATIONS = ("codec", "adapter_discriminator", "adapter_type", "adapter_detect")
ALPHABET = "abcXYZ019_.- /\\\n\t\x00áΩ中😀\x7f"
FLOAT_EDGES = (
    0,
    1,
    0x8000000000000000,
    0x3FB999999999999A,
    0x3FD3333333333333,
    0x7FEFFFFFFFFFFFFF,
    0x0010000000000000,
    0x7FF0000000000000,
    0xFFF0000000000000,
    0x7FF8000000000000,
    0xC30FA36FD398D412,
)


def encoded(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def text(rng: random.Random, maximum: int = 32) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randrange(maximum + 1)))


def node(rng: random.Random, depth: int = 0) -> dict[str, Any]:
    kinds = ["null", "bool", "int", "float", "str"]
    if depth < 4:
        kinds += ["array", "object"]
    kind = rng.choice(kinds)
    if kind == "null":
        return {"kind": kind}
    if kind == "bool":
        return {"kind": kind, "value": bool(rng.getrandbits(1))}
    if kind == "int":
        return {"kind": kind, "value": str(rng.randrange(-(1 << 100), 1 << 100))}
    if kind == "float":
        bits = rng.getrandbits(64) if rng.randrange(2) else rng.choice(FLOAT_EDGES)
        return {"kind": kind, "bits": f"{bits:016x}"}
    if kind == "str":
        return {"kind": kind, "value": text(rng)}
    if kind == "array":
        return {"kind": kind, "items": [node(rng, depth + 1) for _ in range(rng.randrange(4))]}
    # Unique field names prevent non-Python duplicate-map objects entering the domain.
    keys = sorted({text(rng, 10) for _ in range(rng.randrange(4))})
    rng.shuffle(keys)
    return {"kind": kind, "items": [[key, node(rng, depth + 1)] for key in keys]}


def adapter_node(rng: random.Random) -> dict[str, Any]:
    kind = rng.choice(
        ["str"] * 5
        + ["int", "float", "bool", "null", "bytes", "array", "object", "tuple", "set", "foreign"]
    )
    if kind == "str":
        candidates = [
            "",
            "event",
            "tool_call",
            "a" * 64,
            "a" * 65,
            " Bearer synthetic ",
            "sk-synthetic-not-a-real-token",
            "Authorization",
            "password",
            "request.id",
            text(rng, 100),
            "".join(rng.choice("abCD019_.-") for _ in range(rng.randrange(80))),
        ]
        return {"kind": kind, "value": rng.choice(candidates)}
    return {"kind": kind, "length": rng.randrange(129)}


def detect_bytes(rng: random.Random, index: int) -> bytes:
    templates = [
        b"",
        b'{"schema":"sesslint.session/v1"}',
        b'{"schema_version" : "sesslint.session/v1"}',
        b'{"schema": "sesslint.session/v2"}',
        b"sesslint.session",
        b"synthetic unrelated",
        b'{"schema"\t:\n"sesslint.session/v1"}',
    ]
    value = rng.choice(templates)
    if index % 997 == 0:
        value = b" " * 65520 + value
    mode = rng.randrange(5)
    if mode == 0:
        value = b"\xef\xbb\xbf" + value
    elif mode == 1:
        value = value[: rng.randrange(len(value) + 1)]
    elif mode == 2:
        position = rng.randrange(len(value) + 1)
        value = (
            value[:position]
            + bytes(rng.randrange(256) for _ in range(rng.randrange(12)))
            + value[position:]
        )
    elif mode == 3:
        value = bytes(rng.randrange(256) for _ in range(rng.randrange(128))) + value
    return value


def iter_cases(seed: int, count: int) -> Iterator[dict[str, Any]]:
    if type(seed) is not int or type(count) is not int or not 1 <= count <= MAX_CASES:
        raise ValueError("invalid campaign size or seed")
    rng = random.Random(seed)
    anchors = ["foreign", "bad_key", "cycle_array", "cycle_object"]
    for index in range(count):
        op = OPERATIONS[index % len(OPERATIONS)]
        case: dict[str, Any] = {"id": index, "op": op}
        if op == "codec":
            case["input"] = {"kind": anchors[index // 4]} if index < 16 else node(rng)
            case["newline"] = bool(rng.getrandbits(1))
        elif op == "adapter_detect":
            case["input"] = {"hex": detect_bytes(rng, index).hex()}
        else:
            case["input"] = adapter_node(rng)
        if len(encoded(case)) > MAX_LINE:
            raise ValueError("generated case exceeds line budget")
        yield case


def generate(seed: int, count: int) -> list[dict[str, Any]]:
    return list(iter_cases(seed, count))
