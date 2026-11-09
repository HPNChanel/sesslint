import hashlib
import itertools
import json
import math
import random
import struct
import types


def tag(v):
    if v is None:
        return ["null"]
    if type(v) is bool:
        return ["bool", v]
    if type(v) is int:
        return ["int", str(v)]
    if type(v) is float:
        return ["float", struct.pack(">d", v).hex()]
    if type(v) is str:
        return ["str", v]
    if type(v) is list:
        return ["array", [tag(x) for x in v]]
    return ["object", {k: tag(x) for k, x in v.items()}]


def decode(v):
    t = v[0]
    if t == "nested":
        return e.NON_SCALAR
    if t == "missing":
        return None
    if t == "null":
        return None
    if t == "int":
        return int(v[1])
    if t == "float":
        return struct.unpack(">d", bytes.fromhex(v[1]))[0]
    return v[1]


cases = []


def add(op, **kw):
    cases.append(dict(id=len(cases), op=op, **kw))


scalars = [
    None,
    False,
    True,
    -2,
    -1,
    0,
    1,
    12,
    2**53,
    2**53 + 1,
    -(2**53) - 1,
    2**63,
    -(2**63),
    10**400,
    -(10**400),
    0.0,
    -0.0,
    0.5,
    -0.5,
    12.5,
    float(2**53),
    float(2**63),
    float("inf"),
    -float("inf"),
    float("nan"),
    5e-324,
    -5e-324,
    "",
    "true",
    "false",
    "True",
    "0012",
    "12",
    "12.0",
    "12.50",
    " 12",
    "12 ",
    "12\n",
    "12\r\n",
    "١٢.٥",
    "１２",
    "²",
    "Straße",
    "\x1c É \x1f",
    "e\u0301",
    "2026-10-20T12Z",
    "2026-10-20T12",
    "1e400",
    "-0",
    "1_000",
    "null",
]
values = [tag(v) for v in scalars] + [["nested"]]
for v, steps, typed in itertools.product(
    values,
    [[], ["trim"], ["casefold"], ["casefold", "trim"], ["bad", "trim", "trim"]],
    [False, True],
):
    add("basic", value=v, steps=steps, typed=typed)
for a, b, st, tt in itertools.product(values, values, [False, True], [False, True]):
    add("equal", source=a, target=b, source_typed=st, target_typed=tt, steps=[])
for a, b in itertools.product(values, values):
    add(
        "equal",
        source=a,
        target=b,
        source_typed=False,
        target_typed=False,
        steps=["trim", "casefold"],
    )
bounds = [
    tag(v)
    for v in [None, False, True, 0, 1, 12.0, 2**53 + 1, 10**400, float("nan"), float("inf"), "12"]
]
for value, bound, op, typed in itertools.product(
    values + [["missing"]],
    bounds,
    ["present", "absent", "eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "bad"],
    [False, True],
):
    add(
        "predicate",
        value=value,
        bound=bound,
        values=[tag(None), tag("true"), tag(12), tag("Straße")],
        operator=op,
        typed=typed,
    )
rng = random.Random(17541)
for _ in range(1000):
    raw = rng.getrandbits(64)
    v = struct.unpack(">d", raw.to_bytes(8, "big"))[0]
    add("basic", value=tag(v), steps=[], typed=True)
    if math.isfinite(v):
        a = int(v) + rng.choice([-1, 0, 1])
        add(
            "predicate",
            value=tag(a),
            bound=tag(v),
            values=[],
            operator=rng.choice(["gt", "gte", "lt", "lte"]),
            typed=True,
        )
for n in [1, 2, 10, 100, 400, 4300]:
    for sign in [1, -1]:
        add(
            "predicate",
            value=tag(sign * (10 ** (n - 1) + 1)),
            bound=tag(1.7976931348623157e308),
            values=[],
            operator="gt",
            typed=True,
        )
statuses = ["VERIFIED", "VIOLATED", "PENDING", "INCONCLUSIVE", "NOT_APPLICABLE", "NOT_EVALUATED"]
for n in range(4):
    for seq in itertools.product(statuses + ["bad"], repeat=n):
        add("worst", statuses=seq)
for raw in [
    dict(id="a", type="exists", status="VERIFIED", reason="present"),
    dict(
        id="a",
        type="any_of",
        status="INCONCLUSIVE",
        reason="unknown",
        advisory=True,
        detail=dict(x=10**100, z=0.0),
        branches=[dict(id="b", type="exists", status="VIOLATED", reason="missing")],
    ),
]:
    add("condition", raw=json.dumps(raw))
add("vocabulary")
add("unicode")


def expected(engine):
    global e
    e = engine

    def result(raw):
        d = dict(raw)
        d["branches"] = tuple(result(x) for x in d.get("branches", []))
        return e.ConditionResult(**d)

    output = []
    for c in cases:
        try:
            op = c["op"]
            if op == "basic":
                v = decode(c["value"])
                n = e._number(v, typed=c["typed"])
                out = dict(
                    text=e._text(v),
                    normalized=e._normalized(v, c["steps"]),
                    number=tag(n),
                    kinds=[
                        e._kind_ok(v, k, typed=c["typed"])
                        for k in ["string", "integer", "number", "boolean", "date-time", "bad"]
                    ],
                )
            elif op == "equal":
                out = e._equal(
                    decode(c["source"]),
                    decode(c["target"]),
                    c["steps"],
                    types.SimpleNamespace(
                        source_typed=c["source_typed"], target_typed=c["target_typed"]
                    ),
                )
            elif op == "predicate":
                record = {} if c["value"][0] == "missing" else dict(x=decode(c["value"]))
                p = e.Predicate(
                    "x", c["operator"], decode(c["bound"]), tuple(decode(v) for v in c["values"])
                )
                out = e._predicate(p, record, typed=c["typed"])
            elif op == "worst":
                out = e.worst(c["statuses"])
            elif op == "condition":
                out = tag(result(json.loads(c["raw"])).to_dict())
            elif op == "vocabulary":
                out = dict(
                    statuses=list(e.STATUSES),
                    reasons=e.REASONS,
                    limitations=list(e.LIMITATIONS),
                    hashed_key_limitation=e.HASHED_KEY_LIMITATION,
                    max_unmatched_keys=e.MAX_UNMATCHED_KEYS,
                )
            elif op == "unicode":
                s = "".join(chr(n) for n in range(0x110000) if not 0xD800 <= n <= 0xDFFF)
                out = dict(
                    casefold_sha256=hashlib.sha256(
                        e._normalized(s, ["casefold"]).encode()
                    ).hexdigest(),
                    decimal=[
                        [ord(c), tag(e._number(c, typed=False))]
                        for c in s
                        if e._kind_ok(c, "integer", typed=False)
                    ],
                )
            output.append(dict(ok=out))
        except KeyError as err:
            output.append(dict(error="KeyError", key=err.args[0], text=str(err)))
    return output
