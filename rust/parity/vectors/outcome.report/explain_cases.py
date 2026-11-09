import itertools
import json
import math
import random
import struct


def bits(v):
    return None if v is None else struct.pack(">d", v).hex()


def raw(v):
    return json.dumps(v, ensure_ascii=True, allow_nan=False)


def cond(type_, **kw):
    return dict(
        dict(
            id="c",
            type=type_,
            field="field-é",
            source_field="source-é",
            kind="integer",
            values=[None, False, 1, 1.5, "é🚀"],
            normalize=["trim", "casefold"],
            when=[dict(field="paid", op="present")],
        ),
        **kw,
    )


cases = []


def add(c):
    cases.append(dict(op="condition", condition=c))


for kind, disabled, advisory in itertools.product(
    [
        "exists",
        "count",
        "required",
        "type",
        "one_of",
        "equals",
        "range",
        "route",
        "on_time",
        "any_of",
        "unknown",
    ],
    [None, "", "reason"],
    [False, True],
):
    for lo, hi in [(None, None), (0, 0), (1, 2), (-0.9, 0.9), (1.5, None), (None, 1e100)]:
        add(
            cond(
                kind,
                disabled=disabled,
                advisory=advisory,
                minimum_bits=bits(lo),
                maximum_bits=bits(hi),
                allow_null=True,
                allow_empty=True,
                basis="target_time",
                conditions=[cond("exists"), cond("required", advisory=True)],
            )
        )
for field, source, kind, basis, lo, hi in itertools.product(
    [None, ""], [None, ""], [None, "string"], [None, "observation"], [False, True], [False, True]
):
    for typ in ["required", "type", "one_of", "equals", "range", "route", "on_time"]:
        add(
            cond(
                typ,
                field=field,
                source_field=source,
                kind=kind,
                basis=basis,
                allow_null=lo,
                allow_empty=hi,
                when=[],
            )
        )
numbers = [
    0.0,
    -0.0,
    1e-4,
    1e-5,
    1e5,
    1e6,
    999999.4,
    999999.5,
    999999.6,
    5e-324,
    1.7976931348623157e308,
    float("nan"),
    float("inf"),
    -float("inf"),
]
for exp in range(-12, 13):
    for digits in [1, 9.999994, 9.999995, 9.999996, 1.234565, 1.234575]:
        v = digits * 10**exp
        numbers.extend([v, -v, math.nextafter(v, math.inf), math.nextafter(v, -math.inf)])
rng = random.Random(4002)
for _ in range(10000):
    numbers.append(struct.unpack(">d", rng.getrandbits(64).to_bytes(8, "big"))[0])
for n in numbers:
    add(cond("range", minimum_bits=bits(n), maximum_bits=bits(-n)))
    add(cond("count", minimum_bits=bits(n), maximum_bits=bits(n)))
for _ in range(300):
    children = [rng.choice(cases)["condition"] for _ in range(rng.randrange(1, 4))]
    add(cond("any_of", conditions=children))
condition_cases = cases.copy()
for _ in range(300):
    conditions = [rng.choice(condition_cases)["condition"] for _ in range(rng.randrange(4))]
    c = dict(
        name="synthetic-é🚀",
        version="1",
        description=rng.choice([None, "", "text"]),
        source_key=rng.choice([[], ["id"], ["first", "second"]]),
        target_key=["ref"],
        eligibility=rng.choice([[], [dict(field="p", op="eq", value=True)]]),
        due=rng.choice(
            [
                None,
                dict(source_time_field="start", within_seconds=0),
                dict(source_time_field="start", within_seconds=315576000),
            ]
        ),
        conditions=conditions,
        sha256=rng.choice(["0" * 64, "🚀" * 20, "abc"]),
    )
    cases.append(dict(op="contract", contract=c))


def expected(engine, report):
    r = report
    from sesslint.outcome.contract import Condition, Contract, Due, Predicate

    def condition(c):
        c = dict(c)
        c["minimum"] = (
            struct.unpack(">d", bytes.fromhex(c.pop("minimum_bits")))[0]
            if c.get("minimum_bits")
            else None
        )
        c.pop("minimum_bits", None)
        c["maximum"] = (
            struct.unpack(">d", bytes.fromhex(c.pop("maximum_bits")))[0]
            if c.get("maximum_bits")
            else None
        )
        c.pop("maximum_bits", None)
        c["when"] = tuple(Predicate(**p) for p in c.get("when", []))
        c["conditions"] = tuple(condition(x) for x in c.get("conditions", []))
        return Condition(**c)

    output = []
    for c in cases:
        try:
            if c["op"] == "condition":
                out = r._describe_condition(condition(c["condition"]))
            else:
                v = dict(c["contract"])
                v["conditions"] = tuple(condition(x) for x in v["conditions"])
                v["eligibility"] = tuple(Predicate(**p) for p in v["eligibility"])
                v["due"] = Due(**v["due"]) if v["due"] else None
                out = r.explain_contract(Contract(**v))
            output.append(dict(ok=out))
        except (KeyError, ValueError, OverflowError) as error:
            output.append(dict(error=str(error)))
    return output
