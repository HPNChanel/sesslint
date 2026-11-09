import itertools
import json
import random
import struct
import types
from datetime import UTC, datetime, timedelta


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


def raw(v):
    return json.dumps(v, ensure_ascii=True, allow_nan=False)


T = ["2026-11-09T00:00:00Z", "2026-11-09T00:00:01Z", "2026-11-09T00:00:02Z"]
base = dict(
    fields=["x", "done"],
    completeness="complete",
    observed=T[2],
    as_of=T[1],
    unkeyed=0,
    source_typed=True,
    target_typed=True,
    deadline=T[1],
    due_known=True,
    records=[],
    source=raw({"x": "a"}),
)
cases = []


def add(op, **kw):
    cases.append(dict(base, op=op, id=len(cases), **kw))


values = [
    None,
    False,
    True,
    0,
    1,
    -1,
    2**53 + 1,
    10**100,
    0.0,
    1.5,
    "",
    "a",
    "A",
    " a ",
    "Straße",
    "STRASSE",
    "true",
    "12",
    "١٢",
    "1e400",
    [],
    {},
    "2026-11-09T00:00:01Z",
]
records = [{}] + [{"x": v} for v in values]
for record, fields in itertools.product(
    records, [[], ["x"], ["missing", "x"], ["x", "missing"], ["x", "x"]]
):
    add("key", source=raw(record), fields=fields)
preds = [
    dict(field="x", op=op, value=val)
    for op, val in [
        ("present", None),
        ("absent", None),
        ("eq", "a"),
        ("ne", None),
        ("gt", 0),
        ("lt", 1),
    ]
]
for record, pair, typed in itertools.product(
    records, itertools.product(preds, repeat=2), [False, True]
):
    add("predicates", source=raw(record), predicates=pair, typed=typed)
for complete, observed, as_of, unkeyed, deadline, known in itertools.product(
    ["complete", "partial", "unknown", "unavailable"],
    [None, *T],
    [T[0], T[2]],
    [0, 1],
    [None, T[1]],
    [False, True],
):
    add(
        "gates",
        completeness=complete,
        observed=observed,
        as_of=as_of,
        unkeyed=unkeyed,
        deadline=deadline,
        due_known=known,
    )
conditions = [
    dict(id="c", type="required", field="x", allow_null=n, allow_empty=e)
    for n, e in itertools.product([False, True], repeat=2)
]
conditions += [
    dict(id="c", type="equals", field="x", source_field="x", normalize=n)
    for n in [[], ["trim"], ["casefold"]]
]
conditions += [
    dict(id="c", type="type", field="x", kind=k)
    for k in ["string", "integer", "number", "boolean", "date-time", "bad"]
]
conditions += [
    dict(id="c", type=k, field="x", values=[None, "a", "strasse", True, 12], normalize=n)
    for k, n in itertools.product(["one_of", "route"], [[], ["trim", "casefold"]])
]
conditions += [
    dict(id="c", type="range", field="x", minimum=lo, maximum=hi)
    for lo, hi in [(None, None), (0, 2), (1.5, None), (None, 1), (1e300, 1e300)]
]
for c, record, typed in itertools.product(conditions, records, [False, True]):
    add("field", condition=c, records=[raw(record)], target_typed=typed)
    for src in [{}, {"x": None}, {"x": {}}, {"x": 1}, {"x": "A"}] if c["type"] == "equals" else []:
        add("field", condition=c, records=[raw(record)], source=raw(src), target_typed=typed)
for c in conditions:
    for rows in [[], [{}, {"x": "a"}], [{"x": None}, {"x": {}}], [{"x": "a"}, {"x": None}]]:
        add("field", condition=c, records=[raw(r) for r in rows])
    add("field", condition=c, records=[raw({"x": "a"})], fields=[])
rng = random.Random(3602)
for _i in range(5000):
    kw = dict(
        completeness=rng.choice(["complete", "partial", "unknown", "unavailable"]),
        observed=rng.choice([None, *T]),
        as_of=rng.choice(T),
        unkeyed=rng.choice([0, 1]),
        deadline=rng.choice([None, *T]),
        due_known=rng.choice([False, True]),
    )
    low, high = rng.choice(
        [
            (None, None),
            (0, 0),
            (0, None),
            (1, 1),
            (2, 3),
            (1.9, 3.9),
            (-2, -1),
            (1e300, None),
            (None, 1e300),
            (0.0, -0.0),
        ]
    )
    add(
        "count",
        condition=dict(id="c", type=rng.choice(["exists", "count"]), minimum=low, maximum=high),
        matched=rng.choice([0, 1, 2, 3, 4, 100]),
        **kw,
    )
    time = rng.choice(
        [None, "invalid", {}, *T, "2026-11-09T00:00:01.000001Z", "2026-11-09T00:00:00.999999Z"]
    )
    rows = rng.choice(
        [
            [],
            [{}],
            [{"done": time}],
            [{"done": time}, {"done": T[0]}],
            [{"done": time}, {"done": T[2]}],
        ]
    )
    add(
        "time",
        condition=dict(
            id="c", type="on_time", basis=rng.choice(["observation", "target_time"]), field="done"
        ),
        records=[raw(r) for r in rows],
        fields=rng.choice([[], ["done"]]),
        **kw,
    )
for deadline, end in [
    ("0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999Z"),
    ("1700-01-01T00:00:00Z", "9999-12-31T23:59:59.999999Z"),
    (T[0], "2026-11-09T00:00:00.999999Z"),
]:
    add(
        "time",
        condition=dict(id="c", type="on_time", basis="target_time", field="done"),
        records=[raw({"done": end})],
        deadline=deadline,
    )
for seconds in [10**9, 10**10, 10**11, 2 * 10**11, 3 * 10**11] + [
    2**k + d for k in range(32, 39) for d in [-1, 0, 1]
]:
    for micros in range(65):
        end = (
            datetime(1, 1, 1, tzinfo=UTC) + timedelta(microseconds=seconds * 1000000 - micros)
        ).isoformat()
        add(
            "time",
            condition=dict(id="c", type="on_time", basis="target_time", field="done"),
            records=[raw({"done": end})],
            deadline="0001-01-01T00:00:00Z",
        )
for c in conditions + [
    dict(id="c", type="exists"),
    dict(id="c", type="count", minimum=0, maximum=1),
    dict(id="c", type="on_time", field="done", basis="target_time"),
]:
    for complete, rows, known, disabled in itertools.product(
        ["complete", "unavailable"],
        [[], [raw({"x": "a", "done": T[0]})]],
        [False, True],
        [None, ""],
    ):
        add(
            "eval",
            condition=dict(c, disabled=disabled),
            records=rows,
            completeness=complete,
            due_known=known,
        )
for pred, src in itertools.product(preds, [{}, {"x": None}, {"x": "a"}, {"x": 2}]):
    add(
        "eval",
        condition=dict(id="route", type="route", field="x", when=[pred], values=["a"]),
        source=raw(src),
        records=[raw({"x": "a"})],
        completeness="unavailable",
    )
branches = [
    dict(id="a", type="exists"),
    dict(id="b", type="exists", disabled=""),
    dict(id="c", type="required", field="x"),
    dict(id="d", type="route", field="x", when=[dict(field="x", op="absent")], values=["a"]),
    dict(id="e", type="equals", field="x", source_field="missing"),
]
for seq, rows in itertools.product(
    itertools.product(branches, repeat=2), [[], [raw({"x": "a"})], [raw({})]]
):
    add("eval", condition=dict(id="any", type="any_of", conditions=seq), records=rows)
add("eval", condition=dict(id="any", type="any_of", conditions=[]))
statuses = ["VERIFIED", "VIOLATED", "INCONCLUSIVE", "PENDING", "NOT_EVALUATED", "NOT_APPLICABLE"]
for n in range(4):
    for seq in itertools.product(statuses, repeat=n):
        add("per_record", results=[dict(status=s) for s in seq])
        for mode in ["plain", "advisory", "disabled"]:
            add(
                "item",
                results=[
                    dict(
                        status=s,
                        advisory=mode == "advisory" and i == 0,
                        reason="disabled" if mode == "disabled" and i == 0 else "present",
                    )
                    for i, s in enumerate(seq)
                ],
            )
for second in ["c", "other"]:
    add(
        "allowed",
        condition=dict(
            id="c", type="one_of", values=[None, "Straße", " A ", 1], normalize=["trim", "casefold"]
        ),
        next=dict(id=second, type="one_of", values=["different"]),
    )


def expected(engine):
    global e
    e = engine

    def condition(c):
        c = dict(c)
        c["when"] = tuple(e.Predicate(**p) for p in c.get("when", []))
        c["conditions"] = tuple(condition(x) for x in c.get("conditions", []))
        return e.Condition(**c)

    def record(s):
        return (
            e.NON_SCALAR
            if False
            else {
                k: v if v is None or type(v) in (str, int, float, bool) else e.NON_SCALAR
                for k, v in json.loads(s).items()
            }
        )

    def ctx(c):
        target = types.SimpleNamespace(
            fields=set(c["fields"]),
            observed_at=e.parse_instant(c["observed"]),
            completeness=c["completeness"],
        )
        return e._Context(
            types.SimpleNamespace(),
            target,
            e.parse_instant(c["as_of"]),
            c["unkeyed"],
            c["source_typed"],
            c["target_typed"],
        )

    def triple(r):
        return [r[0], r[1], tag(r[2])]

    output = []
    for c in cases:
        op = c["op"]
        d = e.parse_instant(c["deadline"])
        known = c["due_known"]
        context = ctx(c)
        if op == "key":
            k, r = e._key(record(c["source"]), c["fields"])
            out = [list(k) if k is not None else None, r]
        elif op == "predicates":
            out = list(
                e._all_predicates(
                    [e.Predicate(**p) for p in c["predicates"]],
                    record(c["source"]),
                    typed=c["typed"],
                )
            )
        elif op == "gates":
            w = e._waiting(context, d, known)
            out = [e._absence_blocker(context, d), list(w) if w else None]
        elif op == "per_record":
            out = triple(
                e._per_record([(r["status"], f"r{i}", {}) for i, r in enumerate(c["results"])])
            )
        elif op == "item":
            out = list(
                e._item_verdict(
                    [
                        e.ConditionResult("c", "exists", r["status"], r["reason"], r["advisory"])
                        for r in c["results"]
                    ]
                )
            )
        elif op == "allowed":
            out = [
                sorted(context.allowed(condition(c[k])), key=lambda v: (v is not None, v))
                for k in ["condition", "next"]
            ]
        else:
            cond = condition(c["condition"])
            rows = [record(s) for s in c["records"]]
            src = record(c["source"])
            if op == "field":
                out = triple(e._field_check(cond, rows, context, src))
            elif op == "count":
                out = triple(e._count_check(cond, c["matched"], context, d, known))
            elif op == "time":
                out = triple(e._on_time_check(cond, rows, context, d, known))
            elif op == "eval":
                out = tag(e._evaluate_condition(cond, src, rows, context, d, known).to_dict())
            else:
                raise AssertionError(op)
        output.append(dict(ok=out))
    return output
